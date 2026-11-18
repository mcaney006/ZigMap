//! Event-driven scan engine.
//!
//! One thread drives every probe: there is no thread per port or per host.
//! The engine owns all scheduling state (hosts, probe pool, timers,
//! windows, results); the transport owns sockets/packets and reports
//! completions. `Engine(Transport)` is generic so the identical logic runs
//! against the kernel (connect scan) and the deterministic simulator used
//! by the tests.
//!
//! Transport contract (duck-typed, checked at compile time):
//!   fn now(*T) u64                                   monotonic ns
//!   fn send(*T, slot: u32, gen: u32, addr: Addr, port: u16) SendOutcome
//!   fn poll(*T, timeout_ns: u64, out: []Event) usize  waits at most timeout
//!   fn cancel(*T, slot: u32) void                     drop transport state
//!
//! Classification lives in the transport-specific `classify` callback in
//! `Config`, because the meaning of a reply depends on the scan method.

const std = @import("std");
const targets = @import("targets.zig");
const port_state = @import("port_state.zig");
const probe_mod = @import("probe.zig");
const TimerHeap = @import("timer_heap.zig").TimerHeap;
const rtt_mod = @import("rtt.zig");
const congestion = @import("congestion.zig");
const telemetry = @import("telemetry.zig");

const Addr = targets.Addr;
const PortState = port_state.PortState;
const Reason = port_state.Reason;
const PortResult = port_state.PortResult;
const Probe = probe_mod.Probe;

pub const SendOutcome = union(enum) {
    /// Probe is on the wire; a reply or timeout will follow.
    in_flight,
    /// The transport already knows the answer (e.g. connect() returned
    /// immediately on loopback).
    immediate: Reason,
    /// Local resource pressure (EMFILE, EADDRNOTAVAIL, ENOBUFS): not
    /// evidence about the target. The probe is requeued and the group
    /// window is reduced.
    deferred,
};

pub const Event = struct {
    slot: u32,
    generation: u32,
    reason: Reason,
    at_ns: u64,
};

/// Probe slots for a scan with at most `parallelism` probes in flight.
/// Retry-queued probes keep their slot, so there is headroom beyond the window.
pub fn poolCapacity(parallelism: u32) u32 {
    return parallelism * 2 + 16;
}

pub const Classification = struct { state: PortState, definitive: bool };

pub const Config = struct {
    max_retries: u8 = 2,
    rtt: rtt_mod.Config = .{},
    host_window: congestion.WindowConfig = .{ .initial = 10, .max = 128, .initial_ssthresh = 64 },
    group_window: congestion.WindowConfig = .{ .initial = 64, .max = 256, .initial_ssthresh = 128 },
    /// Probes per second across the scan; 0 = unlimited.
    max_rate: u32 = 0,
    /// Per-host wall-clock budget; 0 = none.
    host_timeout_ns: u64 = 0,
    /// Probes issued to one host per round-robin turn.
    quantum: u32 = 8,
    /// State assigned when every attempt went unanswered.
    silent_state: PortState = .filtered,
    /// Replies that prove the host rate-limits its answers (ICMP port
    /// unreachable for UDP: Linux defaults to ~1/s per destination). The
    /// first such reply paces that host to `paced_pps`, so later silence is
    /// not an artefact of our own speed. Silence alone never triggers it.
    pace_trigger: ?*const fn (Reason) bool = null,
    paced_pps: u32 = 1,
    classify: *const fn (Reason) Classification,
};

pub const Host = struct {
    addr: Addr,
    next_port: u32 = 0,
    pending: u32,
    window: congestion.Window,
    rtt: rtt_mod.Estimator,
    retries: probe_mod.Fifo = .{},
    started: bool = false,
    started_ns: u64 = 0,
    finished_ns: u64 = 0,
    done: bool = false,
    timed_out: bool = false,
    replies: u32 = 0,
    /// Set once the host has proven it rate-limits replies.
    limiter: ?congestion.RateLimiter = null,
};

pub const Trace = struct {
    ctx: *anyopaque,
    func: *const fn (ctx: *anyopaque, msg: TraceMsg) void,
};

pub const TraceMsg = struct {
    t_ns: u64,
    kind: enum { send, reply, timeout, stale, deferred },
    addr: Addr,
    port: u16,
    attempt: u8,
    reason: Reason,
};

pub fn Engine(comptime T: type) type {
    comptime {
        for (.{ "now", "send", "poll", "cancel" }) |name| {
            if (!@hasDecl(T, name)) @compileError("transport missing fn " ++ name);
        }
    }
    return struct {
        const Self = @This();

        gpa: std.mem.Allocator,
        cfg: Config,
        transport: *T,
        hosts: []Host,
        ports: []const u16,
        results: []PortResult,
        pool: probe_mod.Pool,
        timers: TimerHeap,
        group: congestion.Window,
        limiter: congestion.RateLimiter,
        stats: telemetry.Stats = .{},
        start_ns: u64,
        rr_cursor: u32 = 0,
        active_hosts: u32,
        trace: ?Trace = null,
        /// Optional externally-owned flag (e.g. set by a SIGINT handler).
        external_cancel: ?*const std.atomic.Value(bool) = null,

        pub fn init(gpa: std.mem.Allocator, cfg: Config, transport: *T, addrs: []const Addr, ports: []const u16) !Self {
            const hosts = try gpa.alloc(Host, addrs.len);
            errdefer gpa.free(hosts);
            for (hosts, addrs) |*h, a| h.* = .{
                .addr = a,
                .pending = @intCast(ports.len),
                .window = .init(cfg.host_window),
                .rtt = .init(cfg.rtt),
            };
            const results = try gpa.alloc(PortResult, addrs.len * ports.len);
            errdefer gpa.free(results);
            @memset(results, .{});
            const cap = poolCapacity(cfg.group_window.max);
            var pool = try probe_mod.Pool.init(gpa, cap);
            errdefer pool.deinit(gpa);
            var timers = try TimerHeap.init(gpa, cap);
            errdefer timers.deinit(gpa);
            const now = transport.now();
            return .{
                .gpa = gpa,
                .cfg = cfg,
                .transport = transport,
                .hosts = hosts,
                .ports = ports,
                .results = results,
                .pool = pool,
                .timers = timers,
                .group = .init(cfg.group_window),
                .limiter = .init(cfg.max_rate, now),
                .start_ns = now,
                .active_hosts = @intCast(addrs.len),
            };
        }

        pub fn deinit(e: *Self) void {
            e.gpa.free(e.hosts);
            e.gpa.free(e.results);
            e.pool.deinit(e.gpa);
            e.timers.deinit(e.gpa);
            e.* = undefined;
        }

        pub fn result(e: *const Self, host: usize, port_index: usize) *const PortResult {
            return &e.results[e.resultIndex(host, port_index)];
        }

        fn resultMut(e: *Self, p: *const Probe) *PortResult {
            return &e.results[e.resultIndex(p.host, p.port_index)];
        }

        fn resultIndex(e: *const Self, host: usize, port_index: usize) usize {
            return host * e.ports.len + port_index;
        }

        fn relUs(e: *const Self, t: u64) u32 {
            return @intCast(@min((t -| e.start_ns) / std.time.ns_per_us, std.math.maxInt(u32)));
        }

        fn emit(e: *Self, kind: @FieldType(TraceMsg, "kind"), p: *const Probe, reason: Reason, t: u64) void {
            if (e.trace) |tr| tr.func(tr.ctx, .{ .t_ns = t -| e.start_ns, .kind = kind, .addr = e.hosts[p.host].addr, .port = p.port, .attempt = p.attempt, .reason = reason });
        }

        /// Runs until every host is complete or timed out, or `external_cancel` is set.
        pub fn run(e: *Self) !void {
            var events: [256]Event = undefined;
            while (e.active_hosts > 0) {
                var now = e.transport.now();
                if (if (e.external_cancel) |f| f.load(.monotonic) else false) {
                    e.cancelAll(now, .canceled);
                    break;
                }
                while (e.timers.popExpired(now)) |t| e.onTimeout(t.id, now);
                e.checkHostTimeouts(now);
                e.issue(now);
                if (e.active_hosts == 0) break;

                now = e.transport.now();
                const wait = e.pollTimeout(now);
                const n = e.transport.poll(wait, &events);
                for (events[0..n]) |ev| e.onReply(ev);
            }
            e.stats.wall_ns = e.transport.now() -| e.start_ns;
        }

        fn pollTimeout(e: *Self, now: u64) u64 {
            var wait: u64 = std.time.ns_per_s;
            if (e.timers.peek()) |t| wait = @min(wait, t.deadline -| now);
            if (e.cfg.max_rate != 0 and e.hasIssuableWork(now)) wait = @min(wait, e.limiter.waitNs(now));
            for (e.hosts) |*h| if (h.limiter) |*hl| {
                if (e.canIssue(h)) wait = @min(wait, @max(1, hl.waitNs(now)));
            };
            if (e.cfg.host_timeout_ns != 0) {
                for (e.hosts) |*h| if (!h.done and h.started) {
                    wait = @min(wait, (h.started_ns + e.cfg.host_timeout_ns) -| now);
                };
            }
            return wait;
        }

        /// A host held back by its own pace limiter does not count: waking
        /// for the global limiter would only spin until the host's token.
        fn hasIssuableWork(e: *Self, now: u64) bool {
            for (e.hosts) |*h| {
                if (h.limiter) |*hl| if (hl.waitNs(now) > 0) continue;
                if (e.canIssue(h)) return true;
            }
            return false;
        }

        fn hasWork(e: *const Self, h: *const Host) bool {
            return !h.done and (h.retries.len > 0 or h.next_port < e.ports.len);
        }

        /// The host has a probe to send and both windows have room for it.
        fn canIssue(e: *const Self, h: *const Host) bool {
            return e.hasWork(h) and h.window.available() > 0 and e.group.available() > 0;
        }

        /// Round robin across hosts: each turn a host may issue up to
        /// `quantum` probes, bounded by its own and the group window. A slow
        /// or silent host therefore cannot starve the others.
        fn issue(e: *Self, now: u64) void {
            const n: u32 = @intCast(e.hosts.len);
            if (n == 0) return;
            var idle_turns: u32 = 0;
            while (idle_turns < n) {
                if (e.group.available() == 0) return;
                const hi = e.rr_cursor;
                e.rr_cursor = (e.rr_cursor + 1) % n;
                const h = &e.hosts[hi];
                if (h.done) {
                    idle_turns += 1;
                    continue;
                }
                var sent: u32 = 0;
                while (sent < e.cfg.quantum and e.canIssue(h)) {
                    if (h.limiter) |*hl| if (hl.waitNs(now) > 0) break;
                    if (!e.limiter.tryTake(now)) return;
                    if (h.limiter) |*hl| _ = hl.tryTake(now);
                    const ok = e.issueOne(hi, now) catch |err| switch (err) {
                        error.NoWork => break,
                        error.PoolExhausted => return,
                    };
                    if (ok) sent += 1;
                }
                idle_turns = if (sent == 0) idle_turns + 1 else 0;
            }
        }

        fn issueOne(e: *Self, hi: u32, now: u64) error{ NoWork, PoolExhausted }!bool {
            const h = &e.hosts[hi];
            const slots = e.pool.slots;
            var id: u32 = undefined;
            if (h.retries.pop(slots)) |rid| {
                id = rid;
                slots[id].to(.ready);
            } else if (h.next_port < e.ports.len) {
                id = e.pool.acquire() orelse return error.PoolExhausted;
                const p = &slots[id];
                p.host = hi;
                p.port_index = h.next_port;
                p.port = e.ports[h.next_port];
                h.next_port += 1;
            } else return error.NoWork;

            if (!h.started) {
                h.started = true;
                h.started_ns = now;
            }
            const p = &slots[id];
            p.attempt += 1;
            p.generation +%= 1;
            p.sent_ns = now;
            const r = e.resultMut(p);
            r.attempts = p.attempt;

            const outcome = e.transport.send(id, p.generation, h.addr, p.port);
            switch (outcome) {
                .in_flight => {
                    p.to(.sent);
                    p.to(.awaiting);
                    h.window.onSend();
                    e.group.onSend();
                    e.stats.probes_sent += 1;
                    if (p.attempt > 1) e.stats.retransmissions += 1;
                    e.stats.max_in_flight = @max(e.stats.max_in_flight, e.group.in_flight);
                    r.record(.{ .kind = .sent, .reason = .none, .attempt = p.attempt, .t_us = e.relUs(now) });
                    e.emit(.send, p, .none, now);
                    const timeout = @min(h.rtt.rto() << @intCast(@min(p.attempt - 1, 6)), e.cfg.rtt.max_rto_ns);
                    e.timers.schedule(id, now + timeout);
                    return true;
                },
                .immediate => |reason| {
                    p.to(.sent);
                    e.stats.probes_sent += 1;
                    r.record(.{ .kind = .sent, .reason = .none, .attempt = p.attempt, .t_us = e.relUs(now) });
                    e.emit(.send, p, .none, now);
                    e.conclude(id, reason, now, false);
                    return true;
                },
                .deferred => {
                    if (e.group.in_flight == 0 and h.window.in_flight == 0) {
                        // Nothing of ours is in flight, so waiting cannot free the
                        // resource: report it instead of spinning.
                        p.to(.sent);
                        e.stats.local_errors += 1;
                        e.conclude(id, .local_resource_exhausted, now, false);
                        return true;
                    }
                    // Not evidence about the target: undo the attempt, requeue,
                    // and shrink the group window to relieve local pressure.
                    p.attempt -= 1;
                    r.attempts = p.attempt;
                    p.to(.retry_queued);
                    h.retries.push(slots, id);
                    e.stats.send_deferred += 1;
                    r.record(.{ .kind = .deferred, .reason = .none, .attempt = p.attempt + 1, .t_us = e.relUs(now) });
                    e.emit(.deferred, p, .none, now);
                    e.group.onLoss();
                    return error.NoWork;
                },
            }
        }

        fn onReply(e: *Self, ev: Event) void {
            if (ev.slot >= e.pool.slots.len) {
                e.stats.invalid_replies += 1;
                return;
            }
            const p = &e.pool.slots[ev.slot];
            if (p.state != .awaiting or p.generation != ev.generation) {
                // Late, duplicate, or for a previous attempt/occupant: never
                // allowed to change classification.
                e.stats.stale_replies += 1;
                if (p.state != .free) {
                    e.resultMut(p).record(.{ .kind = .stale_reply, .reason = ev.reason, .attempt = p.attempt, .t_us = e.relUs(ev.at_ns) });
                    e.emit(.stale, p, ev.reason, ev.at_ns);
                }
                return;
            }
            e.timers.cancel(ev.slot);
            const h = &e.hosts[p.host];
            h.window.onRetire();
            e.group.onRetire();
            e.stats.replies_matched += 1;
            e.conclude(ev.slot, ev.reason, ev.at_ns, true);
        }

        /// Applies a reply's classification. `from_network` distinguishes
        /// network replies (which drive RTT and windows) from transport
        /// answers delivered synchronously at send time.
        fn conclude(e: *Self, id: u32, reason: Reason, at: u64, from_network: bool) void {
            const p = &e.pool.slots[id];
            const h = &e.hosts[p.host];
            const r = e.resultMut(p);
            const rtt = at -| p.sent_ns;
            if (from_network) {
                h.rtt.addSample(rtt);
                h.replies += 1;
                if (p.timeouts > 0) {
                    // An earlier attempt timed out yet this one was
                    // answered: evidence that the path is dropping packets.
                    h.window.onLoss();
                    e.group.onLoss();
                    e.stats.loss_events += 1;
                } else {
                    h.window.onReply();
                    e.group.onReply();
                }
            }
            r.record(.{ .kind = .reply, .reason = reason, .attempt = p.attempt, .t_us = e.relUs(at) });
            e.emit(.reply, p, reason, at);
            if (e.cfg.pace_trigger) |trig| if (h.limiter == null and trig(reason)) {
                h.limiter = .initBurst(e.cfg.paced_pps, 1, at);
                e.stats.paced_hosts += 1;
            };
            const c = e.cfg.classify(reason);
            if (!c.definitive and p.attempt <= e.cfg.max_retries) {
                // Inconclusive (e.g. self-connect): retry with a fresh probe
                // rather than turning ambiguity into a classification.
                e.transport.cancel(id);
                e.stats.inconclusive_replies += 1;
                p.to(.classified);
                p.to(.retry_queued);
                h.retries.push(e.pool.slots, id);
                return;
            }
            r.state = c.state;
            r.reason = reason;
            r.rtt_us = @intCast(@min(rtt / std.time.ns_per_us, std.math.maxInt(u32)));
            e.transport.cancel(id);
            p.to(.classified); // from .awaiting, or .sent for synchronous answers
            p.to(.completed);
            e.finishProbe(id);
        }

        fn onTimeout(e: *Self, id: u32, now: u64) void {
            const p = &e.pool.slots[id];
            const h = &e.hosts[p.host];
            const r = e.resultMut(p);
            p.to(.timed_out);
            p.timeouts += 1;
            h.window.onRetire();
            e.group.onRetire();
            e.transport.cancel(id);
            e.stats.timeouts += 1;
            r.record(.{ .kind = .timeout, .reason = .no_response, .attempt = p.attempt, .t_us = e.relUs(now) });
            e.emit(.timeout, p, .no_response, now);
            if (p.attempt <= e.cfg.max_retries) {
                p.to(.retry_queued);
                h.retries.push(e.pool.slots, id);
                return;
            }
            // Silence is recorded as such; it is never reported as closed.
            r.state = e.cfg.silent_state;
            r.reason = .no_response;
            p.to(.completed);
            e.finishProbe(id);
        }

        fn finishProbe(e: *Self, id: u32) void {
            const p = &e.pool.slots[id];
            const hi = p.host;
            e.pool.release(id);
            e.stats.ports_classified += 1;
            const h = &e.hosts[hi];
            h.pending -= 1;
            if (h.pending == 0) e.finishHost(hi, e.transport.now(), false);
        }

        fn finishHost(e: *Self, hi: u32, now: u64, timed_out: bool) void {
            const h = &e.hosts[hi];
            if (h.done) return;
            h.done = true;
            h.timed_out = timed_out;
            h.finished_ns = now;
            e.active_hosts -= 1;
            e.stats.hosts_completed += 1;
        }

        fn checkHostTimeouts(e: *Self, now: u64) void {
            if (e.cfg.host_timeout_ns == 0) return;
            for (e.hosts, 0..) |*h, hi| {
                if (h.done or !h.started) continue;
                if (now -| h.started_ns < e.cfg.host_timeout_ns) continue;
                e.abortHost(@intCast(hi), now, .host_timeout);
            }
        }

        /// Cancels a host's outstanding work. Unprobed ports stay `unknown`.
        fn abortHost(e: *Self, hi: u32, now: u64, reason: Reason) void {
            const h = &e.hosts[hi];
            for (e.pool.slots, 0..) |*p, id| {
                if (p.state == .free or p.host != hi) continue;
                const r = e.resultMut(p);
                switch (p.state) {
                    .awaiting => {
                        e.timers.cancel(@intCast(id));
                        e.transport.cancel(@intCast(id));
                        h.window.onRetire();
                        e.group.onRetire();
                    },
                    .retry_queued => {},
                    else => continue,
                }
                r.state = .unknown;
                r.reason = reason;
                p.to(.canceled);
                e.pool.release(@intCast(id));
                e.stats.probes_canceled += 1;
            }
            h.retries = .{};
            var i = h.next_port;
            while (i < e.ports.len) : (i += 1) e.results[e.resultIndex(hi, i)].reason = reason;
            h.next_port = @intCast(e.ports.len);
            e.finishHost(hi, now, reason == .host_timeout);
        }

        fn cancelAll(e: *Self, now: u64, reason: Reason) void {
            for (e.hosts, 0..) |h, hi| if (!h.done) e.abortHost(@intCast(hi), now, reason);
        }
    };
}
