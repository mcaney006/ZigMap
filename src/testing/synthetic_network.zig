//! Deterministic virtual-clock network used to test the scan engine.
//!
//! Time only advances inside `poll`, jumping straight to the next reply or
//! to the requested timeout, so multi-minute scans run in milliseconds and
//! every run with the same seed is bit-identical.

const std = @import("std");
const engine_mod = @import("../core/engine.zig");
const targets = @import("../core/targets.zig");
const ps = @import("../core/port_state.zig");
const classify = @import("../scan/classify.zig");

const ms = std.time.ns_per_ms;
const s_ns = std.time.ns_per_s;

pub const Behavior = enum { open, closed, filtered };

pub const HostModel = struct {
    latency_ns: u64,
    jitter_ns: u64 = 0,
    /// Probability (per mille) that a reply is lost on the way back.
    reply_loss_permille: u16 = 0,
    behavior: *const fn (u16) Behavior,
    /// Deliver a duplicate of every reply this much later (stale traffic).
    duplicate_after_ns: ?u64 = null,
    /// First connect to each port "succeeds" as a self-connect.
    self_connect_first: bool = false,
    /// Model a UDP target: open answers with UDP, closed with ICMP port
    /// unreachable, limited like Linux (`icmp_pps`, burst `icmp_burst`).
    udp: bool = false,
    icmp_pps: u32 = 0,
    icmp_burst: u32 = 6,
};

const Pending = struct { at: u64, ev: engine_mod.Event };

pub const Sim = struct {
    gpa: std.mem.Allocator,
    clock: u64 = 1_000,
    prng: std.Random.DefaultPrng,
    /// Indexed by the last octet of the IPv4 target.
    models: []const HostModel,
    queue: std.ArrayList(Pending) = .empty,
    send_times: std.ArrayList(u64) = .empty,
    sends_per_port: [65536]u8 = @splat(0),
    icmp_tokens: [8]f64 = @splat(-1),
    icmp_last: [8]u64 = @splat(0),
    /// Consecutive zero-timeout polls that delivered nothing. The virtual
    /// clock does not move on those, so a scheduler bug would spin forever.
    idle_spins: u32 = 0,

    pub fn init(gpa: std.mem.Allocator, models: []const HostModel, seed: u64) Sim {
        return .{ .gpa = gpa, .prng = .init(seed), .models = models };
    }

    pub fn deinit(s: *Sim) void {
        s.queue.deinit(s.gpa);
        s.send_times.deinit(s.gpa);
    }

    pub fn now(s: *Sim) u64 {
        return s.clock;
    }

    pub fn send(s: *Sim, slot: u32, gen: u32, addr: targets.Addr, port: u16) engine_mod.SendOutcome {
        s.send_times.append(s.gpa, s.clock) catch @panic("oom");
        const m = s.models[addr.bytes[3]];
        s.sends_per_port[port] +|= 1;
        const reason: ps.Reason = if (m.self_connect_first and s.sends_per_port[port] == 1) .self_connect else switch (m.behavior(port)) {
            .open => if (m.udp) .udp_reply else .connected,
            .closed => if (!m.udp) .conn_refused else blk: {
                if (m.icmp_pps > 0 and !s.takeIcmpToken(addr.bytes[3], m)) return .in_flight;
                break :blk .icmp_port_unreach;
            },
            .filtered => return .in_flight,
        };
        const r = s.prng.random();
        if (m.reply_loss_permille > 0 and r.uintLessThan(u16, 1000) < m.reply_loss_permille) return .in_flight;
        const jitter = if (m.jitter_ns > 0) r.uintLessThan(u64, m.jitter_ns) else 0;
        const ev: engine_mod.Event = .{ .slot = slot, .generation = gen, .reason = reason, .at_ns = s.clock + m.latency_ns + jitter };
        s.queue.append(s.gpa, .{ .at = ev.at_ns, .ev = ev }) catch @panic("oom");
        if (m.duplicate_after_ns) |d| {
            var dup = ev;
            dup.at_ns += d;
            s.queue.append(s.gpa, .{ .at = dup.at_ns, .ev = dup }) catch @panic("oom");
        }
        return .in_flight;
    }

    fn takeIcmpToken(s: *Sim, h: u8, m: HostModel) bool {
        if (s.icmp_tokens[h] < 0) s.icmp_tokens[h] = @floatFromInt(m.icmp_burst);
        const dt: f64 = @floatFromInt(s.clock -| s.icmp_last[h]);
        s.icmp_last[h] = s.clock;
        s.icmp_tokens[h] = @min(@as(f64, @floatFromInt(m.icmp_burst)), s.icmp_tokens[h] + dt * @as(f64, @floatFromInt(m.icmp_pps)) / s_ns);
        if (s.icmp_tokens[h] < 1) return false;
        s.icmp_tokens[h] -= 1;
        return true;
    }

    pub fn poll(s: *Sim, timeout_ns: u64, out: []engine_mod.Event) usize {
        if (timeout_ns == 0) {
            s.idle_spins += 1;
            if (s.idle_spins > 100_000) @panic("engine polled with zero timeout 100000 times without progress");
        }
        const limit = s.clock + timeout_ns;
        var earliest: u64 = std.math.maxInt(u64);
        for (s.queue.items) |p| earliest = @min(earliest, p.at);
        s.clock = if (earliest <= limit) @max(s.clock, earliest) else limit;
        var n: usize = 0;
        var i: usize = 0;
        while (i < s.queue.items.len and n < out.len) {
            if (s.queue.items[i].at <= s.clock) {
                out[n] = s.queue.orderedRemove(i).ev;
                n += 1;
            } else i += 1;
        }
        if (n > 0 or timeout_ns > 0) s.idle_spins = 0;
        return n;
    }

    pub fn cancel(_: *Sim, _: u32) void {
        // Like a raw-packet scan, replies already in flight still arrive;
        // the engine must recognise them as stale.
    }
};

const SimEngine = engine_mod.Engine(Sim);

fn mixed(port: u16) Behavior {
    return switch (port % 3) {
        0 => .open,
        1 => .closed,
        else => .filtered,
    };
}
fn allFiltered(_: u16) Behavior {
    return .filtered;
}
fn halfOpen(port: u16) Behavior {
    return if (port % 2 == 0) .open else .closed;
}
fn allClosed(_: u16) Behavior {
    return .closed;
}

fn expected(b: Behavior) ps.PortState {
    return switch (b) {
        .open => .open,
        .closed => .closed,
        .filtered => .filtered,
    };
}

fn baseCfg() engine_mod.Config {
    return .{ .classify = classify.connect };
}

fn addrsFor(n: u8) [8]targets.Addr {
    var a: [8]targets.Addr = undefined;
    for (0..n) |i| a[i] = targets.Addr.v4(.{ 10, 0, 0, @intCast(i) });
    return a;
}

fn portRange(comptime n: u16) [n]u16 {
    var p: [n]u16 = undefined;
    for (&p, 0..) |*x, i| x.* = @intCast(i + 1);
    return p;
}

const testing = std.testing;

test "stable latency: exact classification, silence needs all retries" {
    const models = [_]HostModel{.{ .latency_ns = 20 * ms, .behavior = mixed }};
    var sim = Sim.init(testing.allocator, &models, 1);
    defer sim.deinit();
    const addrs = addrsFor(1);
    const ports = portRange(300);
    var e = try SimEngine.init(testing.allocator, baseCfg(), &sim, addrs[0..1], &ports);
    defer e.deinit();
    try e.run();
    for (ports, 0..) |p, i| {
        const r = e.result(0, i);
        try testing.expectEqual(expected(mixed(p)), r.state);
        if (mixed(p) == .filtered) {
            try testing.expectEqual(@as(u8, 3), r.attempts);
            try testing.expectEqual(ps.Reason.no_response, r.reason);
        } else try testing.expectEqual(@as(u8, 1), r.attempts);
    }
    try testing.expectEqual(@as(u64, 300), e.stats.ports_classified);
    try testing.expectEqual(@as(u64, 100 * 3), e.stats.timeouts);
    try testing.expectEqual(@as(u64, 0), e.stats.stale_replies);
    try testing.expectEqual(@as(u64, 0), e.stats.loss_events);
    try testing.expect(e.hosts[0].rtt.srtt_ns >= 20 * ms and e.hosts[0].rtt.srtt_ns < 21 * ms);
}

test "reply loss never turns open into closed (or vice versa)" {
    const models = [_]HostModel{.{ .latency_ns = 30 * ms, .jitter_ns = 10 * ms, .reply_loss_permille = 300, .behavior = mixed }};
    var sim = Sim.init(testing.allocator, &models, 7);
    defer sim.deinit();
    var cfg = baseCfg();
    cfg.max_retries = 3;
    const addrs = addrsFor(1);
    const ports = portRange(900);
    var e = try SimEngine.init(testing.allocator, cfg, &sim, addrs[0..1], &ports);
    defer e.deinit();
    try e.run();
    var correct: usize = 0;
    for (ports, 0..) |p, i| {
        const got = e.result(0, i).state;
        const want = expected(mixed(p));
        if (got == want) correct += 1 else try testing.expectEqual(ps.PortState.filtered, got);
    }
    // P(all 4 replies lost) = 0.3^4 < 1%, so >= 97% must be exact.
    try testing.expect(correct * 100 >= ports.len * 97);
    try testing.expect(e.stats.loss_events > 0); // replies to retries prove loss
}

test "a silent host does not starve a healthy one" {
    const ports = portRange(500);
    const addrs = addrsFor(2);
    // Healthy host alone.
    const solo_models = [_]HostModel{ .{ .latency_ns = 5 * ms, .behavior = halfOpen }, .{ .latency_ns = 5 * ms, .behavior = halfOpen } };
    var sim1 = Sim.init(testing.allocator, &solo_models, 3);
    defer sim1.deinit();
    var solo = try SimEngine.init(testing.allocator, baseCfg(), &sim1, addrs[1..2], &ports);
    defer solo.deinit();
    try solo.run();
    const solo_ns = solo.hosts[0].finished_ns - solo.hosts[0].started_ns;

    // Same healthy host next to a fully filtered, slow one.
    const models = [_]HostModel{ .{ .latency_ns = 200 * ms, .behavior = allFiltered }, .{ .latency_ns = 5 * ms, .behavior = halfOpen } };
    var sim2 = Sim.init(testing.allocator, &models, 3);
    defer sim2.deinit();
    var both = try SimEngine.init(testing.allocator, baseCfg(), &sim2, addrs[0..2], &ports);
    defer both.deinit();
    try both.run();
    const shared_ns = both.hosts[1].finished_ns - both.hosts[1].started_ns;
    try testing.expect(shared_ns * 2 <= solo_ns * 3); // within 1.5x of running alone
    try testing.expect(both.hosts[0].finished_ns > both.hosts[1].finished_ns);
    for (0..ports.len) |i| try testing.expectEqual(ps.PortState.filtered, both.result(0, i).state);
}

test "max rate is never exceeded in any one-second window" {
    const models = [_]HostModel{.{ .latency_ns = 1 * ms, .behavior = allClosed }};
    var sim = Sim.init(testing.allocator, &models, 5);
    defer sim.deinit();
    var cfg = baseCfg();
    cfg.max_rate = 200;
    const addrs = addrsFor(1);
    const ports = portRange(1000);
    var e = try SimEngine.init(testing.allocator, cfg, &sim, addrs[0..1], &ports);
    defer e.deinit();
    try e.run();
    const t = sim.send_times.items;
    try testing.expectEqual(@as(usize, 1000), t.len);
    var lo: usize = 0;
    for (t, 0..) |x, hi| {
        while (t[lo] + s_ns <= x) lo += 1;
        try testing.expect(hi - lo + 1 <= 200 + e.limiter.burst);
    }
    try testing.expect(e.stats.wall_ns >= 4900 * ms);
}

test "late duplicate replies are stale and cannot overwrite results" {
    const models = [_]HostModel{.{ .latency_ns = 10 * ms, .behavior = halfOpen, .duplicate_after_ns = 45 * ms }};
    var sim = Sim.init(testing.allocator, &models, 9);
    defer sim.deinit();
    var cfg = baseCfg();
    cfg.group_window.max = 8; // small pool so slots are reused while duplicates are in flight
    cfg.host_window.max = 8;
    const addrs = addrsFor(1);
    const ports = portRange(400);
    var e = try SimEngine.init(testing.allocator, cfg, &sim, addrs[0..1], &ports);
    defer e.deinit();
    try e.run();
    for (ports, 0..) |p, i| try testing.expectEqual(expected(halfOpen(p)), e.result(0, i).state);
    try testing.expect(e.stats.stale_replies > 0);
    try testing.expectEqual(@as(u64, 400), e.stats.replies_matched);
}

test "silence alone never shrinks congestion windows" {
    const models = [_]HostModel{.{ .latency_ns = 10 * ms, .behavior = allFiltered }};
    var sim = Sim.init(testing.allocator, &models, 11);
    defer sim.deinit();
    const addrs = addrsFor(1);
    const ports = portRange(200);
    var e = try SimEngine.init(testing.allocator, baseCfg(), &sim, addrs[0..1], &ports);
    defer e.deinit();
    try e.run();
    try testing.expectEqual(@as(u32, 0), e.hosts[0].window.loss_events);
    try testing.expectEqual(@as(u32, 0), e.group.loss_events);
    try testing.expectEqual(@as(u32, 10), e.hosts[0].window.size());
}

test "host timeout ends the host and leaves unprobed ports unknown" {
    const models = [_]HostModel{.{ .latency_ns = 10 * ms, .behavior = allFiltered }};
    var sim = Sim.init(testing.allocator, &models, 13);
    defer sim.deinit();
    var cfg = baseCfg();
    cfg.host_timeout_ns = 2 * s_ns;
    const addrs = addrsFor(1);
    const ports = portRange(1000);
    var e = try SimEngine.init(testing.allocator, cfg, &sim, addrs[0..1], &ports);
    defer e.deinit();
    try e.run();
    try testing.expect(e.hosts[0].timed_out);
    var filtered: usize = 0;
    var unknown: usize = 0;
    for (0..ports.len) |i| switch (e.result(0, i).state) {
        .filtered => filtered += 1,
        .unknown => {
            unknown += 1;
            try testing.expectEqual(ps.Reason.host_timeout, e.result(0, i).reason);
        },
        else => return error.TestUnexpectedResult,
    };
    try testing.expect(unknown > 0 and filtered + unknown == ports.len);
    try testing.expect(e.stats.wall_ns < 3 * s_ns);
}

test "identical seeds give identical scans" {
    const models = [_]HostModel{ .{ .latency_ns = 15 * ms, .jitter_ns = 20 * ms, .reply_loss_permille = 150, .behavior = mixed }, .{ .latency_ns = 40 * ms, .behavior = halfOpen } };
    const addrs = addrsFor(2);
    const ports = portRange(256);
    var runs: [2]struct { stats: @import("../core/telemetry.zig").Stats, states: [512]ps.PortState } = undefined;
    for (&runs) |*run| {
        var sim = Sim.init(testing.allocator, &models, 42);
        defer sim.deinit();
        var e = try SimEngine.init(testing.allocator, baseCfg(), &sim, addrs[0..2], &ports);
        defer e.deinit();
        try e.run();
        run.stats = e.stats;
        for (0..2) |h| for (0..ports.len) |i| {
            run.states[h * ports.len + i] = e.result(h, i).state;
        };
    }
    try testing.expectEqual(runs[0].stats, runs[1].stats);
    try testing.expectEqualSlices(ps.PortState, &runs[0].states, &runs[1].states);
}

test "self-connects are retried and never reported as open" {
    const models = [_]HostModel{.{ .latency_ns = 1 * ms, .behavior = allClosed, .self_connect_first = true }};
    var sim = Sim.init(testing.allocator, &models, 17);
    defer sim.deinit();
    const addrs = addrsFor(1);
    const ports = portRange(50);
    var e = try SimEngine.init(testing.allocator, baseCfg(), &sim, addrs[0..1], &ports);
    defer e.deinit();
    try e.run();
    for (0..ports.len) |i| {
        const r = e.result(0, i);
        try testing.expectEqual(ps.PortState.closed, r.state);
        try testing.expectEqual(@as(u8, 2), r.attempts);
        var it = r.evidenceIter();
        var saw_self = false;
        while (it.next()) |ev| if (ev.reason == .self_connect) {
            saw_self = true;
        };
        try testing.expect(saw_self);
    }
    try testing.expectEqual(@as(u64, 50), e.stats.inconclusive_replies);
    // An answered retry after an inconclusive reply is not evidence of loss.
    try testing.expectEqual(@as(u64, 0), e.stats.loss_events);
}

test "persistent inconclusive answers end as unknown, not open" {
    const models = [_]HostModel{.{ .latency_ns = 1 * ms, .behavior = allClosed, .self_connect_first = true }};
    var sim = Sim.init(testing.allocator, &models, 19);
    defer sim.deinit();
    var cfg = baseCfg();
    cfg.max_retries = 0; // no budget left to resolve the ambiguity
    const addrs = addrsFor(1);
    const ports = portRange(5);
    var e = try SimEngine.init(testing.allocator, cfg, &sim, addrs[0..1], &ports);
    defer e.deinit();
    try e.run();
    for (0..ports.len) |i| {
        try testing.expectEqual(ps.PortState.unknown, e.result(0, i).state);
        try testing.expectEqual(ps.Reason.self_connect, e.result(0, i).reason);
    }
}

test "a full group window under a rate cap waits instead of spinning" {
    // Regression: with tokens available but no room in the group window,
    // the engine polled with a zero timeout until the next reply.
    const models = [_]HostModel{.{ .latency_ns = 50 * ms, .behavior = halfOpen }};
    var sim = Sim.init(testing.allocator, &models, 29);
    defer sim.deinit();
    var cfg = baseCfg();
    cfg.max_rate = 1000;
    cfg.group_window = .{ .initial = 4, .max = 4, .initial_ssthresh = 4 };
    const addrs = addrsFor(1);
    const ports = portRange(40);
    var e = try SimEngine.init(testing.allocator, cfg, &sim, addrs[0..1], &ports);
    defer e.deinit();
    try e.run();
    for (0..ports.len) |i| try testing.expectEqual(expected(halfOpen(ports[i])), e.result(0, i).state);
    try testing.expectEqual(@as(u64, 40), e.stats.probes_sent);
}

fn udpCfg(paced: bool) engine_mod.Config {
    return .{
        .classify = classify.udp,
        .silent_state = .open_filtered,
        .max_retries = 3,
        .pace_trigger = if (paced) struct {
            fn f(r: ps.Reason) bool {
                return r == .icmp_port_unreach;
            }
        }.f else null,
    };
}

test "UDP pacing under a global rate cap neither spins nor stalls" {
    // Regression: a paced host (1 pps) behind a 1000 pps global cap made
    // the engine poll with zero timeout forever.
    const models = [_]HostModel{.{ .latency_ns = 5 * ms, .behavior = udpMix, .udp = true, .icmp_pps = 1, .icmp_burst = 6 }};
    const addrs = addrsFor(1);
    const ports = portRange(40);
    var sim = Sim.init(testing.allocator, &models, 23);
    defer sim.deinit();
    var cfg = udpCfg(true);
    cfg.max_rate = 1000;
    var e = try SimEngine.init(testing.allocator, cfg, &sim, addrs[0..1], &ports);
    defer e.deinit();
    try e.run();
    var closed: usize = 0;
    for (0..ports.len) |i| {
        if (e.result(0, i).state == .closed) closed += 1;
    }
    try testing.expectEqual(@as(usize, 36), closed);
    try testing.expectEqual(@as(u64, 1), e.stats.paced_hosts);
}

fn udpMix(port: u16) Behavior {
    return if (port % 10 == 0) .open else .closed;
}

test "UDP: rate-limited ICMP needs evidence-triggered pacing to classify closed ports" {
    const models = [_]HostModel{.{ .latency_ns = 5 * ms, .behavior = udpMix, .udp = true, .icmp_pps = 1, .icmp_burst = 6 }};
    const addrs = addrsFor(1);
    const ports = portRange(40);
    var counts: [2][3]usize = undefined; // [paced][open, closed, open_filtered]
    for ([_]bool{ false, true }, 0..) |paced, k| {
        var sim = Sim.init(testing.allocator, &models, 23);
        defer sim.deinit();
        var e = try SimEngine.init(testing.allocator, udpCfg(paced), &sim, addrs[0..1], &ports);
        defer e.deinit();
        try e.run();
        counts[k] = .{ 0, 0, 0 };
        for (ports, 0..) |p, i| {
            const st = e.result(0, i).state;
            switch (st) {
                .open => counts[k][0] += 1,
                .closed => counts[k][1] += 1,
                .open_filtered => counts[k][2] += 1,
                else => return error.TestUnexpectedResult,
            }
            // never wrong: open only for open ports, closed only for closed
            if (st == .open) try testing.expectEqual(Behavior.open, udpMix(p));
            if (st == .closed) try testing.expectEqual(Behavior.closed, udpMix(p));
        }
        if (paced) try testing.expectEqual(@as(u64, 1), e.stats.paced_hosts);
    }
    try testing.expectEqual(@as(usize, 4), counts[1][0]);
    try testing.expectEqual(@as(usize, 36), counts[1][1]); // paced: every closed port proven closed
    try testing.expect(counts[0][2] > 0); // unpaced: rate limiting leaves ambiguity
}
