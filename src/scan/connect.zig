//! TCP connect() scan transport.
//!
//! Each attempt is a fresh nonblocking socket, so a completion can only
//! belong to the attempt that created it (unambiguous RTT samples, no
//! cross-attempt confusion). The transport owns every socket it opens and
//! closes it on completion, timeout, or cancellation.

const std = @import("std");
const sys = @import("../platform/sys.zig");
const engine = @import("../core/engine.zig");
const targets = @import("../core/targets.zig");
const Reason = @import("../core/port_state.zig").Reason;

const Dest = struct { addr: targets.Addr, port: u16 };

pub const ConnectTransport = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    fds: []sys.fd_t,
    gens: []u32,
    dests: []Dest,
    poller: sys.Poller,

    pub fn init(gpa: std.mem.Allocator, io: std.Io, slots: u32) !ConnectTransport {
        const fds = try gpa.alloc(sys.fd_t, slots);
        errdefer gpa.free(fds);
        @memset(fds, -1);
        const gens = try gpa.alloc(u32, slots);
        errdefer gpa.free(gens);
        const dests = try gpa.alloc(Dest, slots);
        errdefer gpa.free(dests);
        return .{ .gpa = gpa, .io = io, .fds = fds, .gens = gens, .dests = dests, .poller = try .init(gpa, slots) };
    }

    pub fn deinit(t: *ConnectTransport) void {
        for (t.fds, 0..) |fd, i| if (fd >= 0) t.cancel(@intCast(i));
        t.poller.deinit(t.gpa);
        t.gpa.free(t.fds);
        t.gpa.free(t.gens);
        t.gpa.free(t.dests);
    }

    pub fn now(t: *ConnectTransport) u64 {
        return @intCast(std.Io.Clock.awake.now(t.io).nanoseconds);
    }

    pub fn send(t: *ConnectTransport, slot: u32, gen: u32, addr: targets.Addr, port: u16) engine.SendOutcome {
        std.debug.assert(t.fds[slot] < 0);
        const fd = switch (sys.tcpSocket(addr.is_v6)) {
            .ok => |fd| fd,
            .err => |e| return switch (e) {
                .no_fds, .no_bufs => .deferred,
                .af_not_supported => .{ .immediate = .net_unreach },
                else => .{ .immediate = .local_resource_exhausted },
            },
        };
        const e = sys.connect(fd, addr, port);
        switch (e) {
            .in_progress => {
                const token = (@as(u64, gen) << 32) | slot;
                t.poller.add(fd, token) catch {
                    sys.closeFd(fd);
                    return .deferred;
                };
                t.fds[slot] = fd;
                t.gens[slot] = gen;
                t.dests[slot] = .{ .addr = addr, .port = port };
                return .in_flight;
            },
            .would_block, .addr_not_avail, .no_bufs, .no_fds => {
                // Ephemeral port or buffer exhaustion: local, not target evidence.
                sys.closeFd(fd);
                return .deferred;
            },
            else => {
                // Loopback and some local errors complete synchronously.
                const reason = if (e == .ok and isSelfConnect(fd, addr, port)) .self_connect else reasonFor(e);
                sys.abortClose(fd);
                return .{ .immediate = reason };
            },
        }
    }

    pub fn poll(t: *ConnectTransport, timeout_ns: u64, out: []engine.Event) usize {
        const ms = std.math.divCeil(u64, timeout_ns, std.time.ns_per_ms) catch unreachable;
        var ready: [256]sys.Ready = undefined;
        const n = t.poller.wait(@intCast(@min(ms, std.math.maxInt(i32))), ready[0..@min(ready.len, out.len)]);
        const at = t.now();
        var k: usize = 0;
        for (ready[0..n]) |r| {
            const slot: u32 = @truncate(r.token);
            const gen: u32 = @truncate(r.token >> 32);
            if (slot >= t.fds.len or t.fds[slot] < 0 or t.gens[slot] != gen) continue;
            const err = sys.socketError(t.fds[slot]);
            const d = t.dests[slot];
            const reason: Reason = if (err == .ok and isSelfConnect(t.fds[slot], d.addr, d.port)) .self_connect else reasonFor(err);
            out[k] = .{ .slot = slot, .generation = gen, .reason = reason, .at_ns = at };
            k += 1;
        }
        return k;
    }

    pub fn cancel(t: *ConnectTransport, slot: u32) void {
        const fd = t.fds[slot];
        if (fd < 0) return;
        t.poller.remove(fd, 0);
        sys.abortClose(fd);
        t.fds[slot] = -1;
    }

    /// A "successful" connect whose local endpoint equals the destination
    /// is the socket talking to itself, not a listener.
    fn isSelfConnect(fd: sys.fd_t, addr: targets.Addr, port: u16) bool {
        const local = sys.localEndpoint(fd, addr.is_v6) orelse return false;
        return local.port == port and std.mem.eql(u8, &local.addr, &addr.bytes);
    }

    fn reasonFor(e: sys.Err) Reason {
        return switch (e) {
            .ok => .connected,
            .conn_refused => .conn_refused,
            .timed_out => .kernel_timeout,
            .host_unreach => .host_unreach,
            .net_unreach => .net_unreach,
            .access => .local_policy_denied,
            else => .local_resource_exhausted,
        };
    }
};
