//! NETLINK_ROUTE queries over a raw netlink socket (Linux only, no libc).
//! Replaces parsing `ip route` / `ip neigh` output: the kernel answers
//! directly with route, link and neighbour records.

const std = @import("std");
const linux = std.os.linux;
const msg = @import("../netlink_msg.zig");

pub const Error = error{
    SocketFailed,
    SendFailed,
    RecvFailed,
    Malformed,
    NoRoute,
    NoSuchInterface,
    KernelError,
};

pub const Netlink = struct {
    fd: i32,
    seq: u32 = 1,
    buf: [32 * 1024]u8 align(8) = undefined,

    pub fn open() Error!Netlink {
        const rc = linux.socket(linux.AF.NETLINK, linux.SOCK.RAW | linux.SOCK.CLOEXEC, 0); // NETLINK_ROUTE
        if (linux.errno(rc) != .SUCCESS) return error.SocketFailed;
        return .{ .fd = @intCast(rc) };
    }

    pub fn close(nl: *Netlink) void {
        _ = linux.close(nl.fd);
    }

    fn send(nl: *Netlink, m: []const u8) Error!void {
        var sa: linux.sockaddr.nl = .{ .pid = 0, .groups = 0 };
        const rc = linux.sendto(nl.fd, m.ptr, m.len, 0, @ptrCast(&sa), @sizeOf(linux.sockaddr.nl));
        if (linux.errno(rc) != .SUCCESS) return error.SendFailed;
    }

    /// Calls `ctx.onMessage(m) !bool` for each reply to `seq` until DONE, an
    /// error, or a non-multipart reply. Returning false stops early.
    fn exchange(nl: *Netlink, req: []const u8, ctx: anytype) Error!void {
        const seq = nl.seq;
        nl.seq +%= 1;
        try nl.send(req);
        while (true) {
            const rc = linux.recvfrom(nl.fd, &nl.buf, nl.buf.len, 0, null, null);
            const e = linux.errno(rc);
            if (e == .INTR) continue;
            if (e != .SUCCESS) return error.RecvFailed;
            var it: msg.MessageIterator = .{ .buf = nl.buf[0..rc] };
            var multi = false;
            while (it.next()) |m| {
                if (m.seq != seq) continue; // stale reply to an earlier request
                switch (m.type) {
                    msg.NLMSG_DONE => return,
                    msg.NLMSG_ERROR => {
                        const code = msg.errorCode(m.payload) orelse return error.Malformed;
                        if (code == 0) return; // ACK
                        if (code == -@as(i32, @intFromEnum(linux.E.NETUNREACH)) or code == -@as(i32, @intFromEnum(linux.E.HOSTUNREACH))) return error.NoRoute;
                        if (code == -@as(i32, @intFromEnum(linux.E.NODEV))) return error.NoSuchInterface;
                        return error.KernelError;
                    },
                    else => {
                        if (m.flags & msg.NLM_F_MULTI != 0) multi = true;
                        if (!try ctx.onMessage(m)) return;
                    },
                }
            }
            if (it.malformed) return error.Malformed;
            if (!multi) return;
        }
    }

    /// `dst` is 4 (IPv4) or 16 (IPv6) bytes.
    pub fn routeGet(nl: *Netlink, dst: []const u8) Error!msg.Route {
        var req: [64]u8 = undefined;
        const m = msg.buildRouteGet(&req, nl.seq, dst) catch unreachable;
        var ctx: struct {
            route: ?msg.Route = null,
            fn onMessage(c: *@This(), mm: msg.Message) Error!bool {
                if (mm.type != msg.RTM_NEWROUTE) return true;
                c.route = msg.parseRoute(mm.payload) catch return error.Malformed;
                return false;
            }
        } = .{};
        try nl.exchange(m, &ctx);
        return ctx.route orelse error.NoRoute;
    }

    pub fn linkGet(nl: *Netlink, ifindex: i32) Error!msg.Link {
        var req: [64]u8 = undefined;
        const m = msg.buildLinkGet(&req, nl.seq, ifindex) catch unreachable;
        var ctx: struct {
            link: ?msg.Link = null,
            fn onMessage(c: *@This(), mm: msg.Message) Error!bool {
                if (mm.type != msg.RTM_NEWLINK) return true;
                c.link = msg.parseLink(mm.payload) catch return error.Malformed;
                return false;
            }
        } = .{};
        try nl.exchange(m, &ctx);
        return ctx.link orelse error.NoSuchInterface;
    }

    pub fn linkByName(nl: *Netlink, name: []const u8) Error!msg.Link {
        var req: [64]u8 = undefined;
        const m = msg.buildLinkDump(&req, nl.seq) catch unreachable;
        var ctx: struct {
            want: []const u8,
            link: ?msg.Link = null,
            fn onMessage(c: *@This(), mm: msg.Message) Error!bool {
                if (mm.type != msg.RTM_NEWLINK) return true;
                const l = msg.parseLink(mm.payload) catch return error.Malformed;
                if (c.link == null and std.mem.eql(u8, l.nameSlice(), c.want)) c.link = l;
                return true; // drain the dump
            }
        } = .{ .want = name };
        try nl.exchange(m, &ctx);
        return ctx.link orelse error.NoSuchInterface;
    }

    /// Usable link-layer address for `ip` on `ifindex`, if the kernel has one.
    pub fn neighbor(nl: *Netlink, ifindex: i32, ip: []const u8) Error!?[6]u8 {
        var req: [64]u8 = undefined;
        const m = msg.buildNeighDump(&req, nl.seq, if (ip.len == 16) msg.AF_INET6 else msg.AF_INET) catch unreachable;
        var ctx: struct {
            ifindex: i32,
            ip: []const u8,
            mac: ?[6]u8 = null,
            fn onMessage(c: *@This(), mm: msg.Message) Error!bool {
                if (mm.type != msg.RTM_NEWNEIGH) return true;
                const n = msg.parseNeighbor(mm.payload) catch return error.Malformed;
                if (n.ifindex == c.ifindex and n.state & msg.Nud.usable != 0) {
                    if (n.dst) |d| if (std.mem.eql(u8, d[0..c.ip.len], c.ip)) {
                        if (n.lladdr) |ll| c.mac = ll;
                    };
                }
                return true;
            }
        } = .{ .ifindex = ifindex, .ip = ip };
        try nl.exchange(m, &ctx);
        return ctx.mac;
    }
};
