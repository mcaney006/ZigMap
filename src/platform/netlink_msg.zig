//! NETLINK_ROUTE message encoding and bounded decoding (rtnetlink(7)).
//!
//! Pure byte manipulation with no syscalls, so it builds and is tested on
//! every host. Netlink headers use the host's native byte order; addresses
//! inside attributes are network order. Every length field from the kernel
//! is bounds-checked before use.

const std = @import("std");
const builtin = @import("builtin");

const native = builtin.cpu.arch.endian();

pub const NLMSG_ERROR: u16 = 2;
pub const NLMSG_DONE: u16 = 3;
pub const NLM_F_REQUEST: u16 = 0x01;
pub const NLM_F_MULTI: u16 = 0x02;
pub const NLM_F_ACK: u16 = 0x04;
pub const NLM_F_DUMP: u16 = 0x300;

pub const RTM_NEWLINK: u16 = 16;
pub const RTM_GETLINK: u16 = 18;
pub const RTM_NEWADDR: u16 = 20;
pub const RTM_GETADDR: u16 = 22;
pub const RTM_NEWROUTE: u16 = 24;
pub const RTM_GETROUTE: u16 = 26;
pub const RTM_NEWNEIGH: u16 = 28;
pub const RTM_GETNEIGH: u16 = 30;

pub const RTA_DST: u16 = 1;
pub const RTA_OIF: u16 = 4;
pub const RTA_GATEWAY: u16 = 5;
pub const RTA_PREFSRC: u16 = 7;
pub const RTA_TABLE: u16 = 15;

pub const IFLA_ADDRESS: u16 = 1;
pub const IFLA_IFNAME: u16 = 3;
pub const IFLA_MTU: u16 = 4;

pub const NDA_DST: u16 = 1;
pub const NDA_LLADDR: u16 = 2;

pub const ARPHRD_ETHER: u16 = 1;
pub const ARPHRD_LOOPBACK: u16 = 772;

pub const AF_INET: u8 = 2;
pub const AF_INET6: u8 = 10;
pub const AF_UNSPEC: u8 = 0;

pub const Nud = struct {
    pub const incomplete: u16 = 0x01;
    pub const reachable: u16 = 0x02;
    pub const stale: u16 = 0x04;
    pub const delay: u16 = 0x08;
    pub const probe: u16 = 0x10;
    pub const failed: u16 = 0x20;
    pub const noarp: u16 = 0x40;
    pub const permanent: u16 = 0x80;
    /// States in which the link-layer address is usable.
    pub const usable: u16 = reachable | stale | delay | probe | noarp | permanent;
};

pub const nlmsghdr_len = 16;
const rtmsg_len = 12;
const ifinfomsg_len = 16;
const ndmsg_len = 12;

fn align4(n: usize) usize {
    return (n + 3) & ~@as(usize, 3);
}

pub const Builder = struct {
    buf: []u8,
    len: usize = 0,

    fn put(b: *Builder, bytes: []const u8) error{NoSpace}!void {
        if (b.len + bytes.len > b.buf.len) return error.NoSpace;
        @memcpy(b.buf[b.len..][0..bytes.len], bytes);
        b.len += bytes.len;
    }

    fn pad(b: *Builder) error{NoSpace}!void {
        const n = align4(b.len) - b.len;
        if (b.len + n > b.buf.len) return error.NoSpace;
        @memset(b.buf[b.len..][0..n], 0);
        b.len += n;
    }

    fn header(b: *Builder, msg_type: u16, flags: u16, seq: u32) error{NoSpace}!void {
        var h: [nlmsghdr_len]u8 = undefined;
        std.mem.writeInt(u32, h[0..4], 0, native); // patched by finish()
        std.mem.writeInt(u16, h[4..6], msg_type, native);
        std.mem.writeInt(u16, h[6..8], flags, native);
        std.mem.writeInt(u32, h[8..12], seq, native);
        std.mem.writeInt(u32, h[12..16], 0, native);
        try b.put(&h);
    }

    fn attr(b: *Builder, t: u16, payload: []const u8) error{NoSpace}!void {
        var h: [4]u8 = undefined;
        std.mem.writeInt(u16, h[0..2], @intCast(4 + payload.len), native);
        std.mem.writeInt(u16, h[2..4], t, native);
        try b.put(&h);
        try b.put(payload);
        try b.pad();
    }

    fn finish(b: *Builder) []const u8 {
        std.mem.writeInt(u32, b.buf[0..4], @intCast(b.len), native);
        return b.buf[0..b.len];
    }
};

/// `ip route get <dst>`: asks the kernel which route, interface and
/// preferred source it would use for `dst` (4 or 16 bytes).
pub fn buildRouteGet(buf: []u8, seq: u32, dst: []const u8) error{NoSpace}![]const u8 {
    var b: Builder = .{ .buf = buf };
    try b.header(RTM_GETROUTE, NLM_F_REQUEST, seq);
    var rt: [rtmsg_len]u8 = @splat(0);
    rt[0] = if (dst.len == 16) AF_INET6 else AF_INET;
    rt[1] = @intCast(dst.len * 8); // dst_len
    try b.put(&rt);
    try b.attr(RTA_DST, dst);
    return b.finish();
}

pub fn buildLinkGet(buf: []u8, seq: u32, ifindex: i32) error{NoSpace}![]const u8 {
    var b: Builder = .{ .buf = buf };
    try b.header(RTM_GETLINK, NLM_F_REQUEST, seq);
    var ifi: [ifinfomsg_len]u8 = @splat(0);
    std.mem.writeInt(i32, ifi[4..8], ifindex, native);
    try b.put(&ifi);
    return b.finish();
}

pub fn buildLinkDump(buf: []u8, seq: u32) error{NoSpace}![]const u8 {
    var b: Builder = .{ .buf = buf };
    try b.header(RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP, seq);
    const ifi: [ifinfomsg_len]u8 = @splat(0);
    try b.put(&ifi);
    return b.finish();
}

pub fn buildNeighDump(buf: []u8, seq: u32, family: u8) error{NoSpace}![]const u8 {
    var b: Builder = .{ .buf = buf };
    try b.header(RTM_GETNEIGH, NLM_F_REQUEST | NLM_F_DUMP, seq);
    var nd: [ndmsg_len]u8 = @splat(0);
    nd[0] = family;
    try b.put(&nd);
    return b.finish();
}

// ------------------------------------------------------------- decoding

pub const Message = struct {
    type: u16,
    flags: u16,
    seq: u32,
    payload: []const u8,
};

pub const MessageIterator = struct {
    buf: []const u8,
    off: usize = 0,
    malformed: bool = false,

    pub fn next(it: *MessageIterator) ?Message {
        if (it.off + nlmsghdr_len > it.buf.len) return null;
        const h = it.buf[it.off..];
        const len = std.mem.readInt(u32, h[0..4], native);
        if (len < nlmsghdr_len or it.off + len > it.buf.len) {
            it.malformed = true;
            return null;
        }
        const m: Message = .{
            .type = std.mem.readInt(u16, h[4..6], native),
            .flags = std.mem.readInt(u16, h[6..8], native),
            .seq = std.mem.readInt(u32, h[8..12], native),
            .payload = h[nlmsghdr_len..len],
        };
        it.off += align4(len);
        return m;
    }
};

pub const Attr = struct { type: u16, value: []const u8 };

pub const AttrIterator = struct {
    buf: []const u8,
    off: usize = 0,
    malformed: bool = false,

    pub fn next(it: *AttrIterator) ?Attr {
        if (it.off + 4 > it.buf.len) return null;
        const len = std.mem.readInt(u16, it.buf[it.off..][0..2], native);
        const t = std.mem.readInt(u16, it.buf[it.off + 2 ..][0..2], native) & 0x3fff; // strip NLA_F_* bits
        if (len < 4 or it.off + len > it.buf.len) {
            it.malformed = true;
            return null;
        }
        const a: Attr = .{ .type = t, .value = it.buf[it.off + 4 .. it.off + len] };
        it.off += align4(len);
        return a;
    }
};

/// Decodes an NLMSG_ERROR payload. 0 means ACK; otherwise a negative errno.
pub fn errorCode(payload: []const u8) ?i32 {
    if (payload.len < 4) return null;
    return std.mem.readInt(i32, payload[0..4], native);
}

pub const Route = struct {
    family: u8,
    oif: ?u32 = null,
    gateway: ?[16]u8 = null,
    prefsrc: ?[16]u8 = null,
    type: u8 = 0,
};

fn addrAttr(v: []const u8, family: u8) ?[16]u8 {
    const want: usize = if (family == AF_INET6) 16 else 4;
    if (v.len != want) return null;
    var a: [16]u8 = @splat(0);
    @memcpy(a[0..want], v);
    return a;
}

pub fn parseRoute(payload: []const u8) error{Malformed}!Route {
    if (payload.len < rtmsg_len) return error.Malformed;
    var r: Route = .{ .family = payload[0], .type = payload[7] };
    var it: AttrIterator = .{ .buf = payload[rtmsg_len..] };
    while (it.next()) |a| switch (a.type) {
        RTA_OIF => if (a.value.len == 4) {
            r.oif = std.mem.readInt(u32, a.value[0..4], native);
        },
        RTA_GATEWAY => r.gateway = addrAttr(a.value, r.family),
        RTA_PREFSRC => r.prefsrc = addrAttr(a.value, r.family),
        else => {},
    };
    if (it.malformed) return error.Malformed;
    return r;
}

pub const Link = struct {
    index: i32,
    hw_type: u16,
    flags: u32,
    mac: ?[6]u8 = null,
    mtu: ?u32 = null,
    name: [16]u8 = @splat(0),
    name_len: u8 = 0,

    pub fn nameSlice(l: *const Link) []const u8 {
        return l.name[0..l.name_len];
    }
};

pub fn parseLink(payload: []const u8) error{Malformed}!Link {
    if (payload.len < ifinfomsg_len) return error.Malformed;
    var l: Link = .{
        .hw_type = std.mem.readInt(u16, payload[2..4], native),
        .index = std.mem.readInt(i32, payload[4..8], native),
        .flags = std.mem.readInt(u32, payload[8..12], native),
    };
    var it: AttrIterator = .{ .buf = payload[ifinfomsg_len..] };
    while (it.next()) |a| switch (a.type) {
        IFLA_ADDRESS => if (a.value.len == 6) {
            l.mac = a.value[0..6].*;
        },
        IFLA_MTU => if (a.value.len == 4) {
            l.mtu = std.mem.readInt(u32, a.value[0..4], native);
        },
        IFLA_IFNAME => {
            const n = std.mem.findScalar(u8, a.value, 0) orelse a.value.len;
            const m = @min(n, l.name.len);
            @memcpy(l.name[0..m], a.value[0..m]);
            l.name_len = @intCast(m);
        },
        else => {},
    };
    if (it.malformed) return error.Malformed;
    return l;
}

pub const Neighbor = struct {
    family: u8,
    ifindex: i32,
    state: u16,
    dst: ?[16]u8 = null,
    lladdr: ?[6]u8 = null,
};

pub fn parseNeighbor(payload: []const u8) error{Malformed}!Neighbor {
    if (payload.len < ndmsg_len) return error.Malformed;
    var n: Neighbor = .{
        .family = payload[0],
        .ifindex = std.mem.readInt(i32, payload[4..8], native),
        .state = std.mem.readInt(u16, payload[8..10], native),
    };
    var it: AttrIterator = .{ .buf = payload[ndmsg_len..] };
    while (it.next()) |a| switch (a.type) {
        NDA_DST => n.dst = addrAttr(a.value, n.family),
        NDA_LLADDR => if (a.value.len == 6) {
            n.lladdr = a.value[0..6].*;
        },
        else => {},
    };
    if (it.malformed) return error.Malformed;
    return n;
}

const testing = std.testing;

/// Builds a fake kernel reply for tests.
fn fakeMsg(buf: []u8, msg_type: u16, fixed: []const u8, attrs: []const Attr) []const u8 {
    var b: Builder = .{ .buf = buf };
    b.header(msg_type, 0, 7) catch unreachable;
    b.put(fixed) catch unreachable;
    for (attrs) |a| b.attr(a.type, a.value) catch unreachable;
    return b.finish();
}

test "route get request layout" {
    var buf: [64]u8 = undefined;
    const m = try buildRouteGet(&buf, 42, &.{ 192, 0, 2, 9 });
    try testing.expectEqual(@as(usize, 16 + 12 + 8), m.len);
    try testing.expectEqual(@as(u32, @intCast(m.len)), std.mem.readInt(u32, m[0..4], native));
    try testing.expectEqual(RTM_GETROUTE, std.mem.readInt(u16, m[4..6], native));
    try testing.expectEqual(@as(u8, 32), m[17]); // rtm_dst_len
    try testing.expectEqualSlices(u8, &.{ 192, 0, 2, 9 }, m[32..36]);
}

test "parse route reply: oif, gateway, prefsrc" {
    var buf: [128]u8 = undefined;
    var fixed: [rtmsg_len]u8 = @splat(0);
    fixed[0] = AF_INET;
    fixed[7] = 1; // RTN_UNICAST
    var oif: [4]u8 = undefined;
    std.mem.writeInt(u32, &oif, 7, native);
    const msg = fakeMsg(&buf, RTM_NEWROUTE, &fixed, &.{
        .{ .type = RTA_OIF, .value = &oif },
        .{ .type = RTA_GATEWAY, .value = &.{ 10, 0, 0, 1 } },
        .{ .type = RTA_PREFSRC, .value = &.{ 10, 0, 0, 5 } },
    });
    var it: MessageIterator = .{ .buf = msg };
    const m = it.next().?;
    try testing.expectEqual(RTM_NEWROUTE, m.type);
    const r = try parseRoute(m.payload);
    try testing.expectEqual(@as(?u32, 7), r.oif);
    try testing.expectEqualSlices(u8, &.{ 10, 0, 0, 1 }, r.gateway.?[0..4]);
    try testing.expectEqualSlices(u8, &.{ 10, 0, 0, 5 }, r.prefsrc.?[0..4]);
    try testing.expectEqual(@as(?Message, null), it.next());
}

test "parse link and neighbor" {
    var buf: [128]u8 = undefined;
    var ifi: [ifinfomsg_len]u8 = @splat(0);
    std.mem.writeInt(u16, ifi[2..4], ARPHRD_ETHER, native);
    std.mem.writeInt(i32, ifi[4..8], 3, native);
    var mtu: [4]u8 = undefined;
    std.mem.writeInt(u32, &mtu, 1500, native);
    var it: MessageIterator = .{ .buf = fakeMsg(&buf, RTM_NEWLINK, &ifi, &.{
        .{ .type = IFLA_IFNAME, .value = "eth0\x00" },
        .{ .type = IFLA_ADDRESS, .value = &.{ 2, 0x42, 0xac, 0x11, 0, 2 } },
        .{ .type = IFLA_MTU, .value = &mtu },
    }) };
    const l = try parseLink(it.next().?.payload);
    try testing.expectEqualStrings("eth0", l.nameSlice());
    try testing.expectEqual(@as(?u32, 1500), l.mtu);
    try testing.expectEqual(@as(i32, 3), l.index);

    var nd: [ndmsg_len]u8 = @splat(0);
    nd[0] = AF_INET;
    std.mem.writeInt(i32, nd[4..8], 3, native);
    std.mem.writeInt(u16, nd[8..10], Nud.reachable, native);
    var it2: MessageIterator = .{ .buf = fakeMsg(&buf, RTM_NEWNEIGH, &nd, &.{
        .{ .type = NDA_DST, .value = &.{ 172, 17, 0, 1 } },
        .{ .type = NDA_LLADDR, .value = &.{ 2, 0x42, 0xac, 0x11, 0, 1 } },
    }) };
    const n = try parseNeighbor(it2.next().?.payload);
    try testing.expect(n.state & Nud.usable != 0);
    try testing.expectEqualSlices(u8, &.{ 172, 17, 0, 1 }, n.dst.?[0..4]);
}

test "truncated and lying lengths are rejected" {
    var buf: [128]u8 = undefined;
    var fixed: [rtmsg_len]u8 = @splat(0);
    fixed[0] = AF_INET;
    const msg = fakeMsg(&buf, RTM_NEWROUTE, &fixed, &.{.{ .type = RTA_GATEWAY, .value = &.{ 1, 2, 3, 4 } }});
    var copy: [128]u8 = undefined;
    @memcpy(copy[0..msg.len], msg);
    // attribute claims 200 bytes
    std.mem.writeInt(u16, copy[28..30], 200, native);
    try testing.expectError(error.Malformed, parseRoute(copy[16..msg.len]));
    // message claims more than the buffer
    std.mem.writeInt(u32, copy[0..4], 999, native);
    var it: MessageIterator = .{ .buf = copy[0..msg.len] };
    try testing.expectEqual(@as(?Message, null), it.next());
    try testing.expect(it.malformed);
    // wrong-sized address attribute is ignored, not trusted
    var it2: MessageIterator = .{ .buf = fakeMsg(&buf, RTM_NEWROUTE, &fixed, &.{.{ .type = RTA_GATEWAY, .value = &.{ 1, 2, 3 } }}) };
    try testing.expectEqual(@as(?[16]u8, null), (try parseRoute(it2.next().?.payload)).gateway);
}

test "netlink decoders never panic on arbitrary input" {
    try std.testing.fuzz({}, struct {
        fn one(_: void, smith: *std.testing.Smith) !void {
            var b: [512]u8 = undefined;
            const n = smith.valueRangeAtMost(u32, 0, b.len);
            smith.bytes(b[0..n]);
            var it: MessageIterator = .{ .buf = b[0..n] };
            while (it.next()) |m| {
                _ = parseRoute(m.payload) catch {};
                _ = parseLink(m.payload) catch {};
                _ = parseNeighbor(m.payload) catch {};
                _ = errorCode(m.payload);
            }
        }
    }.one, .{});
}
