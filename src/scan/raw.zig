//! Raw probe construction and reply correlation, IPv4 and IPv6.
//!
//! Each probe slot owns one source port / ICMP identifier (`base_port +
//! slot`). Every probe carries a 32-bit token derived from a keyed SipHash
//! of (dst, dport, sport, generation):
//!   TCP SYN   seq = token        reply must ack token+1 (SYN/ACK or RST/ACK)
//!   TCP ACK   ack = token        reply must be RST with seq == token
//!   UDP       IPv4 ID = token low 16 bits (checked in ICMP quotes only:
//!             a UDP reply echoes nothing, so it binds to the current
//!             generation, and only if address and ports match the slot)
//!   ICMP echo id = sport, seq = token low 16 bits
//! ICMP errors must quote our source address and the probe's ports and
//! token. Nothing is trusted from a frame that fails these checks.
//!
//! Pure: no sockets. The Linux transport feeds it parsed frames.

const std = @import("std");
const packet = @import("../packet.zig");
const parser = packet.parser;
const targets = @import("../core/targets.zig");
const Reason = @import("../core/port_state.zig").Reason;
const SipHash = std.crypto.auth.siphash.SipHash64(2, 4);

pub const Addr = targets.Addr;
pub const default_base_port: u16 = 61000; // above Linux's default ephemeral range (32768-60999)

pub const Kind = enum(u8) { tcp_syn, tcp_ack, udp, icmp_echo };

pub const Slot = struct {
    dst: Addr = .{ .bytes = @splat(0), .is_v6 = false },
    dport: u16 = 0,
    gen: u32 = 0,
    kind: Kind = .tcp_syn,
    /// Ever armed: late replies for the current occupant stay recognisable.
    used: bool = false,
};

pub const CaptureStats = struct {
    frames: u64 = 0,
    outgoing_skipped: u64 = 0,
    parse_errors: u64 = 0,
    not_ours: u64 = 0,
    bad_checksum: u64 = 0,
    partial_checksum_accepted: u64 = 0,
    token_mismatch: u64 = 0,
    foreign_occupant: u64 = 0,
    other_flags: u64 = 0,
    matched_tcp: u64 = 0,
    matched_udp: u64 = 0,
    matched_icmp: u64 = 0,
    kernel_drops: u64 = 0,
    /// Ring blocks the kernel flagged TP_STATUS_LOSING (frames were dropped).
    ring_losing_blocks: u64 = 0,
    /// Matched replies lost because the transport backlog was full.
    events_dropped: u64 = 0,
};

pub const Match = struct { slot: u32, gen: u32, reason: Reason };

/// Facts about a matched reply that OS fingerprinting consumes. Copied out
/// of the frame: never a slice into capture memory.
pub const ReplyFacts = struct {
    ttl: u8 = 0,
    ip_id: u16 = 0,
    df: bool = false,
    window: u16 = 0,
    options: [40]u8 = undefined,
    options_len: u8 = 0,
    flags: u8 = 0,
};

pub const Correlator = struct {
    key: [16]u8,
    src4: ?[4]u8,
    src6: ?[16]u8,
    base_port: u16,
    slots: []Slot,
    stats: CaptureStats = .{},
    /// Filled for every TCP match; read immediately by the transport.
    last_facts: ReplyFacts = .{},

    pub fn init(gpa: std.mem.Allocator, key: [16]u8, src4: ?[4]u8, src6: ?[16]u8, base_port: u16, n: u32) !Correlator {
        if (@as(u32, base_port) + n > 65536) return error.PortRangeOverflow;
        const slots = try gpa.alloc(Slot, n);
        @memset(slots, .{});
        return .{ .key = key, .src4 = src4, .src6 = src6, .base_port = base_port, .slots = slots };
    }

    pub fn deinit(c: *Correlator, gpa: std.mem.Allocator) void {
        gpa.free(c.slots);
    }

    pub fn sport(c: *const Correlator, slot: u32) u16 {
        return @intCast(@as(u32, c.base_port) + slot);
    }

    pub fn token(c: *const Correlator, dst: Addr, dport: u16, sp: u16, gen: u32) u32 {
        var msg: [24]u8 = undefined;
        @memcpy(msg[0..16], &dst.bytes);
        std.mem.writeInt(u16, msg[16..18], dport, .big);
        std.mem.writeInt(u16, msg[18..20], sp, .big);
        std.mem.writeInt(u32, msg[20..24], gen, .big);
        return @truncate(SipHash.toInt(&msg, &c.key));
    }

    pub fn arm(c: *Correlator, slot: u32, gen: u32, kind: Kind, dst: Addr, dport: u16) u32 {
        c.slots[slot] = .{ .dst = dst, .dport = dport, .gen = gen, .kind = kind, .used = true };
        return c.token(dst, dport, c.sport(slot), gen);
    }

    fn slotFor(c: *const Correlator, port: u16) ?u32 {
        if (port < c.base_port) return null;
        const s: u32 = port - c.base_port;
        return if (s < c.slots.len) s else null;
    }

    /// Which recent generation (current or up to 3 back) produced a value
    /// whose low `bits` equal `v`.
    fn genFor(c: *const Correlator, s: *const Slot, slot: u32, v: u32, comptime bits: u6) ?u32 {
        const mask: u32 = if (bits == 32) 0xffff_ffff else (@as(u32, 1) << @intCast(bits)) - 1;
        var back: u32 = 0;
        while (back < 4) : (back += 1) {
            const g = s.gen -% back;
            if (c.token(s.dst, s.dport, c.sport(slot), g) & mask == v & mask) return g;
        }
        return null;
    }

    fn checksumOk(c: *Correlator, st: parser.ChecksumStatus, csum_not_ready: bool) bool {
        switch (st) {
            .good => return true,
            .partial => if (csum_not_ready) {
                // TP_STATUS_CSUMNOTREADY: locally generated, checksum left to offload.
                c.stats.partial_checksum_accepted += 1;
                return true;
            },
            else => {},
        }
        c.stats.bad_checksum += 1;
        return false;
    }

    fn isToUs(c: *const Correlator, p: *const parser.Packet) bool {
        if (!p.has_ip) return false;
        if (p.is_ipv6) return if (c.src6) |s| std.mem.eql(u8, &p.dst, &s) else false;
        return if (c.src4) |s| std.mem.eql(u8, p.dst[0..4], &s) else false;
    }

    fn quoteFromUs(c: *const Correlator, q: *const packet.icmp.Quote) bool {
        if (q.is_ipv6) return if (c.src6) |s| std.mem.eql(u8, &q.src, &s) else false;
        return if (c.src4) |s| std.mem.eql(u8, q.src[0..4], &s) else false;
    }

    fn srcIs(p: *const parser.Packet, a: Addr) bool {
        return p.is_ipv6 == a.is_v6 and std.mem.eql(u8, if (a.is_v6) &p.src else p.src[0..4], if (a.is_v6) &a.bytes else a.bytes[0..4]);
    }

    fn reject(c: *Correlator, comptime field: []const u8) ?Match {
        @field(c.stats, field) += 1;
        return null;
    }

    /// A match carrying an older generation is delivered so the engine can
    /// record it as stale evidence; it never reclassifies.
    pub fn match(c: *Correlator, p: *const parser.Packet, csum_not_ready: bool) ?Match {
        if (!c.isToUs(p)) return c.reject("not_ours");
        switch (p.l4) {
            .tcp => |t| return c.matchTcp(p, t, csum_not_ready),
            .udp => |u| return c.matchUdp(p, u, csum_not_ready),
            .icmp => |m| return c.matchIcmp(p, m, csum_not_ready),
            else => return c.reject("not_ours"),
        }
    }

    fn matchTcp(c: *Correlator, p: *const parser.Packet, t: parser.Tcp, nr: bool) ?Match {
        const slot = c.slotFor(t.header.dst_port) orelse return c.reject("not_ours");
        const s = &c.slots[slot];
        if (!s.used or (s.kind != .tcp_syn and s.kind != .tcp_ack)) return c.reject("not_ours");
        if (!srcIs(p, s.dst) or t.header.src_port != s.dport) return c.reject("foreign_occupant");
        if (!c.checksumOk(t.checksum, nr)) return null;
        const f = t.header.flags;
        var reason: Reason = undefined;
        var gen: ?u32 = null;
        switch (s.kind) {
            .tcp_syn => {
                reason = if (f.syn and f.ack and !f.rst) .syn_ack else if (f.rst and f.ack) .rst else return c.reject("other_flags");
                gen = c.genFor(s, slot, t.header.ack -% 1, 32);
            },
            .tcp_ack => {
                if (!f.rst) return c.reject("other_flags");
                reason = .rst;
                gen = c.genFor(s, slot, t.header.seq, 32);
            },
            else => unreachable,
        }
        const g = gen orelse return c.reject("token_mismatch");
        c.stats.matched_tcp += 1;
        c.last_facts = .{ .ttl = p.ttl, .ip_id = p.ip_id, .df = p.dont_fragment, .window = t.header.window, .flags = t.header.flags.bits() };
        const n: u8 = @intCast(@min(t.options_raw.len, 40));
        @memcpy(c.last_facts.options[0..n], t.options_raw[0..n]);
        c.last_facts.options_len = n;
        return .{ .slot = slot, .gen = g, .reason = reason };
    }

    fn matchUdp(c: *Correlator, p: *const parser.Packet, u: parser.Udp, nr: bool) ?Match {
        const slot = c.slotFor(u.header.dst_port) orelse return c.reject("not_ours");
        const s = &c.slots[slot];
        if (!s.used or s.kind != .udp) return c.reject("not_ours");
        if (!srcIs(p, s.dst) or u.header.src_port != s.dport) return c.reject("foreign_occupant");
        // Unlike TCP and ICMP, a UDP checksum of zero is legal (unverified).
        switch (u.checksum) {
            .good, .unverified => {},
            .partial => if (nr) {
                c.stats.partial_checksum_accepted += 1;
            } else return c.reject("bad_checksum"),
            .bad => return c.reject("bad_checksum"),
        }
        c.stats.matched_udp += 1;
        return .{ .slot = slot, .gen = s.gen, .reason = .udp_reply };
    }

    fn matchIcmp(c: *Correlator, p: *const parser.Packet, m: parser.Icmp, nr: bool) ?Match {
        const v6 = p.is_ipv6;
        const echo_reply: u8 = if (v6) packet.icmp.V6Type.echo_reply else packet.icmp.V4Type.echo_reply;
        if (m.header.type == echo_reply) {
            const slot = c.slotFor(m.header.echoId()) orelse return c.reject("not_ours");
            const s = &c.slots[slot];
            if (!s.used or s.kind != .icmp_echo) return c.reject("not_ours");
            if (!srcIs(p, s.dst)) return c.reject("foreign_occupant");
            if (!c.checksumOk(m.checksum, nr)) return null;
            const g = c.genFor(s, slot, m.header.echoSeq(), 16) orelse return c.reject("token_mismatch");
            c.stats.matched_icmp += 1;
            return .{ .slot = slot, .gen = g, .reason = .echo_reply };
        }
        const unreach: u8 = if (v6) packet.icmp.V6Type.dest_unreachable else packet.icmp.V4Type.dest_unreachable;
        if (m.header.type != unreach) return c.reject("not_ours");
        const q = m.quote orelse return c.reject("not_ours");
        if (!q.transport_ok or !c.quoteFromUs(&q)) return c.reject("not_ours");
        const sp = std.mem.readInt(u16, q.transport[0..2], .big);
        const dp = std.mem.readInt(u16, q.transport[2..4], .big);
        const slot = c.slotFor(sp) orelse return c.reject("not_ours");
        const s = &c.slots[slot];
        const qdst: Addr = if (q.is_ipv6) Addr.v6(q.dst) else Addr.v4(q.dst[0..4].*);
        if (!s.used or !s.dst.eql(qdst) or dp != s.dport) return c.reject("foreign_occupant");
        if (!c.checksumOk(m.checksum, nr)) return null;
        var gen: ?u32 = null;
        switch (s.kind) {
            .tcp_syn => if (q.protocol == packet.ipv4.Protocol.tcp) {
                gen = c.genFor(s, slot, std.mem.readInt(u32, q.transport[4..8], .big), 32);
            },
            .udp => if (q.protocol == packet.ipv4.Protocol.udp) {
                // IPv4 quotes carry our IP ID; IPv6 has no equivalent field.
                gen = if (q.is_ipv6) s.gen else c.genFor(s, slot, q.ip_id, 16);
            },
            // Discovery reads only the echo reply, SYN/ACK or RST; ICMP errors
            // about its ACK and echo probes are not used.
            .tcp_ack, .icmp_echo => return c.reject("not_ours"),
        }
        const g = gen orelse return c.reject("token_mismatch");
        c.stats.matched_icmp += 1;
        return .{ .slot = slot, .gen = g, .reason = if (v6) icmp6Reason(m.header.code) else icmp4Reason(m.header.code) };
    }
};

fn icmp4Reason(code: u8) Reason {
    return switch (code) {
        0 => .icmp_net_unreach,
        1 => .icmp_host_unreach,
        2 => .icmp_proto_unreach,
        3 => .icmp_port_unreach,
        9, 10, 13 => .icmp_admin_prohibited,
        else => .icmp_unreach_other,
    };
}

fn icmp6Reason(code: u8) Reason {
    return switch (code) {
        0 => .icmp_net_unreach, // no route to destination
        1, 5, 6 => .icmp_admin_prohibited, // prohibited / policy / reject route
        3 => .icmp_host_unreach, // address unreachable
        4 => .icmp_port_unreach,
        else => .icmp_unreach_other,
    };
}

// ------------------------------------------------------------ builders

pub const Link = struct { src_mac: [6]u8, dst_mac: [6]u8 };

pub const ProbeSpec = struct {
    kind: Kind,
    src: Addr,
    dst: Addr,
    sport: u16,
    dport: u16,
    token: u32,
    ip_id: u16 = 0,
    hop_limit: u8 = 64,
    payload: []const u8 = &.{},
};

/// Builds the probe. With `link`, an Ethernet frame; without, an IP
/// datagram (IPv4 L3 raw send) or, for IPv6, only the transport segment
/// (the kernel prepends the IPv6 header on raw IPv6 sockets). Returns the
/// bytes written.
pub fn build(spec: ProbeSpec, link: ?Link, out: []u8) !usize {
    var off: usize = 0;
    if (link) |l| {
        off = try packet.ethernet.encode(l.dst_mac, l.src_mac, if (spec.dst.is_v6) packet.ethernet.EtherType.ipv6 else packet.ethernet.EtherType.ipv4, out);
    }
    var seg_buf: [1500]u8 = undefined;
    const proto: u8 = switch (spec.kind) {
        .tcp_syn, .tcp_ack => packet.ipv4.Protocol.tcp,
        .udp => packet.ipv4.Protocol.udp,
        .icmp_echo => if (spec.dst.is_v6) packet.ipv4.Protocol.icmpv6 else packet.ipv4.Protocol.icmp,
    };
    const expected_seg_len: usize = switch (spec.kind) {
        .tcp_syn => 40,
        .tcp_ack => 20,
        .udp => 8 + spec.payload.len,
        .icmp_echo => 8 + spec.payload.len,
    };
    const pseudo: u32 = if (spec.dst.is_v6)
        packet.checksum.pseudoV6(spec.src.bytes, spec.dst.bytes, proto, @intCast(expected_seg_len))
    else
        packet.checksum.pseudoV4(spec.src.bytes4(), spec.dst.bytes4(), proto, @intCast(expected_seg_len));
    const seg_len: usize = switch (spec.kind) {
        .tcp_syn => blk: {
            // A conventional client option set (MSS, SACK, TS, NOP, WS) so the
            // reply shows the target stack's own option layout and values.
            var opts: [20]u8 = undefined;
            const olen = try packet.tcp.encodeOptions(.{ .mss = 1460, .sack_permitted = true, .timestamps = .{ .val = spec.token, .ecr = 0 }, .window_scale = 7 }, &opts);
            break :blk try packet.tcp.encode(.{ .src_port = spec.sport, .dst_port = spec.dport, .seq = spec.token, .flags = .{ .syn = true }, .window = 64240 }, opts[0..olen], &.{}, pseudo, &seg_buf);
        },
        .tcp_ack => try packet.tcp.encode(.{ .src_port = spec.sport, .dst_port = spec.dport, .seq = 0, .ack = spec.token, .flags = .{ .ack = true }, .window = 1024 }, &.{}, &.{}, pseudo, &seg_buf),
        .udp => try packet.udp.encode(spec.sport, spec.dport, spec.payload, pseudo, &seg_buf),
        .icmp_echo => try packet.icmp.encodeEcho(
            if (spec.dst.is_v6) packet.icmp.V6Type.echo_request else packet.icmp.V4Type.echo_request,
            spec.sport,
            @truncate(spec.token),
            spec.payload,
            if (spec.dst.is_v6) pseudo else 0,
            &seg_buf,
        ),
    };
    std.debug.assert(seg_len == expected_seg_len);
    if (spec.dst.is_v6) {
        if (link != null) off += try packet.ipv6.encode(.{ .next_header = proto, .hop_limit = spec.hop_limit, .src = spec.src.bytes, .dst = spec.dst.bytes }, seg_len, out[off..]);
    } else {
        off += try packet.ipv4.encode(.{ .id = spec.ip_id, .ttl = spec.hop_limit, .protocol = proto, .src = spec.src.bytes4(), .dst = spec.dst.bytes4() }, seg_len, out[off..]);
    }
    if (off + seg_len > out.len) return error.BufferTooSmall;
    @memcpy(out[off..][0..seg_len], seg_buf[0..seg_len]);
    return off + seg_len;
}

// ---------------------------------------------------------------- tests

const testing = std.testing;
const me4 = Addr.v4(.{ 10, 9, 0, 2 });
const tg4 = Addr.v4(.{ 10, 9, 0, 3 });
const me6 = Addr.v6(.{ 0x20, 0x01, 0x0d, 0xb8 } ++ @as([11]u8, @splat(0)) ++ [_]u8{2});
const tg6 = Addr.v6(.{ 0x20, 0x01, 0x0d, 0xb8 } ++ @as([11]u8, @splat(0)) ++ [_]u8{3});
const test_link: Link = .{ .src_mac = .{ 2, 0, 0, 0, 0, 0xb }, .dst_mac = .{ 2, 0, 0, 0, 0, 0xa } };
const reply_link: Link = .{ .src_mac = test_link.dst_mac, .dst_mac = test_link.src_mac };

fn setup() !Correlator {
    return Correlator.init(testing.allocator, @splat(0x5a), me4.bytes4(), me6.bytes, 61000, 8);
}

/// Target-side TCP reply built with the same encoders (full checksums).
fn tcpReply(buf: []u8, from: Addr, sp: u16, dp: u16, seq: u32, ack: u32, flags: packet.tcp.Flags) []const u8 {
    const to = if (from.is_v6) me6 else me4;
    var off = packet.ethernet.encode(reply_link.dst_mac, reply_link.src_mac, if (from.is_v6) packet.ethernet.EtherType.ipv6 else packet.ethernet.EtherType.ipv4, buf) catch unreachable;
    const pseudo = if (from.is_v6) packet.checksum.pseudoV6(from.bytes, to.bytes, 6, 20) else packet.checksum.pseudoV4(from.bytes4(), to.bytes4(), 6, 20);
    off += if (from.is_v6)
        packet.ipv6.encode(.{ .next_header = 6, .src = from.bytes, .dst = to.bytes }, 20, buf[off..]) catch unreachable
    else
        packet.ipv4.encode(.{ .protocol = 6, .src = from.bytes4(), .dst = to.bytes4(), .dont_fragment = true }, 20, buf[off..]) catch unreachable;
    const n = packet.tcp.encode(.{ .src_port = sp, .dst_port = dp, .seq = seq, .ack = ack, .flags = flags, .window = 512 }, &.{}, &.{}, pseudo, buf[off..]) catch unreachable;
    return buf[0 .. off + n];
}

test "SYN frames for v4 and v6 parse back with good checksums" {
    var c = try setup();
    defer c.deinit(testing.allocator);
    var f: [128]u8 = undefined;
    for ([_]Addr{ tg4, tg6 }) |dst| {
        const tok = c.arm(2, 1, .tcp_syn, dst, 443);
        const n = try build(.{ .kind = .tcp_syn, .src = if (dst.is_v6) me6 else me4, .dst = dst, .sport = c.sport(2), .dport = 443, .token = tok, .ip_id = 9 }, test_link, &f);
        const p = try parser.parse(.ethernet, f[0..n]);
        try testing.expectEqual(parser.ChecksumStatus.good, p.l4.tcp.checksum);
        try testing.expectEqual(tok, p.l4.tcp.header.seq);
        try testing.expectEqual(dst.is_v6, p.is_ipv6);
    }
}

test "SYN/ACK and RST match v4 and v6; wrong ack rejected" {
    var c = try setup();
    defer c.deinit(testing.allocator);
    var b: [128]u8 = undefined;
    for ([_]Addr{ tg4, tg6 }) |dst| {
        const tok = c.arm(3, 5, .tcp_syn, dst, 22);
        const ok = try parser.parse(.ethernet, tcpReply(&b, dst, 22, 61003, 777, tok +% 1, .{ .syn = true, .ack = true }));
        try testing.expectEqual(Match{ .slot = 3, .gen = 5, .reason = .syn_ack }, c.match(&ok, false).?);
        try testing.expectEqual(@as(u16, 512), c.last_facts.window);
        const rst = try parser.parse(.ethernet, tcpReply(&b, dst, 22, 61003, 0, tok +% 1, .{ .rst = true, .ack = true }));
        try testing.expectEqual(Reason.rst, c.match(&rst, false).?.reason);
        const bad = try parser.parse(.ethernet, tcpReply(&b, dst, 22, 61003, 777, tok +% 2, .{ .syn = true, .ack = true }));
        try testing.expectEqual(@as(?Match, null), c.match(&bad, false));
    }
    try testing.expectEqual(@as(u64, 2), c.stats.token_mismatch);
}

test "spoofed source, background ports, odd flags rejected" {
    var c = try setup();
    defer c.deinit(testing.allocator);
    const tok = c.arm(1, 1, .tcp_syn, tg4, 80);
    var b: [128]u8 = undefined;
    try testing.expectEqual(@as(?Match, null), c.match(&(try parser.parse(.ethernet, tcpReply(&b, Addr.v4(.{ 10, 9, 0, 99 }), 80, 61001, 1, tok +% 1, .{ .syn = true, .ack = true }))), false));
    try testing.expectEqual(@as(?Match, null), c.match(&(try parser.parse(.ethernet, tcpReply(&b, tg4, 80, 40000, 1, tok +% 1, .{ .syn = true, .ack = true }))), false));
    try testing.expectEqual(@as(?Match, null), c.match(&(try parser.parse(.ethernet, tcpReply(&b, tg4, 80, 61001, 1, tok +% 1, .{ .ack = true }))), false));
    try testing.expectEqual(@as(?Match, null), c.match(&(try parser.parse(.ethernet, tcpReply(&b, tg4, 80, 61001, 0, 0, .{ .rst = true }))), false));
    try testing.expectEqual(@as(u64, 1), c.stats.foreign_occupant);
    try testing.expectEqual(@as(u64, 2), c.stats.other_flags);
}

test "stale generation is reported as such; foreign occupant dropped" {
    var c = try setup();
    defer c.deinit(testing.allocator);
    const old = c.arm(4, 10, .tcp_syn, tg4, 8080);
    _ = c.arm(4, 11, .tcp_syn, tg4, 8080);
    var b: [128]u8 = undefined;
    try testing.expectEqual(@as(u32, 10), c.match(&(try parser.parse(.ethernet, tcpReply(&b, tg4, 8080, 61004, 1, old +% 1, .{ .syn = true, .ack = true }))), false).?.gen);
    _ = c.arm(4, 12, .tcp_syn, tg4, 9090);
    try testing.expectEqual(@as(?Match, null), c.match(&(try parser.parse(.ethernet, tcpReply(&b, tg4, 8080, 61004, 1, old +% 1, .{ .syn = true, .ack = true }))), false));
}

test "TCP ACK probe: RST with seq == token" {
    var c = try setup();
    defer c.deinit(testing.allocator);
    const tok = c.arm(0, 3, .tcp_ack, tg4, 80);
    var b: [128]u8 = undefined;
    try testing.expectEqual(Reason.rst, c.match(&(try parser.parse(.ethernet, tcpReply(&b, tg4, 80, 61000, tok, 0, .{ .rst = true }))), false).?.reason);
    try testing.expectEqual(@as(?Match, null), c.match(&(try parser.parse(.ethernet, tcpReply(&b, tg4, 80, 61000, tok +% 1, 0, .{ .rst = true }))), false));
}

test "checksum policy: bad rejected, partial only when kernel says not-ready" {
    var c = try setup();
    defer c.deinit(testing.allocator);
    const tok = c.arm(0, 1, .tcp_syn, tg4, 25);
    var b: [128]u8 = undefined;
    const f = tcpReply(&b, tg4, 25, 61000, 1, tok +% 1, .{ .syn = true, .ack = true });
    var bad: [128]u8 = undefined;
    @memcpy(bad[0..f.len], f);
    bad[34 + 16] ^= 0xff;
    try testing.expectEqual(@as(?Match, null), c.match(&(try parser.parse(.ethernet, bad[0..f.len])), false));
    std.mem.writeInt(u16, bad[34 + 16 ..][0..2], ~packet.checksum.finish(packet.checksum.pseudoV4(tg4.bytes4(), me4.bytes4(), 6, 20)), .big);
    const pp = try parser.parse(.ethernet, bad[0..f.len]);
    try testing.expectEqual(@as(?Match, null), c.match(&pp, false));
    try testing.expect(c.match(&pp, true) != null);
}

fn icmpQuoting(buf: []u8, probe: []const u8, v6: bool, typ: u8, code: u8) []const u8 {
    const from = if (v6) tg6 else tg4;
    const to = if (v6) me6 else me4;
    var off = packet.ethernet.encode(reply_link.dst_mac, reply_link.src_mac, if (v6) packet.ethernet.EtherType.ipv6 else packet.ethernet.EtherType.ipv4, buf) catch unreachable;
    const qlen = @min(probe.len, @as(usize, if (v6) 48 else 28));
    const mlen = 8 + qlen;
    off += if (v6)
        packet.ipv6.encode(.{ .next_header = 58, .src = from.bytes, .dst = to.bytes }, mlen, buf[off..]) catch unreachable
    else
        packet.ipv4.encode(.{ .protocol = 1, .src = from.bytes4(), .dst = to.bytes4() }, mlen, buf[off..]) catch unreachable;
    const m = buf[off..][0..mlen];
    m[0] = typ;
    m[1] = code;
    @memset(m[2..8], 0);
    @memcpy(m[8..][0..qlen], probe[0..qlen]);
    const pseudo: u32 = if (v6) packet.checksum.pseudoV6(from.bytes, to.bytes, 58, @intCast(mlen)) else 0;
    std.mem.writeInt(u16, m[2..4], packet.checksum.finish(packet.checksum.add(pseudo, m)), .big);
    return buf[0 .. off + mlen];
}

test "UDP: reply, ICMPv4 port unreachable with IP ID token, ICMPv6 port unreachable" {
    var c = try setup();
    defer c.deinit(testing.allocator);
    var probe: [128]u8 = undefined;
    var b: [256]u8 = undefined;
    // v4
    const tok = c.arm(5, 7, .udp, tg4, 161);
    const n = try build(.{ .kind = .udp, .src = me4, .dst = tg4, .sport = c.sport(5), .dport = 161, .token = tok, .ip_id = @truncate(tok) }, null, &probe);
    const m4 = c.match(&(try parser.parse(.raw_ip, icmpQuoting(&b, probe[0..n], false, 3, 3)[14..])), false).?;
    try testing.expectEqual(Match{ .slot = 5, .gen = 7, .reason = .icmp_port_unreach }, m4);
    // quote with a different IP ID (not our attempt) is rejected
    var other = probe;
    other[5] ^= 0x55;
    std.mem.writeInt(u16, other[10..12], 0, .big);
    try testing.expectEqual(@as(?Match, null), c.match(&(try parser.parse(.raw_ip, icmpQuoting(&b, other[0..n], false, 3, 3)[14..])), false));
    // direct UDP reply
    var r: [64]u8 = undefined;
    _ = try packet.ipv4.encode(.{ .protocol = 17, .src = tg4.bytes4(), .dst = me4.bytes4() }, 12, &r);
    _ = try packet.udp.encode(161, c.sport(5), "abcd", packet.checksum.pseudoV4(tg4.bytes4(), me4.bytes4(), 17, 12), r[20..]);
    try testing.expectEqual(Reason.udp_reply, c.match(&(try parser.parse(.raw_ip, r[0..32])), false).?.reason);
    // v6
    const tok6 = c.arm(6, 2, .udp, tg6, 53);
    var p6: [128]u8 = undefined;
    const n6 = try build(.{ .kind = .udp, .src = me6, .dst = tg6, .sport = c.sport(6), .dport = 53, .token = tok6 }, test_link, &p6);
    const m6 = c.match(&(try parser.parse(.ethernet, icmpQuoting(&b, p6[14..n6], true, 1, 4))), false).?;
    try testing.expectEqual(Reason.icmp_port_unreach, m6.reason);
    try testing.expectEqual(Reason.icmp_admin_prohibited, c.match(&(try parser.parse(.ethernet, icmpQuoting(&b, p6[14..n6], true, 1, 1))), false).?.reason);
}

test "ICMP echo reply matches id and token" {
    var c = try setup();
    defer c.deinit(testing.allocator);
    const tok = c.arm(1, 4, .icmp_echo, tg4, 0);
    var r: [64]u8 = undefined;
    _ = try packet.ipv4.encode(.{ .protocol = 1, .src = tg4.bytes4(), .dst = me4.bytes4() }, 8, &r);
    _ = try packet.icmp.encodeEcho(packet.icmp.V4Type.echo_reply, c.sport(1), @truncate(tok), &.{}, 0, r[20..]);
    try testing.expectEqual(Reason.echo_reply, c.match(&(try parser.parse(.raw_ip, r[0..28])), false).?.reason);
    _ = try packet.icmp.encodeEcho(packet.icmp.V4Type.echo_reply, c.sport(1), @truncate(tok +% 1), &.{}, 0, r[20..]);
    try testing.expectEqual(@as(?Match, null), c.match(&(try parser.parse(.raw_ip, r[0..28])), false));
}

test "correlator never panics on arbitrary frames" {
    try std.testing.fuzz({}, struct {
        fn one(_: void, smith: *std.testing.Smith) !void {
            var c = try setup();
            defer c.deinit(testing.allocator);
            _ = c.arm(0, 1, .tcp_syn, tg4, 80);
            _ = c.arm(1, 1, .udp, tg6, 53);
            _ = c.arm(2, 1, .icmp_echo, tg4, 0);
            var b: [160]u8 = undefined;
            const n = smith.valueRangeAtMost(u32, 0, b.len);
            smith.bytes(b[0..n]);
            const lt = if (smith.value(bool)) parser.LinkType.ethernet else parser.LinkType.raw_ip;
            const p = parser.parse(lt, b[0..n]) catch return;
            _ = c.match(&p, smith.value(bool));
        }
    }.one, .{});
}
