//! Ethernet II framing with up to two 802.1Q/802.1ad VLAN tags, and ARP
//! for IPv4 over Ethernet (RFC 826).

const std = @import("std");

pub const header_len = 14;
pub const max_vlan_tags = 2;

pub const EtherType = struct {
    pub const ipv4: u16 = 0x0800;
    pub const arp: u16 = 0x0806;
    pub const vlan: u16 = 0x8100;
    pub const qinq: u16 = 0x88a8;
    pub const ipv6: u16 = 0x86dd;
};

pub const Mac = [6]u8;
pub const broadcast: Mac = .{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

pub const Decoded = struct {
    dst: Mac,
    src: Mac,
    /// EtherType after any VLAN tags.
    ethertype: u16,
    vlan_ids: [max_vlan_tags]u12,
    vlan_count: u8,
    payload: []const u8,
};

pub const DecodeError = error{ Truncated, TooManyVlanTags, NotEthernetII };

pub fn decode(bytes: []const u8) DecodeError!Decoded {
    if (bytes.len < header_len) return error.Truncated;
    var d: Decoded = .{
        .dst = bytes[0..6].*,
        .src = bytes[6..12].*,
        .ethertype = std.mem.readInt(u16, bytes[12..14], .big),
        .vlan_ids = .{ 0, 0 },
        .vlan_count = 0,
        .payload = undefined,
    };
    var off: usize = header_len;
    while (d.ethertype == EtherType.vlan or d.ethertype == EtherType.qinq) {
        if (d.vlan_count == max_vlan_tags) return error.TooManyVlanTags;
        if (off + 4 > bytes.len) return error.Truncated;
        const tci = std.mem.readInt(u16, bytes[off..][0..2], .big);
        d.vlan_ids[d.vlan_count] = @truncate(tci);
        d.vlan_count += 1;
        d.ethertype = std.mem.readInt(u16, bytes[off + 2 ..][0..2], .big);
        off += 4;
    }
    // Values below 0x0600 are 802.3 length fields, not EtherTypes.
    if (d.ethertype < 0x0600) return error.NotEthernetII;
    d.payload = bytes[off..];
    return d;
}

pub fn encode(dst: Mac, src: Mac, ethertype: u16, out: []u8) error{BufferTooSmall}!usize {
    if (out.len < header_len) return error.BufferTooSmall;
    @memcpy(out[0..6], &dst);
    @memcpy(out[6..12], &src);
    std.mem.writeInt(u16, out[12..14], ethertype, .big);
    return header_len;
}

// ---------------------------------------------------------------- ARP

pub const arp_len = 28;

pub const ArpOp = struct {
    pub const request: u16 = 1;
    pub const reply: u16 = 2;
};

pub const Arp = struct {
    op: u16,
    sender_mac: Mac,
    sender_ip: [4]u8,
    target_mac: Mac,
    target_ip: [4]u8,
};

pub fn decodeArp(bytes: []const u8) error{ Truncated, Unsupported }!Arp {
    if (bytes.len < arp_len) return error.Truncated;
    const htype = std.mem.readInt(u16, bytes[0..2], .big);
    const ptype = std.mem.readInt(u16, bytes[2..4], .big);
    if (htype != 1 or ptype != EtherType.ipv4 or bytes[4] != 6 or bytes[5] != 4) return error.Unsupported;
    return .{
        .op = std.mem.readInt(u16, bytes[6..8], .big),
        .sender_mac = bytes[8..14].*,
        .sender_ip = bytes[14..18].*,
        .target_mac = bytes[18..24].*,
        .target_ip = bytes[24..28].*,
    };
}

pub fn encodeArp(a: Arp, out: []u8) error{BufferTooSmall}!usize {
    if (out.len < arp_len) return error.BufferTooSmall;
    std.mem.writeInt(u16, out[0..2], 1, .big);
    std.mem.writeInt(u16, out[2..4], EtherType.ipv4, .big);
    out[4] = 6;
    out[5] = 4;
    std.mem.writeInt(u16, out[6..8], a.op, .big);
    @memcpy(out[8..14], &a.sender_mac);
    @memcpy(out[14..18], &a.sender_ip);
    @memcpy(out[18..24], &a.target_mac);
    @memcpy(out[24..28], &a.target_ip);
    return arp_len;
}

const testing = std.testing;

test "double-tagged frame" {
    var f: [64]u8 = undefined;
    _ = try encode(broadcast, .{ 2, 0, 0, 0, 0, 1 }, EtherType.qinq, &f);
    std.mem.writeInt(u16, f[14..16], 100, .big);
    std.mem.writeInt(u16, f[16..18], EtherType.vlan, .big);
    std.mem.writeInt(u16, f[18..20], 0x2000 | 200, .big); // PCP bits set
    std.mem.writeInt(u16, f[20..22], EtherType.ipv6, .big);
    const d = try decode(&f);
    try testing.expectEqual(@as(u8, 2), d.vlan_count);
    try testing.expectEqual(@as(u12, 100), d.vlan_ids[0]);
    try testing.expectEqual(@as(u12, 200), d.vlan_ids[1]);
    try testing.expectEqual(EtherType.ipv6, d.ethertype);
    try testing.expectEqual(@as(usize, 64 - 22), d.payload.len);
}

test "reject triple tag, 802.3 length, truncated tag" {
    var f = @as([30]u8, @splat(0));
    std.mem.writeInt(u16, f[12..14], EtherType.vlan, .big);
    std.mem.writeInt(u16, f[16..18], EtherType.vlan, .big);
    std.mem.writeInt(u16, f[20..22], EtherType.vlan, .big);
    try testing.expectError(error.TooManyVlanTags, decode(&f));
    std.mem.writeInt(u16, f[12..14], 0x0040, .big);
    try testing.expectError(error.NotEthernetII, decode(&f));
    std.mem.writeInt(u16, f[12..14], EtherType.vlan, .big);
    try testing.expectError(error.Truncated, decode(f[0..16]));
}

test "arp round trip" {
    var b: [28]u8 = undefined;
    const a: Arp = .{ .op = ArpOp.request, .sender_mac = .{ 2, 0, 0, 0, 0, 1 }, .sender_ip = .{ 10, 0, 0, 1 }, .target_mac = @as([6]u8, @splat(0)), .target_ip = .{ 10, 0, 0, 2 } };
    _ = try encodeArp(a, &b);
    const d = try decodeArp(&b);
    try testing.expectEqual(ArpOp.request, d.op);
    try testing.expectEqualSlices(u8, &a.target_ip, &d.target_ip);
    b[5] = 16;
    try testing.expectError(error.Unsupported, decodeArp(&b));
}
