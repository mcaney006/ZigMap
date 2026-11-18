//! IPv4 header encoder and bounded decoder (RFC 791).
//!
//! Decoding never casts untrusted bytes to structs; every field is read with
//! explicit bounds and big-endian conversion.

const std = @import("std");
const checksum = @import("checksum.zig");

pub const header_min_len = 20;

pub const Protocol = struct {
    pub const icmp: u8 = 1;
    pub const tcp: u8 = 6;
    pub const udp: u8 = 17;
    pub const icmpv6: u8 = 58;
};

pub const DecodeError = error{
    Truncated,
    BadVersion,
    BadHeaderLength,
    BadTotalLength,
};

pub const Header = struct {
    tos: u8 = 0,
    total_length: u16 = 0,
    id: u16 = 0,
    dont_fragment: bool = false,
    more_fragments: bool = false,
    /// Fragment offset in 8-byte units.
    frag_offset: u13 = 0,
    ttl: u8 = 64,
    protocol: u8,
    checksum: u16 = 0,
    src: [4]u8,
    dst: [4]u8,
};

pub const Decoded = struct {
    header: Header,
    header_len: usize,
    options: []const u8,
    /// Payload bytes actually present (may be shorter than total_length implies).
    payload: []const u8,
    /// True when the buffer ends before `total_length` bytes.
    truncated: bool,
    checksum_ok: bool,

    pub fn isFragment(d: Decoded) bool {
        return d.header.more_fragments or d.header.frag_offset != 0;
    }

    /// First fragment (offset 0) carries the transport header.
    pub fn hasTransportHeader(d: Decoded) bool {
        return d.header.frag_offset == 0;
    }
};

pub const DecodeOptions = struct {
    /// Allow buffers shorter than total_length (ICMP-quoted packets).
    allow_truncated: bool = false,
};

pub fn decode(bytes: []const u8, opts: DecodeOptions) DecodeError!Decoded {
    if (bytes.len < header_min_len) return error.Truncated;
    const version = bytes[0] >> 4;
    if (version != 4) return error.BadVersion;
    const ihl: usize = bytes[0] & 0x0f;
    if (ihl < 5) return error.BadHeaderLength;
    const header_len = ihl * 4;
    if (header_len > bytes.len) return error.Truncated;

    const total_length = std.mem.readInt(u16, bytes[2..4], .big);
    if (total_length < header_len) return error.BadTotalLength;

    var truncated = false;
    var end: usize = total_length;
    if (end > bytes.len) {
        if (!opts.allow_truncated) return error.Truncated;
        truncated = true;
        end = bytes.len;
    }

    const flags_frag = std.mem.readInt(u16, bytes[6..8], .big);
    const h: Header = .{
        .tos = bytes[1],
        .total_length = total_length,
        .id = std.mem.readInt(u16, bytes[4..6], .big),
        .dont_fragment = flags_frag & 0x4000 != 0,
        .more_fragments = flags_frag & 0x2000 != 0,
        .frag_offset = @intCast(flags_frag & 0x1fff),
        .ttl = bytes[8],
        .protocol = bytes[9],
        .checksum = std.mem.readInt(u16, bytes[10..12], .big),
        .src = bytes[12..16].*,
        .dst = bytes[16..20].*,
    };

    return .{
        .header = h,
        .header_len = header_len,
        .options = bytes[header_min_len..header_len],
        .payload = bytes[header_len..end],
        .truncated = truncated,
        .checksum_ok = checksum.verify(bytes[0..header_len]),
    };
}

pub const EncodeError = error{BufferTooSmall};

/// Writes a 20-byte header (no options) with a computed checksum.
/// `payload_len` is used to fill total_length.
pub fn encode(h: Header, payload_len: usize, out: []u8) EncodeError!usize {
    if (out.len < header_min_len) return error.BufferTooSmall;
    const total = header_min_len + payload_len;
    if (total > std.math.maxInt(u16)) return error.BufferTooSmall;
    out[0] = 0x45;
    out[1] = h.tos;
    std.mem.writeInt(u16, out[2..4], @intCast(total), .big);
    std.mem.writeInt(u16, out[4..6], h.id, .big);
    var ff: u16 = h.frag_offset;
    if (h.dont_fragment) ff |= 0x4000;
    if (h.more_fragments) ff |= 0x2000;
    std.mem.writeInt(u16, out[6..8], ff, .big);
    out[8] = h.ttl;
    out[9] = h.protocol;
    out[10] = 0;
    out[11] = 0;
    @memcpy(out[12..16], &h.src);
    @memcpy(out[16..20], &h.dst);
    std.mem.writeInt(u16, out[10..12], checksum.compute(out[0..20]), .big);
    return header_min_len;
}

pub fn format(addr: [4]u8, buf: []u8) []const u8 {
    return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{ addr[0], addr[1], addr[2], addr[3] }) catch buf[0..0];
}

const testing = std.testing;

test "decode published header example" {
    const hdr = [_]u8{ 0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0xb8, 0x61, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7 };
    var buf: [0x73]u8 = undefined;
    @memcpy(buf[0..20], &hdr);
    @memset(buf[20..], 0);
    const d = try decode(&buf, .{});
    try testing.expect(d.checksum_ok);
    try testing.expectEqual(@as(u8, 17), d.header.protocol);
    try testing.expect(d.header.dont_fragment);
    try testing.expect(!d.isFragment());
    try testing.expectEqualSlices(u8, &.{ 192, 168, 0, 199 }, &d.header.dst);
    try testing.expectEqual(@as(usize, 0x73 - 20), d.payload.len);
}

test "reject malformed headers" {
    try testing.expectError(error.Truncated, decode(&@as([10]u8, @splat(0x45)), .{}));
    var b = @as([20]u8, @splat(0));
    b[0] = 0x65;
    try testing.expectError(error.BadVersion, decode(&b, .{}));
    b[0] = 0x44;
    try testing.expectError(error.BadHeaderLength, decode(&b, .{}));
    b[0] = 0x4f; // IHL 15 -> 60 bytes, buffer only 20
    try testing.expectError(error.Truncated, decode(&b, .{}));
    b[0] = 0x45;
    std.mem.writeInt(u16, b[2..4], 10, .big);
    try testing.expectError(error.BadTotalLength, decode(&b, .{}));
    std.mem.writeInt(u16, b[2..4], 100, .big);
    try testing.expectError(error.Truncated, decode(&b, .{}));
    const d = try decode(&b, .{ .allow_truncated = true });
    try testing.expect(d.truncated);
}

test "encode round trip and fragment flags" {
    var out: [20]u8 = undefined;
    const h: Header = .{ .id = 0xbeef, .ttl = 55, .protocol = Protocol.tcp, .src = .{ 10, 0, 0, 1 }, .dst = .{ 10, 0, 0, 2 }, .more_fragments = true, .frag_offset = 3 };
    _ = try encode(h, 0, &out);
    const d = try decode(&out, .{});
    try testing.expect(d.checksum_ok);
    try testing.expect(d.isFragment());
    try testing.expect(!d.hasTransportHeader());
    try testing.expectEqual(@as(u16, 0xbeef), d.header.id);
    try testing.expectEqual(@as(u13, 3), d.header.frag_offset);
}
