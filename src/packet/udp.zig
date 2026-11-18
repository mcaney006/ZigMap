//! UDP header encoder and bounded decoder (RFC 768).

const std = @import("std");
const checksum = @import("checksum.zig");

pub const header_len = 8;

pub const Header = struct {
    src_port: u16,
    dst_port: u16,
    length: u16 = 0,
    checksum: u16 = 0,
};

pub const Decoded = struct {
    header: Header,
    payload: []const u8,
    /// Buffer ended before `length` bytes (normal for ICMP-quoted datagrams).
    truncated: bool,
};

pub const DecodeError = error{ Truncated, BadLength };

pub fn decode(bytes: []const u8) DecodeError!Decoded {
    if (bytes.len < header_len) return error.Truncated;
    const h: Header = .{
        .src_port = std.mem.readInt(u16, bytes[0..2], .big),
        .dst_port = std.mem.readInt(u16, bytes[2..4], .big),
        .length = std.mem.readInt(u16, bytes[4..6], .big),
        .checksum = std.mem.readInt(u16, bytes[6..8], .big),
    };
    if (h.length < header_len) return error.BadLength;
    const end = @min(@as(usize, h.length), bytes.len);
    return .{ .header = h, .payload = bytes[header_len..end], .truncated = h.length > bytes.len };
}

/// Transmits 0xffff when the computed checksum is zero (RFC 768, RFC 8200);
/// zero on the wire means "no checksum" (IPv4 only).
pub fn encode(src_port: u16, dst_port: u16, payload: []const u8, pseudo: u32, out: []u8) error{BufferTooSmall}!usize {
    const total = header_len + payload.len;
    if (out.len < total or total > std.math.maxInt(u16)) return error.BufferTooSmall;
    std.mem.writeInt(u16, out[0..2], src_port, .big);
    std.mem.writeInt(u16, out[2..4], dst_port, .big);
    std.mem.writeInt(u16, out[4..6], @intCast(total), .big);
    out[6] = 0;
    out[7] = 0;
    @memcpy(out[8..total], payload);
    var c = checksum.finish(checksum.add(pseudo, out[0..total]));
    if (c == 0) c = 0xffff;
    std.mem.writeInt(u16, out[6..8], c, .big);
    return total;
}

/// A zero checksum means "not computed" for IPv4 only.
pub fn verify(datagram: []const u8, pseudo: u32, is_ipv6: bool) bool {
    if (datagram.len < header_len) return false;
    if (!is_ipv6 and datagram[6] == 0 and datagram[7] == 0) return true;
    return checksum.finish(checksum.add(pseudo, datagram)) == 0;
}

test "udp round trip" {
    const src = [4]u8{ 127, 0, 0, 1 };
    var out: [64]u8 = undefined;
    const pl = "probe";
    const pseudo = checksum.pseudoV4(src, src, 17, header_len + pl.len);
    const n = try encode(5353, 53, pl, pseudo, &out);
    try std.testing.expect(verify(out[0..n], pseudo, false));
    const d = try decode(out[0..n]);
    try std.testing.expectEqualStrings(pl, d.payload);
    try std.testing.expect(!d.truncated);
    try std.testing.expectError(error.BadLength, decode(&[_]u8{ 0, 1, 0, 2, 0, 3, 0, 0 }));
    const q = try decode(out[0..8]);
    try std.testing.expect(q.truncated);
}
