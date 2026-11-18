//! ICMPv4 (RFC 792) and ICMPv6 (RFC 4443) codecs, including bounded decoding
//! of the invoking packet quoted inside error messages.

const std = @import("std");
const checksum = @import("checksum.zig");
const ipv4 = @import("ipv4.zig");
const ipv6 = @import("ipv6.zig");

pub const header_len = 8;

pub const V4Type = struct {
    pub const echo_reply: u8 = 0;
    pub const dest_unreachable: u8 = 3;
    pub const redirect: u8 = 5;
    pub const echo_request: u8 = 8;
    pub const time_exceeded: u8 = 11;
    pub const parameter_problem: u8 = 12;
    pub const timestamp: u8 = 13;
    pub const timestamp_reply: u8 = 14;
};

pub const V6Type = struct {
    pub const dest_unreachable: u8 = 1;
    pub const packet_too_big: u8 = 2;
    pub const time_exceeded: u8 = 3;
    pub const parameter_problem: u8 = 4;
    pub const echo_request: u8 = 128;
    pub const echo_reply: u8 = 129;
    pub const neighbor_solicitation: u8 = 135;
    pub const neighbor_advertisement: u8 = 136;
};

pub const Header = struct {
    type: u8,
    code: u8,
    checksum: u16,
    /// Bytes 4..8: echo id/seq, MTU, pointer, or unused depending on type.
    rest: [4]u8,

    pub fn echoId(h: Header) u16 {
        return std.mem.readInt(u16, h.rest[0..2], .big);
    }
    pub fn echoSeq(h: Header) u16 {
        return std.mem.readInt(u16, h.rest[2..4], .big);
    }
};

pub const Decoded = struct {
    header: Header,
    body: []const u8,
};

pub fn decode(bytes: []const u8) error{Truncated}!Decoded {
    if (bytes.len < header_len) return error.Truncated;
    return .{
        .header = .{
            .type = bytes[0],
            .code = bytes[1],
            .checksum = std.mem.readInt(u16, bytes[2..4], .big),
            .rest = bytes[4..8].*,
        },
        .body = bytes[8..],
    };
}

pub fn isV4Error(t: u8) bool {
    return t == V4Type.dest_unreachable or t == V4Type.time_exceeded or t == V4Type.parameter_problem or t == V4Type.redirect;
}

pub fn isV6Error(t: u8) bool {
    return t < 128;
}

/// The invoking datagram quoted in an ICMP error, decoded far enough to
/// correlate with an outstanding probe. Quotes are routinely truncated
/// (RFC 792 guarantees only IP header + 8 bytes).
pub const Quote = struct {
    src: [16]u8,
    dst: [16]u8,
    is_ipv6: bool,
    protocol: u8,
    ip_id: u16,
    /// At least the first 8 transport bytes when `transport_ok`.
    transport: []const u8,
    transport_ok: bool,
};

pub fn decodeQuoteV4(body: []const u8) error{ Truncated, BadVersion, BadHeaderLength, BadTotalLength }!Quote {
    const d = try ipv4.decode(body, .{ .allow_truncated = true });
    var q: Quote = .{
        .src = @as([16]u8, @splat(0)),
        .dst = @as([16]u8, @splat(0)),
        .is_ipv6 = false,
        .protocol = d.header.protocol,
        .ip_id = d.header.id,
        .transport = d.payload,
        .transport_ok = d.payload.len >= 8 and d.hasTransportHeader(),
    };
    @memcpy(q.src[0..4], &d.header.src);
    @memcpy(q.dst[0..4], &d.header.dst);
    return q;
}

pub fn decodeQuoteV6(body: []const u8) ipv6.DecodeError!Quote {
    const d = try ipv6.decode(body, .{ .allow_truncated = true });
    return .{
        .src = d.header.src,
        .dst = d.header.dst,
        .is_ipv6 = true,
        .protocol = d.upper_protocol,
        .ip_id = 0,
        .transport = d.upper,
        .transport_ok = d.stop == .upper_layer and d.upper.len >= 8,
    };
}

/// Encodes an echo request. ICMPv4 checksums cover only the message; ICMPv6
/// adds the pseudo-header, so pass `pseudo = 0` for v4.
pub fn encodeEcho(type_: u8, id: u16, seq: u16, payload: []const u8, pseudo: u32, out: []u8) error{BufferTooSmall}!usize {
    const total = header_len + payload.len;
    if (out.len < total) return error.BufferTooSmall;
    out[0] = type_;
    out[1] = 0;
    out[2] = 0;
    out[3] = 0;
    std.mem.writeInt(u16, out[4..6], id, .big);
    std.mem.writeInt(u16, out[6..8], seq, .big);
    @memcpy(out[8..total], payload);
    std.mem.writeInt(u16, out[2..4], checksum.finish(checksum.add(pseudo, out[0..total])), .big);
    return total;
}

pub fn verify(msg: []const u8, pseudo: u32) bool {
    return checksum.finish(checksum.add(pseudo, msg)) == 0;
}

const testing = std.testing;

test "echo v4 round trip" {
    var out: [32]u8 = undefined;
    const n = try encodeEcho(V4Type.echo_request, 0x1234, 7, "zigmap", 0, &out);
    try testing.expect(verify(out[0..n], 0));
    const d = try decode(out[0..n]);
    try testing.expectEqual(@as(u16, 0x1234), d.header.echoId());
    try testing.expectEqual(@as(u16, 7), d.header.echoSeq());
}

test "port unreachable quote with truncated inner datagram" {
    // Inner IPv4/UDP datagram claims 100 bytes but only 28 are quoted.
    var inner: [28]u8 = undefined;
    const h: ipv4.Header = .{ .id = 77, .protocol = ipv4.Protocol.udp, .src = .{ 10, 0, 0, 1 }, .dst = .{ 10, 0, 0, 9 } };
    _ = try ipv4.encode(h, 80, &inner);
    std.mem.writeInt(u16, inner[20..22], 40001, .big);
    std.mem.writeInt(u16, inner[22..24], 161, .big);
    @memset(inner[24..28], 0);
    const q = try decodeQuoteV4(&inner);
    try testing.expect(q.transport_ok);
    try testing.expectEqual(ipv4.Protocol.udp, q.protocol);
    try testing.expectEqual(@as(u16, 161), std.mem.readInt(u16, q.transport[2..4], .big));
    try testing.expectError(error.Truncated, decodeQuoteV4(inner[0..12]));
}
