//! IPv6 fixed header encoder/decoder and bounded extension-header walk
//! (RFC 8200). The walk stops at the first upper-layer protocol, at ESP
//! (payload is opaque), at No-Next-Header, or after `max_ext_headers`.

const std = @import("std");

pub const header_len = 40;
pub const max_ext_headers = 8;

pub const NextHeader = struct {
    pub const hop_by_hop: u8 = 0;
    pub const tcp: u8 = 6;
    pub const udp: u8 = 17;
    pub const routing: u8 = 43;
    pub const fragment: u8 = 44;
    pub const esp: u8 = 50;
    pub const ah: u8 = 51;
    pub const icmpv6: u8 = 58;
    pub const no_next: u8 = 59;
    pub const dest_opts: u8 = 60;
    pub const mobility: u8 = 135;
};

pub const Header = struct {
    traffic_class: u8 = 0,
    flow_label: u20 = 0,
    payload_length: u16 = 0,
    next_header: u8,
    hop_limit: u8 = 64,
    src: [16]u8,
    dst: [16]u8,
};

pub const Fragment = struct {
    offset: u13,
    more: bool,
    id: u32,
};

pub const WalkStop = enum {
    /// `upper_protocol` / `upper` are valid.
    upper_layer,
    no_next_header,
    /// ESP or an unrecognised next header; payload is opaque.
    opaque_payload,
    /// Non-first fragment: the upper-layer header is not in this packet.
    non_first_fragment,
};

pub const Decoded = struct {
    header: Header,
    upper_protocol: u8,
    /// Bytes after the extension chain (actually present in the buffer).
    upper: []const u8,
    stop: WalkStop,
    fragment: ?Fragment,
    ext_count: u8,
    truncated: bool,
};

pub const DecodeError = error{ Truncated, BadVersion, BadExtension, TooManyExtensions };

pub const DecodeOptions = struct { allow_truncated: bool = false };

fn isExtension(nh: u8) bool {
    return switch (nh) {
        NextHeader.hop_by_hop, NextHeader.routing, NextHeader.fragment, NextHeader.dest_opts, NextHeader.ah, NextHeader.mobility => true,
        else => false,
    };
}

pub fn decode(bytes: []const u8, opts: DecodeOptions) DecodeError!Decoded {
    if (bytes.len < header_len) return error.Truncated;
    if (bytes[0] >> 4 != 6) return error.BadVersion;
    const vtf = std.mem.readInt(u32, bytes[0..4], .big);
    const h: Header = .{
        .traffic_class = @truncate(vtf >> 20),
        .flow_label = @truncate(vtf),
        .payload_length = std.mem.readInt(u16, bytes[4..6], .big),
        .next_header = bytes[6],
        .hop_limit = bytes[7],
        .src = bytes[8..24].*,
        .dst = bytes[24..40].*,
    };
    var end: usize = header_len + @as(usize, h.payload_length);
    var truncated = false;
    if (end > bytes.len) {
        if (!opts.allow_truncated) return error.Truncated;
        truncated = true;
        end = bytes.len;
    }
    const body = bytes[header_len..end];

    var nh = h.next_header;
    var off: usize = 0;
    var count: u8 = 0;
    var frag: ?Fragment = null;
    while (isExtension(nh)) {
        if (count >= max_ext_headers) return error.TooManyExtensions;
        count += 1;
        if (off + 8 > body.len) return error.Truncated;
        const ext_len: usize = switch (nh) {
            NextHeader.fragment => 8,
            NextHeader.ah => (@as(usize, body[off + 1]) + 2) * 4,
            else => (@as(usize, body[off + 1]) + 1) * 8,
        };
        if (off + ext_len > body.len) return error.Truncated;
        const next = body[off];
        if (nh == NextHeader.fragment) {
            const fo = std.mem.readInt(u16, body[off + 2 ..][0..2], .big);
            frag = .{
                .offset = @intCast(fo >> 3),
                .more = fo & 1 != 0,
                .id = std.mem.readInt(u32, body[off + 4 ..][0..4], .big),
            };
            off += ext_len;
            nh = next;
            if (frag.?.offset != 0) {
                return .{ .header = h, .upper_protocol = nh, .upper = body[off..], .stop = .non_first_fragment, .fragment = frag, .ext_count = count, .truncated = truncated };
            }
            continue;
        }
        off += ext_len;
        nh = next;
    }
    const stop: WalkStop = switch (nh) {
        NextHeader.no_next => .no_next_header,
        NextHeader.esp => .opaque_payload,
        NextHeader.tcp, NextHeader.udp, NextHeader.icmpv6 => .upper_layer,
        else => .opaque_payload,
    };
    return .{ .header = h, .upper_protocol = nh, .upper = body[off..], .stop = stop, .fragment = frag, .ext_count = count, .truncated = truncated };
}

pub fn encode(h: Header, payload_len: usize, out: []u8) error{BufferTooSmall}!usize {
    if (out.len < header_len or payload_len > std.math.maxInt(u16)) return error.BufferTooSmall;
    const vtf: u32 = (6 << 28) | (@as(u32, h.traffic_class) << 20) | h.flow_label;
    std.mem.writeInt(u32, out[0..4], vtf, .big);
    std.mem.writeInt(u16, out[4..6], @intCast(payload_len), .big);
    out[6] = h.next_header;
    out[7] = h.hop_limit;
    @memcpy(out[8..24], &h.src);
    @memcpy(out[24..40], &h.dst);
    return header_len;
}

/// RFC 5952 style text form (lowercase, longest zero run compressed).
pub fn format(addr: [16]u8, buf: []u8) []const u8 {
    var words: [8]u16 = undefined;
    for (0..8) |i| words[i] = std.mem.readInt(u16, addr[i * 2 ..][0..2], .big);
    var best_start: usize = 8;
    var best_len: usize = 0;
    var i: usize = 0;
    while (i < 8) {
        if (words[i] != 0) {
            i += 1;
            continue;
        }
        var j = i;
        while (j < 8 and words[j] == 0) j += 1;
        if (j - i > best_len and j - i >= 2) {
            best_start = i;
            best_len = j - i;
        }
        i = j;
    }
    var w: std.Io.Writer = .fixed(buf);
    i = 0;
    while (i < 8) {
        if (i == best_start) {
            w.writeAll("::") catch return buf[0..0];
            i += best_len;
            continue;
        }
        w.print("{x}", .{words[i]}) catch return buf[0..0];
        if (i != 7 and i + 1 != best_start) w.writeByte(':') catch return buf[0..0];
        i += 1;
    }
    return w.buffered();
}

const testing = std.testing;

fn buildPacket(buf: []u8, chain: []const u8, upper: []const u8, first_nh: u8) []u8 {
    _ = encode(.{ .next_header = first_nh, .src = @as([15]u8, @splat(0)) ++ [_]u8{1}, .dst = @as([15]u8, @splat(0)) ++ [_]u8{1} }, chain.len + upper.len, buf) catch unreachable;
    @memcpy(buf[40..][0..chain.len], chain);
    @memcpy(buf[40 + chain.len ..][0..upper.len], upper);
    return buf[0 .. 40 + chain.len + upper.len];
}

test "walk hop-by-hop then destination options to TCP" {
    var buf: [128]u8 = undefined;
    const chain = [_]u8{ NextHeader.dest_opts, 0, 1, 4, 0, 0, 0, 0 } ++ [_]u8{ NextHeader.tcp, 0, 1, 4, 0, 0, 0, 0 };
    const pkt = buildPacket(&buf, &chain, &@as([20]u8, @splat(0xaa)), NextHeader.hop_by_hop);
    const d = try decode(pkt, .{});
    try testing.expectEqual(WalkStop.upper_layer, d.stop);
    try testing.expectEqual(NextHeader.tcp, d.upper_protocol);
    try testing.expectEqual(@as(usize, 20), d.upper.len);
    try testing.expectEqual(@as(u8, 2), d.ext_count);
}

test "fragment header: first vs non-first" {
    var buf: [128]u8 = undefined;
    const first = [_]u8{ NextHeader.udp, 0, 0x00, 0x01, 0, 0, 0x12, 0x34 };
    const d1 = try decode(buildPacket(&buf, &first, &@as([8]u8, @splat(0)), NextHeader.fragment), .{});
    try testing.expectEqual(WalkStop.upper_layer, d1.stop);
    try testing.expect(d1.fragment.?.more);
    const later = [_]u8{ NextHeader.udp, 0, 0x00, 0x18, 0, 0, 0x12, 0x34 }; // offset 3
    const d2 = try decode(buildPacket(&buf, &later, &@as([8]u8, @splat(0)), NextHeader.fragment), .{});
    try testing.expectEqual(WalkStop.non_first_fragment, d2.stop);
    try testing.expectEqual(@as(u13, 3), d2.fragment.?.offset);
}

test "extension chain bounded and truncation detected" {
    var buf: [256]u8 = undefined;
    var chain: [80]u8 = undefined;
    for (0..10) |k| {
        chain[k * 8] = NextHeader.dest_opts;
        @memset(chain[k * 8 + 1 ..][0..7], 0);
    }
    try testing.expectError(error.TooManyExtensions, decode(buildPacket(&buf, &chain, &.{}, NextHeader.dest_opts), .{}));
    const bad = [_]u8{ NextHeader.tcp, 9, 0, 0, 0, 0, 0, 0 }; // claims 80 bytes
    try testing.expectError(error.Truncated, decode(buildPacket(&buf, &bad, &.{}, NextHeader.hop_by_hop), .{}));
    try testing.expectError(error.BadVersion, decode(&([_]u8{0x40} ++ @as([39]u8, @splat(0))), .{}));
}

test "format RFC 5952" {
    var b: [64]u8 = undefined;
    try testing.expectEqualStrings("::1", format(@as([15]u8, @splat(0)) ++ [_]u8{1}, &b));
    try testing.expectEqualStrings("2001:db8::1", format(.{ 0x20, 0x01, 0x0d, 0xb8 } ++ @as([11]u8, @splat(0)) ++ [_]u8{1}, &b));
    try testing.expectEqualStrings("fe80::1:0:0:2", format(.{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 2 }, &b));
}
