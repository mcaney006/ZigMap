//! TCP header encoder and bounded decoder (RFC 9293) with option parsing
//! (RFC 9293 MSS, RFC 7323 window scale/timestamps, RFC 2018 SACK).

const std = @import("std");
const checksum = @import("checksum.zig");

pub const header_min_len = 20;

pub const Flags = packed struct(u8) {
    fin: bool = false,
    syn: bool = false,
    rst: bool = false,
    psh: bool = false,
    ack: bool = false,
    urg: bool = false,
    ece: bool = false,
    cwr: bool = false,

    pub fn bits(f: Flags) u8 {
        return @bitCast(f);
    }
    pub fn fromBits(b: u8) Flags {
        return @bitCast(b);
    }
    pub fn eql(a: Flags, b: Flags) bool {
        return a.bits() == b.bits();
    }
};

pub const DecodeError = error{ Truncated, BadDataOffset };

pub const OptionKind = enum(u8) {
    eol = 0,
    nop = 1,
    mss = 2,
    window_scale = 3,
    sack_permitted = 4,
    sack = 5,
    timestamps = 8,
    _,
};

/// Summary of parsed options plus the observed kind ordering, which OS
/// fingerprinting needs. Bounded: at most 40 option bytes exist.
pub const Options = struct {
    mss: ?u16 = null,
    window_scale: ?u8 = null,
    sack_permitted: bool = false,
    ts_val: ?u32 = null,
    ts_ecr: ?u32 = null,
    /// Kinds in wire order (up to 40 entries since each option is >= 1 byte).
    order: [40]u8 = undefined,
    order_len: u8 = 0,
    /// Set when an option's length field is invalid or runs past the header.
    malformed: bool = false,

    pub fn kinds(o: *const Options) []const u8 {
        return o.order[0..o.order_len];
    }
};

pub fn parseOptions(raw: []const u8) Options {
    var o: Options = .{};
    var i: usize = 0;
    while (i < raw.len) {
        const kind = raw[i];
        if (o.order_len < o.order.len) {
            o.order[o.order_len] = kind;
            o.order_len += 1;
        }
        switch (kind) {
            0 => break,
            1 => {
                i += 1;
                continue;
            },
            else => {},
        }
        if (i + 1 >= raw.len) {
            o.malformed = true;
            break;
        }
        const len = raw[i + 1];
        if (len < 2 or i + len > raw.len) {
            o.malformed = true;
            break;
        }
        const body = raw[i + 2 .. i + len];
        switch (kind) {
            2 => if (len == 4) {
                o.mss = std.mem.readInt(u16, body[0..2], .big);
            } else {
                o.malformed = true;
            },
            3 => if (len == 3) {
                o.window_scale = body[0];
            } else {
                o.malformed = true;
            },
            4 => if (len == 2) {
                o.sack_permitted = true;
            } else {
                o.malformed = true;
            },
            8 => if (len == 10) {
                o.ts_val = std.mem.readInt(u32, body[0..4], .big);
                o.ts_ecr = std.mem.readInt(u32, body[4..8], .big);
            } else {
                o.malformed = true;
            },
            else => {},
        }
        i += len;
    }
    return o;
}

pub const Header = struct {
    src_port: u16,
    dst_port: u16,
    seq: u32 = 0,
    ack: u32 = 0,
    flags: Flags = .{},
    window: u16 = 0,
    checksum: u16 = 0,
    urgent: u16 = 0,
};

pub const Decoded = struct {
    header: Header,
    header_len: usize,
    options_raw: []const u8,
    payload: []const u8,
};

/// Decodes the fixed header and data offset. Only the first 8 bytes are
/// needed for ICMP correlation; use `decodeQuoted` for that case.
pub fn decode(bytes: []const u8) DecodeError!Decoded {
    if (bytes.len < header_min_len) return error.Truncated;
    const data_off: usize = (bytes[12] >> 4) * 4;
    if (data_off < header_min_len) return error.BadDataOffset;
    if (data_off > bytes.len) return error.Truncated;
    return .{
        .header = .{
            .src_port = std.mem.readInt(u16, bytes[0..2], .big),
            .dst_port = std.mem.readInt(u16, bytes[2..4], .big),
            .seq = std.mem.readInt(u32, bytes[4..8], .big),
            .ack = std.mem.readInt(u32, bytes[8..12], .big),
            .flags = Flags.fromBits(bytes[13]),
            .window = std.mem.readInt(u16, bytes[14..16], .big),
            .checksum = std.mem.readInt(u16, bytes[16..18], .big),
            .urgent = std.mem.readInt(u16, bytes[18..20], .big),
        },
        .header_len = data_off,
        .options_raw = bytes[header_min_len..data_off],
        .payload = bytes[data_off..],
    };
}

/// Ports and sequence number from a possibly-truncated quoted TCP header
/// (ICMP errors guarantee at least 8 bytes).
pub const Quoted = struct { src_port: u16, dst_port: u16, seq: u32 };

pub fn decodeQuoted(bytes: []const u8) error{Truncated}!Quoted {
    if (bytes.len < 8) return error.Truncated;
    return .{
        .src_port = std.mem.readInt(u16, bytes[0..2], .big),
        .dst_port = std.mem.readInt(u16, bytes[2..4], .big),
        .seq = std.mem.readInt(u32, bytes[4..8], .big),
    };
}

pub const SynOptions = struct {
    mss: ?u16 = 1460,
    sack_permitted: bool = true,
    timestamps: ?struct { val: u32, ecr: u32 } = null,
    window_scale: ?u8 = 7,
};

/// Encodes options in a common, well-formed ordering. Returns bytes written,
/// padded to a multiple of 4 with EOL.
pub fn encodeOptions(o: SynOptions, out: []u8) error{BufferTooSmall}!usize {
    var tmp: [40]u8 = undefined;
    var n: usize = 0;
    if (o.mss) |m| {
        tmp[n] = 2;
        tmp[n + 1] = 4;
        std.mem.writeInt(u16, tmp[n + 2 ..][0..2], m, .big);
        n += 4;
    }
    if (o.sack_permitted) {
        tmp[n] = 4;
        tmp[n + 1] = 2;
        n += 2;
    }
    if (o.timestamps) |ts| {
        tmp[n] = 8;
        tmp[n + 1] = 10;
        std.mem.writeInt(u32, tmp[n + 2 ..][0..4], ts.val, .big);
        std.mem.writeInt(u32, tmp[n + 6 ..][0..4], ts.ecr, .big);
        n += 10;
    }
    if (o.window_scale) |ws| {
        tmp[n] = 1; // NOP to align
        tmp[n + 1] = 3;
        tmp[n + 2] = 3;
        tmp[n + 3] = ws;
        n += 4;
    }
    while (n % 4 != 0) : (n += 1) tmp[n] = 0;
    if (n > out.len) return error.BufferTooSmall;
    @memcpy(out[0..n], tmp[0..n]);
    return n;
}

/// Writes a TCP header plus `options` and `payload`, computing the checksum
/// over the provided pseudo-header partial sum.
pub fn encode(h: Header, options: []const u8, payload: []const u8, pseudo: u32, out: []u8) error{ BufferTooSmall, BadOptions }!usize {
    if (options.len % 4 != 0 or options.len > 40) return error.BadOptions;
    const hlen = header_min_len + options.len;
    const total = hlen + payload.len;
    if (out.len < total) return error.BufferTooSmall;
    std.mem.writeInt(u16, out[0..2], h.src_port, .big);
    std.mem.writeInt(u16, out[2..4], h.dst_port, .big);
    std.mem.writeInt(u32, out[4..8], h.seq, .big);
    std.mem.writeInt(u32, out[8..12], h.ack, .big);
    out[12] = @intCast((hlen / 4) << 4);
    out[13] = h.flags.bits();
    std.mem.writeInt(u16, out[14..16], h.window, .big);
    out[16] = 0;
    out[17] = 0;
    std.mem.writeInt(u16, out[18..20], h.urgent, .big);
    @memcpy(out[20..hlen], options);
    @memcpy(out[hlen..total], payload);
    const c = checksum.finish(checksum.add(pseudo, out[0..total]));
    std.mem.writeInt(u16, out[16..18], c, .big);
    return total;
}

/// Verifies a TCP segment checksum given the pseudo-header partial sum.
pub fn verify(segment: []const u8, pseudo: u32) bool {
    return checksum.verifyWithPseudo(pseudo, segment);
}

const testing = std.testing;

test "options: Linux-style SYN ordering" {
    // MSS 1460, SACK_PERM, TS, NOP, WS 7  (the ordering Linux emits)
    const raw = [_]u8{ 2, 4, 0x05, 0xb4, 4, 2, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0, 1, 3, 3, 7 };
    const o = parseOptions(&raw);
    try testing.expect(!o.malformed);
    try testing.expectEqual(@as(?u16, 1460), o.mss);
    try testing.expect(o.sack_permitted);
    try testing.expectEqual(@as(?u32, 1), o.ts_val);
    try testing.expectEqual(@as(?u8, 7), o.window_scale);
    try testing.expectEqualSlices(u8, &.{ 2, 4, 8, 1, 3 }, o.kinds());
}

test "options: malformed lengths are flagged, not trusted" {
    try testing.expect(parseOptions(&[_]u8{ 2, 1, 0, 0 }).malformed); // len < 2
    try testing.expect(parseOptions(&[_]u8{ 2, 40, 0, 0 }).malformed); // runs past end
    try testing.expect(parseOptions(&[_]u8{2}).malformed); // missing length
    try testing.expect(parseOptions(&[_]u8{ 2, 3, 0 }).malformed); // wrong MSS length
    const eol = parseOptions(&[_]u8{ 1, 0, 2, 4, 0, 0 });
    try testing.expect(!eol.malformed);
    try testing.expectEqual(@as(?u16, null), eol.mss);
}

test "encode/decode SYN with checksum" {
    var opts: [40]u8 = undefined;
    const olen = try encodeOptions(.{ .timestamps = .{ .val = 0xdeadbeef, .ecr = 0 } }, &opts);
    try testing.expectEqual(@as(usize, 20), olen);
    const src = [4]u8{ 192, 0, 2, 1 };
    const dst = [4]u8{ 192, 0, 2, 2 };
    const seg_len: u16 = @intCast(header_min_len + olen);
    const pseudo = checksum.pseudoV4(src, dst, 6, seg_len);
    var out: [60]u8 = undefined;
    const n = try encode(.{ .src_port = 40000, .dst_port = 443, .seq = 0x01020304, .flags = .{ .syn = true }, .window = 64240 }, opts[0..olen], &.{}, pseudo, &out);
    try testing.expect(verify(out[0..n], pseudo));
    const d = try decode(out[0..n]);
    try testing.expect(d.header.flags.syn and !d.header.flags.ack);
    try testing.expectEqual(@as(u32, 0x01020304), d.header.seq);
    const po = parseOptions(d.options_raw);
    try testing.expectEqual(@as(?u32, 0xdeadbeef), po.ts_val);
    out[5] ^= 1;
    try testing.expect(!verify(out[0..n], pseudo));
}

test "decode rejects bad data offset and truncation" {
    var b = @as([20]u8, @splat(0));
    b[12] = 0x40; // 16 bytes
    try testing.expectError(error.BadDataOffset, decode(&b));
    b[12] = 0xf0; // 60 bytes
    try testing.expectError(error.Truncated, decode(&b));
    try testing.expectError(error.Truncated, decodeQuoted(b[0..7]));
}
