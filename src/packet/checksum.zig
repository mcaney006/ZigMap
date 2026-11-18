//! RFC 1071 Internet checksum and transport pseudo-header helpers.
//!
//! The accumulator is a plain `u32` holding a ones-complement partial sum of
//! big-endian 16-bit words. Callers fold and complement with `finish`.
//! Odd-length buffers are padded with a trailing zero byte as RFC 1071 requires.

const std = @import("std");

/// Adds `data` (interpreted as big-endian 16-bit words) to `acc`.
/// Folds as it goes so arbitrary-length input never overflows.
pub fn add(acc: u32, data: []const u8) u32 {
    var sum: u64 = acc;
    var i: usize = 0;
    while (i + 1 < data.len) : (i += 2) {
        sum += (@as(u64, data[i]) << 8) | data[i + 1];
    }
    if (i < data.len) sum += @as(u64, data[i]) << 8;
    while (sum >> 32 != 0) sum = (sum & 0xffff_ffff) + (sum >> 32);
    return @intCast(sum);
}

pub fn addU16(acc: u32, v: u16) u32 {
    const s: u64 = @as(u64, acc) + v;
    return @intCast((s & 0xffff_ffff) + (s >> 32));
}

pub fn addU32(acc: u32, v: u32) u32 {
    return addU16(addU16(acc, @truncate(v >> 16)), @truncate(v));
}

/// Folds the accumulator to 16 bits and returns its ones complement.
pub fn finish(acc: u32) u16 {
    var s = acc;
    while (s >> 16 != 0) s = (s & 0xffff) + (s >> 16);
    return ~@as(u16, @truncate(s));
}

pub fn compute(data: []const u8) u16 {
    return finish(add(0, data));
}

/// True when a buffer that already contains its checksum field sums to zero.
pub fn verify(data: []const u8) bool {
    return compute(data) == 0;
}

/// IPv4 pseudo-header partial sum (RFC 793 / RFC 768).
pub fn pseudoV4(src: [4]u8, dst: [4]u8, protocol: u8, length: u16) u32 {
    var acc = add(0, &src);
    acc = add(acc, &dst);
    acc = addU16(acc, protocol);
    return addU16(acc, length);
}

/// IPv6 pseudo-header partial sum (RFC 8200 section 8.1).
pub fn pseudoV6(src: [16]u8, dst: [16]u8, next_header: u8, length: u32) u32 {
    var acc = add(0, &src);
    acc = add(acc, &dst);
    acc = addU32(acc, length);
    return addU32(acc, next_header);
}

test "RFC 1071 worked example" {
    // RFC 1071 section 3: bytes 00 01 f2 03 f4 f5 f6 f7 sum to 0xddf2.
    const bytes = [_]u8{ 0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7 };
    const s = add(0, &bytes);
    var folded = s;
    while (folded >> 16 != 0) folded = (folded & 0xffff) + (folded >> 16);
    try std.testing.expectEqual(@as(u32, 0xddf2), folded);
    try std.testing.expectEqual(@as(u16, 0x220d), compute(&bytes));
}

test "odd length pads with zero" {
    try std.testing.expectEqual(compute(&[_]u8{ 0xab, 0xcd, 0xef, 0x00 }), compute(&[_]u8{ 0xab, 0xcd, 0xef }));
}

test "verify accepts buffer containing its own checksum" {
    // Published IPv4 header example (checksum 0xb861).
    const hdr = [_]u8{ 0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0xb8, 0x61, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7 };
    try std.testing.expect(verify(&hdr));
    var copy = hdr;
    copy[10] = 0;
    copy[11] = 0;
    try std.testing.expectEqual(@as(u16, 0xb861), compute(&copy));
}

test "large input does not overflow accumulator" {
    const big = @as([70000]u8, @splat(0xff));
    _ = compute(&big);
}
