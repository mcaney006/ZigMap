//! Target and port planning: IP literals and CIDR blocks (IPv4/IPv6),
//! exclusions, and port lists. Expansion is always bounded by an explicit
//! limit, and the planned count is computed before any allocation so the
//! CLI can refuse oversize scans up front.

const std = @import("std");
const IpAddress = std.Io.net.IpAddress;

pub const Addr = struct {
    bytes: [16]u8,
    is_v6: bool,

    pub fn v4(b: [4]u8) Addr {
        var a: Addr = .{ .bytes = @splat(0), .is_v6 = false };
        @memcpy(a.bytes[0..4], &b);
        return a;
    }

    pub fn v6(b: [16]u8) Addr {
        return .{ .bytes = b, .is_v6 = true };
    }

    pub fn bytes4(a: Addr) [4]u8 {
        return a.bytes[0..4].*;
    }

    pub fn eql(a: Addr, b: Addr) bool {
        return a.is_v6 == b.is_v6 and std.mem.eql(u8, &a.bytes, &b.bytes);
    }

    fn asInt(a: Addr) u128 {
        return if (a.is_v6) std.mem.readInt(u128, &a.bytes, .big) else std.mem.readInt(u32, a.bytes[0..4], .big);
    }

    fn fromInt(v: u128, is_v6: bool) Addr {
        var a: Addr = .{ .bytes = @splat(0), .is_v6 = is_v6 };
        if (is_v6) std.mem.writeInt(u128, &a.bytes, v, .big) else std.mem.writeInt(u32, a.bytes[0..4], @intCast(v), .big);
        return a;
    }

    pub fn format(a: Addr, w: *std.Io.Writer) std.Io.Writer.Error!void {
        if (a.is_v6) {
            var buf: [64]u8 = undefined;
            try w.writeAll(@import("../packet/ipv6.zig").format(a.bytes, &buf));
        } else {
            try w.print("{d}.{d}.{d}.{d}", .{ a.bytes[0], a.bytes[1], a.bytes[2], a.bytes[3] });
        }
    }
};

pub const Spec = struct {
    base: Addr,
    prefix: u8,

    pub fn bits(s: Spec) u8 {
        return if (s.base.is_v6) 128 else 32;
    }

    pub fn count(s: Spec) u128 {
        const host_bits = s.bits() - s.prefix;
        if (host_bits >= 128) return std.math.maxInt(u128);
        return @as(u128, 1) << @intCast(host_bits);
    }

    fn first(s: Spec) u128 {
        const host_bits = s.bits() - s.prefix;
        if (host_bits >= 128) return 0;
        const mask = ~((@as(u128, 1) << @intCast(host_bits)) - 1);
        return s.base.asInt() & mask;
    }

    pub fn contains(s: Spec, a: Addr) bool {
        if (a.is_v6 != s.base.is_v6) return false;
        const host_bits = s.bits() - s.prefix;
        if (host_bits >= 128) return true;
        return (a.asInt() >> @intCast(host_bits)) == (s.first() >> @intCast(host_bits));
    }
};

pub const ParseError = error{ InvalidTarget, InvalidPrefix };

/// Accepts "192.0.2.7", "192.0.2.0/24", "2001:db8::1", "2001:db8::/120",
/// "[::1]", and "localhost" (mapped to 127.0.0.1 without DNS).
pub fn parseSpec(text_in: []const u8) ParseError!Spec {
    var text = std.mem.trim(u8, text_in, " \t");
    if (std.mem.eql(u8, text, "localhost")) return .{ .base = Addr.v4(.{ 127, 0, 0, 1 }), .prefix = 32 };
    var prefix: ?u8 = null;
    if (std.mem.findScalar(u8, text, '/')) |slash| {
        prefix = std.fmt.parseInt(u8, text[slash + 1 ..], 10) catch return error.InvalidPrefix;
        text = text[0..slash];
    }
    if (text.len >= 2 and text[0] == '[' and text[text.len - 1] == ']') text = text[1 .. text.len - 1];
    const ip = IpAddress.parse(text, 0) catch return error.InvalidTarget;
    const addr: Addr = switch (ip) {
        .ip4 => |a| Addr.v4(a.bytes),
        .ip6 => |a| Addr.v6(a.bytes),
    };
    const max: u8 = if (addr.is_v6) 128 else 32;
    const p = prefix orelse max;
    if (p > max) return error.InvalidPrefix;
    return .{ .base = addr, .prefix = p };
}

pub const ExpandError = error{TooManyTargets} || std.mem.Allocator.Error;

/// Counts addresses before exclusion (exclusions cannot make a plan larger).
pub fn plannedCount(specs: []const Spec) u128 {
    var total: u128 = 0;
    for (specs) |s| total +|= s.count();
    return total;
}

/// Expands specs into a de-duplicated address list in input order,
/// skipping excluded addresses. Fails before allocating if the planned
/// count exceeds `max_targets`.
pub fn expand(gpa: std.mem.Allocator, specs: []const Spec, excludes: []const Spec, max_targets: u32) ExpandError![]Addr {
    if (plannedCount(specs) > max_targets) return error.TooManyTargets;
    var out: std.ArrayList(Addr) = .empty;
    errdefer out.deinit(gpa);
    var seen: std.AutoHashMapUnmanaged(Addr, void) = .empty;
    defer seen.deinit(gpa);
    for (specs) |s| {
        const n: u128 = s.count();
        var i: u128 = 0;
        while (i < n) : (i += 1) {
            const a = Addr.fromInt(s.first() + i, s.base.is_v6);
            if (isExcluded(a, excludes)) continue;
            const gop = try seen.getOrPut(gpa, a);
            if (gop.found_existing) continue;
            try out.append(gpa, a);
        }
    }
    return out.toOwnedSlice(gpa);
}

pub fn isExcluded(a: Addr, excludes: []const Spec) bool {
    for (excludes) |e| if (e.contains(a)) return true;
    return false;
}

pub const PortError = error{ InvalidPortSpec, EmptyPortSpec } || std.mem.Allocator.Error;

/// Parses "22,80,443", "1-1024", "-" (1-65535), or mixtures. Port 0 is
/// rejected. Result is sorted and de-duplicated.
pub fn parsePorts(gpa: std.mem.Allocator, text: []const u8) PortError![]u16 {
    var set = try std.DynamicBitSetUnmanaged.initEmpty(gpa, 65536);
    defer set.deinit(gpa);
    var it = std.mem.splitScalar(u8, text, ',');
    var any = false;
    while (it.next()) |raw| {
        const part = std.mem.trim(u8, raw, " ");
        if (part.len == 0) continue;
        var lo: u16 = 1;
        var hi: u16 = 65535;
        if (std.mem.findScalar(u8, part, '-')) |d| {
            if (d > 0) lo = std.fmt.parseInt(u16, part[0..d], 10) catch return error.InvalidPortSpec;
            if (d + 1 < part.len) hi = std.fmt.parseInt(u16, part[d + 1 ..], 10) catch return error.InvalidPortSpec;
        } else {
            lo = std.fmt.parseInt(u16, part, 10) catch return error.InvalidPortSpec;
            hi = lo;
        }
        if (lo == 0 or lo > hi) return error.InvalidPortSpec;
        set.setRangeValue(.{ .start = lo, .end = @as(usize, hi) + 1 }, true);
        any = true;
    }
    if (!any) return error.EmptyPortSpec;
    var out = try gpa.alloc(u16, set.count());
    var i: usize = 0;
    var bit_it = set.iterator(.{});
    while (bit_it.next()) |b| : (i += 1) out[i] = @intCast(b);
    return out;
}

const testing = std.testing;

test "parse specs and CIDR math" {
    const s = try parseSpec("192.0.2.77/30");
    try testing.expectEqual(@as(u128, 4), s.count());
    try testing.expect(s.contains(Addr.v4(.{ 192, 0, 2, 76 })));
    try testing.expect(!s.contains(Addr.v4(.{ 192, 0, 2, 80 })));
    try testing.expectError(error.InvalidPrefix, parseSpec("10.0.0.0/33"));
    try testing.expectError(error.InvalidTarget, parseSpec("300.1.1.1"));
    try testing.expectError(error.InvalidTarget, parseSpec("example.invalid"));
    const v6 = try parseSpec("2001:db8::ff/120");
    try testing.expectEqual(@as(u128, 256), v6.count());
    try testing.expect((try parseSpec("[::1]")).base.is_v6);
    try testing.expect(!v6.contains(Addr.v4(.{ 0, 0, 0, 0 })));
}

test "expand respects limit, exclusions and dedup" {
    const gpa = testing.allocator;
    const specs = [_]Spec{ try parseSpec("10.0.0.0/29"), try parseSpec("10.0.0.3") };
    try testing.expectError(error.TooManyTargets, expand(gpa, &specs, &.{}, 8));
    const ex = [_]Spec{ try parseSpec("10.0.0.0/31"), try parseSpec("10.0.0.7") };
    const out = try expand(gpa, &specs, &ex, 16);
    defer gpa.free(out);
    try testing.expectEqual(@as(usize, 5), out.len); // .2 .3 .4 .5 .6
    try testing.expect(out[0].eql(Addr.v4(.{ 10, 0, 0, 2 })));
    // /0 must be refused by count, never enumerated
    const huge = [_]Spec{try parseSpec("::/0")};
    try testing.expectError(error.TooManyTargets, expand(gpa, &huge, &.{}, 1_000_000));
}

test "port lists" {
    const gpa = testing.allocator;
    const p = try parsePorts(gpa, "443, 22,80-82,22");
    defer gpa.free(p);
    try testing.expectEqualSlices(u16, &.{ 22, 80, 81, 82, 443 }, p);
    const all = try parsePorts(gpa, "-");
    defer gpa.free(all);
    try testing.expectEqual(@as(usize, 65535), all.len);
    const tail = try parsePorts(gpa, "65530-");
    defer gpa.free(tail);
    try testing.expectEqual(@as(usize, 6), tail.len);
    try testing.expectError(error.InvalidPortSpec, parsePorts(gpa, "0"));
    try testing.expectError(error.InvalidPortSpec, parsePorts(gpa, "90-80"));
    try testing.expectError(error.InvalidPortSpec, parsePorts(gpa, "http"));
    try testing.expectError(error.EmptyPortSpec, parsePorts(gpa, ","));
}

test "address formatting" {
    var buf: [64]u8 = undefined;
    try testing.expectEqualStrings("10.1.2.3", try std.fmt.bufPrint(&buf, "{f}", .{Addr.v4(.{ 10, 1, 2, 3 })}));
    try testing.expectEqualStrings("::1", try std.fmt.bufPrint(&buf, "{f}", .{(try parseSpec("::1")).base}));
}
