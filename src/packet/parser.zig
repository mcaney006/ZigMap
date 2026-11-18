//! Whole-frame decoder used by the capture path. Converts link-layer bytes
//! into a flat, allocation-free summary that the response correlator can
//! match against outstanding probes. Hostile input yields an error or a
//! partially-filled summary; it never panics or allocates.

const std = @import("std");
const checksum = @import("checksum.zig");
const ethernet = @import("ethernet.zig");
const ipv4 = @import("ipv4.zig");
const ipv6 = @import("ipv6.zig");
const tcp = @import("tcp.zig");
const udp = @import("udp.zig");
const icmp = @import("icmp.zig");

pub const LinkType = enum {
    /// DLT_EN10MB / ARPHRD_ETHER.
    ethernet,
    /// No link header; first nibble is the IP version (Linux SOCK_DGRAM, DLT_RAW).
    raw_ip,
    /// Linux "cooked" capture v1 (16-byte header, DLT_LINUX_SLL).
    linux_sll,
    /// BSD loopback: 4-byte address family in host byte order (DLT_NULL).
    bsd_null,
};

/// Transport checksum verdict. `partial` means the stored value equals the
/// folded pseudo-header sum: the segment left a local stack with checksum
/// offload (CHECKSUM_PARTIAL) and was captured before the NIC finished it.
/// This is normal on loopback/veth captures and must not be read as "bad".
pub const ChecksumStatus = enum { good, bad, partial, unverified };

pub const Tcp = struct {
    header: tcp.Header,
    options_raw: []const u8,
    payload_len: usize,
    checksum: ChecksumStatus,
};

pub const Udp = struct {
    header: udp.Header,
    payload: []const u8,
    checksum: ChecksumStatus,
};

pub const Icmp = struct {
    header: icmp.Header,
    /// Message body after the 8-byte header (slice into the frame).
    body: []const u8,
    quote: ?icmp.Quote,
    checksum: ChecksumStatus,
};

pub const L4 = union(enum) {
    none,
    tcp: Tcp,
    udp: Udp,
    icmp: Icmp,
    arp: ethernet.Arp,
    /// IP fragment without transport header, or unsupported protocol.
    opaque_payload: u8,
};

pub const Packet = struct {
    src_mac: ?ethernet.Mac = null,
    vlan_count: u8 = 0,
    is_ipv6: bool = false,
    has_ip: bool = false,
    src: [16]u8 = @as([16]u8, @splat(0)),
    dst: [16]u8 = @as([16]u8, @splat(0)),
    ttl: u8 = 0,
    ip_id: u16 = 0,
    dont_fragment: bool = false,
    ip_checksum_ok: bool = true,
    fragment: bool = false,
    truncated: bool = false,
    l4: L4 = .none,

    pub fn src4(p: *const Packet) [4]u8 {
        return p.src[0..4].*;
    }
    pub fn dst4(p: *const Packet) [4]u8 {
        return p.dst[0..4].*;
    }
};

pub const ParseError = error{
    Truncated,
    BadLinkHeader,
    UnsupportedEtherType,
    BadIp,
};

pub fn parse(link: LinkType, frame: []const u8) ParseError!Packet {
    var p: Packet = .{};
    var l3: []const u8 = undefined;
    var ethertype: u16 = 0;
    switch (link) {
        .ethernet => {
            const e = ethernet.decode(frame) catch |err| return switch (err) {
                error.Truncated => error.Truncated,
                else => error.BadLinkHeader,
            };
            p.src_mac = e.src;
            p.vlan_count = e.vlan_count;
            ethertype = e.ethertype;
            l3 = e.payload;
        },
        .linux_sll => {
            if (frame.len < 16) return error.Truncated;
            ethertype = std.mem.readInt(u16, frame[14..16], .big);
            l3 = frame[16..];
        },
        .bsd_null => {
            if (frame.len < 4) return error.Truncated;
            // Host byte order; AF_INET is 2 everywhere, AF_INET6 is 24/28/30.
            const fam_le = std.mem.readInt(u32, frame[0..4], .little);
            const fam_be = std.mem.readInt(u32, frame[0..4], .big);
            const fam = if (fam_le < 256) fam_le else fam_be;
            ethertype = switch (fam) {
                2 => ethernet.EtherType.ipv4,
                24, 28, 30 => ethernet.EtherType.ipv6,
                else => return error.BadLinkHeader,
            };
            l3 = frame[4..];
        },
        .raw_ip => {
            if (frame.len < 1) return error.Truncated;
            ethertype = switch (frame[0] >> 4) {
                4 => ethernet.EtherType.ipv4,
                6 => ethernet.EtherType.ipv6,
                else => return error.BadIp,
            };
            l3 = frame;
        },
    }

    switch (ethertype) {
        ethernet.EtherType.arp => {
            p.l4 = .{ .arp = ethernet.decodeArp(l3) catch return error.UnsupportedEtherType };
            return p;
        },
        ethernet.EtherType.ipv4 => try parseV4(&p, l3),
        ethernet.EtherType.ipv6 => try parseV6(&p, l3),
        else => return error.UnsupportedEtherType,
    }
    return p;
}

fn parseV4(p: *Packet, bytes: []const u8) ParseError!void {
    // Captures may be snapped short; record truncation instead of failing.
    const d = ipv4.decode(bytes, .{ .allow_truncated = true }) catch return error.BadIp;
    p.has_ip = true;
    @memcpy(p.src[0..4], &d.header.src);
    @memcpy(p.dst[0..4], &d.header.dst);
    p.ttl = d.header.ttl;
    p.ip_id = d.header.id;
    p.dont_fragment = d.header.dont_fragment;
    p.ip_checksum_ok = d.checksum_ok;
    p.fragment = d.isFragment();
    p.truncated = d.truncated;
    if (!d.hasTransportHeader()) {
        p.l4 = .{ .opaque_payload = d.header.protocol };
        return;
    }
    const pseudo_len: u16 = @intCast(d.header.total_length - d.header_len);
    const pseudo = checksum.pseudoV4(d.header.src, d.header.dst, d.header.protocol, pseudo_len);
    // Checksums are only meaningful over the complete, unfragmented segment.
    const can_verify = !d.truncated and !d.isFragment();
    parseL4(p, d.header.protocol, d.payload, pseudo, can_verify, false);
}

fn parseV6(p: *Packet, bytes: []const u8) ParseError!void {
    const d = ipv6.decode(bytes, .{ .allow_truncated = true }) catch return error.BadIp;
    p.has_ip = true;
    p.is_ipv6 = true;
    p.src = d.header.src;
    p.dst = d.header.dst;
    p.ttl = d.header.hop_limit;
    p.fragment = d.fragment != null;
    p.truncated = d.truncated;
    if (d.stop != .upper_layer) {
        p.l4 = .{ .opaque_payload = d.upper_protocol };
        return;
    }
    const pseudo = checksum.pseudoV6(d.header.src, d.header.dst, d.upper_protocol, @intCast(d.upper.len));
    const can_verify = !d.truncated and d.fragment == null;
    parseL4(p, d.upper_protocol, d.upper, pseudo, can_verify, true);
}

fn parseL4(p: *Packet, proto: u8, seg: []const u8, pseudo: u32, can_verify: bool, v6: bool) void {
    switch (proto) {
        ipv4.Protocol.tcp => {
            const t = tcp.decode(seg) catch {
                p.l4 = .{ .opaque_payload = proto };
                return;
            };
            p.l4 = .{ .tcp = .{
                .header = t.header,
                .options_raw = t.options_raw,
                .payload_len = t.payload.len,
                .checksum = classify(seg, 16, pseudo, can_verify),
            } };
        },
        ipv4.Protocol.udp => {
            const u = udp.decode(seg) catch {
                p.l4 = .{ .opaque_payload = proto };
                return;
            };
            p.l4 = .{ .udp = .{
                .header = u.header,
                .payload = u.payload,
                .checksum = if (!u.truncated and !v6 and u.header.checksum == 0) .unverified else classify(seg[0..@min(seg.len, u.header.length)], 6, pseudo, can_verify and !u.truncated),
            } };
        },
        ipv4.Protocol.icmp, ipv4.Protocol.icmpv6 => {
            if ((proto == ipv4.Protocol.icmp) == v6) {
                p.l4 = .{ .opaque_payload = proto };
                return;
            }
            const m = icmp.decode(seg) catch {
                p.l4 = .{ .opaque_payload = proto };
                return;
            };
            const is_err = if (v6) icmp.isV6Error(m.header.type) else icmp.isV4Error(m.header.type);
            const quote: ?icmp.Quote = if (!is_err) null else if (v6)
                icmp.decodeQuoteV6(m.body) catch null
            else
                icmp.decodeQuoteV4(m.body) catch null;
            p.l4 = .{ .icmp = .{
                .header = m.header,
                .body = m.body,
                .quote = quote,
                .checksum = classify(seg, 2, if (v6) pseudo else 0, can_verify),
            } };
        },
        else => p.l4 = .{ .opaque_payload = proto },
    }
}

test "parser never panics on arbitrary input" {
    try std.testing.fuzz({}, fuzzOne, .{});
}

fn fuzzOne(_: void, smith: *std.testing.Smith) !void {
    var buf: [256]u8 = undefined;
    const len = smith.valueRangeAtMost(u32, 0, buf.len);
    smith.bytes(buf[0..len]);
    inline for (.{ LinkType.ethernet, LinkType.raw_ip, LinkType.linux_sll, LinkType.bsd_null }) |lt| {
        _ = parse(lt, buf[0..len]) catch {};
    }
}

/// `field_off` is the checksum field offset inside `seg`.
fn classify(seg: []const u8, field_off: usize, pseudo: u32, can_verify: bool) ChecksumStatus {
    if (!can_verify or seg.len < field_off + 2) return .unverified;
    if (checksum.finish(checksum.add(pseudo, seg)) == 0) return .good;
    const stored = std.mem.readInt(u16, seg[field_off..][0..2], .big);
    // Offloaded segments carry the folded (uncomplemented) pseudo-header sum.
    if (pseudo != 0 and stored == ~checksum.finish(pseudo)) return .partial;
    return .bad;
}
