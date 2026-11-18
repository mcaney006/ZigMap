//! Golden vectors captured from a real Linux kernel (Alpine 3.20 container,
//! `tcpdump -i lo`), i.e. produced independently of Zigmap's encoders.
//! Expected field values come from tshark's decode of the same capture.
//! See docs/fixtures.md for the exact capture procedure.

const std = @import("std");
const packet = @import("../packet.zig");
const parser = packet.parser;
const tcp = packet.tcp;

fn hex(comptime s: []const u8) [s.len / 2]u8 {
    @setEvalBranchQuota(10_000);
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

/// 127.0.0.1:56582 -> :8080 SYN. tshark: seq_raw=2302396044 win=65495 MSS=65495 WS=10 TSval=2778303639 ip.id=0xf06b
pub const syn_v4 = hex("00000000000000000000000008004500003cf06b400040064c4e7f0000017f000001dd061f90893bc68c00000000a002ffd7fe3000000204ffd70402080aa5998c97000000000103030a");
/// SYN/ACK reply from listening port 8080. tshark: seq_raw=196536841 ack_raw=2302396045
pub const synack_v4 = hex("00000000000000000000000008004500003c0000400040063cba7f0000017f0000011f90dd060bb6ea09893bc68da012ffcbfe3000000204ffd70402080a585ca390a5998c970103030a");
/// Kernel RST/ACK from closed port 9. tshark: seq=0 ack_raw=1623702487 win=0
pub const rst_v4 = hex("0000000000000000000000000800450000280000400040063cce7f0000017f0000010009d5220000000060c7bbd750140000c0030000");
/// IPv6 ::1 RST/ACK from closed port 9. tshark: ack_raw=2132747831 hlim=64
pub const rst_v6 = hex("00000000000000000000000086dd600beed50014064000000000000000000000000000000001000000000000000000000000000000010009835e000000007f1f263750140000001c0000");
/// ICMP type 3 code 3 quoting UDP 51872 -> 9, inner ip.id=0x8535, payload "zigmap-probe".
pub const icmp_port_unreach_v4 = hex("000000000000000000000000080045c0004415c40000400166337f0000017f0000010303ee8a0000000045000028853540004011b78d7f0000017f000001caa000090014fe277a69676d61702d70726f6265");
/// ICMPv6 type 1 code 4 quoting UDP 40173 -> 9 over ::1.
pub const icmp6_port_unreach = hex("00000000000000000000000086dd6005db1400443a4000000000000000000000000000000001000000000000000000000000000000010104441000000000600366540014114000000000000000000000000000000001000000000000000000000000000000019ced0009001400277a69676d61702d70726f6265");

const testing = std.testing;
const loop4 = [4]u8{ 127, 0, 0, 1 };

test "kernel SYN decodes with options matching tshark" {
    const p = try parser.parse(.ethernet, &syn_v4);
    try testing.expectEqualSlices(u8, &loop4, &p.src4());
    try testing.expect(p.ip_checksum_ok);
    try testing.expectEqual(@as(u16, 0xf06b), p.ip_id);
    try testing.expectEqual(@as(u8, 64), p.ttl);
    const t = p.l4.tcp;
    // Captured before offload completion: tshark reports "matches partial checksum".
    try testing.expectEqual(parser.ChecksumStatus.partial, t.checksum);
    try testing.expectEqual(@as(u16, 56582), t.header.src_port);
    try testing.expectEqual(@as(u16, 8080), t.header.dst_port);
    try testing.expectEqual(@as(u32, 2302396044), t.header.seq);
    try testing.expect(t.header.flags.eql(.{ .syn = true }));
    try testing.expectEqual(@as(u16, 65495), t.header.window);
    const o = tcp.parseOptions(t.options_raw);
    try testing.expect(!o.malformed);
    try testing.expectEqual(@as(?u16, 65495), o.mss);
    try testing.expectEqual(@as(?u8, 10), o.window_scale);
    try testing.expectEqual(@as(?u32, 2778303639), o.ts_val);
    try testing.expect(o.sack_permitted);
    // Linux option order: MSS, SACK_PERM, TS, NOP, WS
    try testing.expectEqualSlices(u8, &.{ 2, 4, 8, 1, 3 }, o.kinds());
}

test "SYN/ACK acknowledges the probe's ISN + 1" {
    const syn = (try parser.parse(.ethernet, &syn_v4)).l4.tcp;
    const sa = (try parser.parse(.ethernet, &synack_v4)).l4.tcp;
    try testing.expectEqual(parser.ChecksumStatus.partial, sa.checksum);
    try testing.expect(sa.header.flags.eql(.{ .syn = true, .ack = true }));
    try testing.expectEqual(@as(u32, 196536841), sa.header.seq);
    try testing.expectEqual(syn.header.seq +% 1, sa.header.ack);
}

test "kernel RST/ACK v4 and v6" {
    const r4 = (try parser.parse(.ethernet, &rst_v4)).l4.tcp;
    // Kernel-generated RST is checksummed in software: fully valid.
    try testing.expectEqual(parser.ChecksumStatus.good, r4.checksum);
    try testing.expect(r4.header.flags.eql(.{ .rst = true, .ack = true }));
    try testing.expectEqual(@as(u32, 1623702487), r4.header.ack);
    try testing.expectEqual(@as(u16, 0), r4.header.window);

    const p6 = try parser.parse(.ethernet, &rst_v6);
    try testing.expect(p6.is_ipv6);
    try testing.expectEqual(@as(u8, 64), p6.ttl);
    const r6 = p6.l4.tcp;
    try testing.expectEqual(parser.ChecksumStatus.partial, r6.checksum);
    try testing.expectEqual(@as(u32, 2132747831), r6.header.ack);
}

test "ICMPv4 port unreachable quote correlates to the UDP probe" {
    const p = try parser.parse(.ethernet, &icmp_port_unreach_v4);
    const m = p.l4.icmp;
    try testing.expectEqual(parser.ChecksumStatus.good, m.checksum);
    try testing.expectEqual(@as(u8, 3), m.header.type);
    try testing.expectEqual(@as(u8, 3), m.header.code);
    const q = m.quote.?;
    try testing.expect(q.transport_ok);
    try testing.expectEqual(packet.ipv4.Protocol.udp, q.protocol);
    try testing.expectEqual(@as(u16, 0x8535), q.ip_id);
    try testing.expectEqual(@as(u16, 9), std.mem.readInt(u16, q.transport[2..4], .big));
}

test "ICMPv6 port unreachable quote correlates to the UDP probe" {
    const p = try parser.parse(.ethernet, &icmp6_port_unreach);
    const m = p.l4.icmp;
    try testing.expectEqual(parser.ChecksumStatus.good, m.checksum);
    try testing.expectEqual(@as(u8, 1), m.header.type);
    try testing.expectEqual(@as(u8, 4), m.header.code);
    const q = m.quote.?;
    try testing.expect(q.is_ipv6 and q.transport_ok);
    try testing.expectEqual(@as(u16, 9), std.mem.readInt(u16, q.transport[2..4], .big));
}

test "every truncation of every fixture is rejected or flagged, never trusted" {
    inline for (.{ &syn_v4, &synack_v4, &rst_v4, &rst_v6, &icmp_port_unreach_v4, &icmp6_port_unreach }) |f| {
        // None of these frames carry Ethernet padding, so any cut truncates IP.
        for (0..f.len) |cut| {
            const p = parser.parse(.ethernet, f[0..cut]) catch continue;
            try testing.expect(p.truncated);
            switch (p.l4) {
                .tcp => |t| try testing.expectEqual(parser.ChecksumStatus.unverified, t.checksum),
                .udp => |u| try testing.expectEqual(parser.ChecksumStatus.unverified, u.checksum),
                .icmp => |m| try testing.expectEqual(parser.ChecksumStatus.unverified, m.checksum),
                else => {},
            }
        }
    }
}

test "single bit flips break transport checksums" {
    var f = rst_v4;
    f[f.len - 5] ^= 0x01; // window low byte
    try testing.expectEqual(parser.ChecksumStatus.bad, (try parser.parse(.ethernet, &f)).l4.tcp.checksum);
}

/// Recomputes the full checksum over a captured segment, independent of the
/// value stored in it.
fn fullChecksum(seg: []const u8, field_off: usize, pseudo: u32) u16 {
    var copy: [128]u8 = undefined;
    @memcpy(copy[0..seg.len], seg);
    copy[field_off] = 0;
    copy[field_off + 1] = 0;
    return packet.checksum.finish(packet.checksum.add(pseudo, copy[0..seg.len]));
}

test "full checksums match tshark's independently calculated values" {
    // tshark -o tcp.check_checksum:TRUE: frame1 0xd16e, frame2 0xdfbc, frame8 (v6) 0x8711.
    const syn_seg = syn_v4[34..];
    try testing.expectEqual(@as(u16, 0xd16e), fullChecksum(syn_seg, 16, packet.checksum.pseudoV4(loop4, loop4, 6, @intCast(syn_seg.len))));
    const sa_seg = synack_v4[34..];
    try testing.expectEqual(@as(u16, 0xdfbc), fullChecksum(sa_seg, 16, packet.checksum.pseudoV4(loop4, loop4, 6, @intCast(sa_seg.len))));
    const v6_seg = rst_v6[54..];
    const lo6: [16]u8 = @as([15]u8, @splat(0)) ++ [_]u8{1};
    try testing.expectEqual(@as(u16, 0x8711), fullChecksum(v6_seg, 16, packet.checksum.pseudoV6(lo6, lo6, 6, @intCast(v6_seg.len))));
}

test "a SYN completed with the full checksum classifies as good" {
    var f = syn_v4;
    std.mem.writeInt(u16, f[34 + 16 ..][0..2], 0xd16e, .big);
    try testing.expectEqual(parser.ChecksumStatus.good, (try parser.parse(.ethernet, &f)).l4.tcp.checksum);
}

test "Zigmap's encoder reproduces the kernel SYN byte-for-byte (with full checksum)" {
    var f = syn_v4;
    std.mem.writeInt(u16, f[34 + 16 ..][0..2], 0xd16e, .big);
    const t = (try parser.parse(.ethernet, &f)).l4.tcp;
    const pseudo = packet.checksum.pseudoV4(loop4, loop4, 6, @intCast(20 + t.options_raw.len));
    var out: [60]u8 = undefined;
    const n = try tcp.encode(t.header, t.options_raw, &.{}, pseudo, &out);
    try testing.expectEqualSlices(u8, f[34..][0..n], out[0..n]);
}
