//! Classic BPF socket filter for the capture socket, plus a minimal
//! interpreter for the opcodes it uses so the program is unit-tested on
//! every host before the kernel ever runs it.
//!
//! The filter keeps only frames the correlator could use: ARP, and IPv4 or
//! IPv6 packets addressed to our scan source address. Everything else is
//! dropped in the kernel and never copied to user space. 802.1Q-tagged
//! frames are dropped by design (tags are normally stripped by VLAN
//! offload and reported in auxdata); `--no-bpf` disables the filter.

const std = @import("std");

pub const Insn = extern struct {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
};

// Opcodes (linux/filter.h)
const LD_H_ABS: u16 = 0x28; // BPF_LD | BPF_H | BPF_ABS
const LD_W_ABS: u16 = 0x20; // BPF_LD | BPF_W | BPF_ABS
const JEQ_K: u16 = 0x15; // BPF_JMP | BPF_JEQ | BPF_K
const RET_K: u16 = 0x06; // BPF_RET | BPF_K

pub const accept_len: u32 = 0x40000;
pub const program_len = 16;

/// Builds the 16-instruction filter. Absent families get an address that
/// cannot appear as a destination (all zero), so they never match.
pub fn build(src4: ?[4]u8, src6: ?[16]u8) [program_len]Insn {
    const v4: u32 = if (src4) |a| std.mem.readInt(u32, &a, .big) else 0;
    var w6: [4]u32 = @splat(0);
    if (src6) |a| for (0..4) |i| {
        w6[i] = std.mem.readInt(u32, a[i * 4 ..][0..4], .big);
    };
    const accept = 14;
    const drop = 15;
    const j = struct {
        fn to(from: usize, target: usize) u8 {
            return @intCast(target - from - 1);
        }
    }.to;
    return .{
        .{ .code = LD_H_ABS, .jt = 0, .jf = 0, .k = 12 }, // 0: A = ethertype
        .{ .code = JEQ_K, .jt = j(1, accept), .jf = 0, .k = 0x0806 }, // 1: ARP
        .{ .code = JEQ_K, .jt = 0, .jf = j(2, 5), .k = 0x0800 }, // 2: IPv4?
        .{ .code = LD_W_ABS, .jt = 0, .jf = 0, .k = 30 }, // 3: A = IPv4 dst
        .{ .code = JEQ_K, .jt = j(4, accept), .jf = j(4, drop), .k = v4 }, // 4
        .{ .code = JEQ_K, .jt = 0, .jf = j(5, drop), .k = 0x86dd }, // 5: IPv6?
        .{ .code = LD_W_ABS, .jt = 0, .jf = 0, .k = 38 }, // 6: dst word 0
        .{ .code = JEQ_K, .jt = 0, .jf = j(7, drop), .k = w6[0] },
        .{ .code = LD_W_ABS, .jt = 0, .jf = 0, .k = 42 },
        .{ .code = JEQ_K, .jt = 0, .jf = j(9, drop), .k = w6[1] },
        .{ .code = LD_W_ABS, .jt = 0, .jf = 0, .k = 46 },
        .{ .code = JEQ_K, .jt = 0, .jf = j(11, drop), .k = w6[2] },
        .{ .code = LD_W_ABS, .jt = 0, .jf = 0, .k = 50 },
        .{ .code = JEQ_K, .jt = j(13, accept), .jf = j(13, drop), .k = w6[3] },
        .{ .code = RET_K, .jt = 0, .jf = 0, .k = accept_len }, // 14
        .{ .code = RET_K, .jt = 0, .jf = 0, .k = 0 }, // 15
    };
}

/// Interprets the subset of classic BPF used above, with the kernel's
/// semantics for out-of-bounds loads (the packet is dropped).
pub fn run(prog: []const Insn, pkt: []const u8) u32 {
    var a: u32 = 0;
    var pc: usize = 0;
    var steps: usize = 0;
    while (pc < prog.len and steps < 4096) : (steps += 1) {
        const in = prog[pc];
        switch (in.code) {
            LD_H_ABS => {
                if (in.k + 2 > pkt.len) return 0;
                a = std.mem.readInt(u16, pkt[in.k..][0..2], .big);
            },
            LD_W_ABS => {
                if (in.k + 4 > pkt.len) return 0;
                a = std.mem.readInt(u32, pkt[in.k..][0..4], .big);
            },
            JEQ_K => {
                pc += 1 + @as(usize, if (a == in.k) in.jt else in.jf);
                continue;
            },
            RET_K => return in.k,
            else => return 0,
        }
        pc += 1;
    }
    return 0;
}

const testing = std.testing;
const vectors = @import("../testing/packet_vectors.zig");

test "filter accepts frames to our address and ARP, drops the rest" {
    const lo4 = [4]u8{ 127, 0, 0, 1 };
    const lo6: [16]u8 = @as([15]u8, @splat(0)) ++ [_]u8{1};
    const prog = build(lo4, lo6);
    try testing.expectEqual(accept_len, run(&prog, &vectors.synack_v4));
    try testing.expectEqual(accept_len, run(&prog, &vectors.rst_v6));
    try testing.expectEqual(accept_len, run(&prog, &vectors.icmp_port_unreach_v4));
    const other = build(.{ 10, 0, 0, 1 }, null);
    try testing.expectEqual(@as(u32, 0), run(&other, &vectors.synack_v4));
    try testing.expectEqual(@as(u32, 0), run(&other, &vectors.rst_v6)); // no v6 source configured
    var arp: [42]u8 = @splat(0);
    arp[12] = 0x08;
    arp[13] = 0x06;
    try testing.expectEqual(accept_len, run(&other, &arp));
    try testing.expectEqual(@as(u32, 0), run(&prog, vectors.synack_v4[0..20])); // truncated
}

test "jump targets stay inside the program" {
    const prog = build(.{ 1, 2, 3, 4 }, @splat(7));
    for (prog, 0..) |in, i| if (in.code == JEQ_K) {
        try testing.expect(i + 1 + in.jt < prog.len and i + 1 + in.jf < prog.len);
    };
}
