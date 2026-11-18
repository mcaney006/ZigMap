//! AF_PACKET/SOCK_RAW link-layer socket (packet(7)).
//!
//! Two receive paths: one recvmsg per frame with PACKET_AUXDATA, so the
//! kernel says when a checksum was deliberately left incomplete
//! (TP_STATUS_CSUMNOTREADY), or a TPACKET_V3 ring. tests/bench/capture_bench.sh
//! compares them.

const std = @import("std");
const linux = std.os.linux;

pub const OpenError = error{ PermissionDenied, SocketFailed, BindFailed };

const ETH_P_ALL: u16 = 0x0003;
const TP_STATUS_CSUMNOTREADY: u32 = 1 << 3;

pub const Frame = struct {
    len: usize,
    outgoing: bool,
    csum_not_ready: bool,
};

pub const PacketSocket = struct {
    fd: i32,
    ifindex: i32,

    pub fn open(ifindex: i32) OpenError!PacketSocket {
        const proto = std.mem.nativeToBig(u16, ETH_P_ALL);
        const rc = linux.socket(linux.AF.PACKET, linux.SOCK.RAW | linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC, proto);
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            .PERM, .ACCES => return error.PermissionDenied,
            else => return error.SocketFailed,
        }
        const fd: i32 = @intCast(rc);
        errdefer _ = linux.close(fd);
        var sa: linux.sockaddr.ll = .{ .protocol = proto, .ifindex = ifindex, .hatype = 0, .pkttype = 0, .halen = 0, .addr = @splat(0) };
        if (linux.errno(linux.bind(fd, @ptrCast(&sa), @sizeOf(linux.sockaddr.ll))) != .SUCCESS) return error.BindFailed;
        const one: i32 = 1;
        _ = linux.setsockopt(fd, linux.SOL.PACKET, linux.PACKET.AUXDATA, @ptrCast(&one), @sizeOf(i32));
        // Linux 4.20+: do not queue our own transmissions (and, on loopback,
        // the outgoing copy of every packet). The correlator skips them anyway;
        // dropping them in the kernel halves the load on lo. Older kernels
        // reject the option and we keep skipping in user space.
        _ = linux.setsockopt(fd, linux.SOL.PACKET, PACKET_IGNORE_OUTGOING, @ptrCast(&one), @sizeOf(i32));
        const rcvbuf: i32 = 4 * 1024 * 1024;
        _ = linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.RCVBUF, @ptrCast(&rcvbuf), @sizeOf(i32));
        return .{ .fd = fd, .ifindex = ifindex };
    }

    pub fn close(s: *PacketSocket) void {
        _ = linux.close(s.fd);
    }

    pub const SendError = error{ WouldBlock, SendFailed };

    pub fn send(s: *PacketSocket, frame: []const u8, dst_mac: [6]u8, ethertype: u16) SendError!void {
        var addr: [8]u8 = @splat(0);
        @memcpy(addr[0..6], &dst_mac);
        var sa: linux.sockaddr.ll = .{ .protocol = std.mem.nativeToBig(u16, ethertype), .ifindex = s.ifindex, .hatype = 0, .pkttype = 0, .halen = 6, .addr = addr };
        while (true) {
            const rc = linux.sendto(s.fd, frame.ptr, frame.len, 0, @ptrCast(&sa), @sizeOf(linux.sockaddr.ll));
            switch (linux.errno(rc)) {
                .SUCCESS => return,
                .INTR => continue,
                .AGAIN, .NOBUFS => return error.WouldBlock,
                else => return error.SendFailed,
            }
        }
    }

    /// Nonblocking receive of one frame into `buf`; null when drained.
    pub fn recv(s: *PacketSocket, buf: []u8) ?Frame {
        var sa: linux.sockaddr.ll = undefined;
        var iov = [_]std.posix.iovec{.{ .base = buf.ptr, .len = buf.len }};
        var control: [64]u8 align(8) = undefined;
        var mh: linux.msghdr = .{
            .name = @ptrCast(&sa),
            .namelen = @sizeOf(linux.sockaddr.ll),
            .iov = &iov,
            .iovlen = 1,
            .control = &control,
            .controllen = control.len,
            .flags = 0,
        };
        while (true) {
            const rc = linux.recvmsg(s.fd, &mh, linux.MSG.TRUNC);
            switch (linux.errno(rc)) {
                .SUCCESS => {},
                .INTR => continue,
                else => return null,
            }
            // MSG_TRUNC returns the real length; clamp to what we hold.
            var f: Frame = .{ .len = @min(rc, buf.len), .outgoing = sa.pkttype == linux.PACKET.OUTGOING, .csum_not_ready = false };
            const hdr_len = std.mem.alignForward(usize, @sizeOf(linux.cmsghdr), linux.cmsg_align);
            var off: usize = 0;
            while (off + hdr_len <= mh.controllen) {
                const ch: *align(1) const linux.cmsghdr = @ptrCast(control[off..].ptr);
                if (ch.len < hdr_len or off + ch.len > mh.controllen) break;
                if (ch.level == linux.SOL.PACKET and ch.type == linux.PACKET.AUXDATA and ch.len >= hdr_len + 4) {
                    const status = std.mem.readInt(u32, control[off + hdr_len ..][0..4], @import("builtin").cpu.arch.endian());
                    f.csum_not_ready = status & TP_STATUS_CSUMNOTREADY != 0;
                }
                off += std.mem.alignForward(usize, ch.len, linux.cmsg_align);
            }
            return f;
        }
    }

    /// Waits up to `timeout_ms` for a frame; true if readable.
    pub fn waitReadable(s: *PacketSocket, timeout_ms: i32) bool {
        var pfd = [_]linux.pollfd{.{ .fd = s.fd, .events = linux.POLL.IN, .revents = 0 }};
        const rc = linux.poll(&pfd, 1, timeout_ms);
        if (linux.errno(rc) != .SUCCESS) return false;
        return rc > 0;
    }

    /// Frames the kernel dropped because our receive buffer was full since
    /// the last call (PACKET_STATISTICS resets on read).
    pub fn takeDrops(s: *PacketSocket) u64 {
        var st: extern struct { packets: u32, drops: u32 } = .{ .packets = 0, .drops = 0 };
        var len: u32 = @sizeOf(@TypeOf(st));
        if (linux.errno(linux.getsockopt(s.fd, linux.SOL.PACKET, linux.PACKET.STATISTICS, @ptrCast(&st), &len)) != .SUCCESS) return 0;
        return st.drops;
    }
};

/// AF_INET/SOCK_RAW with IPPROTO_RAW (implies IP_HDRINCL): transmits a
/// complete IPv4 datagram through the kernel's routing/output path.
///
/// Needed for targets the kernel routes locally (loopback and the host's
/// own addresses): a frame injected with AF_PACKET has no route attached,
/// so ip_route_input() drops packets to 127.0.0.0/8 as martians unless
/// net.ipv4.conf.*.route_localnet is enabled, and Zigmap does not change
/// system settings. Capture still happens on the AF_PACKET socket.
pub const RawIpSocket = struct {
    fd: i32,

    pub fn open() OpenError!RawIpSocket {
        const rc = linux.socket(linux.AF.INET, linux.SOCK.RAW | linux.SOCK.CLOEXEC, linux.IPPROTO.RAW);
        switch (linux.errno(rc)) {
            .SUCCESS => return .{ .fd = @intCast(rc) },
            .PERM, .ACCES => return error.PermissionDenied,
            else => return error.SocketFailed,
        }
    }

    pub fn close(s: *RawIpSocket) void {
        _ = linux.close(s.fd);
    }

    pub fn send(s: *RawIpSocket, datagram: []const u8, dst: [4]u8) PacketSocket.SendError!void {
        var sa: linux.sockaddr.in = .{ .port = 0, .addr = @bitCast(dst) };
        while (true) {
            const rc = linux.sendto(s.fd, datagram.ptr, datagram.len, 0, @ptrCast(&sa), @sizeOf(linux.sockaddr.in));
            switch (linux.errno(rc)) {
                .SUCCESS => return,
                .INTR => continue,
                .AGAIN, .NOBUFS => return error.WouldBlock,
                else => return error.SendFailed,
            }
        }
    }
};

/// AF_INET6/SOCK_RAW for one transport protocol. The kernel builds the IPv6
/// header and routes the packet (needed for ::1 for the same reason as
/// RawIpSocket); we supply the transport segment with its checksum already
/// computed for the route's source address. For ICMPv6 the kernel fills the
/// checksum itself.
pub const RawIp6Socket = struct {
    fd: i32,

    pub fn open(protocol: u32) OpenError!RawIp6Socket {
        const rc = linux.socket(linux.AF.INET6, linux.SOCK.RAW | linux.SOCK.CLOEXEC, protocol);
        switch (linux.errno(rc)) {
            .SUCCESS => return .{ .fd = @intCast(rc) },
            .PERM, .ACCES => return error.PermissionDenied,
            else => return error.SocketFailed,
        }
    }

    pub fn close(s: *RawIp6Socket) void {
        _ = linux.close(s.fd);
    }

    pub fn send(s: *RawIp6Socket, segment: []const u8, dst: [16]u8) PacketSocket.SendError!void {
        var sa: linux.sockaddr.in6 = .{ .port = 0, .flowinfo = 0, .addr = dst, .scope_id = 0 };
        while (true) {
            const rc = linux.sendto(s.fd, segment.ptr, segment.len, 0, @ptrCast(&sa), @sizeOf(linux.sockaddr.in6));
            switch (linux.errno(rc)) {
                .SUCCESS => return,
                .INTR => continue,
                .AGAIN, .NOBUFS => return error.WouldBlock,
                else => return error.SendFailed,
            }
        }
    }
};

// ------------------------------------------------------------ fast path

const builtin = @import("builtin");
const bpf = @import("../bpf.zig");
const native = builtin.cpu.arch.endian();

/// Frame metadata handed to a drain callback. `bytes` is only valid during
/// the callback: with the ring it points into a block that is returned to
/// the kernel right after, so callers must copy anything they keep.
pub const FrameView = struct {
    bytes: []const u8,
    outgoing: bool,
    csum_not_ready: bool,
};

const PACKET_IGNORE_OUTGOING: u32 = 23; // linux/if_packet.h

pub const CaptureMode = enum { recvmsg, ring };

const TPACKET_V3: i32 = 2;
const TP_STATUS_KERNEL: u32 = 0;
const TP_STATUS_USER: u32 = 1;
const TP_STATUS_LOSING: u32 = 1 << 2;

const Req3 = extern struct {
    block_size: u32,
    block_nr: u32,
    frame_size: u32,
    frame_nr: u32,
    retire_blk_tov: u32,
    sizeof_priv: u32,
    feature_req_word: u32,
};

/// TPACKET_V3 receive ring: the kernel writes frames into mmap'd blocks
/// and flips block ownership through `block_status`. We read the status
/// with acquire ordering, process every frame in the block in place, then
/// hand the block back with a release store.
pub const Ring = struct {
    mem: []align(std.heap.page_size_min) u8,
    block_size: u32,
    block_nr: u32,
    cur: u32 = 0,
    losing_seen: u64 = 0,

    fn block(r: *Ring, i: u32) []u8 {
        return r.mem[@as(usize, i) * r.block_size ..][0..r.block_size];
    }

    fn statusPtr(b: []u8) *u32 {
        return @ptrCast(@alignCast(&b[8]));
    }
};

pub const RingOptions = struct {
    block_size: u32 = 1 << 16,
    block_nr: u32 = 128,
    frame_size: u32 = 2048,
    /// Block retire timeout: the kernel hands a partly filled block to user
    /// space after this long, so it bounds the latency the ring adds.
    retire_ms: u32 = 1,
};

pub fn enableRing(s: *PacketSocket, opts: RingOptions) !Ring {
    const v: i32 = TPACKET_V3;
    if (linux.errno(linux.setsockopt(s.fd, linux.SOL.PACKET, linux.PACKET.VERSION, @ptrCast(&v), @sizeOf(i32))) != .SUCCESS) return error.RingVersion;
    const req: Req3 = .{
        .block_size = opts.block_size,
        .block_nr = opts.block_nr,
        .frame_size = opts.frame_size,
        .frame_nr = opts.block_size / opts.frame_size * opts.block_nr,
        .retire_blk_tov = opts.retire_ms,
        .sizeof_priv = 0,
        .feature_req_word = 0,
    };
    if (linux.errno(linux.setsockopt(s.fd, linux.SOL.PACKET, linux.PACKET.RX_RING, @ptrCast(&req), @sizeOf(Req3))) != .SUCCESS) return error.RingSetup;
    const len = @as(usize, opts.block_size) * opts.block_nr;
    const rc = linux.mmap(null, len, .{ .READ = true, .WRITE = true }, .{ .TYPE = .SHARED }, s.fd, 0);
    if (linux.errno(rc) != .SUCCESS) return error.RingMmap;
    const ptr: [*]align(std.heap.page_size_min) u8 = @ptrFromInt(rc);
    return .{ .mem = ptr[0..len], .block_size = opts.block_size, .block_nr = opts.block_nr };
}

pub fn unmapRing(r: *Ring) void {
    _ = linux.munmap(r.mem.ptr, r.mem.len);
}

pub fn attachFilter(s: *PacketSocket, prog: []const bpf.Insn) !void {
    const Fprog = extern struct { len: u16, filter: [*]const bpf.Insn };
    const fp: Fprog = .{ .len = @intCast(prog.len), .filter = prog.ptr };
    if (linux.errno(linux.setsockopt(s.fd, linux.SOL.SOCKET, linux.SO.ATTACH_FILTER, @ptrCast(&fp), @sizeOf(Fprog))) != .SUCCESS) return error.FilterAttach;
}

/// Delivers up to roughly `budget` frames to `ctx.onFrame(FrameView)`.
/// Returns the number of frames seen. Never blocks.
pub fn drain(s: *PacketSocket, ring: ?*Ring, buf: []u8, budget: u32, ctx: anytype) u32 {
    var seen: u32 = 0;
    if (ring) |r| {
        while (seen < budget) {
            const b = r.block(r.cur);
            const st = @atomicLoad(u32, Ring.statusPtr(b), .acquire);
            if (st & TP_STATUS_USER == 0) break;
            if (st & TP_STATUS_LOSING != 0) r.losing_seen += 1;
            const num = std.mem.readInt(u32, b[12..16], native);
            var off: usize = std.mem.readInt(u32, b[16..20], native);
            var i: u32 = 0;
            while (i < num and off + 48 <= b.len) : (i += 1) {
                const h = b[off..];
                const next = std.mem.readInt(u32, h[0..4], native);
                const snaplen = std.mem.readInt(u32, h[12..16], native);
                const status = std.mem.readInt(u32, h[20..24], native);
                const mac = std.mem.readInt(u16, h[24..26], native);
                // sockaddr_ll follows the 48-byte header; sll_pkttype at +10.
                const pkttype = if (off + 48 + 11 <= b.len) h[48 + 10] else 0;
                if (mac + snaplen <= h.len) ctx.onFrame(.{
                    .bytes = h[mac..][0..snaplen],
                    .outgoing = pkttype == linux.PACKET.OUTGOING,
                    .csum_not_ready = status & TP_STATUS_CSUMNOTREADY != 0,
                });
                seen += 1;
                if (next == 0) break;
                off += next;
            }
            // No slice into this block survives past here.
            @atomicStore(u32, Ring.statusPtr(b), TP_STATUS_KERNEL, .release);
            r.cur = (r.cur + 1) % r.block_nr;
        }
        return seen;
    }
    while (seen < budget) {
        const f = s.recv(buf) orelse break;
        ctx.onFrame(.{ .bytes = buf[0..f.len], .outgoing = f.outgoing, .csum_not_ready = f.csum_not_ready });
        seen += 1;
    }
    return seen;
}
