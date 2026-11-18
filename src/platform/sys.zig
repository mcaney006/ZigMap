//! Thin, explicit socket layer for the TCP connect scanner.
//!
//! Linux: direct system calls through `std.os.linux` (no libc), readiness
//! via epoll. macOS: `std.c` (libSystem is the only stable syscall ABI
//! there), readiness via poll(2). Zig 0.17's `std.posix` no longer exposes
//! socket/connect, and `std.Io.net` hides the nonblocking connect state
//! machine a scanner needs, so this layer exists.

const std = @import("std");
const builtin = @import("builtin");
const Addr = @import("../core/targets.zig").Addr;

pub const is_linux = builtin.os.tag == .linux;
const linux = std.os.linux;
const c = std.c;

pub const fd_t = i32;

/// The subset of errno values the scanner distinguishes.
pub const Err = enum {
    ok,
    in_progress,
    interrupted,
    would_block,
    conn_refused,
    timed_out,
    host_unreach,
    net_unreach,
    access,
    no_fds,
    no_bufs,
    addr_not_avail,
    af_not_supported,
    other,
};

/// Linux and libSystem errno enums share these tag names.
fn mapErrno(e: anytype) Err {
    return switch (e) {
        .SUCCESS => .ok,
        .INPROGRESS => .in_progress,
        .INTR => .interrupted,
        .AGAIN => .would_block,
        .CONNREFUSED => .conn_refused,
        .TIMEDOUT => .timed_out,
        .HOSTUNREACH, .HOSTDOWN => .host_unreach,
        .NETUNREACH, .NETDOWN => .net_unreach,
        .ACCES, .PERM => .access,
        .MFILE, .NFILE => .no_fds,
        .NOBUFS, .NOMEM => .no_bufs,
        .ADDRNOTAVAIL => .addr_not_avail,
        .AFNOSUPPORT => .af_not_supported,
        else => .other,
    };
}

fn errFromCode(code: i32) Err {
    if (is_linux) return mapErrno(@as(linux.E, @fromBackingInt(@intCast(code))));
    return mapErrno(@as(c.E, @fromBackingInt(@intCast(code))));
}

pub fn SysResult(comptime T: type) type {
    return union(enum) { ok: T, err: Err };
}

/// Creates a nonblocking, close-on-exec TCP socket.
pub fn tcpSocket(v6: bool) SysResult(fd_t) {
    if (is_linux) {
        const af: u32 = if (v6) linux.AF.INET6 else linux.AF.INET;
        const rc = linux.socket(af, linux.SOCK.STREAM | linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC, 0);
        const e = linux.errno(rc);
        if (e != .SUCCESS) return .{ .err = mapErrno(e) };
        return .{ .ok = @intCast(rc) };
    }
    const af: c_uint = if (v6) c.AF.INET6 else c.AF.INET;
    const fd = c.socket(af, c.SOCK.STREAM, 0);
    if (fd < 0) return .{ .err = mapErrno(c.errno(fd)) };
    const fl = c.fcntl(fd, c.F.GETFL, @as(c_int, 0));
    _ = c.fcntl(fd, c.F.SETFL, fl | @as(c_int, @bitCast(c.O{ .NONBLOCK = true })));
    _ = c.fcntl(fd, c.F.SETFD, @as(c_int, c.FD_CLOEXEC));
    var one: c_int = 1;
    // Never raise SIGPIPE on this socket (Darwin has no MSG_NOSIGNAL).
    _ = c.setsockopt(fd, c.SOL.SOCKET, c.SO.NOSIGPIPE, &one, @sizeOf(c_int));
    return .{ .ok = fd };
}

/// Starts a connect. Returns `.in_progress` for the normal nonblocking path.
pub fn connect(fd: fd_t, addr: Addr, port: u16) Err {
    while (true) {
        const e: Err = if (is_linux) blk: {
            if (addr.is_v6) {
                var sa: linux.sockaddr.in6 = .{ .port = std.mem.nativeToBig(u16, port), .flowinfo = 0, .addr = addr.bytes, .scope_id = 0 };
                break :blk mapErrno(linux.errno(linux.connect(fd, &sa, @sizeOf(linux.sockaddr.in6))));
            }
            var sa: linux.sockaddr.in = .{ .port = std.mem.nativeToBig(u16, port), .addr = @bitCast(addr.bytes4()) };
            break :blk mapErrno(linux.errno(linux.connect(fd, &sa, @sizeOf(linux.sockaddr.in))));
        } else blk: {
            if (addr.is_v6) {
                var sa: c.sockaddr.in6 = .{ .port = std.mem.nativeToBig(u16, port), .flowinfo = 0, .addr = addr.bytes, .scope_id = 0 };
                break :blk mapErrno(c.errno(c.connect(fd, @ptrCast(&sa), @sizeOf(c.sockaddr.in6))));
            }
            var sa: c.sockaddr.in = .{ .port = std.mem.nativeToBig(u16, port), .addr = @bitCast(addr.bytes4()) };
            break :blk mapErrno(c.errno(c.connect(fd, @ptrCast(&sa), @sizeOf(c.sockaddr.in))));
        };
        if (e != .interrupted) return e;
    }
}

/// Reads and clears SO_ERROR: the final outcome of a nonblocking connect.
pub fn socketError(fd: fd_t) Err {
    var v: i32 = 0;
    var len: u32 = @sizeOf(i32);
    if (is_linux) {
        const rc = linux.getsockopt(fd, linux.SOL.SOCKET, linux.SO.ERROR, @ptrCast(&v), &len);
        if (linux.errno(rc) != .SUCCESS) return .other;
    } else {
        if (c.getsockopt(fd, c.SOL.SOCKET, c.SO.ERROR, &v, &len) != 0) return .other;
    }
    return if (v == 0) .ok else errFromCode(v);
}

/// Closes with SO_LINGER{1,0}: an established probe connection is reset
/// instead of entering FIN/TIME_WAIT, so scans do not exhaust local ports
/// and do not leave the target holding a half-closed session.
pub fn abortClose(fd: fd_t) void {
    if (is_linux) {
        const l: linux.linger = .{ .onoff = 1, .linger = 0 };
        _ = linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.LINGER, @ptrCast(&l), @sizeOf(linux.linger));
        _ = linux.close(fd);
    } else {
        const l: c.linger = .{ .onoff = 1, .linger = 0 };
        _ = c.setsockopt(fd, c.SOL.SOCKET, c.SO.LINGER, &l, @sizeOf(c.linger));
        _ = c.close(fd);
    }
}

pub fn closeFd(fd: fd_t) void {
    if (is_linux) _ = linux.close(fd) else _ = c.close(fd);
}

/// Soft RLIMIT_NOFILE, used to bound concurrency.
pub fn fileLimit() u64 {
    const r = std.posix.getrlimit(.NOFILE) catch return 256;
    return r.cur;
}

pub const Usage = struct { user_ns: u64, sys_ns: u64, max_rss_bytes: u64 };

pub fn usage() Usage {
    const ru = std.posix.getrusage(0); // RUSAGE_SELF
    const tv = struct {
        fn ns(t: anytype) u64 {
            return @as(u64, @intCast(t.sec)) * std.time.ns_per_s + @as(u64, @intCast(t.usec)) * std.time.ns_per_us;
        }
    };
    // Linux reports ru_maxrss in KiB, Darwin in bytes.
    const rss: u64 = @intCast(ru.maxrss);
    return .{ .user_ns = tv.ns(ru.utime), .sys_ns = tv.ns(ru.stime), .max_rss_bytes = if (is_linux) rss * 1024 else rss };
}

// ------------------------------------------------------------ readiness

/// Write-readiness multiplexer keyed by an opaque 64-bit token.
pub const Poller = if (is_linux) EpollPoller else PollPoller;

pub const Ready = struct { token: u64 };

const EpollPoller = struct {
    epfd: fd_t,

    pub fn init(_: std.mem.Allocator, _: u32) !EpollPoller {
        const rc = linux.epoll_create1(linux.EPOLL.CLOEXEC);
        if (linux.errno(rc) != .SUCCESS) return error.EpollCreateFailed;
        return .{ .epfd = @intCast(rc) };
    }

    pub fn deinit(p: *EpollPoller, _: std.mem.Allocator) void {
        _ = linux.close(p.epfd);
    }

    pub fn add(p: *EpollPoller, fd: fd_t, token: u64) !void {
        var ev: linux.epoll_event = .{ .events = linux.EPOLL.OUT | linux.EPOLL.ERR | linux.EPOLL.HUP, .data = .{ .u64 = token } };
        const rc = linux.epoll_ctl(p.epfd, linux.EPOLL.CTL_ADD, fd, &ev);
        if (linux.errno(rc) != .SUCCESS) return error.EpollAddFailed;
    }

    /// Closing the fd removes it from the epoll set.
    pub fn remove(_: *EpollPoller, _: fd_t, _: u64) void {}

    pub fn wait(p: *EpollPoller, timeout_ms: i32, out: []Ready) usize {
        var evs: [256]linux.epoll_event = undefined;
        const max: u32 = @intCast(@min(evs.len, out.len));
        const rc = linux.epoll_wait(p.epfd, &evs, max, timeout_ms);
        // EINTR and other failures report no events; the engine polls again.
        if (linux.errno(rc) != .SUCCESS) return 0;
        for (evs[0..rc], 0..) |ev, i| out[i] = .{ .token = ev.data.u64 };
        return rc;
    }
};

const PollPoller = struct {
    fds: std.ArrayList(c.pollfd) = .empty,
    tokens: std.ArrayList(u64) = .empty,
    gpa: std.mem.Allocator,

    pub fn init(gpa: std.mem.Allocator, capacity: u32) !PollPoller {
        var p: PollPoller = .{ .gpa = gpa };
        try p.fds.ensureTotalCapacity(gpa, capacity);
        try p.tokens.ensureTotalCapacity(gpa, capacity);
        return p;
    }

    pub fn deinit(p: *PollPoller, gpa: std.mem.Allocator) void {
        p.fds.deinit(gpa);
        p.tokens.deinit(gpa);
    }

    pub fn add(p: *PollPoller, fd: fd_t, token: u64) !void {
        try p.fds.append(p.gpa, .{ .fd = fd, .events = c.POLL.OUT, .revents = 0 });
        try p.tokens.append(p.gpa, token);
    }

    pub fn remove(p: *PollPoller, fd: fd_t, _: u64) void {
        for (p.fds.items, 0..) |pf, i| if (pf.fd == fd) {
            _ = p.fds.swapRemove(i);
            _ = p.tokens.swapRemove(i);
            return;
        };
    }

    pub fn wait(p: *PollPoller, timeout_ms: i32, out: []Ready) usize {
        if (p.fds.items.len == 0) {
            var none: [0]c.pollfd = .{};
            _ = c.poll(&none, 0, timeout_ms);
            return 0;
        }
        const rc = c.poll(p.fds.items.ptr, @intCast(p.fds.items.len), timeout_ms);
        if (rc <= 0) return 0;
        var n: usize = 0;
        for (p.fds.items, p.tokens.items) |pf, tok| {
            if (pf.revents == 0) continue;
            if (n == out.len) break;
            out[n] = .{ .token = tok };
            n += 1;
        }
        return n;
    }
};

/// Local address and port of a socket (getsockname). The port sits at
/// offset 2 of sockaddr_in/sockaddr_in6 on both Linux and Darwin.
pub fn localEndpoint(fd: fd_t, v6: bool) ?struct { addr: [16]u8, port: u16 } {
    var storage: [128]u8 align(8) = undefined;
    var len: u32 = storage.len;
    if (is_linux) {
        if (linux.errno(linux.getsockname(fd, @ptrCast(&storage), &len)) != .SUCCESS) return null;
    } else {
        if (c.getsockname(fd, @ptrCast(&storage), &len) != 0) return null;
    }
    var addr: [16]u8 = @splat(0);
    if (v6) @memcpy(&addr, storage[8..24]) else @memcpy(addr[0..4], storage[4..8]);
    return .{ .addr = addr, .port = std.mem.readInt(u16, storage[2..4], .big) };
}

// ------------------------------------------------- stream I/O for -sV

pub const IoResult = union(enum) { n: usize, would_block, eof, err: Err };

pub fn recvSome(fd: fd_t, buf: []u8) IoResult {
    while (true) {
        if (is_linux) {
            const rc = linux.recvfrom(fd, buf.ptr, buf.len, 0, null, null);
            switch (linux.errno(rc)) {
                .SUCCESS => return if (rc == 0) .eof else .{ .n = rc },
                .INTR => continue,
                .AGAIN => return .would_block,
                else => |e| return .{ .err = mapErrno(e) },
            }
        } else {
            const rc = c.recv(fd, buf.ptr, buf.len, 0);
            if (rc > 0) return .{ .n = @intCast(rc) };
            if (rc == 0) return .eof;
            switch (c.errno(rc)) {
                .INTR => continue,
                .AGAIN => return .would_block,
                else => |e| return .{ .err = mapErrno(e) },
            }
        }
    }
}

pub fn sendSome(fd: fd_t, data: []const u8) IoResult {
    while (true) {
        if (is_linux) {
            const rc = linux.sendto(fd, data.ptr, data.len, linux.MSG.NOSIGNAL, null, 0);
            switch (linux.errno(rc)) {
                .SUCCESS => return .{ .n = rc },
                .INTR => continue,
                .AGAIN => return .would_block,
                else => |e| return .{ .err = mapErrno(e) },
            }
        } else {
            const rc = c.send(fd, data.ptr, data.len, 0);
            if (rc >= 0) return .{ .n = @intCast(rc) };
            switch (c.errno(rc)) {
                .INTR => continue,
                .AGAIN => return .would_block,
                else => |e| return .{ .err = mapErrno(e) },
            }
        }
    }
}

pub const PollFd = if (is_linux) linux.pollfd else c.pollfd;
pub const POLL_IN: i16 = if (is_linux) linux.POLL.IN else c.POLL.IN;
pub const POLL_OUT: i16 = if (is_linux) linux.POLL.OUT else c.POLL.OUT;

/// poll(2) over `fds`; returns how many are ready (0 on timeout or EINTR).
pub fn pollFds(fds: []PollFd, timeout_ms: i32) usize {
    if (is_linux) {
        const rc = linux.poll(fds.ptr, fds.len, timeout_ms);
        return if (linux.errno(rc) == .SUCCESS) rc else 0;
    }
    const rc = c.poll(fds.ptr, @intCast(fds.len), timeout_ms);
    return if (rc > 0) @intCast(rc) else 0;
}
