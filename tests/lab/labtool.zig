//! Lab-only helpers for tests/lab and tests/bench. Not part of the scanner
//! and never installed by `zig build`; build it with `zig build lab-tools`.
//! Linux only: it runs inside the throwaway lab containers.
//!
//!   labtool listen SPEC...     hold TCP listeners and UDP echo sockets open
//!       SPEC is tcp:ADDR:PORT, tcp6only:ADDR:PORT or udp-echo:ADDR:PORT;
//!       IPv6 addresses go in brackets, e.g. tcp:[::1]:20001.
//!       TCP listeners never accept: the kernel completes the handshake.
//!       UDP echo answers every datagram with "pong".
//!   labtool serve ADDR         service fakes for -sV: SSH, FTP and SMTP
//!       banners on 2222/2121/2525, DNS over TCP on 53 (version.bind) and
//!       HTTP on 8080. Writes /tmp/ready once every socket is bound.
//!   labtool wait-tcp ADDR PORT connect until something listens (10 s max)
//!   labtool udp-noise SRC DST PORT
//!       send 64-byte UDP datagrams from SRC to DST:PORT forever
const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

comptime {
    if (builtin.os.tag != .linux) @compileError("labtool runs only inside the Linux lab containers");
}

const Addr = struct {
    v6: bool,
    bytes: [16]u8 = @splat(0),
};

fn parseAddr(s: []const u8) !Addr {
    if (std.mem.indexOfScalar(u8, s, ':') != null) return .{ .v6 = true, .bytes = try parseIp6(s) };
    var a: Addr = .{ .v6 = false };
    var it = std.mem.splitScalar(u8, s, '.');
    var i: usize = 0;
    while (it.next()) |part| : (i += 1) {
        if (i == 4) return error.BadAddress;
        a.bytes[i] = try std.fmt.parseInt(u8, part, 10);
    }
    if (i != 4) return error.BadAddress;
    return a;
}

fn parseIp6(s: []const u8) ![16]u8 {
    var head: [8]u16 = undefined;
    var tail: [8]u16 = undefined;
    var nh: usize = 0;
    var nt: usize = 0;
    const gap = std.mem.indexOf(u8, s, "::");
    const left = if (gap) |g| s[0..g] else s;
    const right = if (gap) |g| s[g + 2 ..] else "";
    if (left.len > 0) {
        var it = std.mem.splitScalar(u8, left, ':');
        while (it.next()) |g| : (nh += 1) {
            if (nh == 8) return error.BadAddress;
            head[nh] = try std.fmt.parseInt(u16, g, 16);
        }
    }
    if (right.len > 0) {
        var it = std.mem.splitScalar(u8, right, ':');
        while (it.next()) |g| : (nt += 1) {
            if (nt == 8) return error.BadAddress;
            tail[nt] = try std.fmt.parseInt(u16, g, 16);
        }
    }
    if (gap == null and nh != 8) return error.BadAddress;
    const max_groups: usize = if (gap == null) 8 else 7;
    if (nh + nt > max_groups) return error.BadAddress;
    var groups: [8]u16 = @splat(0);
    @memcpy(groups[0..nh], head[0..nh]);
    @memcpy(groups[8 - nt ..], tail[0..nt]);
    var out: [16]u8 = undefined;
    for (groups, 0..) |g, i| std.mem.writeInt(u16, out[i * 2 ..][0..2], g, .big);
    return out;
}

/// ADDR:PORT, with an IPv6 ADDR in brackets.
fn parseEndpoint(s: []const u8) !struct { addr: Addr, port: u16 } {
    if (s.len > 0 and s[0] == '[') {
        const close = std.mem.indexOfScalar(u8, s, ']') orelse return error.BadAddress;
        if (close + 1 >= s.len or s[close + 1] != ':') return error.BadAddress;
        return .{ .addr = try parseAddr(s[1..close]), .port = try std.fmt.parseInt(u16, s[close + 2 ..], 10) };
    }
    const colon = std.mem.lastIndexOfScalar(u8, s, ':') orelse return error.BadAddress;
    return .{ .addr = try parseAddr(s[0..colon]), .port = try std.fmt.parseInt(u16, s[colon + 1 ..], 10) };
}

fn sys(rc: usize) !usize {
    return switch (linux.errno(rc)) {
        .SUCCESS => rc,
        .INTR => error.Interrupted,
        else => |e| {
            std.debug.print("labtool: syscall failed: {t}\n", .{e});
            return error.SyscallFailed;
        },
    };
}

const SockAddr = union(enum) {
    in: linux.sockaddr.in,
    in6: linux.sockaddr.in6,

    fn init(a: Addr, port: u16) SockAddr {
        const p = std.mem.nativeToBig(u16, port);
        if (a.v6) return .{ .in6 = .{ .port = p, .flowinfo = 0, .addr = a.bytes, .scope_id = 0 } };
        return .{ .in = .{ .port = p, .addr = @bitCast(a.bytes[0..4].*) } };
    }
    fn ptr(self: *const SockAddr) *const linux.sockaddr {
        return switch (self.*) {
            .in => |*s| @ptrCast(s),
            .in6 => |*s| @ptrCast(s),
        };
    }
    fn len(self: *const SockAddr) linux.socklen_t {
        return switch (self.*) {
            .in => @sizeOf(linux.sockaddr.in),
            .in6 => @sizeOf(linux.sockaddr.in6),
        };
    }
};

fn setInt(fd: i32, level: i32, opt: u32, v: c_int) !void {
    _ = try sys(linux.setsockopt(fd, level, opt, std.mem.asBytes(&v), @sizeOf(c_int)));
}

fn bound(kind: u32, a: Addr, port: u16, v6only: bool) !i32 {
    const af: u32 = if (a.v6) linux.AF.INET6 else linux.AF.INET;
    const fd: i32 = @intCast(try sys(linux.socket(af, kind | linux.SOCK.CLOEXEC, 0)));
    try setInt(fd, linux.SOL.SOCKET, linux.SO.REUSEADDR, 1);
    if (a.v6 and v6only) try setInt(fd, linux.IPPROTO.IPV6, linux.IPV6.V6ONLY, 1);
    const sa = SockAddr.init(a, port);
    _ = try sys(linux.bind(fd, sa.ptr(), sa.len()));
    return fd;
}

fn tcpListener(a: Addr, port: u16, v6only: bool, backlog: u32) !i32 {
    const fd = try bound(linux.SOCK.STREAM, a, port, v6only);
    _ = try sys(linux.listen(fd, backlog));
    return fd;
}

fn sleepMs(ms: u64) void {
    const ts: linux.timespec = .{ .sec = @intCast(ms / 1000), .nsec = @intCast((ms % 1000) * std.time.ns_per_ms) };
    _ = linux.nanosleep(&ts, null);
}

fn sleepForever() noreturn {
    while (true) sleepMs(60_000);
}

fn acceptConn(lfd: i32) ?i32 {
    const rc = linux.accept4(lfd, null, null, linux.SOCK.CLOEXEC);
    if (linux.errno(rc) != .SUCCESS) return null;
    const fd: i32 = @intCast(rc);
    // A client that connects and goes quiet must not stall the service.
    const tv: linux.timeval = .{ .sec = 2, .usec = 0 };
    _ = linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.RCVTIMEO, std.mem.asBytes(&tv), @sizeOf(linux.timeval));
    return fd;
}

fn writeAll(fd: i32, data: []const u8) bool {
    var off: usize = 0;
    while (off < data.len) {
        const rc = linux.sendto(fd, data[off..].ptr, data.len - off, linux.MSG.NOSIGNAL, null, 0);
        switch (linux.errno(rc)) {
            .SUCCESS => off += rc,
            .INTR => {},
            else => return false,
        }
    }
    return true;
}

/// Reads exactly buf.len bytes; false on EOF, timeout or error.
fn readExact(fd: i32, buf: []u8) bool {
    var off: usize = 0;
    while (off < buf.len) {
        const rc = linux.recvfrom(fd, buf[off..].ptr, buf.len - off, 0, null, null);
        switch (linux.errno(rc)) {
            .SUCCESS => {
                if (rc == 0) return false;
                off += rc;
            },
            .INTR => {},
            else => return false,
        }
    }
    return true;
}

fn bannerLoop(lfd: i32, banner: []const u8) void {
    while (true) {
        const fd = acceptConn(lfd) orelse continue;
        _ = writeAll(fd, banner);
        // Give the client time to read before the close.
        sleepMs(200);
        _ = linux.close(fd);
    }
}

/// Answers any query over TCP with one CHAOS TXT record, which is what a
/// version.bind query expects.
fn dnsLoop(lfd: i32) void {
    const version = "9.18-lab";
    var q: [512]u8 = undefined;
    var ans: [1024]u8 = undefined;
    while (true) {
        const fd = acceptConn(lfd) orelse continue;
        defer _ = linux.close(fd);
        var lenb: [2]u8 = undefined;
        if (!readExact(fd, &lenb)) continue;
        const n = std.mem.readInt(u16, &lenb, .big);
        if (n < 12 or n > q.len or !readExact(fd, q[0..n])) continue;
        var w: usize = 2;
        const put = struct {
            fn f(buf: []u8, at: *usize, bytes: []const u8) void {
                @memcpy(buf[at.*..][0..bytes.len], bytes);
                at.* += bytes.len;
            }
        }.f;
        put(&ans, &w, q[0..2]); // transaction id
        put(&ans, &w, "\x84\x00\x00\x01\x00\x01\x00\x00\x00\x00"); // response, AA; 1 question, 1 answer
        put(&ans, &w, q[12..n]); // question, echoed
        put(&ans, &w, "\xc0\x0c\x00\x10\x00\x03\x00\x00\x00\x00"); // name ptr, TXT, CHAOS, TTL 0
        var rd: [3]u8 = undefined;
        std.mem.writeInt(u16, rd[0..2], version.len + 1, .big);
        rd[2] = version.len;
        put(&ans, &w, &rd);
        put(&ans, &w, version);
        std.mem.writeInt(u16, ans[0..2], @intCast(w - 2), .big);
        _ = writeAll(fd, ans[0..w]);
    }
}

fn httpLoop(lfd: i32) void {
    const body = "<html><body>zigmap lab</body></html>\n";
    const resp = std.fmt.comptimePrint(
        "HTTP/1.0 200 OK\r\nServer: zigmap-lab/1.0\r\nContent-Type: text/html\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}",
        .{ body.len, body },
    );
    var buf: [4096]u8 = undefined;
    while (true) {
        const fd = acceptConn(lfd) orelse continue;
        defer _ = linux.close(fd);
        // Read the request head (or give up at the buffer size or timeout).
        var got: usize = 0;
        while (got < buf.len) {
            const rc = linux.recvfrom(fd, buf[got..].ptr, buf.len - got, 0, null, null);
            if (linux.errno(rc) != .SUCCESS or rc == 0) break;
            got += rc;
            if (std.mem.indexOf(u8, buf[0..got], "\r\n\r\n") != null) break;
        }
        if (got > 0) _ = writeAll(fd, resp);
    }
}

fn udpEchoLoop(fd: i32) void {
    var buf: [2048]u8 = undefined;
    var from: linux.sockaddr.in6 = undefined;
    while (true) {
        var flen: linux.socklen_t = @sizeOf(linux.sockaddr.in6);
        const rc = linux.recvfrom(fd, &buf, buf.len, 0, @ptrCast(&from), &flen);
        if (linux.errno(rc) != .SUCCESS) continue;
        _ = linux.sendto(fd, "pong", 4, 0, @ptrCast(&from), flen);
    }
}

fn spawn(comptime f: anytype, args: anytype) !void {
    const t = try std.Thread.spawn(.{ .stack_size = 64 * 1024 }, f, args);
    t.detach();
}

fn cmdListen(specs: []const [:0]const u8) !void {
    if (specs.len == 0) return error.Usage;
    for (specs) |spec| {
        const colon = std.mem.indexOfScalar(u8, spec, ':') orelse return error.Usage;
        const kind = spec[0..colon];
        const ep = try parseEndpoint(spec[colon + 1 ..]);
        if (std.mem.eql(u8, kind, "tcp") or std.mem.eql(u8, kind, "tcp6only")) {
            _ = try tcpListener(ep.addr, ep.port, std.mem.eql(u8, kind, "tcp6only"), 128);
        } else if (std.mem.eql(u8, kind, "udp-echo")) {
            try spawn(udpEchoLoop, .{try bound(linux.SOCK.DGRAM, ep.addr, ep.port, false)});
        } else return error.Usage;
    }
    sleepForever();
}

fn cmdServe(host: []const u8) !void {
    const a = try parseAddr(host);
    const banners = [_]struct { port: u16, text: []const u8 }{
        .{ .port = 2222, .text = "SSH-2.0-OpenSSH_9.6p1 lab\r\n" },
        .{ .port = 2121, .text = "220 (vsFTPd 3.0.5)\r\n" },
        .{ .port = 2525, .text = "220 mail.lab ESMTP Postfix\r\n" },
    };
    for (banners) |b| try spawn(bannerLoop, .{ try tcpListener(a, b.port, false, 64), b.text });
    try spawn(dnsLoop, .{try tcpListener(a, 53, false, 16)});
    try spawn(httpLoop, .{try tcpListener(a, 8080, false, 16)});
    const ready = try sys(linux.openat(linux.AT.FDCWD, "/tmp/ready", .{ .ACCMODE = .WRONLY, .CREAT = true, .CLOEXEC = true }, 0o644));
    _ = linux.close(@intCast(ready));
    sleepForever();
}

fn cmdWaitTcp(host: []const u8, port_s: []const u8) !void {
    const a = try parseAddr(host);
    const sa = SockAddr.init(a, try std.fmt.parseInt(u16, port_s, 10));
    const af: u32 = if (a.v6) linux.AF.INET6 else linux.AF.INET;
    var i: usize = 0;
    while (i < 100) : (i += 1) {
        const fd: i32 = @intCast(try sys(linux.socket(af, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0)));
        const ok = linux.errno(linux.connect(fd, sa.ptr(), sa.len())) == .SUCCESS;
        _ = linux.close(fd);
        if (ok) return;
        sleepMs(100);
    }
    return error.NothingListening;
}

fn cmdUdpNoise(src: []const u8, dst: []const u8, port_s: []const u8) !void {
    const s = try parseAddr(src);
    const d = SockAddr.init(try parseAddr(dst), try std.fmt.parseInt(u16, port_s, 10));
    const fd = try bound(linux.SOCK.DGRAM, s, 0, false);
    const payload: [64]u8 = @splat('x');
    while (true) _ = linux.sendto(fd, &payload, payload.len, 0, d.ptr(), d.len());
}

const usage =
    \\usage: labtool listen tcp:ADDR:PORT|tcp6only:ADDR:PORT|udp-echo:ADDR:PORT ...
    \\       labtool serve ADDR
    \\       labtool wait-tcp ADDR PORT
    \\       labtool udp-noise SRC DST PORT
    \\
;

pub fn main(init: std.process.Init) !u8 {
    const argv = try init.minimal.args.toSlice(init.arena.allocator());
    const cmd = if (argv.len > 1) argv[1] else "";
    const rest = if (argv.len > 2) argv[2..] else argv[0..0];
    const result = if (std.mem.eql(u8, cmd, "listen"))
        cmdListen(rest)
    else if (std.mem.eql(u8, cmd, "serve") and rest.len == 1)
        cmdServe(rest[0])
    else if (std.mem.eql(u8, cmd, "wait-tcp") and rest.len == 2)
        cmdWaitTcp(rest[0], rest[1])
    else if (std.mem.eql(u8, cmd, "udp-noise") and rest.len == 3)
        cmdUdpNoise(rest[0], rest[1], rest[2])
    else
        error.Usage;
    result catch |err| {
        if (err == error.Usage) std.debug.print("{s}", .{usage}) else std.debug.print("labtool {s}: {t}\n", .{ cmd, err });
        return 2;
    };
    return 0;
}

test "parse endpoints" {
    const v4 = try parseEndpoint("127.0.0.1:20001");
    try std.testing.expect(!v4.addr.v6);
    try std.testing.expectEqualSlices(u8, &.{ 127, 0, 0, 1 }, v4.addr.bytes[0..4]);
    try std.testing.expectEqual(@as(u16, 20001), v4.port);
    const lo6 = try parseEndpoint("[::1]:53");
    try std.testing.expect(lo6.addr.v6);
    try std.testing.expectEqual(@as(u8, 1), lo6.addr.bytes[15]);
    const any6 = try parseAddr("::");
    try std.testing.expectEqualSlices(u8, &@as([16]u8, @splat(0)), &any6.bytes);
    const ula = try parseAddr("fd5a:42::10");
    try std.testing.expectEqualSlices(u8, &.{ 0xfd, 0x5a, 0x00, 0x42 }, ula.bytes[0..4]);
    try std.testing.expectEqual(@as(u8, 0x10), ula.bytes[15]);
    try std.testing.expectError(error.BadAddress, parseAddr("1.2.3"));
    try std.testing.expectError(error.BadAddress, parseAddr("1:2:3"));
}
