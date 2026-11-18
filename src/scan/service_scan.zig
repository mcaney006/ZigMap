//! Service detection over TCP (-sV): small, bounded protocol exchanges on
//! open ports, multiplexed with poll() on one thread.
//!
//! Probe order per port: probes whose port list names this port first
//! (by rarity), then the NULL banner probe, then probes listed for other
//! ports, up to the intensity. Each exchange is capped in bytes and time. The first
//! confident match wins; otherwise the port stays "unknown", with a short
//! sanitised banner excerpt as evidence.

const std = @import("std");
const sys = @import("../platform/sys.zig");
const targets = @import("../core/targets.zig");
const svc = @import("../fingerprint/service.zig");

pub const Task = struct { addr: targets.Addr, port: u16 };

pub const Options = struct {
    concurrency: u32 = 32,
    /// Highest probe rarity tried on ports no probe lists explicitly.
    intensity: u8 = 3,
    connect_timeout_ms: u32 = 3000,
};

const max_probes_per_port = 4;

const Conn = struct {
    task: u32,
    fd: sys.fd_t = -1,
    probe: *const svc.Probe,
    state: enum { connecting, sending, reading } = .connecting,
    deadline_ms: i64,
    out: []const u8 = "",
    sent: usize = 0,
    buf: [16384]u8 = undefined,
    len: usize = 0,
    send_buf: [512]u8 = undefined,
};

const Plan = struct {
    probes: [max_probes_per_port]*const svc.Probe = undefined,
    n: u8 = 0,
    next: u8 = 0,
    done: bool = false,
};

fn planFor(db: *const svc.Db, port: u16, intensity: u8) Plan {
    var p: Plan = .{};
    // 1. probes that list this port, by rarity
    var r: u8 = 0;
    while (r <= 9) : (r += 1) for (db.probes) |*pr| {
        if (p.n == max_probes_per_port) break;
        if (pr.rarity == r and pr.ports != null and pr.appliesTo(port) and pr.transport == .tcp) {
            p.probes[p.n] = pr;
            p.n += 1;
        }
    };
    // 2. NULL banner probe
    if (db.probeByName("NULL")) |nul| if (p.n < max_probes_per_port) {
        p.probes[p.n] = nul;
        p.n += 1;
    };
    // 3. probes listed for other ports
    for (db.probes) |*pr| {
        if (p.n == max_probes_per_port) break;
        if (pr.ports == null or pr.appliesTo(port) or pr.rarity > intensity or pr.transport != .tcp) continue;
        p.probes[p.n] = pr;
        p.n += 1;
    }
    return p;
}

fn nowMs(io: std.Io) i64 {
    return @intCast(@divTrunc(std.Io.Clock.awake.now(io).nanoseconds, std.time.ns_per_ms));
}

fn formatDate(epoch_s: u64, buf: []u8) []const u8 {
    const es: std.time.epoch.EpochSeconds = .{ .secs = epoch_s };
    const yd = es.getEpochDay().calculateYearDay();
    const md = yd.calculateMonthDay();
    return std.fmt.bufPrint(buf, "{d}-{d:0>2}-{d:0>2}", .{ yd.year, md.month.numeric(), md.day_index + 1 }) catch "";
}

fn evaluate(db: *const svc.Db, c: *const Conn) ?svc.Identity {
    const resp = c.buf[0..c.len];
    switch (c.probe.handler) {
        .tls => {
            const t = svc.parseServerFlight(resp);
            if (t.server_version == null and t.alert == null) return null;
            var id: svc.Identity = .{ .service = "ssl/tls", .confidence = .high, .probe = c.probe.name, .matched = true };
            var e: [160]u8 = undefined;
            var w: std.Io.Writer = .fixed(&e);
            if (t.server_version) |v| {
                id.setProduct(svc.tlsVersionName(v));
                w.print("tls={s}", .{svc.tlsVersionName(v)}) catch {};
                if (t.cipher) |cs| w.print(" cipher=0x{x:0>4}", .{cs}) catch {};
                if (t.cert_cn_len > 0) w.print(" cn={s}", .{t.cert_cn[0..t.cert_cn_len]}) catch {};
                if (t.issuer_cn_len > 0) w.print(" issuer={s}", .{t.issuer_cn[0..t.issuer_cn_len]}) catch {};
                if (t.san_count > 0) w.print(" san={d}({s})", .{ t.san_count, t.first_san[0..t.first_san_len] }) catch {};
                if (t.not_after) |na| {
                    var date_buf: [16]u8 = undefined;
                    w.print(" not_after={s}", .{formatDate(na, &date_buf)}) catch {};
                }
            } else {
                // A TLS alert to a TLS 1.2 hello still proves a TLS service.
                id.confidence = .medium;
                w.print("tls alert={d} (server rejected the TLS1.2 hello; possibly TLS1.3-only)", .{t.alert.?}) catch {};
            }
            id.setExtra(w.buffered());
            return id;
        },
        .dns_tcp => {
            const d = svc.parseDnsResponse(resp, true);
            if (!d.is_dns) return null;
            var id: svc.Identity = .{ .service = "domain", .confidence = .high, .probe = c.probe.name, .matched = true };
            if (d.version_len > 0) id.setVersion(d.version[0..d.version_len]);
            var e: [32]u8 = undefined;
            id.setExtra(std.fmt.bufPrint(&e, "rcode={d}", .{d.rcode}) catch "");
            return id;
        },
        .none => return svc.match(db, c.probe.name, resp),
    }
}

/// Returns one identity per task (unknown when nothing matched).
pub fn run(gpa: std.mem.Allocator, io: std.Io, db: *const svc.Db, tasks: []const Task, opts: Options) ![]svc.Identity {
    const ids = try gpa.alloc(svc.Identity, tasks.len);
    @memset(ids, .{});
    const plans = try gpa.alloc(Plan, tasks.len);
    defer gpa.free(plans);
    for (tasks, plans) |t, *p| p.* = planFor(db, t.port, opts.intensity);
    const banners = try gpa.alloc([48]u8, tasks.len);
    defer gpa.free(banners);
    const banner_len = try gpa.alloc(u8, tasks.len);
    defer gpa.free(banner_len);
    @memset(banner_len, 0);

    const conns = try gpa.alloc(Conn, opts.concurrency);
    defer gpa.free(conns);
    var active: std.ArrayList(u32) = .empty; // indexes into conns
    defer active.deinit(gpa);
    var free_conns: std.ArrayList(u32) = .empty;
    defer free_conns.deinit(gpa);
    for (0..opts.concurrency) |i| try free_conns.append(gpa, @intCast(opts.concurrency - 1 - i));
    const pfds = try gpa.alloc(sys.PollFd, opts.concurrency);
    defer gpa.free(pfds);

    var next_task: u32 = 0;
    var remaining: usize = tasks.len;
    var rnd: [32]u8 = undefined;
    while (remaining > 0) {
        // launch attempts while capacity remains
        var scan: u32 = 0;
        while (free_conns.items.len > 0 and scan < tasks.len) : (scan += 1) {
            const ti = (next_task + scan) % @as(u32, @intCast(tasks.len));
            const p = &plans[ti];
            if (p.done or p.next == p.n or isActive(conns, active.items, ti)) continue;
            const pr = p.probes[p.next];
            p.next += 1;
            const ci = free_conns.pop().?;
            const c = &conns[ci];
            c.* = .{ .task = ti, .probe = pr, .deadline_ms = nowMs(io) + opts.connect_timeout_ms };
            const fd = switch (sys.tcpSocket(tasks[ti].addr.is_v6)) {
                .ok => |fd| fd,
                .err => {
                    try free_conns.append(gpa, ci);
                    if (active.items.len > 0) {
                        // Out of sockets: retry this probe once a connection closes.
                        p.next -= 1;
                        break;
                    }
                    // Nothing open can free a socket, so waiting would never end.
                    if (finishAttempt(p)) remaining -= 1;
                    continue;
                },
            };
            c.fd = fd;
            switch (sys.connect(fd, tasks[ti].addr, tasks[ti].port)) {
                .ok, .in_progress => try active.append(gpa, ci),
                else => {
                    sys.closeFd(fd);
                    try free_conns.append(gpa, ci);
                    if (finishAttempt(p)) remaining -= 1;
                },
            }
        }
        next_task = (next_task + 1) % @as(u32, @intCast(tasks.len));
        if (active.items.len == 0) {
            // all remaining tasks exhausted their plans synchronously
            var left: usize = 0;
            for (plans) |p| {
                if (!p.done and p.next < p.n) left += 1;
            }
            if (left == 0) break;
            continue;
        }

        for (active.items, 0..) |ci, k| {
            const c = &conns[ci];
            pfds[k] = .{ .fd = c.fd, .events = if (c.state == .reading) sys.POLL_IN else sys.POLL_OUT, .revents = 0 };
        }
        var wait: i64 = 1000;
        const now0 = nowMs(io);
        for (active.items) |ci| wait = @min(wait, @max(0, conns[ci].deadline_ms - now0));
        _ = sys.pollFds(pfds[0..active.items.len], @intCast(wait));
        const now = nowMs(io);

        var k: usize = active.items.len;
        while (k > 0) {
            k -= 1;
            const ci = active.items[k];
            const c = &conns[ci];
            const p = &plans[c.task];
            var finished = false;
            const rev = pfds[k].revents;
            if (c.state == .connecting and rev != 0) {
                if (sys.socketError(c.fd) != .ok) {
                    finished = true;
                } else {
                    c.state = .sending;
                    c.deadline_ms = now + c.probe.wait_ms;
                    c.out = switch (c.probe.handler) {
                        .tls => blk: {
                            io.random(&rnd);
                            break :blk svc.buildClientHello(rnd, &c.send_buf);
                        },
                        .dns_tcp => svc.buildDnsVersionQuery(true, &c.send_buf),
                        .none => c.probe.payload,
                    };
                    if (c.out.len == 0) c.state = .reading;
                }
            } else if (c.state == .sending and rev != 0) {
                switch (sys.sendSome(c.fd, c.out[c.sent..])) {
                    .n => |n| {
                        c.sent += n;
                        if (c.sent == c.out.len) c.state = .reading;
                    },
                    .would_block => {},
                    else => finished = true,
                }
            } else if (c.state == .reading and rev != 0) {
                const cap = @min(c.probe.cap, c.buf.len);
                switch (sys.recvSome(c.fd, c.buf[c.len..cap])) {
                    .n => |n| {
                        c.len += n;
                        if (c.len >= cap) finished = true;
                        // stop early once a rule already matches
                        if (c.probe.handler == .none and svc.match(db, c.probe.name, c.buf[0..c.len]) != null) finished = true;
                    },
                    .would_block => {},
                    .eof, .err => finished = true,
                }
            }
            if (!finished and now >= c.deadline_ms) finished = true;
            if (!finished) continue;

            if (c.len > 0 and banner_len[c.task] == 0) {
                const n: u8 = @intCast(@min(c.len, 48));
                @memcpy(banners[c.task][0..n], c.buf[0..n]);
                banner_len[c.task] = n;
            }
            if (!p.done) if (evaluate(db, c)) |id| {
                ids[c.task] = id;
                p.done = true;
                remaining -= 1;
            };
            sys.abortClose(c.fd);
            _ = active.swapRemove(k);
            try free_conns.append(gpa, ci);
            if (!isActive(conns, active.items, c.task) and finishAttempt(p)) remaining -= 1;
        }
    }
    for (ids, 0..) |*id, i| if (!id.matched and banner_len[i] > 0) id.setExtra(banners[i][0..banner_len[i]]);
    return ids;
}

fn isActive(conns: []const Conn, active: []const u32, task: u32) bool {
    for (active) |ci| if (conns[ci].task == task) return true;
    return false;
}

fn finishAttempt(p: *Plan) bool {
    if (!p.done and p.next == p.n) {
        p.done = true;
        return true;
    }
    return false;
}
