const std = @import("std");
const builtin = @import("builtin");
const zigmap = @import("zigmap");

const args_mod = zigmap.cli.args;
const targets = zigmap.core.targets;
const engine_mod = zigmap.core.engine;
const ps = zigmap.core.port_state;
const report = zigmap.output.report;
const sys = zigmap.platform.sys;
const classify = zigmap.scan.classify;
const svc = zigmap.fingerprint.service;
const os_fp = zigmap.fingerprint.os;
const ConnectTransport = zigmap.scan.connect.ConnectTransport;
const Addr = targets.Addr;

/// The only process-global mutable state: async-signal handlers cannot
/// receive a context pointer. Engines poll it once per loop iteration.
var interrupted = std.atomic.Value(bool).init(false);

fn onSigint(_: std.posix.SIG) callconv(.c) void {
    interrupted.store(true, .monotonic);
}

fn installSigint() void {
    const act: std.posix.Sigaction = .{
        .handler = .{ .handler = onSigint },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    std.posix.sigaction(.INT, &act, null);
}

const TraceCtx = struct {
    w: *std.Io.Writer,
    fn emit(ctx: *anyopaque, m: engine_mod.TraceMsg) void {
        const self: *TraceCtx = @ptrCast(@alignCast(ctx));
        const tag = switch (m.kind) {
            .send => "SENT",
            .reply => "RCVD",
            .timeout => "TIMEOUT",
            .stale => "STALE",
            .deferred => "DEFER",
        };
        self.w.print("{d: >12.3} ms {s: <7} {f} port {d} attempt {d}", .{ @as(f64, @floatFromInt(m.t_ns)) / std.time.ns_per_ms, tag, m.addr, m.port, m.attempt }) catch return;
        if (m.kind == .reply or m.kind == .stale) self.w.print(" {s}", .{m.reason.label()}) catch return;
        self.w.writeByte('\n') catch return;
        self.w.flush() catch return;
    }
};

const Ctx = struct {
    gpa: std.mem.Allocator,
    arena: std.mem.Allocator,
    io: std.Io,
    out: *std.Io.Writer,
    errw: *std.Io.Writer,
    hw: *std.Io.Writer,
    opts: *const args_mod.Options,
    ports: []const u16,
    parallelism: u32,
    trace: TraceCtx,

    fn baseConfig(c: *const Ctx, classifier: *const fn (ps.Reason) engine_mod.Classification) engine_mod.Config {
        var cfg: engine_mod.Config = .{
            .classify = classifier,
            .max_retries = c.opts.max_retries,
            .max_rate = c.opts.max_rate,
            .host_timeout_ns = c.opts.host_timeout_ms * std.time.ns_per_ms,
            .rtt = .{
                .initial_rto_ns = c.opts.initial_rtt_ms * std.time.ns_per_ms,
                .min_rto_ns = c.opts.min_rtt_ms * std.time.ns_per_ms,
                .max_rto_ns = c.opts.max_rtt_ms * std.time.ns_per_ms,
            },
        };
        cfg.group_window.max = c.parallelism;
        cfg.group_window.initial = @min(cfg.group_window.initial, c.parallelism);
        cfg.host_window.max = @min(cfg.host_window.max, c.parallelism);
        cfg.host_window.initial = @min(cfg.host_window.initial, c.parallelism);
        return cfg;
    }

    fn discoveryConfig(c: *const Ctx) engine_mod.Config {
        var cfg = c.baseConfig(classify.discovery);
        cfg.max_retries = 1;
        cfg.rtt.initial_rto_ns = @min(cfg.rtt.initial_rto_ns, 1000 * std.time.ns_per_ms);
        return cfg;
    }

    fn attach(c: *Ctx, eng: anytype) void {
        eng.external_cancel = &interrupted;
        if (c.opts.packet_trace) eng.trace = .{ .ctx = &c.trace, .func = TraceCtx.emit };
    }
};

fn udpPaceTrigger(r: ps.Reason) bool {
    return r == .icmp_port_unreach;
}

/// Resolves host names with the system resolver; each name contributes its
/// first address of each family returned.
fn resolveNames(ctx: *Ctx, specs: *std.ArrayList(targets.Spec)) !bool {
    for (ctx.opts.hostnames.items) |name| {
        const hn = std.Io.net.HostName.init(name) catch {
            try ctx.errw.print("zigmap: '{s}' is not a valid host name\n", .{name});
            return false;
        };
        var buf: [32]std.Io.net.HostName.LookupResult = undefined;
        var q: std.Io.Queue(std.Io.net.HostName.LookupResult) = .init(&buf);
        hn.lookup(ctx.io, &q, .{ .port = 0 }) catch |err| {
            try ctx.errw.print("zigmap: cannot resolve '{s}': {t}\n", .{ name, err });
            return false;
        };
        var got4 = false;
        var got6 = false;
        while (q.getOne(ctx.io)) |r| switch (r) {
            .address => |ip| switch (ip) {
                .ip4 => |a| if (!got4) {
                    got4 = true;
                    try specs.append(ctx.arena, .{ .base = Addr.v4(a.bytes), .prefix = 32 });
                    try ctx.hw.print("Resolved {s} -> {f}\n", .{ name, Addr.v4(a.bytes) });
                },
                .ip6 => |a| if (!got6) {
                    got6 = true;
                    try specs.append(ctx.arena, .{ .base = Addr.v6(a.bytes), .prefix = 128 });
                    try ctx.hw.print("Resolved {s} -> {f}\n", .{ name, Addr.v6(a.bytes) });
                },
            },
            .canonical_name => {},
        } else |_| {}
        if (!got4 and !got6) {
            try ctx.errw.print("zigmap: '{s}' resolved to no addresses\n", .{name});
            return false;
        }
    }
    return true;
}

pub fn main(init: std.process.Init) !u8 {
    const gpa = init.gpa;
    const arena = init.arena.allocator();
    const io = init.io;

    var out_buf: [16 * 1024]u8 = undefined;
    var out_fw: std.Io.File.Writer = .init(.stdout(), io, &out_buf);
    const out = &out_fw.interface;
    var err_buf: [4096]u8 = undefined;
    var err_fw: std.Io.File.Writer = .init(.stderr(), io, &err_buf);
    const errw = &err_fw.interface;
    defer out.flush() catch {};
    defer errw.flush() catch {};

    const argv = try init.minimal.args.toSlice(arena);
    var diag: args_mod.Diagnostic = .{};
    var opts = args_mod.parse(arena, argv, &diag) catch |err| {
        try errw.print("zigmap: {s}: {s} ({t})\n", .{ diag.arg, diag.msg, err });
        try errw.writeAll("Try 'zigmap --help'.\n");
        return 2;
    };
    if (opts.help) {
        try out.writeAll(args_mod.usage);
        return 0;
    }
    if (opts.version) {
        try out.print("zigmap {s} (schema {s}, zig {s}, {t}-{t})\n", .{ report.version, report.schema, builtin.zig_version_string, builtin.cpu.arch, builtin.os.tag });
        return 0;
    }
    if (opts.target_specs.items.len == 0 and opts.hostnames.items.len == 0) {
        try errw.writeAll("zigmap: no targets given; targets are always explicit (see --help)\n");
        return 2;
    }
    const raw_method = opts.method == .syn or opts.method == .udp;
    if (raw_method and builtin.os.tag != .linux) {
        try errw.writeAll("zigmap: -sS/-sU need the Linux raw-packet backend; the macOS BPF backend is not implemented. Use -sT.\n");
        return 2;
    }
    if (opts.os_detection and opts.method != .syn) {
        try errw.writeAll("zigmap: -O reads SYN-scan replies; add -sS\n");
        return 2;
    }

    const stdout_formats = for ([_]?[]const u8{ opts.jsonl_path, opts.json_path, opts.xml_path }) |p| {
        if (p) |path| if (std.mem.eql(u8, path, "-")) break true;
    } else false;
    const hw = if (stdout_formats) errw else out;

    // Raw scans spend one source port per probe slot; connect scans one fd.
    const budget: u64 = if (raw_method) ((65536 - @as(u64, opts.source_port_base)) -| 16) / 2 else sys.fileLimit() -| 64;
    var ctx: Ctx = .{
        .gpa = gpa,
        .arena = arena,
        .io = io,
        .out = out,
        .errw = errw,
        .hw = hw,
        .opts = &opts,
        .ports = &.{},
        .parallelism = @intCast(@max(1, @min(opts.max_parallelism, budget))),
        .trace = .{ .w = errw },
    };

    if (!try resolveNames(&ctx, &opts.target_specs)) return 2;
    ctx.ports = if (opts.discovery_only) &.{} else targets.parsePorts(arena, opts.ports_text) catch |err| {
        try errw.print("zigmap: invalid port list '{s}' ({t})\n", .{ opts.ports_text, err });
        return 2;
    };
    const planned = targets.plannedCount(opts.target_specs.items);
    const addrs = targets.expand(arena, opts.target_specs.items, opts.exclude_specs.items, opts.max_targets) catch |err| switch (err) {
        error.TooManyTargets => {
            try errw.print("zigmap: target list expands to {d} addresses, above --max-targets {d}; narrow the targets or raise the limit explicitly\n", .{ planned, opts.max_targets });
            return 2;
        },
        else => return err,
    };
    if (addrs.len == 0) {
        try errw.writeAll("zigmap: every target is excluded; nothing to scan\n");
        return 2;
    }

    const method_name: []const u8 = switch (opts.method) {
        .connect => "TCP connect",
        .syn => "TCP SYN",
        .udp => "UDP",
    };
    try hw.print("Zigmap {s}: {s} scan of {d} host(s) x {d} port(s) (max retries {d}, parallelism <= {d}, rate {s}, discovery {s})\n", .{
        report.version,
        if (opts.discovery_only) "host discovery" else method_name,
        addrs.len,
        ctx.ports.len,
        opts.max_retries,
        ctx.parallelism,
        if (opts.max_rate == 0) "unlimited" else "capped",
        if (opts.skip_discovery) "skipped (-Pn)" else "on",
    });
    if (opts.dry_run) {
        try hw.writeAll("Dry run: targets in order:\n");
        for (addrs, 0..) |a, i| {
            if (i == 64) {
                try hw.print("  ... and {d} more\n", .{addrs.len - 64});
                break;
            }
            try hw.print("  {f}\n", .{a});
        }
        try hw.print("Ports: {s} ({d})\nExcluded specs: {d}\nNo packets were sent.\n", .{ opts.ports_text, ctx.ports.len, opts.exclude_specs.items.len });
        return 0;
    }
    try hw.flush();
    installSigint();

    if (raw_method) {
        if (builtin.os.tag == .linux) return runRaw(&ctx, addrs);
        unreachable;
    }
    return runConnect(&ctx, addrs);
}

// ------------------------------------------------------------- connect

fn runConnect(ctx: *Ctx, addrs: []const Addr) !u8 {
    const slots = engine_mod.poolCapacity(ctx.parallelism);
    var up: std.ArrayList(Addr) = .empty;
    var up_reason: std.ArrayList(ps.Reason) = .empty;
    var down: std.ArrayList(report.DownHost) = .empty;

    if (ctx.opts.skip_discovery) {
        try up.appendSlice(ctx.arena, addrs);
        try up_reason.appendNTimes(ctx.arena, .none, addrs.len);
    } else {
        // Unprivileged discovery: a completed handshake or a refusal on
        // 80/443 proves the host is up.
        const dports = [_]u16{ 80, 443 };
        var t = try ConnectTransport.init(ctx.gpa, ctx.io, slots);
        defer t.deinit();
        var eng = try engine_mod.Engine(ConnectTransport).init(ctx.gpa, ctx.discoveryConfig(), &t, addrs, &dports);
        defer eng.deinit();
        ctx.attach(&eng);
        try eng.run();
        try splitDiscovery(ctx, addrs, &dports, eng.results, &up, &up_reason, &down);
    }
    if (ctx.opts.discovery_only or up.items.len == 0) return emitDiscovery(ctx, up.items, up_reason.items, down.items, null);

    var t = try ConnectTransport.init(ctx.gpa, ctx.io, slots);
    defer t.deinit();
    var eng = try engine_mod.Engine(ConnectTransport).init(ctx.gpa, ctx.baseConfig(classify.connect), &t, up.items, ctx.ports);
    defer eng.deinit();
    ctx.attach(&eng);
    try eng.run();

    const services = if (ctx.opts.service_detection) try detectServices(ctx, eng.hosts, eng.results) else null;
    return emit(ctx, .{
        .hosts = eng.hosts,
        .ports = ctx.ports,
        .results = eng.results,
        .stats = eng.stats,
        .method = "connect",
        .max_retries = ctx.opts.max_retries,
        .max_rate = ctx.opts.max_rate,
        .up_reason = up_reason.items,
        .down = down.items,
        .services = services,
        .usage = sys.usage(),
    });
}

/// A host is up if any discovery probe drew a reply ("open" in discovery
/// classification). The first such reason is kept as the evidence.
fn splitDiscovery(ctx: *Ctx, addrs: []const Addr, dports: []const u16, results: []const ps.PortResult, up: *std.ArrayList(Addr), up_reason: *std.ArrayList(ps.Reason), down: *std.ArrayList(report.DownHost)) !void {
    for (addrs, 0..) |a, hi| {
        var reason: ?ps.Reason = null;
        var last: ps.Reason = .no_response;
        for (0..dports.len) |i| {
            const r = results[hi * dports.len + i];
            if (r.state == .open and reason == null) reason = r.reason;
            if (r.reason != .none) last = r.reason;
        }
        if (reason) |r| {
            try up.append(ctx.arena, a);
            try up_reason.append(ctx.arena, r);
        } else try down.append(ctx.arena, .{ .addr = a, .reason = if (last == .host_timeout or last == .canceled) .no_response else last });
    }
}

fn detectServices(ctx: *Ctx, hosts: []const engine_mod.Host, results: []const ps.PortResult) !?[]svc.Identity {
    var pd: svc.ParseDiag = .{};
    var db = svc.parse(ctx.gpa, svc.probe_file, &pd) catch |err| {
        try ctx.errw.print("zigmap: built-in probe file invalid at line {d}: {t}\n", .{ pd.line, err });
        return null;
    };
    defer db.deinit();
    var tasks: std.ArrayList(zigmap.scan.service_scan.Task) = .empty;
    var where: std.ArrayList(usize) = .empty;
    for (hosts, 0..) |h, hi| for (ctx.ports, 0..) |p, i| {
        const idx = hi * ctx.ports.len + i;
        if (results[idx].state != .open) continue;
        try tasks.append(ctx.arena, .{ .addr = h.addr, .port = p });
        try where.append(ctx.arena, idx);
    };
    const all = try ctx.arena.alloc(svc.Identity, results.len);
    @memset(all, .{});
    if (tasks.items.len == 0) return all;
    try ctx.hw.print("Service detection on {d} open port(s)...\n", .{tasks.items.len});
    try ctx.hw.flush();
    const ids = try zigmap.scan.service_scan.run(ctx.gpa, ctx.io, &db, tasks.items, .{ .intensity = ctx.opts.version_intensity });
    defer ctx.gpa.free(ids);
    // Identities reference names inside `db`; copy them before it is freed.
    for (ids, where.items) |id, idx| {
        all[idx] = id;
        all[idx].service = try ctx.arena.dupe(u8, id.service);
        all[idx].probe = try ctx.arena.dupe(u8, id.probe);
    }
    return all;
}

const Format = enum { jsonl, json, xml };

fn writeFormat(w: *std.Io.Writer, view: report.View, explain: bool, which: Format) !void {
    switch (which) {
        .jsonl => try report.writeJsonl(w, view, explain),
        .json => try report.writeJson(w, view, explain),
        .xml => try report.writeXml(w, view),
    }
}

fn writeTo(ctx: *Ctx, path: []const u8, view: report.View, which: Format) !bool {
    if (std.mem.eql(u8, path, "-")) {
        try writeFormat(ctx.out, view, ctx.opts.explain, which);
        return true;
    }
    const f = std.Io.Dir.cwd().createFile(ctx.io, path, .{}) catch |err| {
        try ctx.errw.print("zigmap: cannot create '{s}': {t}\n", .{ path, err });
        return false;
    };
    defer f.close(ctx.io);
    var fbuf: [16 * 1024]u8 = undefined;
    var fw: std.Io.File.Writer = .init(f, ctx.io, &fbuf);
    try writeFormat(&fw.interface, view, ctx.opts.explain, which);
    try fw.interface.flush();
    return true;
}

/// Capture loss means replies may never have reached us, so "filtered" and
/// "open|filtered" results can be wrong. Always said, not only with --stats.
fn warnCaptureLoss(ctx: *Ctx, capture: ?zigmap.scan.raw.CaptureStats) !void {
    const c = capture orelse return;
    if (c.kernel_drops == 0 and c.ring_losing_blocks == 0) return;
    try ctx.errw.print("warning: the capture lost frames (kernel drops {d}, lossy ring blocks {d}); replies may be missing, so filtered results are not reliable. Keep the BPF filter on (do not pass --no-bpf), try --capture ring, or lower --max-rate.\n", .{ c.kernel_drops, c.ring_losing_blocks });
    try ctx.errw.flush();
}

fn emit(ctx: *Ctx, scanned: report.View) !u8 {
    const o = ctx.opts;
    var view = scanned;
    view.completion = try report.completion(ctx.arena, view.results, view.stats.wall_ns);
    try warnCaptureLoss(ctx, view.capture);
    if (ctx.hw == ctx.out) {
        try report.writeText(ctx.out, view, o.show_all, o.explain);
        if (o.stats) {
            try report.writeStats(ctx.out, view.stats, view.usage, view.completion);
            if (view.capture) |c| try report.writeCaptureText(ctx.out, c);
        }
        try ctx.out.print("\nZigmap done: {d} host(s) up, {d} down; port scan took {d:.3} ms{s}\n", .{
            view.hosts.len,
            view.down.len,
            @as(f64, @floatFromInt(view.stats.wall_ns)) / std.time.ns_per_ms,
            if (interrupted.load(.monotonic)) " (interrupted)" else "",
        });
    }
    var ok = true;
    if (o.jsonl_path) |p| ok = try writeTo(ctx, p, view, .jsonl) and ok;
    if (o.json_path) |p| ok = try writeTo(ctx, p, view, .json) and ok;
    if (o.xml_path) |p| ok = try writeTo(ctx, p, view, .xml) and ok;
    if (interrupted.load(.monotonic)) return 130;
    return if (ok) 0 else 1;
}

/// Output for -sn (and for scans where every host was down): one line per
/// host with its discovery evidence; JSONL gets one host record each.
fn emitDiscovery(ctx: *Ctx, up: []const Addr, why: []const ps.Reason, down: []const report.DownHost, capture: ?zigmap.scan.raw.CaptureStats) !u8 {
    const w = ctx.hw;
    try warnCaptureLoss(ctx, capture);
    for (up, why) |a, r| try w.print("Host {f} is up ({s})\n", .{ a, r.label() });
    for (down) |d| try w.print("Host {f} appears down ({s})\n", .{ d.addr, d.reason.label() });
    if (ctx.opts.stats) if (capture) |c| try report.writeCaptureText(w, c);
    try w.print("Discovery: {d} up, {d} down\n", .{ up.len, down.len });
    if (ctx.opts.jsonl_path) |p| {
        var buf: std.ArrayList(u8) = .empty;
        var aw: std.Io.Writer.Allocating = .fromArrayList(ctx.arena, &buf);
        const jw = &aw.writer;
        for (up, why) |a, r| try jw.print("{{\"schema\":\"{s}\",\"type\":\"host\",\"host\":\"{f}\",\"status\":\"up\",\"discovery\":\"{s}\"}}\n", .{ report.schema, a, r.label() });
        for (down) |d| try jw.print("{{\"schema\":\"{s}\",\"type\":\"host\",\"host\":\"{f}\",\"status\":\"down\",\"discovery\":\"{s}\"}}\n", .{ report.schema, d.addr, d.reason.label() });
        if (std.mem.eql(u8, p, "-")) try ctx.out.writeAll(aw.written()) else {
            const f = std.Io.Dir.cwd().createFile(ctx.io, p, .{}) catch |err| {
                try ctx.errw.print("zigmap: cannot create '{s}': {t}\n", .{ p, err });
                return 1;
            };
            defer f.close(ctx.io);
            var fbuf: [4096]u8 = undefined;
            var fw: std.Io.File.Writer = .init(f, ctx.io, &fbuf);
            try fw.interface.writeAll(aw.written());
            try fw.interface.flush();
        }
    }
    return if (interrupted.load(.monotonic)) 130 else 0;
}

// ------------------------------------------------------------------ raw

const rt = if (builtin.os.tag == .linux) zigmap.scan.raw_transport else struct {};
const psock = if (builtin.os.tag == .linux) zigmap.platform.linux.packet_socket else struct {};

fn openSocket(ctx: *Ctx, ifindex: i32) !?psock.PacketSocket {
    return psock.PacketSocket.open(ifindex) catch |err| switch (err) {
        error.PermissionDenied => {
            try ctx.errw.writeAll("zigmap: raw scanning needs CAP_NET_RAW to open an AF_PACKET socket, and this process does not have it.\n" ++
                "        Zigmap does not elevate privileges. Run it as root or grant the capability\n" ++
                "        (setcap cap_net_raw+ep zigmap), or use -sT for an unprivileged connect scan.\n");
            return null;
        },
        else => {
            try ctx.errw.print("zigmap: cannot open packet socket: {t}\n", .{err});
            return null;
        },
    };
}

fn transportOptions(ctx: *const Ctx, mode: rt.Mode, slots: u32) rt.RawTransport.Options {
    return .{
        .mode = mode,
        .slots = slots,
        .base_port = ctx.opts.source_port_base,
        .capture = switch (ctx.opts.capture) {
            .ring => .ring,
            .recvmsg => .recvmsg,
        },
        .bpf_filter = ctx.opts.bpf_filter,
    };
}

fn runRaw(ctx: *Ctx, addrs: []const Addr) !u8 {
    const opts = ctx.opts;
    var d: rt.Diagnostic = .{};
    var plan = rt.plan(ctx.gpa, addrs, opts.interface, &d) catch |err| {
        if (d.target) |t| {
            try ctx.errw.print("zigmap: {f}: {s} ({t})\n", .{ t, d.msg, err });
        } else try ctx.errw.print("zigmap: {s} ({t})\n", .{ d.msg, err });
        return 2;
    };
    defer plan.deinit(ctx.gpa);
    const slots = engine_mod.poolCapacity(ctx.parallelism);
    try ctx.hw.print("Raw backend: interface {s} (ifindex {d}, {s}), capture {t}{s}, source ports {d}-{d}\n", .{
        plan.ifName(),
        plan.ifindex,
        if (plan.isLoopback()) "loopback: L3 raw send" else "ethernet",
        opts.capture,
        if (opts.bpf_filter) " + BPF filter" else "",
        opts.source_port_base,
        opts.source_port_base + slots - 1,
    });

    // Host discovery: our own ARP/NDP for next hops the kernel did not know.
    {
        var sock = (try openSocket(ctx, plan.ifindex)) orelse return 77;
        defer sock.close();
        _ = rt.resolveNeighbors(&plan, &sock, ctx.io, 3, 400);
    }

    var up: std.ArrayList(Addr) = .empty;
    var up_reason: std.ArrayList(ps.Reason) = .empty;
    var down: std.ArrayList(report.DownHost) = .empty;
    var probe_needed: std.ArrayList(Addr) = .empty;
    for (addrs, 0..) |a, i| {
        const on_link = plan.next_hop[i].eql(a);
        if (plan.isLoopback()) {
            try up.append(ctx.arena, a);
            try up_reason.append(ctx.arena, if (opts.skip_discovery) .none else .local_host);
        } else if (plan.next_hop_mac[i] == null) {
            // Without a next-hop MAC no frame can be addressed, -Pn or not.
            try down.append(ctx.arena, .{ .addr = a, .reason = .no_neighbor_reply });
        } else if (opts.skip_discovery) {
            try up.append(ctx.arena, a);
            try up_reason.append(ctx.arena, .none);
        } else if (on_link and plan.answered_resolution[i]) {
            try up.append(ctx.arena, a);
            try up_reason.append(ctx.arena, if (a.is_v6) .nd_reply else .arp_reply);
        } else try probe_needed.append(ctx.arena, a);
    }

    var disc_capture: ?zigmap.scan.raw.CaptureStats = null;
    if (probe_needed.items.len > 0) {
        const sock = (try openSocket(ctx, plan.ifindex)) orelse return 77;
        var t = rt.RawTransport.init(ctx.gpa, ctx.io, sock, &plan, addrs, transportOptions(ctx, .discovery, slots)) catch |err| {
            try ctx.errw.print("zigmap: raw transport setup failed: {t}\n", .{err});
            return 1;
        };
        defer t.deinit();
        var eng = try engine_mod.Engine(rt.RawTransport).init(ctx.gpa, ctx.discoveryConfig(), &t, probe_needed.items, &rt.discovery_ports);
        defer eng.deinit();
        ctx.attach(&eng);
        try eng.run();
        try splitDiscovery(ctx, probe_needed.items, &rt.discovery_ports, eng.results, &up, &up_reason, &down);
        disc_capture = t.corr.stats;
    }
    if (opts.discovery_only or up.items.len == 0) return emitDiscovery(ctx, up.items, up_reason.items, down.items, disc_capture);

    const mode: rt.Mode = if (opts.method == .udp) .udp else .syn;
    const sock = (try openSocket(ctx, plan.ifindex)) orelse return 77;
    var t = rt.RawTransport.init(ctx.gpa, ctx.io, sock, &plan, addrs, transportOptions(ctx, mode, slots)) catch |err| {
        try ctx.errw.print("zigmap: raw transport setup failed: {t}\n", .{err});
        return 1;
    };
    defer t.deinit();
    var cfg = ctx.baseConfig(if (mode == .udp) classify.udp else classify.syn);
    if (mode == .udp) {
        cfg.silent_state = .open_filtered;
        cfg.pace_trigger = udpPaceTrigger;
        cfg.paced_pps = 1;
    }
    var eng = try engine_mod.Engine(rt.RawTransport).init(ctx.gpa, cfg, &t, up.items, ctx.ports);
    defer eng.deinit();
    ctx.attach(&eng);
    try eng.run();

    var oses: ?[]?os_fp.Verdict = null;
    if (opts.os_detection) {
        const v = try ctx.arena.alloc(?os_fp.Verdict, eng.hosts.len);
        for (eng.hosts, v) |h, *slot| {
            const f = t.facts.get(h.addr) orelse rt.HostFacts{};
            slot.* = os_fp.classify(os_fp.extract(f.synack, f.rst));
        }
        oses = v;
    }
    const services = if (opts.service_detection and mode == .syn) try detectServices(ctx, eng.hosts, eng.results) else null;
    if (opts.service_detection and mode == .udp) try ctx.hw.writeAll("Note: -sV probes TCP services; UDP replies to the DNS/NTP payloads already show as open.\n");
    return emit(ctx, .{
        .hosts = eng.hosts,
        .ports = ctx.ports,
        .results = eng.results,
        .stats = eng.stats,
        .method = if (mode == .udp) "udp" else "syn",
        .proto = if (mode == .udp) "udp" else "tcp",
        .max_retries = opts.max_retries,
        .max_rate = opts.max_rate,
        .up_reason = up_reason.items,
        .down = down.items,
        .services = services,
        .os = oses,
        .capture = t.corr.stats,
        .usage = sys.usage(),
    });
}
