//! Command-line parsing. Nmap-style flags are accepted only where the
//! behavior is actually implemented; anything else is a hard error rather
//! than a silent substitution.

const std = @import("std");
const targets = @import("../core/targets.zig");

pub const Method = enum { connect, syn, udp };
/// Conservative default; `--max-rate 0` removes the cap explicitly.
pub const default_max_rate: u32 = 1000;

pub const Capture = enum { ring, recvmsg };

pub const Options = struct {
    method: Method = .connect,
    target_specs: std.ArrayList(targets.Spec) = .empty,
    exclude_specs: std.ArrayList(targets.Spec) = .empty,
    /// Names that are not IP literals; resolved by the caller.
    hostnames: std.ArrayList([]const u8) = .empty,
    ports_text: []const u8 = "1-1024",
    max_targets: u32 = 4096,
    max_retries: u8 = 2,
    max_rate: u32 = default_max_rate,
    max_parallelism: u32 = 256,
    host_timeout_ms: u64 = 0,
    initial_rtt_ms: u64 = 1000,
    min_rtt_ms: u64 = 100,
    max_rtt_ms: u64 = 10_000,
    skip_discovery: bool = false,
    dry_run: bool = false,
    explain: bool = false,
    packet_trace: bool = false,
    show_all: bool = false,
    stats: bool = false,
    jsonl_path: ?[]const u8 = null,
    interface: ?[]const u8 = null,
    source_port_base: u16 = 61000,
    service_detection: bool = false,
    version_intensity: u8 = 3,
    os_detection: bool = false,
    discovery_only: bool = false,
    capture: Capture = .recvmsg,
    bpf_filter: bool = true,
    json_path: ?[]const u8 = null,
    xml_path: ?[]const u8 = null,
    help: bool = false,
    version: bool = false,
};

pub const usage =
    \\Usage: zigmap [options] <target>...
    \\
    \\Targets: IPv4/IPv6 literals, CIDR blocks (192.0.2.0/28, 2001:db8::/124),
    \\         "localhost", or host names (resolved through the system resolver).
    \\
    \\Scan method:
    \\  -sT                     TCP connect() scan (default; no privileges needed)
    \\  -sS                     Raw TCP SYN scan (Linux, IPv4/IPv6, needs CAP_NET_RAW).
    \\                          Without the capability it fails; it never falls
    \\                          back to connect() silently
    \\  -sU                     Raw UDP scan (Linux, needs CAP_NET_RAW). Silence is
    \\                          reported open|filtered, never open
    \\  -sA, -sN, -sF, -sX      Not implemented (rejected)
    \\  -sn                     Host discovery only, no port scan
    \\  -sV                     Service/version detection on open TCP ports
    \\  --version-intensity <n> highest probe rarity tried on unlisted ports (default 3)
    \\  -O                      OS fingerprint from SYN-scan replies (with -sS)
    \\  -e, --interface <name>  require this egress interface (raw scans)
    \\  --source-port-base <p>  first source port of the raw probe range (default 61000)
    \\  --capture ring|recvmsg  raw capture path: recvmsg (default) or TPACKET_V3 ring
    \\  --no-bpf                do not attach the kernel packet filter
    \\Ports and targets:
    \\  -p <list>               e.g. 22,80,443,8000-8100 or "-" for 1-65535 (default 1-1024)
    \\  --exclude <list>        comma-separated addresses/CIDRs to skip
    \\  --max-targets <n>       refuse to expand more addresses than this (default 4096)
    \\  -Pn                     skip host discovery; treat every target as up
    \\Timing and safety:
    \\  --max-rate <pps>        cap probe transmissions per second (default 1000; 0 = no cap)
    \\  --max-retries <n>       retransmissions per port before "filtered" (default 2)
    \\  --max-parallelism <n>   cap probes in flight (default 256, bounded by RLIMIT_NOFILE)
    \\  --host-timeout <ms>     give up on a host after this long (default none)
    \\  --initial-rtt-timeout <ms>, --min-rtt-timeout <ms>, --max-rtt-timeout <ms>
    \\Output:
    \\  -oJ <file|->            versioned JSON Lines (schema zigmap.v1)
    \\  --json <file|->         one JSON document
    \\  -oX <file|->            XML
    \\  --explain               show the evidence behind each classification
    \\  --packet-trace          log every probe, reply and timeout to stderr
    \\  --all                   also list closed ports
    \\  --stats                 print engine and resource metrics
    \\  --dry-run               print the scan plan and exit without sending anything
    \\  -h, --help    --version
    \\
;

pub const ParseError = error{ InvalidArgument, MissingValue, NotImplemented } || targets.ParseError || std.mem.Allocator.Error;

pub const Diagnostic = struct {
    arg: []const u8 = "",
    msg: []const u8 = "",
};

fn parseNum(comptime T: type, s: []const u8, diag: *Diagnostic) ParseError!T {
    return std.fmt.parseInt(T, s, 10) catch {
        diag.* = .{ .arg = s, .msg = "expected a non-negative integer" };
        return error.InvalidArgument;
    };
}

fn looksLikeHostname(s: []const u8) bool {
    if (s.len == 0 or s.len > 253) return false;
    var alpha = false;
    for (s) |ch| switch (ch) {
        'a'...'z', 'A'...'Z' => alpha = true,
        '0'...'9', '-', '.' => {},
        else => return false,
    };
    return alpha;
}

/// `names` receives tokens that are syntactically host names (only for
/// targets; exclusions must be addresses).
fn addSpecs(gpa: std.mem.Allocator, list: *std.ArrayList(targets.Spec), names: ?*std.ArrayList([]const u8), text: []const u8, diag: *Diagnostic) ParseError!void {
    var it = std.mem.splitScalar(u8, text, ',');
    while (it.next()) |raw_t| {
        const t = std.mem.trim(u8, raw_t, " ");
        if (t.len == 0) continue;
        const s = targets.parseSpec(t) catch |err| {
            if (err == error.InvalidTarget) if (names) |n| if (looksLikeHostname(t)) {
                try n.append(gpa, t);
                continue;
            };
            diag.* = .{ .arg = t, .msg = if (err == error.InvalidPrefix) "invalid CIDR prefix" else "not an IP address, CIDR block or host name" };
            return err;
        };
        try list.append(gpa, s);
    }
}

pub fn parse(gpa: std.mem.Allocator, args: []const [:0]const u8, diag: *Diagnostic) ParseError!Options {
    var o: Options = .{};
    errdefer {
        o.target_specs.deinit(gpa);
        o.exclude_specs.deinit(gpa);
        o.hostnames.deinit(gpa);
    }
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a: []const u8 = args[i];
        const Next = struct {
            fn get(as: []const [:0]const u8, idx: *usize, d: *Diagnostic) ParseError![]const u8 {
                if (idx.* + 1 >= as.len) {
                    d.* = .{ .arg = as[idx.*], .msg = "requires a value" };
                    return error.MissingValue;
                }
                idx.* += 1;
                return as[idx.*];
            }
        };
        if (std.mem.eql(u8, a, "-h") or std.mem.eql(u8, a, "--help")) {
            o.help = true;
        } else if (std.mem.eql(u8, a, "--version")) {
            o.version = true;
        } else if (std.mem.eql(u8, a, "-sT")) {
            o.method = .connect;
        } else if (std.mem.eql(u8, a, "-sS")) {
            o.method = .syn;
        } else if (std.mem.eql(u8, a, "-e") or std.mem.eql(u8, a, "--interface")) {
            o.interface = try Next.get(args, &i, diag);
        } else if (std.mem.eql(u8, a, "--source-port-base")) {
            o.source_port_base = try parseNum(u16, try Next.get(args, &i, diag), diag);
            if (o.source_port_base < 1024) {
                diag.* = .{ .arg = a, .msg = "must be >= 1024" };
                return error.InvalidArgument;
            }
        } else if (std.mem.eql(u8, a, "-sU")) {
            o.method = .udp;
        } else if (std.mem.eql(u8, a, "-sV")) {
            o.service_detection = true;
        } else if (std.mem.eql(u8, a, "--version-intensity")) {
            o.version_intensity = try parseNum(u8, try Next.get(args, &i, diag), diag);
        } else if (std.mem.eql(u8, a, "-O")) {
            o.os_detection = true;
        } else if (std.mem.eql(u8, a, "-sn")) {
            o.discovery_only = true;
        } else if (std.mem.eql(u8, a, "--capture")) {
            const v = try Next.get(args, &i, diag);
            o.capture = std.meta.stringToEnum(Capture, v) orelse {
                diag.* = .{ .arg = v, .msg = "expected ring or recvmsg" };
                return error.InvalidArgument;
            };
        } else if (std.mem.eql(u8, a, "--no-bpf")) {
            o.bpf_filter = false;
        } else if (std.mem.eql(u8, a, "--json")) {
            o.json_path = try Next.get(args, &i, diag);
        } else if (std.mem.eql(u8, a, "-oX")) {
            o.xml_path = try Next.get(args, &i, diag);
        } else if (std.mem.eql(u8, a, "-sA") or std.mem.eql(u8, a, "-sN") or std.mem.eql(u8, a, "-sF") or std.mem.eql(u8, a, "-sX")) {
            diag.* = .{ .arg = a, .msg = "this scan method is not implemented; refusing to substitute another method" };
            return error.NotImplemented;
        } else if (std.mem.eql(u8, a, "-Pn")) {
            o.skip_discovery = true;
        } else if (std.mem.eql(u8, a, "-p")) {
            o.ports_text = try Next.get(args, &i, diag);
        } else if (std.mem.startsWith(u8, a, "-p") and a.len > 2) {
            o.ports_text = a[2..];
        } else if (std.mem.eql(u8, a, "--exclude")) {
            try addSpecs(gpa, &o.exclude_specs, null, try Next.get(args, &i, diag), diag);
        } else if (std.mem.eql(u8, a, "--max-targets")) {
            o.max_targets = try parseNum(u32, try Next.get(args, &i, diag), diag);
        } else if (std.mem.eql(u8, a, "--max-retries")) {
            o.max_retries = try parseNum(u8, try Next.get(args, &i, diag), diag);
        } else if (std.mem.eql(u8, a, "--max-rate")) {
            o.max_rate = try parseNum(u32, try Next.get(args, &i, diag), diag);
        } else if (std.mem.eql(u8, a, "--max-parallelism")) {
            o.max_parallelism = try parseNum(u32, try Next.get(args, &i, diag), diag);
            if (o.max_parallelism == 0) {
                diag.* = .{ .arg = a, .msg = "must be at least 1" };
                return error.InvalidArgument;
            }
        } else if (std.mem.eql(u8, a, "--host-timeout")) {
            o.host_timeout_ms = try parseNum(u64, try Next.get(args, &i, diag), diag);
        } else if (std.mem.eql(u8, a, "--initial-rtt-timeout")) {
            o.initial_rtt_ms = try parseNum(u64, try Next.get(args, &i, diag), diag);
        } else if (std.mem.eql(u8, a, "--min-rtt-timeout")) {
            o.min_rtt_ms = try parseNum(u64, try Next.get(args, &i, diag), diag);
        } else if (std.mem.eql(u8, a, "--max-rtt-timeout")) {
            o.max_rtt_ms = try parseNum(u64, try Next.get(args, &i, diag), diag);
        } else if (std.mem.eql(u8, a, "-oJ")) {
            o.jsonl_path = try Next.get(args, &i, diag);
        } else if (std.mem.eql(u8, a, "--explain")) {
            o.explain = true;
        } else if (std.mem.eql(u8, a, "--packet-trace")) {
            o.packet_trace = true;
        } else if (std.mem.eql(u8, a, "--all")) {
            o.show_all = true;
        } else if (std.mem.eql(u8, a, "--stats")) {
            o.stats = true;
        } else if (std.mem.eql(u8, a, "--dry-run") or std.mem.eql(u8, a, "--plan")) {
            o.dry_run = true;
        } else if (a.len > 1 and a[0] == '-') {
            diag.* = .{ .arg = a, .msg = "unknown option" };
            return error.InvalidArgument;
        } else {
            try addSpecs(gpa, &o.target_specs, &o.hostnames, a, diag);
        }
    }
    if (o.min_rtt_ms == 0 or o.min_rtt_ms > o.max_rtt_ms) {
        diag.* = .{ .arg = "--min-rtt-timeout", .msg = "must be >= 1 and <= --max-rtt-timeout" };
        return error.InvalidArgument;
    }
    return o;
}

const testing = std.testing;

test "parse common flags and reject unimplemented methods" {
    const gpa = testing.allocator;
    var d: Diagnostic = .{};
    var o = try parse(gpa, &.{ "zigmap", "-p", "22,80", "--max-rate", "100", "127.0.0.1", "::1/127", "--exclude", "127.0.0.2", "--explain" }, &d);
    defer {
        o.target_specs.deinit(gpa);
        o.exclude_specs.deinit(gpa);
        o.hostnames.deinit(gpa);
    }
    try testing.expectEqualStrings("22,80", o.ports_text);
    try testing.expectEqual(@as(u32, 100), o.max_rate);
    try testing.expectEqual(@as(usize, 2), o.target_specs.items.len);
    try testing.expectEqual(@as(usize, 1), o.exclude_specs.items.len);
    try testing.expect(o.explain);
    try testing.expectError(error.NotImplemented, parse(gpa, &.{ "zigmap", "-sA", "127.0.0.1" }, &d));
    try testing.expectError(error.InvalidArgument, parse(gpa, &.{ "zigmap", "--bogus" }, &d));
    try testing.expectError(error.MissingValue, parse(gpa, &.{ "zigmap", "-p" }, &d));
    try testing.expectError(error.InvalidTarget, parse(gpa, &.{ "zigmap", "bad_name!" }, &d));
    var h = try parse(gpa, &.{ "zigmap", "-sU", "-sV", "example.test" }, &d);
    defer h.hostnames.deinit(gpa);
    try testing.expectEqual(Method.udp, h.method);
    try testing.expectEqualStrings("example.test", h.hostnames.items[0]);
}
