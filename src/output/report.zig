//! Output: terminal text, JSON Lines (stable schema), one JSON document,
//! and XML. All formats render the same `View`.
//!
//! JSONL schema "zigmap.v1" (one object per line, `type` discriminates):
//!   scan_start {schema, version, method, proto, targets, ports, max_retries, max_rate}
//!   port       {host, port, proto, method, state, reason, attempts, rtt_us,
//!               evidence?: [{kind, reason, attempt, t_us}], evidence_dropped?,
//!               service?: {name, product, version, confidence, probe, rule, extra}}
//!   host       {host, status: completed|timed_out|canceled|down, discovery,
//!               counts{...}, srtt_us, rto_us, replies,
//!               os?: {confidence, name, score, reasons[], middlebox[]}}
//!   capture    {frames, ... raw backend counters}           (raw scans only)
//!   scan_end   {stats{...}, wall_ms, cpu_user_ms, cpu_sys_ms, peak_rss_bytes,
//!               ports_per_s, completion_us{p50,p95,p99}}
//! Fields and record types are only ever added; never renamed or retyped.

const std = @import("std");
const engine = @import("../core/engine.zig");
const ps = @import("../core/port_state.zig");
const Stats = @import("../core/telemetry.zig").Stats;
const Usage = @import("../platform/sys.zig").Usage;
const svc = @import("../fingerprint/service.zig");
const os_fp = @import("../fingerprint/os.zig");
const targets = @import("../core/targets.zig");
const CaptureStats = @import("../scan/raw.zig").CaptureStats;

pub const schema = "zigmap.v1";
pub const version = "0.2.0";

pub const DownHost = struct { addr: targets.Addr, reason: ps.Reason };

pub const View = struct {
    hosts: []const engine.Host,
    ports: []const u16,
    results: []const ps.PortResult,
    stats: Stats,
    method: []const u8,
    proto: []const u8 = "tcp",
    max_retries: u8,
    max_rate: u32,
    /// Discovery evidence per scanned host (`.none` = assumed up with -Pn).
    up_reason: ?[]const ps.Reason = null,
    down: []const DownHost = &.{},
    /// Parallel to `results` when service detection ran.
    services: ?[]const svc.Identity = null,
    /// Parallel to `hosts` when OS detection ran.
    os: ?[]const ?os_fp.Verdict = null,
    capture: ?CaptureStats = null,
    usage: Usage = .{ .user_ns = 0, .sys_ns = 0, .max_rss_bytes = 0 },
    completion: ?Completion = null,

    pub fn result(v: View, h: usize, i: usize) *const ps.PortResult {
        return &v.results[h * v.ports.len + i];
    }

    pub fn service(v: View, h: usize, i: usize) ?*const svc.Identity {
        const s = v.services orelse return null;
        const id = &s[h * v.ports.len + i];
        return if (id.matched or id.extra_len > 0) id else null;
    }

    fn upReason(v: View, h: usize) ps.Reason {
        return if (v.up_reason) |u| u[h] else .none;
    }
};

pub const Counts = std.EnumArray(ps.PortState, u32);

pub fn countHost(v: View, h: usize) Counts {
    var c = Counts.initFill(0);
    for (0..v.ports.len) |i| c.getPtr(v.result(h, i).state).* += 1;
    return c;
}

fn hostStatus(h: *const engine.Host) []const u8 {
    if (h.timed_out) return "timed_out";
    if (!h.done) return "canceled";
    return "completed";
}

fn usFrom(ns: u64) u64 {
    return ns / std.time.ns_per_us;
}

fn discoveryText(r: ps.Reason) []const u8 {
    return switch (r) {
        .none => "assumed up (-Pn: discovery skipped)",
        .arp_reply => "up: answered ARP on the local segment",
        .nd_reply => "up: answered IPv6 neighbour solicitation",
        .echo_reply => "up: answered ICMP echo",
        .syn_ack, .rst => "up: answered a TCP discovery probe",
        .connected, .conn_refused => "up: answered a TCP connection attempt",
        .icmp_port_unreach, .icmp_proto_unreach => "up: the host itself sent ICMP unreachable",
        .local_host => "local host (loopback route)",
        else => "up",
    };
}

fn downText(r: ps.Reason) []const u8 {
    return switch (r) {
        .no_neighbor_reply => "no ARP/NDP reply on the local segment",
        .no_response => "no reply to any discovery probe",
        .icmp_host_unreach, .icmp_net_unreach, .host_unreach, .net_unreach => "an intermediate device reported it unreachable",
        .icmp_admin_prohibited => "discovery probes administratively prohibited",
        else => "no evidence it is up",
    };
}

// ------------------------------------------------------------- terminal

pub fn writeText(w: *std.Io.Writer, v: View, show_all: bool, explain: bool) !void {
    for (v.down) |d| try w.print("\nHost {f} appears down: {s}. Not scanned (use -Pn to scan anyway).\n", .{ d.addr, downText(d.reason) });
    for (v.hosts, 0..) |*h, hi| {
        const c = countHost(v, hi);
        try w.print("\nZigmap report for {f}", .{h.addr});
        if (h.timed_out) try w.writeAll("  [host timeout reached]");
        try w.print("\n  Host: {s}\n", .{discoveryText(v.upReason(hi))});
        if (h.replies > 0) try w.print("  srtt {d} us, rto {d} us, {d} replies\n", .{ usFrom(h.rtt.srtt_ns), usFrom(h.rtt.rto()), h.replies });
        var shown: usize = 0;
        for (v.ports, 0..) |port, i| {
            const r = v.result(hi, i);
            if (!show_all and r.state == .closed) continue;
            if (shown == 0) try w.print("  PORT      STATE            REASON                 TRIES  RTT{s}\n", .{if (v.services != null) "        SERVICE" else ""});
            shown += 1;
            var pbuf: [16]u8 = undefined;
            const pstr = try std.fmt.bufPrint(&pbuf, "{d}/{s}", .{ port, v.proto });
            try w.print("  {s: <9} {s: <16} {s: <22} {d: >5}  ", .{ pstr, r.state.label(), r.reason.label(), r.attempts });
            var rbuf: [24]u8 = undefined;
            const rtt = if (r.rtt_us > 0) try std.fmt.bufPrint(&rbuf, "{d} us", .{r.rtt_us}) else "-";
            try w.print("{s: <10}", .{rtt});
            if (v.service(hi, i)) |s| {
                try w.print(" {s}", .{s.service});
                if (s.product_len > 0) try w.print(" {s}", .{s.productSlice()});
                if (s.version_len > 0) try w.print(" {s}", .{s.versionSlice()});
                if (s.matched) try w.print(" ({s})", .{s.confidence.label()});
            }
            try w.writeByte('\n');
            if (explain) {
                try writeEvidenceText(w, r);
                if (v.service(hi, i)) |s| {
                    if (s.matched) try w.print("      service: probe {s}, rule #{d}", .{ s.probe, s.rule_index orelse 0 }) else try w.writeAll("      service: no rule matched");
                    if (s.extra_len > 0) try w.print("; {s}", .{s.extraSlice()});
                    try w.writeByte('\n');
                }
            }
        }
        const closed = c.get(.closed);
        if (!show_all and closed > 0) try w.print("  Not shown: {d} closed ports\n", .{closed});
        if (shown == 0 and closed == 0) try w.writeAll("  (no ports classified)\n");
        try w.print("  Summary: {d} open, {d} closed, {d} filtered, {d} open|filtered, {d} unknown\n", .{ c.get(.open), closed, c.get(.filtered), c.get(.open_filtered), c.get(.unknown) });
        if (v.os) |oses| if (oses[hi]) |o| {
            try w.print("  OS: {s} ({s}", .{ o.name orelse "no match", o.confidence.label() });
            if (o.name != null) try w.print(", score {d:.2}", .{o.score});
            try w.writeAll(")\n");
            if (explain) try w.print("      observed: {s}\n", .{o.observedText()});
            for (o.reasonList()) |r| try w.print("      - {s}\n", .{r});
            for (o.middleboxList()) |m| try w.print("      ! {s}\n", .{m});
        };
    }
}

fn writeEvidenceText(w: *std.Io.Writer, r: *const ps.PortResult) !void {
    if (r.evidenceDropped() > 0) try w.print("      ... {d} earlier events not retained\n", .{r.evidenceDropped()});
    var it = r.evidenceIter();
    while (it.next()) |e| {
        try w.print("      t={d: >10} us  attempt {d}  {s}", .{ e.t_us, e.attempt, @tagName(e.kind) });
        if (e.kind == .reply or e.kind == .stale_reply) try w.print(" ({s})", .{e.reason.label()});
        try w.writeByte('\n');
    }
    const why: []const u8 = switch (r.reason) {
        .connected => "the TCP handshake completed, so the port accepted a connection",
        .conn_refused => "the connection was refused (an RST answered the SYN)",
        .syn_ack => "a SYN/ACK acknowledged our probe's sequence number",
        .rst => "an RST acknowledged our probe's sequence number",
        .udp_reply => "a UDP datagram came back from the port",
        .icmp_port_unreach => "ICMP port unreachable quoted our probe",
        .icmp_host_unreach, .icmp_net_unreach, .icmp_proto_unreach, .icmp_admin_prohibited, .icmp_unreach_other => "an ICMP unreachable quoted our probe",
        .no_response => "no attempt drew any reply; silence is not proof of closure",
        .host_unreach, .net_unreach => "the local stack reported the destination unreachable",
        .local_policy_denied => "a local policy refused the connection attempt",
        .kernel_timeout => "the kernel's own connection attempt timed out",
        .host_timeout => "the host timeout expired before this port was decided",
        .canceled => "the scan was canceled before this port was decided",
        .self_connect => "every attempt connected the socket to itself; no listener evidence",
        else => "no definitive evidence",
    };
    try w.print("      => {s}: {s}\n", .{ r.state.label(), why });
}

/// When each port was classified, measured from scan start, plus overall
/// throughput. A port's completion time is its last recorded evidence.
pub const Completion = struct {
    p50_us: u32,
    p95_us: u32,
    p99_us: u32,
    ports_per_s: u64,
};

pub fn completion(gpa: std.mem.Allocator, results: []const ps.PortResult, wall_ns: u64) !Completion {
    const times = try gpa.alloc(u32, results.len);
    defer gpa.free(times);
    var n: usize = 0;
    for (results) |*r| {
        if (r.evidence_total == 0) continue;
        times[n] = r.evidence[(r.evidence_total - 1) % ps.evidence_slots].t_us;
        n += 1;
    }
    const t = times[0..n];
    std.mem.sort(u32, t, {}, std.sort.asc(u32));
    const pick = struct {
        fn at(xs: []const u32, pct: usize) u32 {
            if (xs.len == 0) return 0;
            return xs[@min(xs.len - 1, (xs.len * pct + 99) / 100 - 1)];
        }
    };
    return .{
        .p50_us = pick.at(t, 50),
        .p95_us = pick.at(t, 95),
        .p99_us = pick.at(t, 99),
        .ports_per_s = if (wall_ns == 0) 0 else @intCast(@as(u128, n) * std.time.ns_per_s / wall_ns),
    };
}

pub fn writeStats(w: *std.Io.Writer, s: Stats, u: Usage, c: ?Completion) !void {
    try w.print(
        \\
        \\Engine metrics:
        \\  probes sent {d} (retransmissions {d}), replies matched {d} (inconclusive {d}), stale {d}, invalid {d}
        \\  timeouts {d}, evidenced loss events {d}, deferred sends {d}, local errors {d}, canceled {d}, paced hosts {d}
        \\  ports classified {d}, hosts completed {d}, peak in flight {d}
        \\  wall {d} ms, cpu user {d} ms, sys {d} ms, peak RSS {d} KiB
        \\
    , .{
        s.probes_sent,       s.retransmissions,  s.replies_matched, s.inconclusive_replies, s.stale_replies,
        s.invalid_replies,   s.timeouts,         s.loss_events,     s.send_deferred,        s.local_errors,
        s.probes_canceled,   s.paced_hosts,      s.ports_classified, s.hosts_completed,     s.max_in_flight,
        s.wall_ns / std.time.ns_per_ms,
        u.user_ns / std.time.ns_per_ms,
        u.sys_ns / std.time.ns_per_ms,
        u.max_rss_bytes / 1024,
    });
    if (c) |x| try w.print("  ports classified per second {d}; port completion p50 {d:.1} ms, p95 {d:.1} ms, p99 {d:.1} ms\n", .{
        x.ports_per_s,
        @as(f64, @floatFromInt(x.p50_us)) / 1000,
        @as(f64, @floatFromInt(x.p95_us)) / 1000,
        @as(f64, @floatFromInt(x.p99_us)) / 1000,
    });
}

pub fn writeCaptureText(w: *std.Io.Writer, c: CaptureStats) !void {
    try w.print(
        \\Capture (raw backend):
        \\  frames {d}, own outgoing skipped {d}, parse errors {d}, not ours {d}
        \\  matched tcp {d}, udp {d}, icmp {d}, token mismatch {d}, previous-occupant {d}, other flags {d}
        \\  bad checksum {d}, offload-partial accepted {d}, kernel receive drops {d}, ring blocks flagged losing {d}
        \\
    , .{ c.frames, c.outgoing_skipped, c.parse_errors, c.not_ours, c.matched_tcp, c.matched_udp, c.matched_icmp, c.token_mismatch, c.foreign_occupant, c.other_flags, c.bad_checksum, c.partial_checksum_accepted, c.kernel_drops, c.ring_losing_blocks });
}

// ----------------------------------------------------- JSON primitives

/// Writes a JSON string. All dynamic text in Zigmap is already sanitised
/// to printable ASCII, but escaping is still applied defensively.
fn jstr(w: *std.Io.Writer, s: []const u8) !void {
    try w.writeByte('"');
    for (s) |ch| switch (ch) {
        '"' => try w.writeAll("\\\""),
        '\\' => try w.writeAll("\\\\"),
        0...0x1f, 0x7f...0xff => try w.print("\\u{x:0>4}", .{ch}),
        else => try w.writeByte(ch),
    };
    try w.writeByte('"');
}

fn writeServiceJson(w: *std.Io.Writer, s: *const svc.Identity) !void {
    try w.writeAll("{\"name\":");
    try jstr(w, s.service);
    try w.writeAll(",\"product\":");
    try jstr(w, s.productSlice());
    try w.writeAll(",\"version\":");
    try jstr(w, s.versionSlice());
    try w.print(",\"confidence\":\"{s}\",\"matched\":{},\"probe\":", .{ if (s.matched) s.confidence.label() else "none", s.matched });
    try jstr(w, s.probe);
    if (s.rule_index) |ri| try w.print(",\"rule\":{d}", .{ri});
    try w.writeAll(",\"extra\":");
    try jstr(w, s.extraSlice());
    try w.writeByte('}');
}

fn writeOsJson(w: *std.Io.Writer, o: *const os_fp.Verdict) !void {
    try w.print("{{\"confidence\":\"{s}\",\"name\":", .{o.confidence.label()});
    if (o.name) |n| try jstr(w, n) else try w.writeAll("null");
    try w.print(",\"score\":{d:.3},\"observed\":", .{o.score});
    try jstr(w, o.observedText());
    try w.writeAll(",\"reasons\":[");
    for (o.reasonList(), 0..) |r, i| {
        if (i > 0) try w.writeByte(',');
        try jstr(w, r);
    }
    try w.writeAll("],\"middlebox\":[");
    for (o.middleboxList(), 0..) |m, i| {
        if (i > 0) try w.writeByte(',');
        try jstr(w, m);
    }
    try w.writeAll("]}");
}

fn writePortFields(w: *std.Io.Writer, v: View, hi: usize, i: usize, explain: bool) !void {
    const r = v.result(hi, i);
    try w.print("\"port\":{d},\"proto\":\"{s}\",\"method\":\"{s}\",\"state\":\"{s}\",\"reason\":\"{s}\",\"attempts\":{d},\"rtt_us\":{d}", .{ v.ports[i], v.proto, v.method, r.state.label(), r.reason.label(), r.attempts, r.rtt_us });
    if (explain) {
        try w.writeAll(",\"evidence\":[");
        var it = r.evidenceIter();
        var first = true;
        while (it.next()) |e| {
            if (!first) try w.writeByte(',');
            first = false;
            try w.print("{{\"kind\":\"{s}\",\"reason\":\"{s}\",\"attempt\":{d},\"t_us\":{d}}}", .{ @tagName(e.kind), e.reason.label(), e.attempt, e.t_us });
        }
        try w.print("],\"evidence_dropped\":{d}", .{r.evidenceDropped()});
    }
    if (v.service(hi, i)) |s| {
        try w.writeAll(",\"service\":");
        try writeServiceJson(w, s);
    }
}

fn writeHostFields(w: *std.Io.Writer, v: View, hi: usize) !void {
    const h = &v.hosts[hi];
    const c = countHost(v, hi);
    try w.print("\"host\":\"{f}\",\"status\":\"{s}\",\"discovery\":\"{s}\",\"counts\":{{", .{ h.addr, hostStatus(h), v.upReason(hi).label() });
    inline for (@typeInfo(ps.PortState).@"enum".field_names, 0..) |name, k| {
        if (k > 0) try w.writeByte(',');
        try w.print("\"{s}\":{d}", .{ name, c.get(@field(ps.PortState, name)) });
    }
    try w.print("}},\"srtt_us\":{d},\"rto_us\":{d},\"replies\":{d}", .{ usFrom(h.rtt.srtt_ns), usFrom(h.rtt.rto()), h.replies });
    if (v.os) |oses| if (oses[hi]) |*o| {
        try w.writeAll(",\"os\":");
        try writeOsJson(w, o);
    };
}

fn writeStatsObject(w: *std.Io.Writer, s: Stats) !void {
    try w.writeByte('{');
    inline for (@typeInfo(Stats).@"struct".field_names, 0..) |name, k| {
        if (k > 0) try w.writeByte(',');
        try w.print("\"{s}\":{d}", .{ name, @field(s, name) });
    }
    try w.writeByte('}');
}

fn writeCaptureObject(w: *std.Io.Writer, c: CaptureStats) !void {
    try w.writeByte('{');
    inline for (@typeInfo(CaptureStats).@"struct".field_names, 0..) |name, k| {
        if (k > 0) try w.writeByte(',');
        try w.print("\"{s}\":{d}", .{ name, @field(c, name) });
    }
    try w.writeByte('}');
}

// ---------------------------------------------------------------- JSONL

pub fn writeJsonl(w: *std.Io.Writer, v: View, explain: bool) !void {
    try w.print("{{\"schema\":\"{s}\",\"type\":\"scan_start\",\"version\":\"{s}\",\"method\":\"{s}\",\"proto\":\"{s}\",\"targets\":{d},\"ports\":{d},\"max_retries\":{d},\"max_rate\":{d}}}\n", .{ schema, version, v.method, v.proto, v.hosts.len + v.down.len, v.ports.len, v.max_retries, v.max_rate });
    for (v.down) |d| try w.print("{{\"schema\":\"{s}\",\"type\":\"host\",\"host\":\"{f}\",\"status\":\"down\",\"discovery\":\"{s}\"}}\n", .{ schema, d.addr, d.reason.label() });
    for (v.hosts, 0..) |h, hi| {
        for (0..v.ports.len) |i| {
            try w.print("{{\"schema\":\"{s}\",\"type\":\"port\",\"host\":\"{f}\",", .{ schema, h.addr });
            try writePortFields(w, v, hi, i, explain);
            try w.writeAll("}\n");
        }
        try w.print("{{\"schema\":\"{s}\",\"type\":\"host\",", .{schema});
        try writeHostFields(w, v, hi);
        try w.writeAll("}\n");
    }
    if (v.capture) |c| {
        try w.print("{{\"schema\":\"{s}\",\"type\":\"capture\",\"stats\":", .{schema});
        try writeCaptureObject(w, c);
        try w.writeAll("}\n");
    }
    try w.print("{{\"schema\":\"{s}\",\"type\":\"scan_end\",\"stats\":", .{schema});
    try writeStatsObject(w, v.stats);
    try w.print(",\"wall_ms\":{d},\"cpu_user_ms\":{d},\"cpu_sys_ms\":{d},\"peak_rss_bytes\":{d}", .{ v.stats.wall_ns / std.time.ns_per_ms, v.usage.user_ns / std.time.ns_per_ms, v.usage.sys_ns / std.time.ns_per_ms, v.usage.max_rss_bytes });
    try writeCompletionFields(w, v.completion);
    try w.writeAll("}\n");
}

fn writeCompletionFields(w: *std.Io.Writer, c: ?Completion) !void {
    const x = c orelse return;
    try w.print(",\"ports_per_s\":{d},\"completion_us\":{{\"p50\":{d},\"p95\":{d},\"p99\":{d}}}", .{ x.ports_per_s, x.p50_us, x.p95_us, x.p99_us });
}

// ------------------------------------------------------- JSON document

pub fn writeJson(w: *std.Io.Writer, v: View, explain: bool) !void {
    try w.print("{{\"schema\":\"{s}\",\"version\":\"{s}\",\"method\":\"{s}\",\"proto\":\"{s}\",\"hosts\":[", .{ schema, version, v.method, v.proto });
    var first = true;
    for (v.down) |d| {
        if (!first) try w.writeByte(',');
        first = false;
        try w.print("{{\"host\":\"{f}\",\"status\":\"down\",\"discovery\":\"{s}\",\"ports\":[]}}", .{ d.addr, d.reason.label() });
    }
    for (v.hosts, 0..) |_, hi| {
        if (!first) try w.writeByte(',');
        first = false;
        try w.writeByte('{');
        try writeHostFields(w, v, hi);
        try w.writeAll(",\"ports\":[");
        for (0..v.ports.len) |i| {
            if (i > 0) try w.writeByte(',');
            try w.writeByte('{');
            try writePortFields(w, v, hi, i, explain);
            try w.writeByte('}');
        }
        try w.writeAll("]}");
    }
    try w.writeAll("],\"stats\":");
    try writeStatsObject(w, v.stats);
    try writeCompletionFields(w, v.completion);
    if (v.capture) |c| {
        try w.writeAll(",\"capture\":");
        try writeCaptureObject(w, c);
    }
    try w.writeAll("}\n");
}

// ------------------------------------------------------------------ XML

fn xattr(w: *std.Io.Writer, name: []const u8, value: []const u8) !void {
    try w.print(" {s}=\"", .{name});
    for (value) |ch| switch (ch) {
        '"' => try w.writeAll("&quot;"),
        '&' => try w.writeAll("&amp;"),
        '<' => try w.writeAll("&lt;"),
        '>' => try w.writeAll("&gt;"),
        0...0x1f, 0x7f...0xff => try w.writeByte('?'),
        else => try w.writeByte(ch),
    };
    try w.writeByte('"');
}

pub fn writeXml(w: *std.Io.Writer, v: View) !void {
    try w.writeAll("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<zigmaprun");
    try xattr(w, "schema", schema);
    try xattr(w, "version", version);
    try xattr(w, "method", v.method);
    try xattr(w, "proto", v.proto);
    try w.writeAll(">\n");
    var abuf: [64]u8 = undefined;
    for (v.down) |d| {
        try w.writeAll("  <host");
        try xattr(w, "addr", try std.fmt.bufPrint(&abuf, "{f}", .{d.addr}));
        try xattr(w, "status", "down");
        try xattr(w, "discovery", d.reason.label());
        try w.writeAll("/>\n");
    }
    for (v.hosts, 0..) |*h, hi| {
        try w.writeAll("  <host");
        try xattr(w, "addr", try std.fmt.bufPrint(&abuf, "{f}", .{h.addr}));
        try xattr(w, "status", hostStatus(h));
        try xattr(w, "discovery", v.upReason(hi).label());
        try w.writeAll(">\n");
        for (v.ports, 0..) |port, i| {
            const r = v.result(hi, i);
            try w.print("    <port number=\"{d}\"", .{port});
            try xattr(w, "proto", v.proto);
            try xattr(w, "state", r.state.label());
            try xattr(w, "reason", r.reason.label());
            try w.print(" attempts=\"{d}\" rtt_us=\"{d}\"", .{ r.attempts, r.rtt_us });
            if (v.service(hi, i)) |s| {
                try w.writeAll(">\n      <service");
                try xattr(w, "name", s.service);
                try xattr(w, "product", s.productSlice());
                try xattr(w, "version", s.versionSlice());
                try xattr(w, "confidence", if (s.matched) s.confidence.label() else "none");
                try xattr(w, "probe", s.probe);
                try xattr(w, "extra", s.extraSlice());
                try w.writeAll("/>\n    </port>\n");
            } else try w.writeAll("/>\n");
        }
        if (v.os) |oses| if (oses[hi]) |o| {
            try w.writeAll("    <os");
            try xattr(w, "confidence", o.confidence.label());
            try xattr(w, "name", o.name orelse "");
            try w.writeAll(">\n");
            for (o.reasonList()) |r| {
                try w.writeAll("      <reason");
                try xattr(w, "text", r);
                try w.writeAll("/>\n");
            }
            for (o.middleboxList()) |m| {
                try w.writeAll("      <middlebox");
                try xattr(w, "text", m);
                try w.writeAll("/>\n");
            }
            try w.writeAll("    </os>\n");
        };
        try w.writeAll("  </host>\n");
    }
    try w.print("  <stats probes_sent=\"{d}\" replies_matched=\"{d}\" wall_ms=\"{d}\"/>\n</zigmaprun>\n", .{ v.stats.probes_sent, v.stats.replies_matched, v.stats.wall_ns / std.time.ns_per_ms });
}

test "json string escaping and xml attribute escaping" {
    var buf: [128]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try jstr(&w, "a\"b\\c\x01");
    try std.testing.expectEqualStrings("\"a\\\"b\\\\c\\u0001\"", w.buffered());
    var buf2: [128]u8 = undefined;
    var w2: std.Io.Writer = .fixed(&buf2);
    try xattr(&w2, "x", "<a&\"b\">");
    try std.testing.expectEqualStrings(" x=\"&lt;a&amp;&quot;b&quot;&gt;\"", w2.buffered());
}
