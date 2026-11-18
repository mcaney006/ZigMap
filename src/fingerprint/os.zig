//! Passive-on-active OS fingerprinting from the replies a SYN scan already
//! receives: the SYN/ACK from an open port and the RST from a closed one.
//!
//! References are collected in Zigmap's own lab (see `references` and
//! docs/os-fingerprints.md); nothing comes from nmap-os-db. A verdict needs
//! TCP option evidence: TTL alone always yields `insufficient`.

const std = @import("std");
const packet = @import("../packet.zig");
const raw = @import("../scan/raw.zig");

pub const Features = struct {
    have_synack: bool = false,
    have_rst: bool = false,
    initial_ttl: u8 = 0,
    observed_ttl: u8 = 0,
    df: bool = false,
    window: u16 = 0,
    options: [16]u8 = undefined,
    options_len: u8 = 0,
    mss: ?u16 = null,
    wscale: ?u8 = null,
    rst_window: ?u16 = null,
    rst_df: ?bool = null,
    rst_initial_ttl: ?u8 = null,

    pub fn optionKinds(f: *const Features) []const u8 {
        return f.options[0..f.options_len];
    }
};

/// Smallest common initial TTL at or above the observed value.
pub fn initialTtl(observed: u8) u8 {
    for ([_]u8{ 32, 64, 128, 255 }) |t| if (observed <= t) return t;
    return 255;
}

pub fn extract(synack: ?raw.ReplyFacts, rst: ?raw.ReplyFacts) Features {
    var f: Features = .{};
    if (synack) |s| {
        f.have_synack = true;
        f.observed_ttl = s.ttl;
        f.initial_ttl = initialTtl(s.ttl);
        f.df = s.df;
        f.window = s.window;
        const o = packet.tcp.parseOptions(s.options[0..s.options_len]);
        const k = o.kinds();
        const n: u8 = @intCast(@min(k.len, f.options.len));
        @memcpy(f.options[0..n], k[0..n]);
        f.options_len = n;
        f.mss = o.mss;
        f.wscale = o.window_scale;
    }
    if (rst) |r| {
        f.have_rst = true;
        f.rst_window = r.window;
        f.rst_df = r.df;
        f.rst_initial_ttl = initialTtl(r.ttl);
        if (!f.have_synack) {
            f.observed_ttl = r.ttl;
            f.initial_ttl = initialTtl(r.ttl);
        }
    }
    return f;
}

pub const Reference = struct {
    name: []const u8,
    provenance: []const u8,
    initial_ttl: u8,
    df: bool,
    options: []const u8,
    window: u16,
    wscale: ?u8,
    rst_window: u16,
    rst_df: bool,
};

/// Lab-collected references. Values were read from Zigmap's own capture of
/// the target's replies to Zigmap's SYN probe (MSS 1460, SACK, TS, NOP, WS 7).
pub const references = [_]Reference{
    .{
        .name = "Linux 7.x (default TCP sysctls)",
        .provenance = "captured by tests/lab/syn_lab.sh: Alpine 3.20 container, kernel 7.2.12 (OrbStack), aarch64; observed synack ttl=64 df=1 win=65160 ws=10 opts=MSS,SACK,TS,NOP,WS; rst win=0 df=1",
        .initial_ttl = 64,
        .df = true,
        .options = &.{ 2, 4, 8, 1, 3 },
        .window = 65160,
        .wscale = 10, // depends on the receiver's memory sizing; weighted lightly
        .rst_window = 0,
        .rst_df = true,
    },
};

pub const Confidence = enum {
    strong,
    probable,
    weak,
    insufficient,

    pub fn label(c: Confidence) []const u8 {
        return @tagName(c);
    }
};

pub const max_reasons = 8;

pub const Verdict = struct {
    confidence: Confidence,
    name: ?[]const u8,
    score: f32,
    reasons: [max_reasons][]const u8 = undefined,
    n_reasons: u8 = 0,
    middlebox: [4][]const u8 = undefined,
    n_middlebox: u8 = 0,
    /// The raw features the verdict was computed from, for explanation and
    /// for collecting new references.
    observed: [192]u8 = undefined,
    observed_len: u8 = 0,

    fn why(v: *Verdict, r: []const u8) void {
        if (v.n_reasons < max_reasons) {
            v.reasons[v.n_reasons] = r;
            v.n_reasons += 1;
        }
    }

    fn flag(v: *Verdict, r: []const u8) void {
        if (v.n_middlebox < v.middlebox.len) {
            v.middlebox[v.n_middlebox] = r;
            v.n_middlebox += 1;
        }
    }

    pub fn reasonList(v: *const Verdict) []const []const u8 {
        return v.reasons[0..v.n_reasons];
    }

    pub fn middleboxList(v: *const Verdict) []const []const u8 {
        return v.middlebox[0..v.n_middlebox];
    }

    pub fn observedText(v: *const Verdict) []const u8 {
        return v.observed[0..v.observed_len];
    }
};

fn scoreAgainst(f: *const Features, r: *const Reference, v: ?*Verdict) f32 {
    var got: f32 = 0;
    var total: f32 = 0;
    const W = struct { w: f32, ok: bool, yes: []const u8, no: []const u8 };
    const checks = [_]W{
        .{ .w = 3, .ok = std.mem.eql(u8, f.optionKinds(), r.options), .yes = "TCP option order matches", .no = "TCP option order differs" },
        .{ .w = 2, .ok = f.window == r.window, .yes = "SYN/ACK window matches", .no = "SYN/ACK window differs" },
        .{ .w = 1, .ok = f.wscale == r.wscale, .yes = "window scale matches", .no = "window scale differs" },
        .{ .w = 1, .ok = f.initial_ttl == r.initial_ttl, .yes = "initial TTL matches", .no = "initial TTL differs" },
        .{ .w = 1, .ok = f.df == r.df, .yes = "DF bit matches", .no = "DF bit differs" },
    };
    for (checks) |c| {
        total += c.w;
        if (c.ok) got += c.w;
        if (v) |vv| vv.why(if (c.ok) c.yes else c.no);
    }
    if (f.have_rst) {
        total += 1;
        const ok = f.rst_window.? == r.rst_window and f.rst_df.? == r.rst_df;
        if (ok) got += 1;
        if (v) |vv| vv.why(if (ok) "closed-port RST matches" else "closed-port RST differs");
    }
    return got / total;
}

pub fn classify(f: Features) Verdict {
    var v: Verdict = .{ .confidence = .insufficient, .name = null, .score = 0 };
    describe(&f, &v);
    if (!f.have_synack) {
        v.why("no SYN/ACK observed (no open port): TCP option evidence is missing, and TTL alone is not used");
        return v;
    }
    if (f.options_len == 0) v.flag("SYN/ACK carries no TCP options although the probe offered them: stripped by a middlebox or a minimal stack");
    if (f.mss) |m| if (m < 1200) v.flag("MSS below 1200: likely clamped by a tunnel or middlebox");
    if (f.rst_initial_ttl) |rt| if (rt != f.initial_ttl) v.flag("SYN/ACK and RST imply different initial TTLs: different devices may be answering");

    var best: ?*const Reference = null;
    var best_score: f32 = 0;
    for (&references) |*r| {
        const s = scoreAgainst(&f, r, null);
        if (s > best_score) {
            best_score = s;
            best = r;
        }
    }
    const r = best orelse return v;
    v.score = scoreAgainst(&f, r, &v);
    const options_ok = std.mem.eql(u8, f.optionKinds(), r.options);
    v.confidence = if (v.score >= 0.95 and options_ok and v.n_middlebox == 0)
        .strong
    else if (v.score >= 0.75 and options_ok)
        .probable
    else if (v.score >= 0.5)
        .weak
    else
        .insufficient;
    if (v.confidence != .insufficient) v.name = r.name;
    return v;
}

fn describe(f: *const Features, v: *Verdict) void {
    var w: std.Io.Writer = .fixed(&v.observed);
    if (f.have_synack) {
        w.print("synack ttl={d}(init {d}) df={d} win={d}", .{ f.observed_ttl, f.initial_ttl, @intFromBool(f.df), f.window }) catch {};
        if (f.wscale) |ws| w.print(" ws={d}", .{ws}) catch {};
        if (f.mss) |m| w.print(" mss={d}", .{m}) catch {};
        w.writeAll(" opts=") catch {};
        for (f.optionKinds(), 0..) |k, i| {
            if (i > 0) w.writeByte(',') catch {};
            w.writeAll(switch (k) {
                0 => "EOL",
                1 => "NOP",
                2 => "MSS",
                3 => "WS",
                4 => "SACK",
                8 => "TS",
                else => "?",
            }) catch {};
        }
    } else w.writeAll("no synack") catch {};
    if (f.have_rst) w.print("; rst win={d} df={d} init_ttl={d}", .{ f.rst_window.?, @intFromBool(f.rst_df.?), f.rst_initial_ttl.? }) catch {};
    v.observed_len = @intCast(w.buffered().len);
}

const testing = std.testing;

fn facts(ttl: u8, df: bool, window: u16, opts: []const u8) raw.ReplyFacts {
    var f: raw.ReplyFacts = .{ .ttl = ttl, .df = df, .window = window };
    @memcpy(f.options[0..opts.len], opts);
    f.options_len = @intCast(opts.len);
    return f;
}

const linux_opts = [_]u8{ 2, 4, 5, 0xb4, 4, 2, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0, 1, 3, 3, 10 };

test "lab Linux SYN/ACK + RST is a strong match with reasons" {
    const v = classify(extract(facts(64, true, 65160, &linux_opts), facts(64, true, 0, &.{})));
    try testing.expectEqual(Confidence.strong, v.confidence);
    try testing.expectEqualStrings(references[0].name, v.name.?);
    try testing.expect(v.n_reasons >= 5);
    try testing.expectEqual(@as(u8, 0), v.n_middlebox);
}

test "TTL alone is never enough" {
    const v = classify(extract(null, facts(64, true, 0, &.{})));
    try testing.expectEqual(Confidence.insufficient, v.confidence);
    try testing.expectEqual(@as(?[]const u8, null), v.name);
}

test "stripped options and clamped MSS are flagged and lower confidence" {
    const v = classify(extract(facts(61, true, 65160, &.{}), facts(250, false, 0, &.{})));
    try testing.expect(v.n_middlebox >= 2);
    try testing.expect(v.confidence != .strong and v.confidence != .probable);
    const clamp = [_]u8{ 2, 4, 0x03, 0xe8, 4, 2, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0, 1, 3, 3, 10 };
    const v2 = classify(extract(facts(64, true, 65160, &clamp), null));
    try testing.expect(v2.n_middlebox == 1);
    try testing.expect(v2.confidence != .strong);
}

test "a different stack (other order, window, TTL) is not called Linux" {
    const other = [_]u8{ 2, 4, 5, 0xb4, 1, 3, 3, 8, 1, 1, 4, 2 };
    const v = classify(extract(facts(128, true, 8192, &other), null));
    try testing.expect(v.confidence == .weak or v.confidence == .insufficient);
    if (v.confidence == .insufficient) try testing.expectEqual(@as(?[]const u8, null), v.name);
}

test "initial TTL inference" {
    try testing.expectEqual(@as(u8, 64), initialTtl(53));
    try testing.expectEqual(@as(u8, 128), initialTtl(113));
    try testing.expectEqual(@as(u8, 255), initialTtl(240));
}
