//! Service identification: the probe file format, a bounded literal
//! matcher, and protocol handlers for TLS metadata and DNS.
//!
//! Matching is deliberately not regular expressions: rules are prefix /
//! contains / not-contains tests plus one bounded capture, which keeps
//! cost linear in the (capped) response and the semantics obvious.

const std = @import("std");

pub const probe_file = @embedFile("probes.zmp");
pub const format_version = 1;

pub const Transport = enum { tcp, udp };
pub const Handler = enum { none, tls, dns_tcp };
pub const Confidence = enum {
    high,
    medium,
    low,
    pub fn label(c: Confidence) []const u8 {
        return @tagName(c);
    }
};

pub const Probe = struct {
    name: []const u8,
    transport: Transport,
    /// null = every port
    ports: ?[]const u16,
    wait_ms: u32,
    cap: u32,
    rarity: u8,
    handler: Handler = .none,
    payload: []const u8 = "",

    pub fn appliesTo(p: *const Probe, port: u16) bool {
        const list = p.ports orelse return true;
        return std.mem.findScalar(u16, list, port) != null;
    }
};

pub const TestKind = enum { prefix, contains, not_contains };
pub const Test = struct { kind: TestKind, lit: []const u8 };
pub const CaptureAs = enum { product_version, version, product };

pub const Rule = struct {
    service: []const u8,
    probe: ?[]const u8, // null = any probe
    tests: [6]Test = undefined,
    n_tests: u8 = 0,
    product: ?[]const u8 = null,
    capture_after: ?[]const u8 = null,
    capture_stop: []const u8 = " \r\n",
    capture_split: []const u8 = "/",
    capture_as: CaptureAs = .product_version,
    confidence: Confidence = .medium,
};

pub const Db = struct {
    arena: std.heap.ArenaAllocator,
    probes: []Probe,
    rules: []Rule,

    pub fn deinit(d: *Db) void {
        d.arena.deinit();
    }

    pub fn probeByName(d: *const Db, name: []const u8) ?*const Probe {
        for (d.probes) |*p| if (std.mem.eql(u8, p.name, name)) return p;
        return null;
    }
};

pub const ParseError = error{ BadHeader, UnsupportedVersion, BadLine, BadEscape, BadNumber, MissingQuote, UnknownKey, SendWithoutProbe } || std.mem.Allocator.Error;

pub const ParseDiag = struct { line: usize = 0 };

fn unescape(a: std.mem.Allocator, s: []const u8) ParseError![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < s.len) : (i += 1) {
        if (s[i] != '\\') {
            try out.append(a, s[i]);
            continue;
        }
        i += 1;
        if (i >= s.len) return error.BadEscape;
        switch (s[i]) {
            'r' => try out.append(a, '\r'),
            'n' => try out.append(a, '\n'),
            't' => try out.append(a, '\t'),
            '\\' => try out.append(a, '\\'),
            '"' => try out.append(a, '"'),
            'x' => {
                if (i + 2 >= s.len) return error.BadEscape;
                try out.append(a, std.fmt.parseInt(u8, s[i + 1 .. i + 3], 16) catch return error.BadEscape);
                i += 2;
            },
            else => return error.BadEscape,
        }
    }
    return out.toOwnedSlice(a);
}

/// Splits a line into `key=value` / bare tokens; values may be quoted.
const Tokenizer = struct {
    s: []const u8,
    i: usize = 0,
    const Tok = struct { key: []const u8, value: ?[]const u8, quoted: bool };
    fn next(t: *Tokenizer) ParseError!?Tok {
        while (t.i < t.s.len and (t.s[t.i] == ' ' or t.s[t.i] == '\t')) t.i += 1;
        if (t.i >= t.s.len) return null;
        const start = t.i;
        while (t.i < t.s.len and t.s[t.i] != ' ' and t.s[t.i] != '=' and t.s[t.i] != '"') t.i += 1;
        const key = t.s[start..t.i];
        if (t.i < t.s.len and t.s[t.i] == '"') {
            // bare quoted token (send "...")
            return .{ .key = "", .value = try t.quoted(), .quoted = true };
        }
        if (t.i >= t.s.len or t.s[t.i] != '=') return .{ .key = key, .value = null, .quoted = false };
        t.i += 1;
        if (t.i < t.s.len and t.s[t.i] == '"') return .{ .key = key, .value = try t.quoted(), .quoted = true };
        const vs = t.i;
        while (t.i < t.s.len and t.s[t.i] != ' ') t.i += 1;
        return .{ .key = key, .value = t.s[vs..t.i], .quoted = false };
    }
    fn quoted(t: *Tokenizer) ParseError![]const u8 {
        t.i += 1; // opening quote
        const start = t.i;
        while (t.i < t.s.len) : (t.i += 1) {
            if (t.s[t.i] == '\\') {
                t.i += 1;
                continue;
            }
            if (t.s[t.i] == '"') {
                const v = t.s[start..t.i];
                t.i += 1;
                return v;
            }
        }
        return error.MissingQuote;
    }
};

fn num(comptime T: type, s: ?[]const u8) ParseError!T {
    return std.fmt.parseInt(T, s orelse return error.BadNumber, 10) catch error.BadNumber;
}

pub fn parse(gpa: std.mem.Allocator, text: []const u8, diag: *ParseDiag) ParseError!Db {
    var arena = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();
    const a = arena.allocator();
    var probes: std.ArrayList(Probe) = .empty;
    var rules: std.ArrayList(Rule) = .empty;
    var lines = std.mem.splitScalar(u8, text, '\n');
    var lineno: usize = 0;
    var header = false;
    while (lines.next()) |raw_line| {
        lineno += 1;
        diag.line = lineno;
        const line = std.mem.trim(u8, raw_line, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;
        if (!header) {
            if (!std.mem.startsWith(u8, line, "zigmap-probes ")) return error.BadHeader;
            if ((num(u32, line["zigmap-probes ".len..]) catch return error.BadHeader) != format_version) return error.UnsupportedVersion;
            header = true;
            continue;
        }
        var tz: Tokenizer = .{ .s = line };
        const first = (try tz.next()) orelse continue;
        if (std.mem.eql(u8, first.key, "probe")) {
            const name = ((try tz.next()) orelse return error.BadLine).key;
            const tr = ((try tz.next()) orelse return error.BadLine).key;
            var p: Probe = .{
                .name = try a.dupe(u8, name),
                .transport = if (std.mem.eql(u8, tr, "tcp")) .tcp else if (std.mem.eql(u8, tr, "udp")) .udp else return error.BadLine,
                .ports = null,
                .wait_ms = 3000,
                .cap = 4096,
                .rarity = 5,
            };
            while (try tz.next()) |tok| {
                const v = tok.value orelse return error.BadLine;
                if (std.mem.eql(u8, tok.key, "ports")) {
                    if (!std.mem.eql(u8, v, "*")) {
                        var list: std.ArrayList(u16) = .empty;
                        var it = std.mem.splitScalar(u8, v, ',');
                        while (it.next()) |x| try list.append(a, try num(u16, x));
                        p.ports = try list.toOwnedSlice(a);
                    }
                } else if (std.mem.eql(u8, tok.key, "wait")) {
                    p.wait_ms = try num(u32, v);
                } else if (std.mem.eql(u8, tok.key, "cap")) {
                    p.cap = @min(try num(u32, v), 65536);
                } else if (std.mem.eql(u8, tok.key, "rarity")) {
                    p.rarity = try num(u8, v);
                } else if (std.mem.eql(u8, tok.key, "handler")) {
                    p.handler = if (std.mem.eql(u8, v, "tls")) .tls else if (std.mem.eql(u8, v, "dns-tcp")) .dns_tcp else return error.UnknownKey;
                } else return error.UnknownKey;
            }
            try probes.append(a, p);
        } else if (std.mem.eql(u8, first.key, "send")) {
            if (probes.items.len == 0) return error.SendWithoutProbe;
            const tok = (try tz.next()) orelse return error.BadLine;
            probes.items[probes.items.len - 1].payload = try unescape(a, tok.value orelse return error.BadLine);
        } else if (std.mem.eql(u8, first.key, "match")) {
            var r: Rule = .{ .service = try a.dupe(u8, ((try tz.next()) orelse return error.BadLine).key), .probe = null };
            while (try tz.next()) |tok| {
                const v = tok.value orelse return error.BadLine;
                const kind: ?TestKind = if (std.mem.eql(u8, tok.key, "prefix")) .prefix else if (std.mem.eql(u8, tok.key, "contains")) .contains else if (std.mem.eql(u8, tok.key, "not-contains")) .not_contains else null;
                if (kind) |k| {
                    if (r.n_tests == r.tests.len) return error.BadLine;
                    r.tests[r.n_tests] = .{ .kind = k, .lit = try unescape(a, v) };
                    r.n_tests += 1;
                } else if (std.mem.eql(u8, tok.key, "probe")) {
                    r.probe = if (std.mem.eql(u8, v, "*")) null else try a.dupe(u8, v);
                } else if (std.mem.eql(u8, tok.key, "product")) {
                    r.product = try unescape(a, v);
                } else if (std.mem.eql(u8, tok.key, "capture")) {
                    r.capture_after = try unescape(a, v);
                } else if (std.mem.eql(u8, tok.key, "stop")) {
                    r.capture_stop = try unescape(a, v);
                } else if (std.mem.eql(u8, tok.key, "split")) {
                    r.capture_split = try unescape(a, v);
                } else if (std.mem.eql(u8, tok.key, "as")) {
                    r.capture_as = if (std.mem.eql(u8, v, "product-version")) .product_version else if (std.mem.eql(u8, v, "version")) .version else if (std.mem.eql(u8, v, "product")) .product else return error.UnknownKey;
                } else if (std.mem.eql(u8, tok.key, "confidence")) {
                    r.confidence = std.meta.stringToEnum(Confidence, v) orelse return error.UnknownKey;
                } else return error.UnknownKey;
            }
            try rules.append(a, r);
        } else return error.BadLine;
    }
    if (!header) return error.BadHeader;
    return .{ .arena = arena, .probes = try probes.toOwnedSlice(a), .rules = try rules.toOwnedSlice(a) };
}

// ------------------------------------------------------------- matching

pub const max_field = 64;

pub const Identity = struct {
    service: []const u8 = "unknown",
    product: [max_field]u8 = undefined,
    product_len: u8 = 0,
    version: [max_field]u8 = undefined,
    version_len: u8 = 0,
    confidence: Confidence = .low,
    /// Which probe and rule produced the match (provenance).
    probe: []const u8 = "",
    rule_index: ?u16 = null,
    extra: [160]u8 = undefined,
    extra_len: u8 = 0,
    matched: bool = false,

    pub fn productSlice(i: *const Identity) []const u8 {
        return i.product[0..i.product_len];
    }
    pub fn versionSlice(i: *const Identity) []const u8 {
        return i.version[0..i.version_len];
    }
    pub fn extraSlice(i: *const Identity) []const u8 {
        return i.extra[0..i.extra_len];
    }

    fn setText(buf: []u8, len: *u8, s: []const u8) void {
        var n: usize = 0;
        for (s) |c| {
            if (n == buf.len) break;
            // keep output printable and JSON/XML-safe
            buf[n] = if (c >= 0x20 and c < 0x7f and c != '"' and c != '\\' and c != '<' and c != '>' and c != '&') c else '?';
            n += 1;
        }
        len.* = @intCast(n);
    }
    pub fn setProduct(i: *Identity, s: []const u8) void {
        setText(&i.product, &i.product_len, s);
    }
    pub fn setVersion(i: *Identity, s: []const u8) void {
        setText(&i.version, &i.version_len, s);
    }
    pub fn setExtra(i: *Identity, s: []const u8) void {
        setText(&i.extra, &i.extra_len, s);
    }
};

fn holds(t: Test, resp: []const u8) bool {
    return switch (t.kind) {
        .prefix => std.mem.startsWith(u8, resp, t.lit),
        .contains => std.mem.find(u8, resp, t.lit) != null,
        .not_contains => std.mem.find(u8, resp, t.lit) == null,
    };
}

fn capture(r: *const Rule, resp: []const u8) ?[]const u8 {
    const after = r.capture_after orelse return null;
    const at = std.mem.find(u8, resp, after) orelse return null;
    const rest = resp[at + after.len ..];
    var end: usize = 0;
    while (end < rest.len and end < max_field and std.mem.findScalar(u8, r.capture_stop, rest[end]) == null) end += 1;
    return if (end == 0) null else rest[0..end];
}

pub fn match(db: *const Db, probe_name: []const u8, resp: []const u8) ?Identity {
    for (db.rules, 0..) |*r, idx| {
        if (r.probe) |p| if (!std.mem.eql(u8, p, probe_name)) continue;
        var ok = true;
        for (r.tests[0..r.n_tests]) |t| if (!holds(t, resp)) {
            ok = false;
            break;
        };
        if (!ok) continue;
        var id: Identity = .{ .service = r.service, .confidence = r.confidence, .probe = probe_name, .rule_index = @intCast(idx), .matched = true };
        if (r.product) |p| id.setProduct(p);
        if (capture(r, resp)) |c| switch (r.capture_as) {
            .version => id.setVersion(c),
            .product => id.setProduct(c),
            .product_version => if (std.mem.findAny(u8, c, r.capture_split)) |s| {
                id.setProduct(c[0..s]);
                id.setVersion(c[s + 1 ..]);
            } else id.setProduct(c),
        };
        return id;
    }
    return null;
}

// ------------------------------------------------------------------ TLS

/// TLS 1.2 ClientHello (no SNI: targets are addresses). Offering only 1.2
/// keeps the server's Certificate message in cleartext; a 1.3-only server
/// answers with a protocol_version alert, which is itself reported.
pub fn buildClientHello(random: [32]u8, out: []u8) []const u8 {
    const suites = [_]u16{ 0xc02f, 0xc02b, 0xc030, 0xc02c, 0xcca8, 0xcca9, 0x009c, 0x009d, 0x002f, 0x0035 };
    var w: std.Io.Writer = .fixed(out);
    w.writeAll(&.{ 0x16, 0x03, 0x01, 0, 0 }) catch unreachable; // record header, length patched
    w.writeAll(&.{ 0x01, 0, 0, 0 }) catch unreachable; // handshake header, length patched
    w.writeAll(&.{ 0x03, 0x03 }) catch unreachable;
    w.writeAll(&random) catch unreachable;
    w.writeByte(0) catch unreachable; // session id
    w.writeInt(u16, suites.len * 2, .big) catch unreachable;
    for (suites) |s| w.writeInt(u16, s, .big) catch unreachable;
    w.writeAll(&.{ 1, 0 }) catch unreachable; // null compression
    const ext = [_]u8{
        0x00, 0x0a, 0x00, 0x08, 0x00, 0x06, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, // supported_groups
        0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, // ec_point_formats
        0x00, 0x0d, 0x00, 0x10, 0x00, 0x0e, 0x04, 0x03, 0x05, 0x03, 0x08, 0x04, 0x08, 0x05, 0x04, 0x01, 0x05, 0x01, 0x02, 0x01, // signature_algorithms
        0xff, 0x01, 0x00, 0x01, 0x00, // renegotiation_info
    };
    w.writeInt(u16, ext.len, .big) catch unreachable;
    w.writeAll(&ext) catch unreachable;
    const b = w.buffered();
    std.mem.writeInt(u16, b[3..5], @intCast(b.len - 5), .big);
    std.mem.writeInt(u24, b[6..9], @intCast(b.len - 9), .big);
    return b;
}

pub const TlsInfo = struct {
    server_version: ?u16 = null,
    cipher: ?u16 = null,
    alert: ?u8 = null,
    cert_cn: [max_field]u8 = undefined,
    cert_cn_len: u8 = 0,
    issuer_cn: [max_field]u8 = undefined,
    issuer_cn_len: u8 = 0,
    not_after: ?u64 = null,
    san_count: u16 = 0,
    first_san: [max_field]u8 = undefined,
    first_san_len: u8 = 0,
    complete: bool = false,
};

fn copyField(dst: []u8, len: *u8, src: []const u8) void {
    const n = @min(src.len, dst.len);
    for (src[0..n], 0..) |c, i| dst[i] = if (c >= 0x20 and c < 0x7f and c != '"' and c != '\\' and c != '<' and c != '>' and c != '&') c else '?';
    len.* = @intCast(n);
}

/// Finds the commonName attribute (2.5.4.3) value inside a DER Name.
pub fn cnFromName(name: []const u8) ?[]const u8 {
    const oid = [_]u8{ 0x06, 0x03, 0x55, 0x04, 0x03 };
    const at = std.mem.find(u8, name, &oid) orelse return null;
    const i = at + oid.len;
    if (i + 2 > name.len) return null;
    const len = name[i + 1];
    if (len >= 0x80 or i + 2 + len > name.len) return null;
    return name[i + 2 ..][0..len];
}

/// Parses TLS records (handshake and alert) from a captured response.
pub fn parseServerFlight(data: []const u8) TlsInfo {
    var info: TlsInfo = .{};
    var hs_buf: [16384]u8 = undefined;
    var hs_len: usize = 0;
    var off: usize = 0;
    while (off + 5 <= data.len) {
        const ct = data[off];
        const rlen = std.mem.readInt(u16, data[off + 3 ..][0..2], .big);
        if (off + 5 + rlen > data.len) break;
        const body = data[off + 5 ..][0..rlen];
        if (ct == 21 and body.len >= 2) info.alert = body[1];
        if (ct == 22) {
            const n = @min(body.len, hs_buf.len - hs_len);
            @memcpy(hs_buf[hs_len..][0..n], body[0..n]);
            hs_len += n;
        }
        if (ct != 21 and ct != 22 and ct != 20) break;
        off += 5 + rlen;
    }
    var h: usize = 0;
    const hs = hs_buf[0..hs_len];
    while (h + 4 <= hs.len) {
        const t = hs[h];
        const len = std.mem.readInt(u24, hs[h + 1 ..][0..3], .big);
        if (h + 4 + len > hs.len) break;
        const m = hs[h + 4 ..][0..len];
        switch (t) {
            2 => if (m.len >= 38) { // ServerHello
                info.server_version = std.mem.readInt(u16, m[0..2], .big);
                const sid = m[34];
                if (35 + sid + 2 <= m.len) info.cipher = std.mem.readInt(u16, m[35 + sid ..][0..2], .big);
            },
            11 => if (m.len >= 6) { // Certificate
                const clen = std.mem.readInt(u24, m[3..6], .big);
                if (6 + clen <= m.len) parseLeaf(&info, m[6..][0..clen]);
            },
            14 => info.complete = true, // ServerHelloDone
            else => {},
        }
        h += 4 + len;
    }
    return info;
}

fn parseLeaf(info: *TlsInfo, der: []const u8) void {
    const cert: std.crypto.Certificate = .{ .buffer = der, .index = 0 };
    const p = cert.parse() catch return;
    copyField(&info.cert_cn, &info.cert_cn_len, p.commonName());
    if (cnFromName(p.issuer())) |icn| copyField(&info.issuer_cn, &info.issuer_cn_len, icn);
    info.not_after = p.validity.not_after;
    const san = p.subjectAltName();
    // SEQUENCE of GeneralName; dNSName is [2] IMPLICIT IA5String (tag 0x82).
    if (san.len >= 2 and san[0] == 0x30) {
        var i: usize = 2;
        if (san[1] & 0x80 != 0) i = 2 + (san[1] & 0x7f);
        while (i + 2 <= san.len) {
            const tag = san[i];
            const l = san[i + 1];
            if (l >= 0x80 or i + 2 + l > san.len) break;
            if (tag == 0x82) {
                if (info.san_count == 0) copyField(&info.first_san, &info.first_san_len, san[i + 2 ..][0..l]);
                info.san_count += 1;
            }
            i += 2 + l;
        }
    }
}

pub fn tlsVersionName(v: u16) []const u8 {
    return switch (v) {
        0x0300 => "SSLv3",
        0x0301 => "TLS1.0",
        0x0302 => "TLS1.1",
        0x0303 => "TLS1.2",
        0x0304 => "TLS1.3",
        else => "unknown",
    };
}

// ------------------------------------------------------------------ DNS

pub const dns_query_id: u16 = 0x7a6d;

/// version.bind TXT CH query. `tcp` prepends the RFC 1035 length field.
pub fn buildDnsVersionQuery(tcp: bool, out: []u8) []const u8 {
    const q = "\x7a\x6d\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03";
    var n: usize = 0;
    if (tcp) {
        std.mem.writeInt(u16, out[0..2], q.len, .big);
        n = 2;
    }
    @memcpy(out[n..][0..q.len], q);
    return out[0 .. n + q.len];
}

pub const DnsInfo = struct {
    is_dns: bool = false,
    rcode: u8 = 0,
    version: [max_field]u8 = undefined,
    version_len: u8 = 0,
};

/// Validates a DNS response to our query and extracts a TXT answer if any.
pub fn parseDnsResponse(msg_in: []const u8, tcp: bool) DnsInfo {
    var info: DnsInfo = .{};
    var msg = msg_in;
    if (tcp) {
        if (msg.len < 2) return info;
        const l = std.mem.readInt(u16, msg[0..2], .big);
        msg = msg[2..@min(msg.len, 2 + @as(usize, l))];
    }
    if (msg.len < 12) return info;
    if (std.mem.readInt(u16, msg[0..2], .big) != dns_query_id) return info;
    if (msg[2] & 0x80 == 0) return info; // not a response
    info.is_dns = true;
    info.rcode = msg[3] & 0x0f;
    const an = std.mem.readInt(u16, msg[6..8], .big);
    if (an == 0) return info;
    // skip the echoed question: name + 4 bytes
    var i: usize = 12;
    while (i < msg.len and msg[i] != 0) {
        if (msg[i] & 0xc0 != 0) {
            i += 1;
            break;
        }
        i += 1 + msg[i];
    }
    i += 1 + 4;
    // answer: name (pointer or labels), type, class, ttl, rdlength, rdata
    if (i >= msg.len) return info;
    if (msg[i] & 0xc0 == 0xc0) i += 2 else {
        while (i < msg.len and msg[i] != 0) i += 1 + msg[i];
        i += 1;
    }
    if (i + 10 > msg.len) return info;
    const typ = std.mem.readInt(u16, msg[i..][0..2], .big);
    const rdlen = std.mem.readInt(u16, msg[i + 8 ..][0..2], .big);
    i += 10;
    if (typ != 16 or i + rdlen > msg.len or rdlen < 1) return info;
    const tl = msg[i];
    if (1 + @as(usize, tl) > rdlen) return info;
    copyField(&info.version, &info.version_len, msg[i + 1 ..][0..tl]);
    return info;
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

test "bundled probe file parses" {
    var d: ParseDiag = .{};
    var db = try parse(testing.allocator, probe_file, &d);
    defer db.deinit();
    try testing.expect(db.probes.len >= 4);
    try testing.expect(db.rules.len >= 15);
    try testing.expectEqual(Handler.tls, db.probeByName("TLSHello").?.handler);
    try testing.expect(db.probeByName("HTTPGet").?.appliesTo(8080));
    try testing.expect(!db.probeByName("HTTPGet").?.appliesTo(22));
    try testing.expectEqualStrings("GET / HTTP/1.0\r\n", db.probeByName("HTTPGet").?.payload[0..16]);
}

test "parser rejects malformed files with a line number" {
    var d: ParseDiag = .{};
    try testing.expectError(error.BadHeader, parse(testing.allocator, "probe x tcp\n", &d));
    try testing.expectError(error.UnsupportedVersion, parse(testing.allocator, "zigmap-probes 9\n", &d));
    try testing.expectError(error.SendWithoutProbe, parse(testing.allocator, "zigmap-probes 1\nsend \"x\"\n", &d));
    try testing.expectError(error.MissingQuote, parse(testing.allocator, "zigmap-probes 1\nmatch a prefix=\"abc\n", &d));
    try testing.expectEqual(@as(usize, 2), d.line);
    try testing.expectError(error.BadEscape, parse(testing.allocator, "zigmap-probes 1\nmatch a prefix=\"\\q\"\n", &d));
}

test "banner matching with provenance" {
    var d: ParseDiag = .{};
    var db = try parse(testing.allocator, probe_file, &d);
    defer db.deinit();
    const ssh = match(&db, "NULL", "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n").?;
    try testing.expectEqualStrings("ssh", ssh.service);
    try testing.expectEqualStrings("OpenSSH", ssh.productSlice());
    try testing.expectEqualStrings("9.6p1", ssh.versionSlice());
    try testing.expectEqual(Confidence.high, ssh.confidence);
    const ftp = match(&db, "NULL", "220 (vsFTPd 3.0.5)\r\n").?;
    try testing.expectEqualStrings("vsftpd", ftp.productSlice());
    try testing.expectEqualStrings("3.0.5", ftp.versionSlice());
    const http = match(&db, "HTTPGet", "HTTP/1.1 200 OK\r\nServer: nginx/1.25.3\r\n\r\n").?;
    try testing.expectEqualStrings("nginx", http.productSlice());
    try testing.expectEqualStrings("1.25.3", http.versionSlice());
    const generic = match(&db, "HTTPGet", "HTTP/1.0 200 OK\r\nServer: lighttpd/1.4.76 extra\r\n").?;
    try testing.expectEqualStrings("lighttpd", generic.productSlice());
    try testing.expectEqualStrings("1.4.76", generic.versionSlice());
    try testing.expectEqual(Confidence.medium, generic.confidence);
    // a probe-specific rule never fires for another probe's response
    try testing.expectEqual(@as(?Identity, null), match(&db, "NULL", "HTTP/1.1 200 OK\r\n"));
    // unknown stays unknown
    try testing.expectEqual(@as(?Identity, null), match(&db, "NULL", "\x00\x01garbage"));
    // hostile bytes in captures are neutralised for output
    const weird = match(&db, "NULL", "SSH-2.0-Evil<script>\"x\r\n").?;
    try testing.expect(std.mem.findScalar(u8, weird.productSlice(), '<') == null);
}

test "ClientHello is a well-formed TLS 1.2 handshake record" {
    var out: [512]u8 = undefined;
    const ch = buildClientHello(@splat(7), &out);
    try testing.expectEqual(@as(u8, 0x16), ch[0]);
    try testing.expectEqual(@as(usize, ch.len - 5), std.mem.readInt(u16, ch[3..5], .big));
    try testing.expectEqual(@as(u8, 1), ch[5]);
    try testing.expectEqual(@as(usize, ch.len - 9), std.mem.readInt(u24, ch[6..9], .big));
    try testing.expectEqual(@as(u16, 0x0303), std.mem.readInt(u16, ch[9..11], .big));
}

test "server flight parsing: ServerHello, alert, truncation" {
    // ServerHello TLS1.2, cipher 0xc02f, then ServerHelloDone
    const sh = [_]u8{ 0x16, 0x03, 0x03, 0x00, 0x2e, 0x02, 0x00, 0x00, 0x26, 0x03, 0x03 } ++ @as([32]u8, @splat(1)) ++ [_]u8{ 0x00, 0xc0, 0x2f, 0x00 } ++ [_]u8{ 0x0e, 0x00, 0x00, 0x00 };
    const i = parseServerFlight(&sh);
    try testing.expectEqual(@as(?u16, 0x0303), i.server_version);
    try testing.expectEqual(@as(?u16, 0xc02f), i.cipher);
    try testing.expect(i.complete);
    const alert = [_]u8{ 0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x46 };
    try testing.expectEqual(@as(?u8, 0x46), parseServerFlight(&alert).alert);
    _ = parseServerFlight(sh[0..20]);
}

test "DNS version.bind round trip" {
    var q: [64]u8 = undefined;
    const tcpq = buildDnsVersionQuery(true, &q);
    try testing.expectEqual(@as(u16, @intCast(tcpq.len - 2)), std.mem.readInt(u16, tcpq[0..2], .big));
    // response: header(an=1) + question + answer (ptr, TXT, CH, ttl, rdlen, "9.18.24")
    const ver = "9.18.24";
    const resp = [_]u8{ 0x7a, 0x6d, 0x84, 0x00, 0, 1, 0, 1, 0, 0, 0, 0 } ++ "\x07version\x04bind\x00\x00\x10\x00\x03".* ++
        [_]u8{ 0xc0, 0x0c, 0x00, 0x10, 0x00, 0x03, 0, 0, 0, 0, 0, ver.len + 1, ver.len } ++ ver.*;
    const d = parseDnsResponse(&resp, false);
    try testing.expect(d.is_dns);
    try testing.expectEqualStrings(ver, d.version[0..d.version_len]);
    var wrong = resp;
    wrong[0] = 0;
    try testing.expect(!parseDnsResponse(&wrong, false).is_dns);
}

test "matchers and parsers never panic on arbitrary input" {
    var d: ParseDiag = .{};
    var db = try parse(testing.allocator, probe_file, &d);
    defer db.deinit();
    try std.testing.fuzz(&db, struct {
        fn one(dbp: *Db, smith: *std.testing.Smith) !void {
            var b: [512]u8 = undefined;
            const n = smith.valueRangeAtMost(u32, 0, b.len);
            smith.bytes(b[0..n]);
            _ = match(dbp, "NULL", b[0..n]);
            _ = match(dbp, "HTTPGet", b[0..n]);
            _ = parseServerFlight(b[0..n]);
            _ = parseDnsResponse(b[0..n], smith.value(bool));
            var pd: ParseDiag = .{};
            if (parse(testing.allocator, b[0..n], &pd)) |x| {
                var y = x;
                y.deinit();
            } else |_| {}
        }
    }.one, .{});
}
