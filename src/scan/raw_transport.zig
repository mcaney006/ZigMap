//! Linux raw-packet transport for SYN, UDP and host-discovery probes over
//! IPv4 and IPv6. NETLINK_ROUTE supplies routes, links and neighbours;
//! AF_PACKET captures (recvmsg reference path or TPACKET_V3 ring, with an
//! optional classic BPF filter) and transmits on Ethernet; raw IP sockets
//! transmit to loopback-routed targets.
//!
//! Kernel RST behaviour: our probes have no kernel socket behind them, so
//! when a target answers SYN/ACK the local kernel replies with RST. That
//! closes the half-open connection on the target; Zigmap never installs
//! firewall rules to suppress it.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const packet = @import("../packet.zig");
const engine = @import("../core/engine.zig");
const targets = @import("../core/targets.zig");
const raw = @import("raw.zig");
const service = @import("../fingerprint/service.zig");
const nlmsg = @import("../platform/netlink_msg.zig");
const bpf = @import("../platform/bpf.zig");
const Netlink = @import("../platform/linux/netlink.zig").Netlink;
const ps_mod = @import("../platform/linux/packet_socket.zig");
const PacketSocket = ps_mod.PacketSocket;

comptime {
    if (builtin.os.tag != .linux) @compileError("raw_transport is Linux-only");
}

const Addr = targets.Addr;

pub const SetupError = error{
    NoRoute,
    MixedInterfaces,
    InterfaceMismatch,
    UnsupportedLinkType,
    NoSourceAddress,
    LinkLocalNeedsZone,
    NetlinkFailed,
} || std.mem.Allocator.Error;

pub const Plan = struct {
    ifindex: i32,
    if_name: [16]u8,
    if_name_len: u8,
    hw_type: u16,
    src_mac: [6]u8,
    src4: ?[4]u8 = null,
    src6: ?[16]u8 = null,
    mtu: u32,
    /// Per target (same order as the input list).
    next_hop: []Addr,
    next_hop_mac: []?[6]u8,
    /// True when the next hop was resolved by our own ARP/NDP exchange,
    /// i.e. the host itself (on-link) answered: evidence it is up.
    answered_resolution: []bool,

    pub fn ifName(p: *const Plan) []const u8 {
        return p.if_name[0..p.if_name_len];
    }

    pub fn isLoopback(p: *const Plan) bool {
        return p.hw_type == nlmsg.ARPHRD_LOOPBACK;
    }

    pub fn deinit(p: *Plan, gpa: std.mem.Allocator) void {
        gpa.free(p.next_hop);
        gpa.free(p.next_hop_mac);
        gpa.free(p.answered_resolution);
    }
};

pub const Diagnostic = struct { msg: []const u8 = "", target: ?Addr = null };

fn addrSlice(a: *const Addr) []const u8 {
    return if (a.is_v6) &a.bytes else a.bytes[0..4];
}

/// Resolves route, interface, source address and next hop for every target.
/// All targets must leave through one interface (one capture socket).
pub fn plan(gpa: std.mem.Allocator, addrs: []const Addr, iface: ?[]const u8, diag: *Diagnostic) SetupError!Plan {
    var nl = Netlink.open() catch return error.NetlinkFailed;
    defer nl.close();
    const hops = try gpa.alloc(Addr, addrs.len);
    errdefer gpa.free(hops);
    const macs = try gpa.alloc(?[6]u8, addrs.len);
    errdefer gpa.free(macs);
    const answered = try gpa.alloc(bool, addrs.len);
    errdefer gpa.free(answered);
    @memset(answered, false);
    @memset(macs, null);

    var oif: ?u32 = null;
    var src4: ?[4]u8 = null;
    var src6: ?[16]u8 = null;
    for (addrs, 0..) |*a, i| {
        if (a.is_v6 and a.bytes[0] == 0xfe and a.bytes[1] & 0xc0 == 0x80) {
            diag.* = .{ .msg = "link-local IPv6 targets need an interface zone, which this build does not parse", .target = a.* };
            return error.LinkLocalNeedsZone;
        }
        const r = nl.routeGet(addrSlice(a)) catch |err| {
            diag.* = .{ .msg = "the kernel has no route to this target", .target = a.* };
            return if (err == error.NoRoute) error.NoRoute else error.NetlinkFailed;
        };
        const this_oif = r.oif orelse {
            diag.* = .{ .msg = "route has no output interface", .target = a.* };
            return error.NoRoute;
        };
        if (oif) |o| if (o != this_oif) {
            diag.* = .{ .msg = "targets route through different interfaces; scan them separately", .target = a.* };
            return error.MixedInterfaces;
        };
        oif = this_oif;
        if (r.prefsrc) |s| {
            if (a.is_v6) {
                if (src6 == null) src6 = s;
            } else if (src4 == null) src4 = s[0..4].*;
        }
        hops[i] = if (r.gateway) |g| (if (a.is_v6) Addr.v6(g) else Addr.v4(g[0..4].*)) else a.*;
    }
    const link = nl.linkGet(@intCast(oif.?)) catch return error.NetlinkFailed;
    if (iface) |want| if (!std.mem.eql(u8, want, link.nameSlice())) {
        diag.* = .{ .msg = "the kernel routes these targets through a different interface than -e names" };
        return error.InterfaceMismatch;
    };
    if (link.hw_type != nlmsg.ARPHRD_ETHER and link.hw_type != nlmsg.ARPHRD_LOOPBACK) {
        diag.* = .{ .msg = "egress interface is not Ethernet or loopback; raw scanning on this link type is not implemented" };
        return error.UnsupportedLinkType;
    }
    for (addrs) |a| {
        if ((a.is_v6 and src6 == null) or (!a.is_v6 and src4 == null)) {
            diag.* = .{ .msg = "the kernel reported no preferred source address for this family", .target = a };
            return error.NoSourceAddress;
        }
    }
    var p: Plan = .{
        .ifindex = link.index,
        .if_name = link.name,
        .if_name_len = link.name_len,
        .hw_type = link.hw_type,
        .src_mac = link.mac orelse @splat(0),
        .src4 = src4,
        .src6 = src6,
        .mtu = link.mtu orelse 1500,
        .next_hop = hops,
        .next_hop_mac = macs,
        .answered_resolution = answered,
    };
    if (p.isLoopback()) {
        @memset(p.next_hop_mac, @as(?[6]u8, @splat(0)));
    } else {
        for (hops, 0..) |*h, i| p.next_hop_mac[i] = nl.neighbor(link.index, addrSlice(h)) catch null;
    }
    return p;
}

fn solicitedNode(t: [16]u8) [16]u8 {
    var a: [16]u8 = .{ 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, 0, 0, 0 };
    @memcpy(a[13..16], t[13..16]);
    return a;
}

/// Neighbour Solicitation (RFC 4861) for `target`, as an Ethernet frame.
pub fn buildNeighborSolicitation(src_mac: [6]u8, src: [16]u8, target: [16]u8, out: []u8) !usize {
    const dst = solicitedNode(target);
    const mac: [6]u8 = .{ 0x33, 0x33, dst[12], dst[13], dst[14], dst[15] };
    var off = try packet.ethernet.encode(mac, src_mac, packet.ethernet.EtherType.ipv6, out);
    const body_len = 8 + 16 + 8;
    off += try packet.ipv6.encode(.{ .next_header = 58, .hop_limit = 255, .src = src, .dst = dst }, body_len, out[off..]);
    const m = out[off..][0..body_len];
    @memset(m, 0);
    m[0] = packet.icmp.V6Type.neighbor_solicitation;
    @memcpy(m[8..24], &target);
    m[24] = 1; // source link-layer address option
    m[25] = 1; // length in units of 8 bytes
    @memcpy(m[26..32], &src_mac);
    const pseudo = packet.checksum.pseudoV6(src, dst, 58, body_len);
    std.mem.writeInt(u16, m[2..4], packet.checksum.finish(packet.checksum.add(pseudo, m)), .big);
    return off + body_len;
}

/// Parses a Neighbour Advertisement body: (target, target link-layer address).
pub fn parseNeighborAdvertisement(body: []const u8) ?struct { target: [16]u8, mac: [6]u8 } {
    if (body.len < 16) return null;
    const target = body[0..16].*;
    var off: usize = 16;
    while (off + 8 <= body.len) {
        const t = body[off];
        const len = @as(usize, body[off + 1]) * 8;
        if (len == 0 or off + len > body.len) return null;
        if (t == 2 and len >= 8) return .{ .target = target, .mac = body[off + 2 ..][0..6].* };
        off += len;
    }
    return null;
}

/// Our own ARP / NDP for next hops the kernel had no entry for. Hosts that
/// answer are recorded as having answered (on-link liveness evidence).
pub fn resolveNeighbors(p: *Plan, sock: *PacketSocket, io: std.Io, tries: u32, wait_ms: i64) u32 {
    if (p.isLoopback()) return 0;
    const nowMs = struct {
        fn f(i: std.Io) i64 {
            return @intCast(@divTrunc(std.Io.Clock.awake.now(i).nanoseconds, std.time.ns_per_ms));
        }
    }.f;
    var buf: [4096]u8 = undefined;
    var attempt: u32 = 0;
    while (attempt < tries) : (attempt += 1) {
        var pending: u32 = 0;
        for (p.next_hop_mac, p.next_hop, 0..) |m, hop, i| {
            if (m != null) continue;
            const dup = for (p.next_hop[0..i], p.next_hop_mac[0..i]) |prev, pm| {
                if (pm == null and prev.eql(hop)) break true;
            } else false;
            if (dup) continue;
            pending += 1;
            var f: [128]u8 = undefined;
            if (hop.is_v6) {
                const n = buildNeighborSolicitation(p.src_mac, p.src6.?, hop.bytes, &f) catch continue;
                sock.send(f[0..n], f[0..6].*, packet.ethernet.EtherType.ipv6) catch {};
            } else {
                _ = packet.ethernet.encode(packet.ethernet.broadcast, p.src_mac, packet.ethernet.EtherType.arp, &f) catch unreachable;
                _ = packet.ethernet.encodeArp(.{ .op = packet.ethernet.ArpOp.request, .sender_mac = p.src_mac, .sender_ip = p.src4.?, .target_mac = @splat(0), .target_ip = hop.bytes4() }, f[14..]) catch unreachable;
                sock.send(f[0..42], packet.ethernet.broadcast, packet.ethernet.EtherType.arp) catch {};
            }
        }
        if (pending == 0) break;
        const deadline = nowMs(io) + wait_ms;
        while (nowMs(io) < deadline) {
            if (!sock.waitReadable(@intCast(@max(1, deadline - nowMs(io))))) continue;
            while (sock.recv(&buf)) |fr| {
                if (fr.outgoing) continue;
                const pk = packet.parser.parse(.ethernet, buf[0..fr.len]) catch continue;
                var who: ?Addr = null;
                var mac: [6]u8 = undefined;
                switch (pk.l4) {
                    .arp => |a| if (a.op == packet.ethernet.ArpOp.reply and p.src4 != null and std.mem.eql(u8, &a.target_ip, &p.src4.?)) {
                        who = Addr.v4(a.sender_ip);
                        mac = a.sender_mac;
                    },
                    .icmp => |m| if (pk.is_ipv6 and m.header.type == packet.icmp.V6Type.neighbor_advertisement and m.checksum == .good) {
                        if (parseNeighborAdvertisement(m.body)) |na| {
                            who = Addr.v6(na.target);
                            mac = na.mac;
                        }
                    },
                    else => {},
                }
                const w = who orelse continue;
                for (p.next_hop_mac, p.next_hop, p.answered_resolution) |*m, hop, *ans| {
                    if (m.* == null and hop.eql(w)) {
                        m.* = mac;
                        ans.* = true;
                    }
                }
            }
        }
    }
    var left: u32 = 0;
    for (p.next_hop_mac) |m| {
        if (m == null) left += 1;
    }
    return left;
}

// ------------------------------------------------------------ transport

pub const Mode = enum { syn, udp, discovery };

/// Discovery "ports": each engine port index is one probe type.
pub const DiscoveryProbe = enum(u16) { icmp_echo = 1, tcp_syn_443 = 2, tcp_ack_80 = 3 };
pub const discovery_ports = blk: {
    const probes = std.enums.values(DiscoveryProbe);
    var ports: [probes.len]u16 = undefined;
    for (probes, &ports) |p, *port| port.* = @backingInt(p);
    break :blk ports;
};

const ntp_client = [_]u8{0x23} ++ @as([47]u8, @splat(0));

/// Original, minimal UDP payloads that elicit replies from common services.
pub fn udpPayload(port: u16) []const u8 {
    return switch (port) {
        53 => service.dns_version_query,
        // NTP: version 4, mode 3 (client), otherwise zero
        123 => &ntp_client,
        else => "",
    };
}

pub const HostFacts = struct {
    synack: ?raw.ReplyFacts = null,
    rst: ?raw.ReplyFacts = null,
};

pub const RawTransport = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    mode: Mode,
    sock: PacketSocket,
    ring: ?ps_mod.Ring,
    l3_v4: ?ps_mod.RawIpSocket = null,
    l3_v6_tcp: ?ps_mod.RawIp6Socket = null,
    l3_v6_udp: ?ps_mod.RawIp6Socket = null,
    l3_v6_icmp: ?ps_mod.RawIp6Socket = null,
    corr: raw.Correlator,
    src_mac: [6]u8,
    macs: std.AutoHashMap(Addr, [6]u8),
    facts: std.AutoHashMap(Addr, HostFacts),
    ip_id: u16,
    rx: [65536]u8 = undefined,
    events: []engine.Event = &.{},
    n_events: usize = 0,
    /// Matched replies that did not fit in the engine's buffer. A ring block
    /// is drained whole, so one poll can match more replies than `events`
    /// holds; the rest are delivered on the next poll instead of dropped.
    backlog: [4096]engine.Event = undefined,
    n_backlog: usize = 0,

    pub const Options = struct {
        mode: Mode,
        slots: u32,
        base_port: u16,
        capture: ps_mod.CaptureMode = .ring,
        bpf_filter: bool = true,
    };

    pub fn init(gpa: std.mem.Allocator, io: std.Io, sock: PacketSocket, p: *const Plan, addrs: []const Addr, opts: Options) !RawTransport {
        var key: [16]u8 = undefined;
        io.random(&key);
        var id_seed: [2]u8 = undefined;
        io.random(&id_seed);
        var t: RawTransport = .{
            .gpa = gpa,
            .io = io,
            .mode = opts.mode,
            .sock = sock,
            .ring = null,
            .corr = try .init(gpa, key, p.src4, p.src6, opts.base_port, opts.slots),
            .src_mac = p.src_mac,
            .macs = .init(gpa),
            .facts = .init(gpa),
            .ip_id = std.mem.readInt(u16, &id_seed, .little),
        };
        errdefer t.deinit();
        for (addrs, p.next_hop_mac) |a, m| if (m) |mac| try t.macs.put(a, mac);
        if (opts.bpf_filter) {
            const prog = bpf.build(p.src4, p.src6);
            ps_mod.attachFilter(&t.sock, &prog) catch return error.FilterAttach;
        }
        if (opts.capture == .ring) t.ring = try ps_mod.enableRing(&t.sock, .{});
        if (p.isLoopback()) {
            if (p.src4 != null) t.l3_v4 = try ps_mod.RawIpSocket.open();
            if (p.src6 != null) {
                t.l3_v6_tcp = try ps_mod.RawIp6Socket.open(linux.IPPROTO.TCP);
                t.l3_v6_udp = try ps_mod.RawIp6Socket.open(linux.IPPROTO.UDP);
                t.l3_v6_icmp = try ps_mod.RawIp6Socket.open(linux.IPPROTO.ICMPV6);
            }
        }
        return t;
    }

    pub fn deinit(t: *RawTransport) void {
        t.macs.deinit();
        t.facts.deinit();
        t.corr.deinit(t.gpa);
        if (t.ring) |*r| ps_mod.unmapRing(r);
        t.sock.close();
        if (t.l3_v4) |*s| s.close();
        if (t.l3_v6_tcp) |*s| s.close();
        if (t.l3_v6_udp) |*s| s.close();
        if (t.l3_v6_icmp) |*s| s.close();
    }

    pub fn now(t: *RawTransport) u64 {
        return @intCast(std.Io.Clock.awake.now(t.io).nanoseconds);
    }

    fn src(t: *const RawTransport, v6: bool) Addr {
        return if (v6) Addr.v6(t.corr.src6.?) else Addr.v4(t.corr.src4.?);
    }

    pub fn send(t: *RawTransport, slot: u32, gen: u32, addr: Addr, port: u16) engine.SendOutcome {
        const mac = t.macs.get(addr) orelse return .{ .immediate = .host_unreach };
        var kind: raw.Kind = undefined;
        var dport: u16 = port;
        switch (t.mode) {
            .syn => kind = .tcp_syn,
            .udp => kind = .udp,
            .discovery => switch (@as(DiscoveryProbe, @fromBackingInt(@intCast(port)))) {
                .icmp_echo => {
                    kind = .icmp_echo;
                    dport = 0;
                },
                .tcp_syn_443 => {
                    kind = .tcp_syn;
                    dport = 443;
                },
                .tcp_ack_80 => {
                    kind = .tcp_ack;
                    dport = 80;
                },
            },
        }
        const tok = t.corr.arm(slot, gen, kind, addr, dport);
        t.ip_id +%= 1;
        const spec: raw.ProbeSpec = .{
            .kind = kind,
            .src = t.src(addr.is_v6),
            .dst = addr,
            .sport = t.corr.sport(slot),
            .dport = dport,
            .token = tok,
            // UDP binds the attempt into the IPv4 ID so ICMP quotes prove it.
            .ip_id = if (kind == .udp) @truncate(tok) else t.ip_id,
            .payload = if (kind == .udp) udpPayload(dport) else &.{},
        };
        var f: [1600]u8 = undefined;
        const l3 = t.l3_v4 != null or t.l3_v6_tcp != null;
        const n = raw.build(spec, if (l3) null else .{ .src_mac = t.src_mac, .dst_mac = mac }, &f) catch return .{ .immediate = .local_resource_exhausted };
        const result = if (!l3)
            t.sock.send(f[0..n], mac, if (addr.is_v6) packet.ethernet.EtherType.ipv6 else packet.ethernet.EtherType.ipv4)
        else if (!addr.is_v6)
            t.l3_v4.?.send(f[0..n], addr.bytes4())
        else switch (kind) {
            .tcp_syn, .tcp_ack => t.l3_v6_tcp.?.send(f[0..n], addr.bytes),
            .udp => t.l3_v6_udp.?.send(f[0..n], addr.bytes),
            .icmp_echo => t.l3_v6_icmp.?.send(f[0..n], addr.bytes),
        };
        result catch |err| {
            return switch (err) {
                error.WouldBlock => .deferred,
                error.SendFailed => .{ .immediate = .local_resource_exhausted },
            };
        };
        return .in_flight;
    }

    pub fn onFrame(t: *RawTransport, fr: ps_mod.FrameView) void {
        t.corr.stats.frames += 1;
        if (fr.outgoing) {
            t.corr.stats.outgoing_skipped += 1;
            return;
        }
        const pk = packet.parser.parse(.ethernet, fr.bytes) catch {
            t.corr.stats.parse_errors += 1;
            return;
        };
        const m = t.corr.match(&pk, fr.csum_not_ready) orelse return;
        if (t.mode == .syn and (m.reason == .syn_ack or m.reason == .rst)) {
            const s = t.corr.slots[m.slot];
            const gop = t.facts.getOrPut(s.dst) catch return;
            if (!gop.found_existing) gop.value_ptr.* = .{};
            if (m.reason == .syn_ack and gop.value_ptr.synack == null) gop.value_ptr.synack = t.corr.last_facts;
            if (m.reason == .rst and gop.value_ptr.rst == null) gop.value_ptr.rst = t.corr.last_facts;
        }
        const ev: engine.Event = .{ .slot = m.slot, .generation = m.gen, .reason = m.reason, .at_ns = t.now() };
        if (t.n_events < t.events.len) {
            t.events[t.n_events] = ev;
            t.n_events += 1;
        } else if (t.n_backlog < t.backlog.len) {
            t.backlog[t.n_backlog] = ev;
            t.n_backlog += 1;
        } else t.corr.stats.events_dropped += 1;
    }

    pub fn poll(t: *RawTransport, timeout_ns: u64, out: []engine.Event) usize {
        const ms = std.math.divCeil(u64, timeout_ns, std.time.ns_per_ms) catch unreachable;
        t.events = out;
        // Hand over replies left from the previous drain before reading more.
        t.n_events = @min(t.n_backlog, out.len);
        @memcpy(out[0..t.n_events], t.backlog[0..t.n_events]);
        std.mem.copyForwards(engine.Event, t.backlog[0 .. t.n_backlog - t.n_events], t.backlog[t.n_events..t.n_backlog]);
        t.n_backlog -= t.n_events;
        if (t.n_events == out.len) return t.n_events;
        const wait_ms: i32 = if (t.n_events > 0) 0 else @intCast(@min(ms, std.math.maxInt(i32)));
        if (!t.sock.waitReadable(wait_ms)) return t.n_events;
        // Bounded drain: a capture flood cannot starve the scheduler.
        _ = ps_mod.drain(&t.sock, if (t.ring) |*r| r else null, &t.rx, 4096, t);
        t.corr.stats.kernel_drops += t.sock.takeDrops();
        if (t.ring) |r| t.corr.stats.ring_losing_blocks = r.losing_seen;
        return t.n_events;
    }

    /// Replies captured but not yet handed to the engine.
    pub fn pending(t: *const RawTransport) usize {
        return t.n_backlog;
    }

    /// Nothing to release: the correlator slot stays "used" so late
    /// replies are still recognised as stale.
    pub fn cancel(_: *RawTransport, _: u32) void {}
};
