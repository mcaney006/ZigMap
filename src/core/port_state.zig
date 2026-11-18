//! Port classifications, the evidence behind them, and compact per-port
//! result records. Results are hot-path data (one per host×port), so they
//! are kept small and fixed-size; evidence history is a bounded ring.

const std = @import("std");

pub const PortState = enum(u8) {
    /// Not classified (scan canceled or host timed out first).
    unknown,
    open,
    closed,
    filtered,
    unfiltered,
    open_filtered,
    closed_filtered,

    pub fn label(s: PortState) []const u8 {
        return switch (s) {
            .unknown => "unknown",
            .open => "open",
            .closed => "closed",
            .filtered => "filtered",
            .unfiltered => "unfiltered",
            .open_filtered => "open|filtered",
            .closed_filtered => "closed|filtered",
        };
    }
};

/// Why a probe concluded the way it did. Values describe observed evidence,
/// not inference.
pub const Reason = enum(u8) {
    none,
    /// connect() completed: the three-way handshake succeeded.
    connected,
    /// connect() failed with ECONNREFUSED: the target (or a device
    /// impersonating it) answered with RST.
    conn_refused,
    /// No reply to any attempt within the retransmission timeouts.
    no_response,
    /// The local kernel reported an ICMP-derived or routing failure.
    host_unreach,
    net_unreach,
    /// Local policy refused the operation (EACCES/EPERM), e.g. a local firewall.
    local_policy_denied,
    /// connect() reported ETIMEDOUT from the kernel's own SYN retries.
    kernel_timeout,
    host_timeout,
    canceled,
    /// Local resource exhaustion persisted with nothing in flight.
    local_resource_exhausted,
    /// Raw SYN scan: SYN/ACK answered the probe (ack == ISN + 1).
    syn_ack,
    /// Raw SYN scan: RST/ACK answered the probe (ack == ISN + 1).
    rst,
    /// ICMP destination unreachable quoting the probe, by code family.
    icmp_net_unreach,
    icmp_host_unreach,
    icmp_proto_unreach,
    icmp_port_unreach,
    icmp_admin_prohibited,
    icmp_unreach_other,
    /// Raw UDP scan: a UDP datagram came back from the probed port.
    udp_reply,
    /// Discovery: ICMP echo reply carrying our token.
    echo_reply,
    /// Discovery: ARP (IPv4) or NDP (IPv6) answered for the address.
    arp_reply,
    nd_reply,
    /// Discovery: the target is one of this host's own addresses (loopback route).
    local_host,
    /// Discovery: an on-link address did not answer ARP/NDP.
    no_neighbor_reply,
    /// connect() "succeeded" because the kernel chose a source port equal to
    /// the target port on the same address (TCP simultaneous open with
    /// itself). Not evidence of a listener; the probe is retried.
    self_connect,

    pub fn label(r: Reason) []const u8 {
        return @tagName(r);
    }
};

pub const EvidenceKind = enum(u8) {
    sent,
    reply,
    timeout,
    stale_reply,
    deferred,
};

pub const Evidence = struct {
    kind: EvidenceKind,
    reason: Reason,
    attempt: u8,
    /// Microseconds since scan start (u32 covers ~71 minutes; saturates).
    t_us: u32,
};

pub const evidence_slots = 6;

pub const PortResult = struct {
    state: PortState = .unknown,
    reason: Reason = .none,
    attempts: u8 = 0,
    /// Round trip of the deciding reply, microseconds (0 when none).
    rtt_us: u32 = 0,
    evidence: [evidence_slots]Evidence = undefined,
    /// Total evidence recorded; ring keeps the last `evidence_slots`.
    evidence_total: u16 = 0,

    pub fn record(r: *PortResult, e: Evidence) void {
        r.evidence[r.evidence_total % evidence_slots] = e;
        r.evidence_total +|= 1;
    }

    /// Oldest-to-newest view of the retained evidence.
    pub fn evidenceIter(r: *const PortResult) EvidenceIterator {
        const n: u16 = @min(r.evidence_total, evidence_slots);
        return .{ .r = r, .i = 0, .n = n, .start = if (r.evidence_total > evidence_slots) r.evidence_total % evidence_slots else 0 };
    }

    pub fn evidenceDropped(r: *const PortResult) u16 {
        return r.evidence_total -| evidence_slots;
    }
};

pub const EvidenceIterator = struct {
    r: *const PortResult,
    i: u16,
    n: u16,
    start: u16,

    pub fn next(it: *EvidenceIterator) ?Evidence {
        if (it.i >= it.n) return null;
        const e = it.r.evidence[(it.start + it.i) % evidence_slots];
        it.i += 1;
        return e;
    }
};

test "evidence ring keeps newest entries in order" {
    var r: PortResult = .{};
    for (0..9) |k| r.record(.{ .kind = .sent, .reason = .none, .attempt = @intCast(k), .t_us = @intCast(k) });
    var it = r.evidenceIter();
    var expect: u8 = 3;
    while (it.next()) |e| : (expect += 1) try std.testing.expectEqual(expect, e.attempt);
    try std.testing.expectEqual(@as(u8, 9), expect);
    try std.testing.expectEqual(@as(u16, 3), r.evidenceDropped());
}
