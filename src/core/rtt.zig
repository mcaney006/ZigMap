//! Retransmission-timeout estimation following RFC 6298 (SRTT/RTTVAR/RTO)
//! with configurable clamps. Per-attempt backoff is applied by the engine
//! (`rto << (attempt - 1)`), so silence never inflates the estimator.
//!
//! Sampling rule (Karn): only feed samples whose send time is unambiguous.
//! Zigmap gives every retry its own socket (connect scan) or its own
//! generation nonce (raw scans), so a reply always identifies exactly one
//! transmission and retries may be sampled too.

const std = @import("std");

pub const Config = struct {
    initial_rto_ns: u64 = 1000 * std.time.ns_per_ms,
    min_rto_ns: u64 = 100 * std.time.ns_per_ms,
    max_rto_ns: u64 = 10 * std.time.ns_per_s,
    /// Clock granularity G from RFC 6298.
    granularity_ns: u64 = 1 * std.time.ns_per_ms,
};

pub const Estimator = struct {
    cfg: Config,
    srtt_ns: u64 = 0,
    rttvar_ns: u64 = 0,
    samples: u32 = 0,

    pub fn init(cfg: Config) Estimator {
        return .{ .cfg = cfg };
    }

    pub fn addSample(e: *Estimator, rtt_ns: u64) void {
        if (e.samples == 0) {
            e.srtt_ns = rtt_ns;
            e.rttvar_ns = rtt_ns / 2;
        } else {
            const diff = if (e.srtt_ns > rtt_ns) e.srtt_ns - rtt_ns else rtt_ns - e.srtt_ns;
            e.rttvar_ns = (3 * e.rttvar_ns + diff) / 4;
            e.srtt_ns = (7 * e.srtt_ns + rtt_ns) / 8;
        }
        e.samples +|= 1;
    }

    fn baseRto(e: *const Estimator) u64 {
        if (e.samples == 0) return e.cfg.initial_rto_ns;
        return e.srtt_ns + @max(e.cfg.granularity_ns, 4 * e.rttvar_ns);
    }

    pub fn rto(e: *const Estimator) u64 {
        return std.math.clamp(e.baseRto(), e.cfg.min_rto_ns, e.cfg.max_rto_ns);
    }
};

const testing = std.testing;
const ms = std.time.ns_per_ms;

test "first sample and steady state follow RFC 6298" {
    var e = Estimator.init(.{});
    try testing.expectEqual(@as(u64, 1000 * ms), e.rto());
    e.addSample(200 * ms);
    try testing.expectEqual(@as(u64, 200 * ms), e.srtt_ns);
    try testing.expectEqual(@as(u64, 100 * ms), e.rttvar_ns);
    try testing.expectEqual(@as(u64, 600 * ms), e.rto()); // 200 + 4*100
    for (0..50) |_| e.addSample(200 * ms);
    try testing.expect(e.rttvar_ns < 1 * ms);
    try testing.expectEqual(@as(u64, 201 * ms), e.rto()); // srtt + G (rttvar decayed)
}

test "jitter widens RTO; clamps apply" {
    var e = Estimator.init(.{});
    var i: usize = 0;
    while (i < 40) : (i += 1) e.addSample(if (i % 2 == 0) 50 * ms else 250 * ms);
    try testing.expect(e.rto() > 400 * ms);
    var tiny = Estimator.init(.{});
    tiny.addSample(1 * ms);
    for (0..20) |_| tiny.addSample(1 * ms);
    try testing.expectEqual(@as(u64, 100 * ms), tiny.rto()); // min clamp
}
