//! Congestion windows and transmit pacing.
//!
//! Window: TCP-style slow start / congestion avoidance (RFC 5681 concepts)
//! applied to *probes in flight*, kept per host and for the whole group.
//!
//! The key departure from TCP: a timeout is NOT a congestion signal, because
//! firewalls silently drop probes by design. Only *evidenced loss* shrinks a
//! window: a reply to retransmission N of a probe whose earlier
//! transmissions went unanswered proves something on the path dropped
//! packets. Silent filtered ports therefore never throttle a healthy scan.
//!
//! The window is fixed-point (1/1024 probe units) to keep it integral and
//! deterministic across platforms.

const std = @import("std");

pub const unit: u32 = 1024;

pub const WindowConfig = struct {
    initial: u32 = 4,
    min: u32 = 1,
    max: u32 = 256,
    initial_ssthresh: u32 = 64,
};

pub const Window = struct {
    cfg: WindowConfig,
    cwnd: u32, // fixed point
    ssthresh: u32, // whole probes
    in_flight: u32 = 0,
    loss_events: u32 = 0,

    pub fn init(cfg: WindowConfig) Window {
        return .{ .cfg = cfg, .cwnd = cfg.initial * unit, .ssthresh = cfg.initial_ssthresh };
    }

    pub fn size(w: *const Window) u32 {
        return @max(w.cfg.min, w.cwnd / unit);
    }

    pub fn available(w: *const Window) u32 {
        const s = w.size();
        return if (w.in_flight >= s) 0 else s - w.in_flight;
    }

    pub fn onSend(w: *Window) void {
        w.in_flight += 1;
    }

    /// Probe left flight (reply, timeout, or cancel) without changing cwnd.
    pub fn onRetire(w: *Window) void {
        std.debug.assert(w.in_flight > 0);
        w.in_flight -= 1;
    }

    /// A probe received a definitive reply.
    pub fn onReply(w: *Window) void {
        if (w.size() < w.ssthresh) {
            w.cwnd += unit; // slow start: +1 per reply
        } else {
            w.cwnd += @max(1, unit * unit / w.cwnd); // avoidance: +1 per window
        }
        w.cwnd = @min(w.cwnd, w.cfg.max * unit);
    }

    /// Evidenced loss: multiplicative decrease.
    pub fn onLoss(w: *Window) void {
        w.loss_events += 1;
        const half = @max(w.cfg.min, w.size() / 2);
        w.ssthresh = @max(2, half);
        w.cwnd = half * unit;
    }
};

/// Token bucket enforcing an upper bound on probe transmissions per second.
/// `rate == 0` disables pacing.
pub const RateLimiter = struct {
    rate_per_s: u32,
    burst: u32,
    tokens_milli: u64,
    last_ns: u64,

    pub fn init(rate_per_s: u32, now_ns: u64) RateLimiter {
        return initBurst(rate_per_s, @max(1, rate_per_s / 50), now_ns); // ~20 ms of traffic
    }

    pub fn initBurst(rate_per_s: u32, burst: u32, now_ns: u64) RateLimiter {
        return .{ .rate_per_s = rate_per_s, .burst = burst, .tokens_milli = @as(u64, burst) * 1000, .last_ns = now_ns };
    }

    /// Converts elapsed time to milli-tokens. `last_ns` advances only by the
    /// time actually converted, so frequent calls at a low rate (1 pps needs
    /// a full millisecond per milli-token) still accumulate.
    fn refill(r: *RateLimiter, now_ns: u64) void {
        if (now_ns <= r.last_ns) return;
        const cap = @as(u64, r.burst) * 1000;
        const add = (now_ns - r.last_ns) * r.rate_per_s / std.time.ns_per_ms; // milli-tokens
        if (r.tokens_milli + add >= cap) {
            r.tokens_milli = cap;
            r.last_ns = now_ns;
            return;
        }
        if (add == 0) return;
        r.tokens_milli += add;
        r.last_ns += add * std.time.ns_per_ms / r.rate_per_s;
    }

    pub fn tryTake(r: *RateLimiter, now_ns: u64) bool {
        if (r.rate_per_s == 0) return true;
        r.refill(now_ns);
        if (r.tokens_milli < 1000) return false;
        r.tokens_milli -= 1000;
        return true;
    }

    /// Nanoseconds until one token is available (0 if now).
    pub fn waitNs(r: *RateLimiter, now_ns: u64) u64 {
        if (r.rate_per_s == 0) return 0;
        r.refill(now_ns);
        if (r.tokens_milli >= 1000) return 0;
        const missing = 1000 - r.tokens_milli;
        return std.math.divCeil(u64, missing * std.time.ns_per_ms, r.rate_per_s) catch unreachable;
    }
};

const testing = std.testing;

test "slow start, avoidance, loss halving" {
    var w = Window.init(.{ .initial = 2, .initial_ssthresh = 8, .max = 100 });
    try testing.expectEqual(@as(u32, 2), w.size());
    for (0..6) |_| w.onReply();
    try testing.expectEqual(@as(u32, 8), w.size());
    for (0..9) |_| w.onReply(); // ~ +1 per window (increment shrinks as cwnd grows)
    try testing.expectEqual(@as(u32, 9), w.size());
    w.onLoss();
    try testing.expectEqual(@as(u32, 4), w.size());
    try testing.expectEqual(@as(u32, 4), w.ssthresh);
    for (0..10_000) |_| w.onReply();
    try testing.expectEqual(@as(u32, 100), w.size());
}

test "available respects in-flight" {
    var w = Window.init(.{ .initial = 3 });
    w.onSend();
    w.onSend();
    try testing.expectEqual(@as(u32, 1), w.available());
    w.onSend();
    try testing.expectEqual(@as(u32, 0), w.available());
    w.onRetire();
    try testing.expectEqual(@as(u32, 1), w.available());
}

test "token bucket enforces rate over a virtual second" {
    var r = RateLimiter.init(1000, 0);
    var sent: u32 = 0;
    var t: u64 = 0;
    while (t < std.time.ns_per_s) : (t += 100 * std.time.ns_per_us) {
        while (r.tryTake(t)) sent += 1;
    }
    // burst (20) + 1000/s * 0.9999s
    try testing.expect(sent >= 1000 and sent <= 1000 + r.burst);
    // Low rate, polled every 100 us: the fractions must add up.
    var slow = RateLimiter.initBurst(1, 1, 0);
    try testing.expect(slow.tryTake(0));
    t = 0;
    var got: u32 = 0;
    while (t <= 3 * std.time.ns_per_s) : (t += 100 * std.time.ns_per_us) {
        if (slow.tryTake(t)) got += 1;
    }
    try testing.expectEqual(@as(u32, 3), got);
    var r2 = RateLimiter.init(10, 0);
    while (r2.tryTake(0)) {}
    try testing.expectEqual(@as(u64, 100 * std.time.ns_per_ms), r2.waitNs(0));
}
