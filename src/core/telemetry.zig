//! Scan counters. Transmit, receive, correlation, and classification are
//! tracked separately.

pub const Stats = struct {
    probes_sent: u64 = 0,
    retransmissions: u64 = 0,
    replies_matched: u64 = 0,
    stale_replies: u64 = 0,
    /// Replies that matched a probe but proved nothing (e.g. self-connect).
    inconclusive_replies: u64 = 0,
    invalid_replies: u64 = 0,
    timeouts: u64 = 0,
    loss_events: u64 = 0,
    send_deferred: u64 = 0,
    local_errors: u64 = 0,
    probes_canceled: u64 = 0,
    ports_classified: u64 = 0,
    hosts_completed: u64 = 0,
    /// Hosts slowed after proving they rate-limit replies.
    paced_hosts: u64 = 0,
    max_in_flight: u32 = 0,
    wall_ns: u64 = 0,
};
