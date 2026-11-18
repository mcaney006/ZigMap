//! Per-method interpretation of transport reasons.

const ps = @import("../core/port_state.zig");
const Classification = @import("../core/engine.zig").Classification;

/// TCP connect(): the kernel performs the handshake, so success proves the
/// port accepted a connection and ECONNREFUSED proves an RST came back.
/// Unreachability reported by the kernel means something on the path
/// answered for the target: filtered, never closed.
pub fn connect(r: ps.Reason) Classification {
    return switch (r) {
        .connected => .{ .state = .open, .definitive = true },
        .conn_refused => .{ .state = .closed, .definitive = true },
        .host_unreach, .net_unreach, .local_policy_denied, .kernel_timeout => .{ .state = .filtered, .definitive = true },
        .self_connect => .{ .state = .unknown, .definitive = false },
        else => .{ .state = .unknown, .definitive = false },
    };
}

/// Raw TCP SYN scan. A SYN/ACK proves a listener; an RST proves the port is
/// reachable and closed. ICMP unreachables quoting our probe mean something
/// on the path refused it: filtered.
pub fn syn(r: ps.Reason) Classification {
    return switch (r) {
        .syn_ack => .{ .state = .open, .definitive = true },
        .rst => .{ .state = .closed, .definitive = true },
        .host_unreach, .icmp_net_unreach, .icmp_host_unreach, .icmp_proto_unreach, .icmp_port_unreach, .icmp_admin_prohibited, .icmp_unreach_other => .{ .state = .filtered, .definitive = true },
        else => .{ .state = .unknown, .definitive = false },
    };
}

/// Raw UDP scan. Any UDP reply from the port proves it open. ICMP port
/// unreachable is the target's own "closed"; other unreachables are
/// filtering. Silence is open|filtered (set as the engine's silent state),
/// never open: many UDP services ignore unexpected payloads.
pub fn udp(r: ps.Reason) Classification {
    return switch (r) {
        .udp_reply => .{ .state = .open, .definitive = true },
        .icmp_port_unreach => .{ .state = .closed, .definitive = true },
        .host_unreach, .icmp_net_unreach, .icmp_host_unreach, .icmp_proto_unreach, .icmp_admin_prohibited, .icmp_unreach_other => .{ .state = .filtered, .definitive = true },
        else => .{ .state = .unknown, .definitive = false },
    };
}

/// Host discovery probes: any reply at all proves the host is up. "open"
/// here means "this discovery probe was answered".
pub fn discovery(r: ps.Reason) Classification {
    return switch (r) {
        .echo_reply, .syn_ack, .rst, .arp_reply, .nd_reply, .connected, .conn_refused => .{ .state = .open, .definitive = true },
        .icmp_port_unreach, .icmp_proto_unreach => .{ .state = .open, .definitive = true }, // the host itself answered
        .host_unreach, .net_unreach, .icmp_net_unreach, .icmp_host_unreach, .icmp_admin_prohibited, .icmp_unreach_other => .{ .state = .filtered, .definitive = true },
        else => .{ .state = .unknown, .definitive = false },
    };
}
