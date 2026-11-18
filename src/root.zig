//! Zigmap library API. The CLI in main.zig is one consumer; everything here
//! is usable without it.

const builtin = @import("builtin");

pub const packet = @import("packet.zig");
pub const core = @import("core.zig");
pub const platform = struct {
    pub const sys = @import("platform/sys.zig");
    pub const netlink_msg = @import("platform/netlink_msg.zig");
    pub const bpf = @import("platform/bpf.zig");
    pub const linux = if (builtin.os.tag == .linux) struct {
        pub const netlink = @import("platform/linux/netlink.zig");
        pub const packet_socket = @import("platform/linux/packet_socket.zig");
    } else struct {};
};
pub const scan = struct {
    pub const classify = @import("scan/classify.zig");
    pub const connect = @import("scan/connect.zig");
    pub const raw = @import("scan/raw.zig");
    pub const service_scan = @import("scan/service_scan.zig");
    pub const raw_transport = if (builtin.os.tag == .linux) @import("scan/raw_transport.zig") else struct {};
};
pub const fingerprint = struct {
    pub const service = @import("fingerprint/service.zig");
    pub const os = @import("fingerprint/os.zig");
};
pub const output = struct {
    pub const report = @import("output/report.zig");
};
pub const cli = struct {
    pub const args = @import("cli/args.zig");
};

test {
    const std = @import("std");
    std.testing.refAllDecls(@This());
    std.testing.refAllDecls(platform);
    std.testing.refAllDecls(platform.linux);
    std.testing.refAllDecls(scan);
    std.testing.refAllDecls(fingerprint);
    std.testing.refAllDecls(output);
    std.testing.refAllDecls(cli);
    _ = @import("testing/packet_vectors.zig");
    _ = @import("testing/synthetic_network.zig");
}
