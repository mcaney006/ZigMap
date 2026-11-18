//! Wire-format codecs. Every decoder works on byte slices with explicit
//! bounds and big-endian reads; nothing casts untrusted memory to structs.

pub const checksum = @import("packet/checksum.zig");
pub const ethernet = @import("packet/ethernet.zig");
pub const ipv4 = @import("packet/ipv4.zig");
pub const ipv6 = @import("packet/ipv6.zig");
pub const tcp = @import("packet/tcp.zig");
pub const udp = @import("packet/udp.zig");
pub const icmp = @import("packet/icmp.zig");
pub const parser = @import("packet/parser.zig");

test {
    @import("std").testing.refAllDecls(@This());
}
