//! Probe slots and their explicit state machine.
//!
//!   free -> ready -> sent -> awaiting -> classified -> completed -> free
//!                    sent -> classified                (answer known at send time)
//!            ready -> retry_queued                     (send deferred by local pressure)
//!                    awaiting -> timed_out -> retry_queued -> ready
//!                              timed_out -> completed  (attempts exhausted)
//!                              classified -> retry_queued  (inconclusive)
//!   ready, awaiting, retry_queued -> canceled -> free
//!
//! A slot's `generation` increments every time it is (re)armed. Transports
//! echo the generation back with every reply, so a late reply to an older
//! attempt (or to a previous occupant of the slot) can never overwrite the
//! state of the current one.

const std = @import("std");

pub const State = enum(u8) {
    free,
    ready,
    sent,
    awaiting,
    classified,
    timed_out,
    retry_queued,
    completed,
    canceled,
};

pub fn canTransition(from: State, to: State) bool {
    return switch (from) {
        .free => to == .ready,
        .ready => to == .sent or to == .canceled or to == .retry_queued,
        .sent => to == .awaiting or to == .classified,
        .awaiting => to == .classified or to == .timed_out or to == .canceled,
        // An inconclusive classification may be retried.
        .classified => to == .completed or to == .retry_queued,
        .timed_out => to == .retry_queued or to == .completed,
        .retry_queued => to == .ready or to == .canceled,
        .completed, .canceled => to == .free,
    };
}

pub const none: u32 = std.math.maxInt(u32);

pub const Probe = struct {
    state: State = .free,
    host: u32 = 0,
    port_index: u32 = 0,
    port: u16 = 0,
    attempt: u8 = 0,
    /// Attempts that ended in a timeout; a later reply is then evidence of loss.
    timeouts: u8 = 0,
    generation: u32 = 0,
    sent_ns: u64 = 0,
    /// Intrusive link for the free list and per-host retry FIFOs.
    next: u32 = none,

    pub fn to(p: *Probe, s: State) void {
        if (!canTransition(p.state, s)) std.debug.panic("illegal probe transition {t} -> {t}", .{ p.state, s });
        p.state = s;
    }
};

/// Fixed-capacity pool; never allocates after init.
pub const Pool = struct {
    slots: []Probe,
    free_head: u32,

    pub fn init(gpa: std.mem.Allocator, capacity: u32) !Pool {
        const slots = try gpa.alloc(Probe, capacity);
        for (slots, 0..) |*s, i| s.* = .{ .next = if (i + 1 < capacity) @intCast(i + 1) else none };
        return .{ .slots = slots, .free_head = if (capacity > 0) 0 else none };
    }

    pub fn deinit(p: *Pool, gpa: std.mem.Allocator) void {
        gpa.free(p.slots);
        p.* = undefined;
    }

    pub fn acquire(p: *Pool) ?u32 {
        const id = p.free_head;
        if (id == none) return null;
        const s = &p.slots[id];
        p.free_head = s.next;
        const gen = s.generation;
        s.* = .{ .generation = gen };
        s.to(.ready);
        return id;
    }

    pub fn release(p: *Pool, id: u32) void {
        const s = &p.slots[id];
        s.to(.free);
        // Invalidate any reply still in flight for this occupant.
        s.generation +%= 1;
        s.next = p.free_head;
        p.free_head = id;
    }
};

/// Intrusive FIFO of slot ids threaded through `Probe.next`.
pub const Fifo = struct {
    head: u32 = none,
    tail: u32 = none,
    len: u32 = 0,

    pub fn push(f: *Fifo, slots: []Probe, id: u32) void {
        slots[id].next = none;
        if (f.tail == none) f.head = id else slots[f.tail].next = id;
        f.tail = id;
        f.len += 1;
    }

    pub fn pop(f: *Fifo, slots: []Probe) ?u32 {
        const id = f.head;
        if (id == none) return null;
        f.head = slots[id].next;
        if (f.head == none) f.tail = none;
        slots[id].next = none;
        f.len -= 1;
        return id;
    }
};

const testing = std.testing;

test "legal and illegal transitions" {
    try testing.expect(canTransition(.awaiting, .classified));
    try testing.expect(canTransition(.awaiting, .timed_out));
    try testing.expect(canTransition(.timed_out, .retry_queued));
    try testing.expect(!canTransition(.classified, .timed_out));
    try testing.expect(!canTransition(.completed, .awaiting));
    try testing.expect(!canTransition(.free, .awaiting));
    try testing.expect(!canTransition(.timed_out, .classified));
}

test "pool reuse bumps generation; fifo order" {
    var pool = try Pool.init(testing.allocator, 3);
    defer pool.deinit(testing.allocator);
    const a = pool.acquire().?;
    const gen0 = pool.slots[a].generation;
    pool.slots[a].to(.canceled);
    pool.release(a);
    const b = pool.acquire().?;
    try testing.expectEqual(a, b);
    try testing.expect(pool.slots[b].generation != gen0);
    _ = pool.acquire().?;
    _ = pool.acquire().?;
    try testing.expectEqual(@as(?u32, null), pool.acquire());

    var f: Fifo = .{};
    f.push(pool.slots, 2);
    f.push(pool.slots, 0);
    try testing.expectEqual(@as(?u32, 2), f.pop(pool.slots));
    try testing.expectEqual(@as(?u32, 0), f.pop(pool.slots));
    try testing.expectEqual(@as(?u32, null), f.pop(pool.slots));
}
