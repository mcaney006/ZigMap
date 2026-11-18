//! Indexed binary min-heap of probe deadlines.
//!
//! Why a heap and not a timing wheel: outstanding probes are bounded by the
//! group congestion window (hundreds to low thousands), deadlines are
//! RTO-derived and highly non-uniform (100 ms .. 10 s), and the engine needs
//! the exact earliest deadline to size its poll timeout. A heap gives exact
//! ordering with O(log n) insert/update/cancel and O(1) peek, with zero
//! allocation after init.
//!
//! Measured (`zig build bench -Doptimize=ReleaseFast`, Apple M-series): an
//! O(N) sweep is faster at N=64 (0.3x) and equal at N=256, the default
//! parallelism; the heap is 4.9x faster at 1024 and 39x at 16384. The heap
//! is kept because cost must stay flat when parallelism is raised.
//!
//! Ties are broken by insertion sequence so expiry order is deterministic.

const std = @import("std");

pub const none: u32 = std.math.maxInt(u32);

pub const Entry = struct {
    deadline: u64,
    seq: u64,
    id: u32,

    fn less(a: Entry, b: Entry) bool {
        return a.deadline < b.deadline or (a.deadline == b.deadline and a.seq < b.seq);
    }
};

pub const TimerHeap = struct {
    entries: []Entry,
    /// pos[id] = index into entries, or `none`.
    pos: []u32,
    len: u32 = 0,
    next_seq: u64 = 0,

    pub fn init(gpa: std.mem.Allocator, capacity: u32) !TimerHeap {
        const entries = try gpa.alloc(Entry, capacity);
        errdefer gpa.free(entries);
        const pos = try gpa.alloc(u32, capacity);
        @memset(pos, none);
        return .{ .entries = entries, .pos = pos };
    }

    pub fn deinit(h: *TimerHeap, gpa: std.mem.Allocator) void {
        gpa.free(h.entries);
        gpa.free(h.pos);
        h.* = undefined;
    }

    pub fn contains(h: *const TimerHeap, id: u32) bool {
        return h.pos[id] != none;
    }

    /// Inserts or moves `id` to `deadline`.
    pub fn schedule(h: *TimerHeap, id: u32, deadline: u64) void {
        const e: Entry = .{ .deadline = deadline, .seq = h.next_seq, .id = id };
        h.next_seq += 1;
        const p = h.pos[id];
        if (p != none) {
            const old = h.entries[p];
            h.entries[p] = e;
            if (Entry.less(e, old)) h.siftUp(p) else h.siftDown(p);
            return;
        }
        std.debug.assert(h.len < h.entries.len);
        h.entries[h.len] = e;
        h.pos[id] = h.len;
        h.len += 1;
        h.siftUp(h.len - 1);
    }

    pub fn cancel(h: *TimerHeap, id: u32) void {
        const p = h.pos[id];
        if (p == none) return;
        h.removeAt(p);
    }

    pub fn peek(h: *const TimerHeap) ?Entry {
        return if (h.len == 0) null else h.entries[0];
    }

    /// Pops the earliest entry if its deadline is <= now.
    pub fn popExpired(h: *TimerHeap, now: u64) ?Entry {
        if (h.len == 0 or h.entries[0].deadline > now) return null;
        const e = h.entries[0];
        h.removeAt(0);
        return e;
    }

    fn removeAt(h: *TimerHeap, p: u32) void {
        const removed = h.entries[p];
        h.pos[removed.id] = none;
        h.len -= 1;
        if (p == h.len) return;
        h.entries[p] = h.entries[h.len];
        h.pos[h.entries[p].id] = p;
        if (p > 0 and Entry.less(h.entries[p], h.entries[(p - 1) / 2])) h.siftUp(p) else h.siftDown(p);
    }

    fn swap(h: *TimerHeap, a: u32, b: u32) void {
        std.mem.swap(Entry, &h.entries[a], &h.entries[b]);
        h.pos[h.entries[a].id] = a;
        h.pos[h.entries[b].id] = b;
    }

    fn siftUp(h: *TimerHeap, start: u32) void {
        var i = start;
        while (i > 0) {
            const parent = (i - 1) / 2;
            if (!Entry.less(h.entries[i], h.entries[parent])) break;
            h.swap(i, parent);
            i = parent;
        }
    }

    fn siftDown(h: *TimerHeap, start: u32) void {
        var i = start;
        while (true) {
            const l = 2 * i + 1;
            if (l >= h.len) break;
            var m = l;
            if (l + 1 < h.len and Entry.less(h.entries[l + 1], h.entries[l])) m = l + 1;
            if (!Entry.less(h.entries[m], h.entries[i])) break;
            h.swap(i, m);
            i = m;
        }
    }
};

const testing = std.testing;

test "expiry order, ties by insertion, updates and cancels" {
    var h = try TimerHeap.init(testing.allocator, 16);
    defer h.deinit(testing.allocator);
    h.schedule(3, 300);
    h.schedule(1, 100);
    h.schedule(2, 100); // tie with 1, inserted later
    h.schedule(4, 50);
    h.schedule(4, 400); // move later
    h.schedule(5, 10);
    h.cancel(5);
    try testing.expect(!h.contains(5));
    try testing.expectEqual(@as(?u32, null), if (h.popExpired(99)) |e| e.id else null);
    const want = [_]u32{ 1, 2, 3, 4 };
    for (want) |id| try testing.expectEqual(id, h.popExpired(1000).?.id);
    try testing.expectEqual(@as(?Entry, null), h.peek());
}

test "randomized against reference model" {
    const gpa = testing.allocator;
    var h = try TimerHeap.init(gpa, 256);
    defer h.deinit(gpa);
    var model: [256]?u64 = @splat(null);
    var prng = std.Random.DefaultPrng.init(0x5eed);
    const r = prng.random();
    var now: u64 = 0;
    for (0..20_000) |_| {
        const id = r.uintLessThan(u32, 256);
        switch (r.uintLessThan(u8, 4)) {
            0, 1 => {
                const d = now + r.uintLessThan(u64, 1000);
                h.schedule(id, d);
                model[id] = d;
            },
            2 => {
                h.cancel(id);
                model[id] = null;
            },
            else => {
                now += r.uintLessThan(u64, 50);
                while (h.popExpired(now)) |e| {
                    try testing.expect(model[e.id] != null);
                    try testing.expectEqual(model[e.id].?, e.deadline);
                    try testing.expect(e.deadline <= now);
                    model[e.id] = null;
                }
                for (model) |m| if (m) |d| try testing.expect(d > now);
            },
        }
    }
}
