//! Compares the indexed timer heap against an O(N) deadline sweep under the
//! engine's access pattern: N outstanding probes, each "tick" a few replies
//! cancel timers, a few timers expire, and new probes are armed.
//! Run: zig build bench -Doptimize=ReleaseFast

const std = @import("std");
const zigmap = @import("zigmap");
const TimerHeap = zigmap.core.timer_heap.TimerHeap;

const Sweep = struct {
    deadlines: []u64,
    const empty = std.math.maxInt(u64);
    fn schedule(s: *Sweep, id: u32, d: u64) void {
        s.deadlines[id] = d;
    }
    fn cancel(s: *Sweep, id: u32) void {
        s.deadlines[id] = empty;
    }
    /// One full scan per tick to find expired entries and the next deadline.
    fn expire(s: *Sweep, now: u64, out: *u64) void {
        var next: u64 = empty;
        for (s.deadlines) |*d| {
            if (d.* <= now) {
                d.* = empty;
                out.* += 1;
            } else next = @min(next, d.*);
        }
        std.mem.doNotOptimizeAway(next);
    }
};

fn runHeap(gpa: std.mem.Allocator, n: u32, ticks: u32, seed: u64) !u64 {
    var h = try TimerHeap.init(gpa, n);
    defer h.deinit(gpa);
    var prng = std.Random.DefaultPrng.init(seed);
    const r = prng.random();
    var now: u64 = 0;
    for (0..n) |i| h.schedule(@intCast(i), r.uintLessThan(u64, 1_000_000));
    var expired: u64 = 0;
    for (0..ticks) |_| {
        now += 100;
        for (0..4) |_| h.cancel(r.uintLessThan(u32, n));
        while (h.popExpired(now)) |e| {
            expired += 1;
            h.schedule(e.id, now + r.uintLessThan(u64, 1_000_000));
        }
        for (0..4) |_| h.schedule(r.uintLessThan(u32, n), now + r.uintLessThan(u64, 1_000_000));
        if (h.peek()) |p| std.mem.doNotOptimizeAway(p.deadline);
    }
    return expired;
}

fn runSweep(gpa: std.mem.Allocator, n: u32, ticks: u32, seed: u64) !u64 {
    var s: Sweep = .{ .deadlines = try gpa.alloc(u64, n) };
    defer gpa.free(s.deadlines);
    var prng = std.Random.DefaultPrng.init(seed);
    const r = prng.random();
    var now: u64 = 0;
    for (0..n) |i| s.schedule(@intCast(i), r.uintLessThan(u64, 1_000_000));
    var expired: u64 = 0;
    for (0..ticks) |_| {
        now += 100;
        for (0..4) |_| s.cancel(r.uintLessThan(u32, n));
        var before = expired;
        s.expire(now, &expired);
        // re-arm the same number that expired (ids are not tracked, approximate)
        while (before < expired) : (before += 1) s.schedule(r.uintLessThan(u32, n), now + r.uintLessThan(u64, 1_000_000));
        for (0..4) |_| s.schedule(r.uintLessThan(u32, n), now + r.uintLessThan(u64, 1_000_000));
    }
    return expired;
}

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.gpa;
    var buf: [4096]u8 = undefined;
    var fw: std.Io.File.Writer = .init(.stdout(), io, &buf);
    const w = &fw.interface;
    const ticks: u32 = 20_000;
    try w.print("timer benchmark: {d} ticks, 4 cancels + 4 arms per tick (median of 5 runs)\n", .{ticks});
    try w.print("{s: >8}  {s: >14}  {s: >14}  {s: >8}\n", .{ "N", "heap ns/tick", "sweep ns/tick", "ratio" });
    for ([_]u32{ 64, 256, 1024, 4096, 16384 }) |n| {
        var heap_ns: [5]u64 = undefined;
        var sweep_ns: [5]u64 = undefined;
        for (0..5) |rep| {
            const t0 = std.Io.Clock.awake.now(io);
            std.mem.doNotOptimizeAway(try runHeap(gpa, n, ticks, rep));
            const t1 = std.Io.Clock.awake.now(io);
            std.mem.doNotOptimizeAway(try runSweep(gpa, n, ticks, rep));
            const t2 = std.Io.Clock.awake.now(io);
            heap_ns[rep] = @intCast(t0.durationTo(t1).nanoseconds);
            sweep_ns[rep] = @intCast(t1.durationTo(t2).nanoseconds);
        }
        std.mem.sort(u64, &heap_ns, {}, std.sort.asc(u64));
        std.mem.sort(u64, &sweep_ns, {}, std.sort.asc(u64));
        const h = heap_ns[2] / ticks;
        const s = sweep_ns[2] / ticks;
        try w.print("{d: >8}  {d: >14}  {d: >14}  {d: >7.1}x\n", .{ n, h, s, @as(f64, @floatFromInt(s)) / @as(f64, @floatFromInt(@max(h, 1))) });
    }
    try w.flush();
}
