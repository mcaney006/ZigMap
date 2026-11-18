const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const zigmap = b.addModule("zigmap", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const exe = b.addExecutable(.{
        .name = "zigmap",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "zigmap", .module = zigmap }},
        }),
    });
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    run_cmd.addPassthruArgs();
    b.step("run", "Run zigmap").dependOn(&run_cmd.step);

    const bench = b.addExecutable(.{
        .name = "timer_bench",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/timer_bench.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "zigmap", .module = zigmap }},
        }),
    });
    b.step("bench", "Run the timer-structure benchmark").dependOn(&b.addRunArtifact(bench).step);

    // Static release binaries for the supported targets, written to
    // zig-out/release/zigmap-<arch>-<os>. tests/release/reproducible.sh
    // builds them twice from empty caches and compares the hashes.
    const release = b.step("release", "Build ReleaseSafe binaries for every supported target");
    const release_targets = [_]std.Target.Query{
        .{ .cpu_arch = .x86_64, .os_tag = .linux },
        .{ .cpu_arch = .aarch64, .os_tag = .linux },
        .{ .cpu_arch = .x86_64, .os_tag = .macos },
        .{ .cpu_arch = .aarch64, .os_tag = .macos },
    };
    for (release_targets) |q| {
        const rt = b.resolveTargetQuery(q);
        const rel_lib = b.createModule(.{ .root_source_file = b.path("src/root.zig"), .target = rt, .optimize = .ReleaseSafe });
        const rel = b.addExecutable(.{
            .name = "zigmap",
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/main.zig"),
                .target = rt,
                .optimize = .ReleaseSafe,
                // Debug info records a per-build cache path, so it would make
                // otherwise identical builds differ.
                .strip = true,
                .imports = &.{.{ .name = "zigmap", .module = rel_lib }},
            }),
        });
        const install = b.addInstallArtifact(rel, .{
            .dest_dir = .{ .override = .{ .custom = "release" } },
            .dest_sub_path = b.fmt("zigmap-{t}-{t}", .{ q.cpu_arch.?, q.os_tag.? }),
        });
        release.dependOn(&install.step);
    }

    // Lab-only helpers (service fakes, listeners, UDP noise) for tests/lab
    // and tests/bench. Linux only; never part of the default install.
    const labtool_mod = b.createModule(.{
        .root_source_file = b.path("tests/lab/labtool.zig"),
        .target = target,
        .optimize = optimize,
    });
    const labtool = b.addExecutable(.{ .name = "labtool", .root_module = labtool_mod });
    b.step("lab-tools", "Build the Linux lab helper (labtool) into the install prefix").dependOn(&b.addInstallArtifact(labtool, .{}).step);

    const lib_tests = b.addTest(.{ .root_module = zigmap });
    const exe_tests = b.addTest(.{ .root_module = exe.root_module });
    const test_step = b.step("test", "Run unit, golden-vector and simulation tests");
    test_step.dependOn(&b.addRunArtifact(lib_tests).step);
    test_step.dependOn(&b.addRunArtifact(exe_tests).step);
    if (target.result.os.tag == .linux) {
        test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = labtool_mod })).step);
    }
}
