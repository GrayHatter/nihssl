const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});

    const optimize = b.standardOptimizeOption(.{});

    const lib = b.addStaticLibrary(.{
        .name = "zig-tls",
        .root_source_file = .{ .path = "src/root.zig" },
        .target = target,
        .optimize = optimize,
    });

    const nihssl = b.addModule("nihssl", .{
        .root_source_file = .{ .path = "src/root.zig" },
        .target = target,
        .optimize = optimize,
    });

    b.installArtifact(lib);

    const lib_unit_tests = b.addTest(.{
        .root_source_file = .{ .path = "src/root.zig" },
        .target = target,
        .optimize = optimize,
    });

    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_unit_tests.step);

    const probe = b.addExecutable(.{
        .name = "probe",
        .root_source_file = .{ .path = "utils/probe.zig" },
        .target = target,
        .optimize = optimize,
    });
    probe.root_module.addImport("nihssl", nihssl);
    const run_probe = b.addRunArtifact(probe);
    const probe_step = b.step("probe", "Probe hosts for supported suites");
    probe_step.dependOn(&run_probe.step);
}
