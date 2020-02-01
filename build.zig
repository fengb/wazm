const std = @import("std");

pub fn build(b: *std.build.Builder) void {
    const mode = b.standardReleaseOptions();
    const exe = b.addExecutable("wasi", "src/wasi.zig");
    exe.setBuildMode(mode);
    exe.install();

    var all_tests = b.addTest("src/main.zig");
    all_tests.setBuildMode(mode);
    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&all_tests.step);

    addScript(b, "opcodes");
}

fn addScript(b: *std.build.Builder, name: []const u8) void {
    const filename = std.fmt.allocPrint(std.heap.page_allocator, "scripts/{}.zig", .{name}) catch unreachable;
    const mode = b.standardReleaseOptions();
    const exe = b.addExecutable(name, filename);
    exe.setBuildMode(mode);
    exe.addPackagePath("self", "src/main.zig");

    const run_cmd = exe.run();

    const run_step = b.step(name, filename);
    run_step.dependOn(&run_cmd.step);
}
