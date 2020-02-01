const Builder = @import("std").build.Builder;

pub fn build(b: *Builder) void {
    const mode = b.standardReleaseOptions();
    const exe = b.addExecutable("wasi", "src/wasi.zig");
    exe.setBuildMode(mode);
    exe.install();

    var all_tests = b.addTest("src/main.zig");
    all_tests.setBuildMode(mode);
    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&all_tests.step);
}
