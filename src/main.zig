const std = @import("std");

pub const Instance = @import("instance.zig");
pub const Module = @import("module.zig");
pub const Op = @import("op.zig");
pub const Wat = @import("wat.zig");
pub const Wasi = @import("wasi.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = &gpa.allocator;

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    const file = try std.fs.cwd().openFile(args[1], .{});
    defer file.close();

    var wasi = Wasi{ .argv = args[1..] };
    try wasi.run(&gpa.allocator, file.reader());
}

test "" {
    _ = Instance;
    _ = Module;
    _ = Op;
    _ = Wat;
    _ = Wasi;

    _ = main;
    _ = @import("func/basic.zig");
    _ = @import("func/imports.zig");
    _ = @import("func/logic.zig");
    _ = @import("func/global.zig");
}
