const std = @import("std");

const Wat = @import("../wat.zig");
const Instance = @import("../instance.zig");

test "if/else" {
    var fbs = std.io.fixedBufferStream(
        \\(module
        \\  (func (param i32) (result i32)
        \\    local.get 0
        \\    if (result i32)
        \\      i32.const 1
        \\    else
        \\      i32.const 42
        \\    end)
        \\  (export "if" (func 0)))
    );
    var module = try Wat.parse(std.testing.allocator, fbs.reader());
    defer module.deinit();

    var instance = try module.instantiate(std.testing.allocator, null, struct {});
    defer instance.deinit();

    {
        const result = try instance.call("if", .{@as(i32, 1)});
        try std.testing.expectEqual(@as(i32, 1), result.?.I32);
    }
    {
        const result = try instance.call("if", .{@as(i32, 0)});
        try std.testing.expectEqual(@as(i32, 42), result.?.I32);
    }
}

test "select" {
    var fbs = std.io.fixedBufferStream(
        \\(module
        \\  (func (param i32) (result i32)
        \\    i32.const 1
        \\    i32.const 42
        \\    local.get 0
        \\    select)
        \\  (export "if" (func 0)))
    );
    var module = try Wat.parse(std.testing.allocator, fbs.reader());
    defer module.deinit();

    var instance = try module.instantiate(std.testing.allocator, null, struct {});
    defer instance.deinit();

    {
        const result = try instance.call("if", .{@as(i32, 1)});
        try std.testing.expectEqual(@as(i32, 1), result.?.I32);
    }
    {
        const result = try instance.call("if", .{@as(i32, 0)});
        try std.testing.expectEqual(@as(i32, 42), result.?.I32);
    }
}
