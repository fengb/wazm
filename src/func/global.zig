const std = @import("std");

const Wat = @import("../wat.zig");
const Instance = @import("../instance.zig");

test "get global" {
    var fbs = std.io.fixedBufferStream(
        \\(module
        \\  (global (;0;) i32 (i32.const 10))
        \\  (func (param i32) (result i32)
        \\    local.get 0
        \\	  global.get 0
        \\    i32.add)
        \\  (export "add" (func 0)))
    );
    var module = try Wat.parse(std.testing.allocator, fbs.reader());
    defer module.deinit();

    var instance = try module.instantiate(std.testing.allocator, null, struct {});
    defer instance.deinit();

    {
        const result = try instance.call("add", .{@as(i32, 1)});
        try std.testing.expectEqual(@as(i32, 11), result.?.I32);
    }
    {
        const result = try instance.call("add", .{@as(i32, 5)});
        try std.testing.expectEqual(@as(i32, 15), result.?.I32);
    }
}

test "set global" {
    var fbs = std.io.fixedBufferStream(
        \\(module
        \\  (global (;0;) i32 (i32.const 0))
        \\  (func (param i32)
        \\    local.get 0
        \\    global.set 0)
        \\  (export "get" (func 0)))
    );
    var module = try Wat.parse(std.testing.allocator, fbs.reader());
    defer module.deinit();

    var instance = try module.instantiate(std.testing.allocator, null, struct {});
    defer instance.deinit();

    {
        const result = try instance.call("get", .{@as(i32, 1)});
        try std.testing.expectEqual(Instance.Value{ .I32 = 1 }, instance.getGlobal(0));
    }

    {
        const result = try instance.call("get", .{@as(i32, 5)});
        try std.testing.expectEqual(Instance.Value{ .I32 = 5 }, instance.getGlobal(0));
    }
}
