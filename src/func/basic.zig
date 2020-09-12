const std = @import("std");

const Wat = @import("../wat.zig");
const Instance = @import("../instance.zig");

test "i32 math" {
    var fbs = std.io.fixedBufferStream(
        \\(module
        \\  (func (result i32)
        \\    i32.const 40
        \\    i32.const 2
        \\    i32.add)
        \\  (func (result i32)
        \\    i32.const 40
        \\    i32.const 2
        \\    i32.sub)
        \\  (func (result i32)
        \\    i32.const 40
        \\    i32.const 2
        \\    i32.mul)
        \\  (func (result i32)
        \\    i32.const 40
        \\    i32.const 2
        \\    i32.div_s)
        \\  (export "add" (func 0))
        \\  (export "sub" (func 1))
        \\  (export "mul" (func 2))
        \\  (export "div" (func 3)))
    );
    var module = try Wat.parse(std.testing.allocator, fbs.reader());
    defer module.deinit();

    var instance = try module.instantiate(std.testing.allocator, struct {});
    defer instance.deinit();

    {
        const result = try instance.call("add", &[0]Instance.Value{});
        std.testing.expectEqual(@as(i32, 42), result.?.I32);
    }
    {
        const result = try instance.call("sub", &[0]Instance.Value{});
        std.testing.expectEqual(@as(i32, 38), result.?.I32);
    }
    {
        const result = try instance.call("mul", &[0]Instance.Value{});
        std.testing.expectEqual(@as(i32, 80), result.?.I32);
    }
    {
        const result = try instance.call("div", &[0]Instance.Value{});
        std.testing.expectEqual(@as(i32, 20), result.?.I32);
    }
}
