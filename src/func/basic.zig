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

    var instance = try module.instantiate(std.testing.allocator, null, struct {});
    defer instance.deinit();

    {
        const result = try instance.call("add", .{});
        std.testing.expectEqual(@as(i32, 42), result.?.I32);
    }
    {
        const result = try instance.call("sub", .{});
        std.testing.expectEqual(@as(i32, 38), result.?.I32);
    }
    {
        const result = try instance.call("mul", .{});
        std.testing.expectEqual(@as(i32, 80), result.?.I32);
    }
    {
        const result = try instance.call("div", .{});
        std.testing.expectEqual(@as(i32, 20), result.?.I32);
    }
}

test "i64 math" {
    var fbs = std.io.fixedBufferStream(
        \\(module
        \\  (func (result i64)
        \\    i64.const 40
        \\    i64.const 2
        \\    i64.add)
        \\  (func (result i64)
        \\    i64.const 40
        \\    i64.const 2
        \\    i64.sub)
        \\  (func (result i64)
        \\    i64.const 40
        \\    i64.const 2
        \\    i64.mul)
        \\  (func (result i64)
        \\    i64.const 40
        \\    i64.const 2
        \\    i64.div_s)
        \\  (export "add" (func 0))
        \\  (export "sub" (func 1))
        \\  (export "mul" (func 2))
        \\  (export "div" (func 3)))
    );
    var module = try Wat.parse(std.testing.allocator, fbs.reader());
    defer module.deinit();

    var instance = try module.instantiate(std.testing.allocator, null, struct {});
    defer instance.deinit();

    {
        const result = try instance.call("add", .{});
        std.testing.expectEqual(@as(i64, 42), result.?.I64);
    }
    {
        const result = try instance.call("sub", .{});
        std.testing.expectEqual(@as(i64, 38), result.?.I64);
    }
    {
        const result = try instance.call("mul", .{});
        std.testing.expectEqual(@as(i64, 80), result.?.I64);
    }
    {
        const result = try instance.call("div", .{});
        std.testing.expectEqual(@as(i64, 20), result.?.I64);
    }
}

test "f32 math" {
    var fbs = std.io.fixedBufferStream(
        \\(module
        \\  (func (result f32)
        \\    f32.const 40
        \\    f32.const 2
        \\    f32.add)
        \\  (func (result f32)
        \\    f32.const 40
        \\    f32.const 2
        \\    f32.sub)
        \\  (func (result f32)
        \\    f32.const 40
        \\    f32.const 2
        \\    f32.mul)
        \\  (func (result f32)
        \\    f32.const 40
        \\    f32.const 2
        \\    f32.div)
        \\  (export "add" (func 0))
        \\  (export "sub" (func 1))
        \\  (export "mul" (func 2))
        \\  (export "div" (func 3)))
    );
    var module = try Wat.parse(std.testing.allocator, fbs.reader());
    defer module.deinit();

    var instance = try module.instantiate(std.testing.allocator, null, struct {});
    defer instance.deinit();

    {
        const result = try instance.call("add", .{});
        std.testing.expectEqual(@as(f32, 42), result.?.F32);
    }
    {
        const result = try instance.call("sub", .{});
        std.testing.expectEqual(@as(f32, 38), result.?.F32);
    }
    {
        const result = try instance.call("mul", .{});
        std.testing.expectEqual(@as(f32, 80), result.?.F32);
    }
    {
        const result = try instance.call("div", .{});
        std.testing.expectEqual(@as(f32, 20), result.?.F32);
    }
}

test "f64 math" {
    var fbs = std.io.fixedBufferStream(
        \\(module
        \\  (func (result f64)
        \\    f64.const 1
        \\    f64.const 2
        \\    f64.add)
        \\  (func (result f64)
        \\    f64.const 1
        \\    f64.const 2
        \\    f64.sub)
        \\  (func (result f64)
        \\    f64.const 1
        \\    f64.const 2
        \\    f64.mul)
        \\  (func (result f64)
        \\    f64.const 1
        \\    f64.const 2
        \\    f64.div)
        \\  (export "add" (func 0))
        \\  (export "sub" (func 1))
        \\  (export "mul" (func 2))
        \\  (export "div" (func 3)))
    );
    var module = try Wat.parse(std.testing.allocator, fbs.reader());
    defer module.deinit();

    var instance = try module.instantiate(std.testing.allocator, null, struct {});
    defer instance.deinit();

    {
        const result = try instance.call("add", .{});
        std.testing.expectEqual(@as(f64, 3), result.?.F64);
    }
    {
        const result = try instance.call("sub", .{});
        std.testing.expectEqual(@as(f64, -1), result.?.F64);
    }
    {
        const result = try instance.call("mul", .{});
        std.testing.expectEqual(@as(f64, 2), result.?.F64);
    }
    {
        const result = try instance.call("div", .{});
        std.testing.expectEqual(@as(f64, 0.5), result.?.F64);
    }
}

test "call with args" {
    var fbs = std.io.fixedBufferStream(
        \\(module
        \\  (func (param i32) (param i32) (result i32)
        \\    local.get 0
        \\    local.get 1
        \\    i32.add)
        \\  (func (param i32) (param i32) (result i32) (local i32) (local i64) (local f64)
        \\    local.get 0
        \\    local.get 1
        \\    i32.add)
        \\  (export "add" (func 0))
        \\  (export "addtemp" (func 1)))
    );
    var module = try Wat.parse(std.testing.allocator, fbs.reader());
    defer module.deinit();

    var instance = try module.instantiate(std.testing.allocator, null, struct {});
    defer instance.deinit();

    std.testing.expectError(error.TypeSignatureMismatch, instance.call("add", &[0]Instance.Value{}));

    {
        const result = try instance.call("add", .{ @as(i32, 16), @as(i32, 8) });
        std.testing.expectEqual(@as(i32, 24), result.?.I32);
    }

    {
        const result = try instance.call("addtemp", .{ @as(i32, 16), @as(i32, 8) });
        std.testing.expectEqual(@as(i32, 24), result.?.I32);
    }
}

test "call call call" {
    var fbs = std.io.fixedBufferStream(
        \\(module
        \\  (func (param i32) (param i32) (result i32)
        \\    local.get 0
        \\    local.get 1
        \\    i32.add)
        \\  (func (param i32) (param i32) (result i32)
        \\    local.get 0
        \\    local.get 1
        \\    call 0
        \\    i32.const 2
        \\    i32.mul)
        \\  (export "addDouble" (func 1)))
    );
    var module = try Wat.parse(std.testing.allocator, fbs.reader());
    defer module.deinit();

    var instance = try module.instantiate(std.testing.allocator, null, struct {});
    defer instance.deinit();

    {
        const result = try instance.call("addDouble", .{ @as(i32, 16), @as(i32, 8) });
        std.testing.expectEqual(@as(i32, 48), result.?.I32);
    }
}
