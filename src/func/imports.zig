const std = @import("std");

const Wat = @import("../wat.zig");
const Instance = @import("../instance.zig");

test "import" {
    var fbs = std.io.fixedBufferStream(
        \\(module
        \\  (type (;0;) (func (param i32) (result i32)))
        \\  (import "env" "thing" (func (type 0)))
        \\  (export "run" (func 0)))
    );
    var module = try Wat.parse(std.testing.allocator, fbs.reader());
    defer module.deinit();

    var instance = try module.instantiate(std.testing.allocator, struct {
        pub const env = struct {
            pub fn thing(arg: i32) i32 {
                return arg + 1;
            }
        };
    });
    defer instance.deinit();

    {
        const result = try instance.call("run", &[_]Instance.Value{.{ .I32 = 1 }});
        std.testing.expectEqual(@as(i32, 2), result.?.I32);
    }
    {
        const result = try instance.call("run", &[_]Instance.Value{.{ .I32 = 42 }});
        std.testing.expectEqual(@as(i32, 43), result.?.I32);
    }
}

test "import multiple" {
    var fbs = std.io.fixedBufferStream(
        \\(module
        \\  (type (;0;) (func (param i32) (param i32) (result i32)))
        \\  (import "env" "add" (func (type 0)))
        \\  (import "env" "mul" (func (type 0)))
        \\  (export "add" (func 0))
        \\  (export "mul" (func 1)))
    );
    var module = try Wat.parse(std.testing.allocator, fbs.reader());
    defer module.deinit();

    var instance = try module.instantiate(std.testing.allocator, struct {
        pub const env = struct {
            pub fn add(arg0: i32, arg1: i32) i32 {
                return arg0 + arg1;
            }

            pub fn mul(arg0: i32, arg1: i32) i32 {
                return arg0 * arg1;
            }
        };
    });
    defer instance.deinit();

    {
        const result = try instance.call("add", &[_]Instance.Value{ .{ .I32 = 2 }, .{ .I32 = 3 } });
        std.testing.expectEqual(@as(i32, 5), result.?.I32);
    }

    {
        const result = try instance.call("mul", &[_]Instance.Value{ .{ .I32 = 2 }, .{ .I32 = 3 } });
        std.testing.expectEqual(@as(i32, 6), result.?.I32);
    }
}
