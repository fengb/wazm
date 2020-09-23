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
