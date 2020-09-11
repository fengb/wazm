const std = @import("std");

const Wat = @import("../wat.zig");
const Instance = @import("../instance.zig");

test "stuff" {
    var fbs = std.io.fixedBufferStream(
        \\(module
        \\  (func (result i32)
        \\    i32.const 1
        \\    i32.const 42
        \\    i32.add)
        \\  (export "make it so" (func 0)))
    );
    var module = try Wat.parse(std.testing.allocator, fbs.reader());
    defer module.deinit();

    var instance = try module.instantiate(std.testing.allocator, struct {});
    defer instance.deinit();

    const result = try instance.call("make it so", &[0]Instance.Value{});
    std.testing.expectEqual(@as(isize, 43), result.?.I32);
}
