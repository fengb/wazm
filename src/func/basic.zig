const std = @import("std");

const Wat = @import("../wat.zig");

test "stuff" {
    var module = try Wat.parse(std.testing.allocator,
        \\(module
        \\  (func (param i32) (param i32) (result i32)
        \\    local.get 0
        \\    local.get 1
        \\    i32.add))
    );
    defer module.deinit();

    std.debug.print("{}\n", .{module.code[0].code[0]});
}
