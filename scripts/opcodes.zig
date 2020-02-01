const std = @import("std");
const self = @import("self");

pub fn main() void {
    for (self.op.all) |op, i| {
        var buf = [_]u8{' '} ** 13;
        if (op) |o| {
            std.mem.copy(u8, &buf, o.name);
        }
        std.debug.warn("{}", .{buf});

        if (i % 0x10 == 0xF) {
            std.debug.warn("\n", .{});
        }
    }
}
