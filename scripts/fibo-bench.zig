const std = @import("std");
const Wat = @import("self").Wat;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = &gpa.allocator;

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    const iters: u32 = try std.fmt.parseInt(u8, args[1], 10);

    var fbs = std.io.fixedBufferStream(
        \\(module
        \\  (func (param i32) (result i32) (local i32)
        \\    i32.const       1
        \\    local.set       1
        \\    block
        \\      local.get       0
        \\      i32.const       2
        \\      i32.lt_s
        \\      br_if           0
        \\      local.get       0
        \\      i32.const      -1
        \\      i32.add
        \\      call 0
        \\      local.get       0
        \\      i32.const      -2
        \\      i32.add
        \\      call 0
        \\      i32.add
        \\      local.set       1
        \\    end
        \\    local.get 1)
        \\  (export "fib" (func 0)))
    );

    var module = try Wat.parse(allocator, fbs.reader());
    defer module.deinit();

    var instance = try module.instantiate(allocator, null, struct {});
    defer instance.deinit();

    const result = try instance.call("fib", .{iters});
    std.debug.print("{}\n", .{result.?.I32});
}
