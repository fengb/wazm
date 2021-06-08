const std = @import("std");
const Op = @import("op.zig");
const Module = @import("module.zig");
const Instance = @import("instance.zig");
const Memory = @import("Memory.zig");
const util = @import("util.zig");

const Execution = @This();

memory: *Memory,
funcs: []const Instance.Func,
allocator: *std.mem.Allocator,
instance: *const Instance,

stack: []Op.Fixval,
stack_top: usize,
current_frame: Frame = Frame.terminus(),

pub fn run(instance: *Instance, stack: []Op.Fixval, func_id: usize, params: []Op.Fixval) !?Op.Fixval {
    var ctx = Execution{
        .memory = &instance.memory,
        .funcs = instance.funcs,
        .allocator = instance.allocator,
        .instance = instance,

        .stack = stack,
        .stack_top = 0,
    };

    // initCall assumes the params are already pushed onto the stack
    for (params) |param| {
        try ctx.push(Op.Fixval, param);
    }

    try ctx.initCall(func_id);
    if (ctx.current_frame.isTerminus()) {
        return switch (ctx.stack_top) {
            0 => null,
            1 => ctx.stack[0],
            else => unreachable,
        };
    }

    while (true) {
        const func = ctx.funcs[ctx.current_frame.func];
        if (ctx.current_frame.instr < func.kind.instrs.len) {
            const instr = func.kind.instrs[ctx.current_frame.instr];
            ctx.current_frame.instr += 1;

            const pops = ctx.popN(instr.pop_len);

            const result = try Op.step(instr.op, &ctx, instr.arg, pops.ptr);
            if (result) |res| {
                try ctx.push(@TypeOf(res), res);
            }
        } else {
            const result = ctx.unwindCall();

            if (ctx.current_frame.isTerminus()) {
                std.debug.assert(ctx.stack_top == 0);
                return result;
            } else {
                if (result) |res| {
                    ctx.push(Op.Fixval, res) catch unreachable;
                }
            }
        }
    }
}

pub fn getLocal(self: Execution, idx: usize) Op.Fixval {
    return self.stack[idx + self.localOffset()];
}

pub fn getLocals(self: Execution, idx: usize, len: usize) []Op.Fixval {
    return self.stack[idx + self.localOffset() ..][0..len];
}

pub fn setLocal(self: Execution, idx: usize, value: Op.Fixval) void {
    self.stack[idx + self.localOffset()] = value;
}

fn localOffset(self: Execution) usize {
    const func = self.funcs[self.current_frame.func];
    const return_frame = 1;
    return self.current_frame.stack_begin - return_frame - func.params.len - func.locals.len;
}

pub fn getGlobal(self: Execution, idx: usize) Op.Fixval {
    return switch (self.instance.globals[idx]) {
        .I32 => |val| .{ .I32 = val },
        .I64 => |val| .{ .I64 = val },
        .F32 => |val| .{ .F32 = val },
        .F64 => |val| .{ .F64 = val },
    };
}

pub fn setGlobal(self: Execution, idx: usize, value: anytype) void {
    switch (self.instance.globals[idx]) {
        .I32 => |*val| val.* = value.I32,
        .I64 => |*val| val.* = value.I64,
        .F32 => |*val| val.* = value.F32,
        .F64 => |*val| val.* = value.F64,
    }
}

pub fn initCall(self: *Execution, func_id: usize) !void {
    const func = self.funcs[func_id];
    if (func.kind == .imported) {
        // TODO: investigate imported calling another imported
        const params = self.popN(func.params.len);
        const result = try func.kind.imported.func(self, params);

        if (result) |res| {
            self.push(Op.Fixval, res) catch unreachable;
        }
    } else {
        // TODO: assert params on the callstack are correct
        for (func.locals) |local| {
            try self.push(u128, 0);
        }

        try self.push(Frame, self.current_frame);

        self.current_frame = .{
            .func = @intCast(u32, func_id),
            .instr = 0,
            .stack_begin = @intCast(u32, self.stack_top),
        };
    }
}

pub fn unwindCall(self: *Execution) ?Op.Fixval {
    const func = self.funcs[self.current_frame.func];

    const result = if (func.result) |_|
        self.pop(Op.Fixval)
    else
        null;

    self.stack_top = self.current_frame.stack_begin;

    self.current_frame = self.pop(Frame);
    _ = self.popN(func.params.len + func.locals.len);

    return result;
}

pub fn jump(self: *Execution, table_idx: ?u32) void {
    const meta = self.instance.module.post_process.?.jumps.get(.{
        .func = self.current_frame.func,
        .instr = self.current_frame.instr - 1,
    }).?;

    const target = if (table_idx) |idx|
        meta.many[idx]
    else
        meta.one;

    const result = if (target.has_value)
        self.peek(Op.Fixval)
    else
        null;

    _ = self.popN(target.stack_unroll);
    // Jumps to 1 after the target.
    // If target == "end", this skips a noop and is faster.
    // If target == "else", this correctly skips over the annoying check.
    self.current_frame.instr = target.addr + 1;

    if (result) |value| {
        self.push(Op.Fixval, value) catch unreachable;
    }
}

pub fn peek(self: *Execution, comptime T: type) T {
    std.debug.assert(@sizeOf(T) == 16);
    return @bitCast(T, self.stack[self.stack_top - 1]);
}

pub fn pop(self: *Execution, comptime T: type) T {
    std.debug.assert(@sizeOf(T) == 16);
    self.stack_top -= 1;
    return @bitCast(T, self.stack[self.stack_top]);
}

pub fn popN(self: *Execution, size: usize) []Op.Fixval {
    std.debug.assert(self.stack_top + size <= self.stack.len);
    self.stack_top -= size;
    return self.stack[self.stack_top..][0..size];
}

pub fn push(self: *Execution, comptime T: type, value: T) !void {
    std.debug.assert(@sizeOf(T) == 16);
    self.stack[self.stack_top] = @bitCast(Op.Fixval, value);
    self.stack_top = try std.math.add(usize, self.stack_top, 1);
}

pub fn pushOpaque(self: *Execution, comptime len: usize) !*[len]Op.Fixval {
    const start = self.stack_top;
    self.stack_top = try std.math.add(usize, len, 1);
    return self.stack[start..][0..len];
}

const Frame = extern struct {
    func: u32,
    instr: u32,
    stack_begin: u32,
    _pad: u32 = undefined,

    pub fn terminus() Frame {
        return @bitCast(Frame, @as(u128, 0));
    }

    pub fn isTerminus(self: Frame) bool {
        return @bitCast(u128, self) == 0;
    }
};
