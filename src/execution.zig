const std = @import("std");
const Op = @import("op.zig");
const Module = @import("module.zig");
const Instance = @import("instance.zig");
const util = @import("util.zig");

const Execution = @This();

memory: []u8,
funcs: []const Instance.Func,
allocator: *std.mem.Allocator,
jumps: Module.InstrJumps,

stack: []Op.Fixval,
stack_top: usize,
current_frame: Frame = Frame.terminus(),

pub fn run(instance: *Instance, stack: []Op.Fixval, func_id: usize, params: []Op.Fixval) !?Op.Fixval {
    var ctx = Execution{
        .memory = instance.memory,
        .funcs = instance.funcs,
        .allocator = instance.allocator,
        .jumps = instance.module.jumps,

        .stack = stack,
        .stack_top = 0,
    };
    // Execution may have grown the memory, so we need to copy the new memory in
    // TODO: rearchitect so this copying is unnecessary
    defer instance.memory = ctx.memory;

    // initCall assumes the params are already pushed onto the stack
    for (params) |param| {
        try ctx.push(Op.Fixval, param);
    }

    try ctx.initCall(func_id);

    while (true) {
        const func = ctx.funcs[ctx.current_frame.func];
        // TODO: investigate imported calling another imported
        if (ctx.current_frame.instr == 0 and func.kind == .imported) {
            const result = try func.kind.imported.func(&ctx, ctx.getLocals(0, func.params.len));

            _ = ctx.unwindCall();

            if (ctx.current_frame.isTerminus()) {
                std.debug.assert(ctx.stack_top == 0);
                return result;
            } else {
                if (result) |res| {
                    ctx.push(Op.Fixval, res) catch unreachable;
                }
            }
        } else if (ctx.current_frame.instr < func.kind.instrs.len) {
            const instr = func.kind.instrs[ctx.current_frame.instr];
            ctx.current_frame.instr += 1;

            ctx.stack_top -= instr.pop_len;
            const pop_array: [*]Op.Fixval = ctx.stack.ptr + ctx.stack_top;

            const result = try Op.step(instr.op, &ctx, instr.arg, pop_array);
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
    @panic("TODO");
}

pub fn setGlobal(self: Execution, idx: usize, value: anytype) void {
    @panic("TODO");
}

// TODO: move these memory methods?
pub fn load(self: Execution, comptime T: type, start: usize, offset: usize) !T {
    const Int = std.meta.Int(.unsigned, @bitSizeOf(T));
    const raw = std.mem.readIntLittle(Int, try self.memGet(start, offset, @sizeOf(T)));
    return @bitCast(T, raw);
}

pub fn store(self: Execution, comptime T: type, start: usize, offset: usize, value: T) !void {
    const bytes = try self.memGet(start, offset, @sizeOf(T));
    const Int = std.meta.Int(.unsigned, @bitSizeOf(T));
    std.mem.writeIntLittle(Int, bytes, @bitCast(Int, value));
}

fn memGet(self: Execution, start: usize, offset: usize, comptime length: usize) !*[length]u8 {
    const tail = start +% offset +% (length - 1);
    const is_overflow = tail < start;
    const is_seg_fault = tail >= self.memory.len;
    if (is_overflow or is_seg_fault) {
        return error.OutOfBounds;
    }
    return self.memory[start + offset ..][0..length];
}

pub fn initCall(self: *Execution, func_id: usize) !void {
    const func = self.funcs[func_id];
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

pub fn unwindCall(self: *Execution) ?Op.Fixval {
    const func = self.funcs[self.current_frame.func];

    const result = if (func.result) |_|
        self.pop(Op.Fixval)
    else
        null;

    self.stack_top = self.current_frame.stack_begin;

    self.current_frame = self.pop(Frame);
    self.dropN(func.params.len + func.locals.len);

    return result;
}

pub fn jump(self: *Execution, table_idx: ?u32) void {
    const meta = self.jumps.get(.{
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

    self.dropN(target.stack_unroll);
    self.current_frame.instr = target.addr;

    if (result) |value| {
        self.push(Op.Fixval, value) catch unreachable;
    }
}

pub fn dropN(self: *Execution, size: usize) void {
    std.debug.assert(self.stack_top + size <= self.stack.len);
    self.stack_top -= size;
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
