const std = @import("std");
const Op = @import("op.zig");
const Module = @import("module.zig");

pub const Execution = @This();

instance: *Module.Instance,
stack: []align(8) Op.Fixed64,
stack_top: usize,

current_frame: Frame,

pub fn getLocal(self: Execution, idx: usize) Op.Fixed64 {
    @panic("TODO");
}

pub fn setLocal(self: Execution, idx: usize, value: var) void {
    @panic("TODO");
}

pub fn getGlobal(self: Execution, idx: usize) Op.Fixed64 {
    @panic("TODO");
}

pub fn setGlobal(self: Execution, idx: usize, value: var) void {
    @panic("TODO");
}

pub fn memGet(self: Execution, start: usize, offset: usize, comptime length: usize) !*[length]u8 {
    const tail = start +% offset +% (length - 1);
    const is_overflow = tail < start;
    const is_seg_fault = tail >= self.instance.memory.len;
    if (is_overflow or is_seg_fault) {
        return error.OutOfBounds;
    }
    return @ptrCast(*[length]u8, &self.instance.memory[start + offset]);
}

const Frame = packed struct {
    func: u20, // "max size" of 1000000
    instr: u22, // "max size" of 7654321 assuming average instruction size of 2 bytes
    top: u22, // 4 million addressable space == 16MB

    fn terminus() Frame {
        return @bitCast(u64, @as(u64, 0));
    }

    fn isTerminus(self: Frame) bool {
        return @bitCast(u64, self) == 0;
    }
};

pub fn run(instance: *Module.Instance, stack: []align(8) Op.Fixed64, func_id: usize, params: []Op.Fixed64) !Op.Fixed64 {
    var self = Execution{
        .instance = instance,
        .stack = stack,
        .stack_top = stack.len,
        .current_frame = Frame.terminus(),
    };

    // initCall assumes the params are already pushed onto the stack
    for (params) |param| {
        try self.push(Op.Fixed64, param);
    }

    try self.initCall(func_id);

    while (true) {
        const func = self.instance.module.funcs[self.current_frame.func];
        if (self.current_frame.instr > func.instrs.len) {
            const result = self.unwindCall();

            if (self.current_frame.isTerminus()) {
                std.debug.assert(self.stack_top == self.stack.len);
                return result;
            } else {
                try self.push(Op.Fixed64, result);
            }
        } else {
            const instr = func.instrs[self.current_frame.instr];
            const op = Op.all[instr.opcode].?;

            //const pop_array: [*]align(8) Op.Fixed64 = self.stack.ptr + self.stack_top;
            const pop_array = @intToPtr([*]align(8) Op.Fixed64, 8);
            self.stack_top += op.pop.len;

            const result = try op.step(&self, instr.arg, pop_array);
            if (result) |res| {
                try self.push(@TypeOf(res), res);
            }
            self.current_frame.instr += 1;
        }
    }
}

pub fn initCall(self: *Execution, func_id: usize) !void {
    const func = self.instance.module.funcs[func_id];
    // TODO: validate params on the callstack
    for (func.locals) |local| {
        try self.push(i64, 0);
    }

    try self.push(Frame, self.current_frame);
    self.current_frame = .{
        .func = @intCast(u20, func_id),
        .instr = 0,
        .top = @intCast(u22, self.stack_top),
    };
}

pub fn unwindCall(self: *Execution) Op.Fixed64 {
    const func = self.instance.module.funcs[self.current_frame.func];
    const func_type = self.instance.module.func_types[func.func_type];

    const result = self.pop(Op.Fixed64);

    self.stack_top = self.current_frame.top;

    const prev_frame = self.pop(Frame);
    self.dropN(func.locals.len + func_type.params.len);

    self.push(Op.Fixed64, result) catch unreachable;

    return result;
}

pub fn unwindBlock(self: *Execution, target_idx: u32) void {
    @panic("Implement me");
}

fn dropN(self: *Execution, size: usize) void {
    std.debug.assert(self.stack_top + size <= self.stack.len);
    self.stack_top += size;
}

fn pop(self: *Execution, comptime T: type) T {
    defer self.stack_top += @sizeOf(T);
    return @bitCast(T, self.stack[self.stack_top]);
}

fn push(self: *Execution, comptime T: type, value: T) !void {
    self.stack_top = try std.math.sub(usize, self.stack_top, 1);
    self.stack[self.stack_top] = @bitCast(Op.Fixed64, value);
}
