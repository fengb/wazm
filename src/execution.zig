const std = @import("std");
const Op = @import("op.zig");
const Instance = @import("instance.zig");
const util = @import("util.zig");

pub const Execution = @This();

instance: *Instance,
stack: []Op.Fixval,
stack_top: usize,

current_frame: Frame,

pub fn getLocal(self: Execution, idx: usize) Op.Fixval {
    return self.stack[idx + self.localOffset()];
}

pub fn setLocal(self: Execution, idx: usize, value: Op.Fixval) void {
    self.stack[idx + self.localOffset()] = value;
}

fn localOffset(self: Execution) usize {
    const func = self.instance.funcs[self.current_frame.func];
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
    const Int = std.meta.Int(false, @bitSizeOf(T));
    const raw = std.mem.readIntLittle(Int, try self.memGet(start, offset, @sizeOf(T)));
    return @bitCast(T, raw);
}

pub fn store(self: Execution, comptime T: type, start: usize, offset: usize, value: T) !void {
    const bytes = try self.memGet(start, offset, @sizeOf(T));
    const Int = std.meta.Int(false, @bitSizeOf(T));
    std.mem.writeIntLittle(Int, bytes, @bitCast(Int, value));
}

fn memGet(self: Execution, start: usize, offset: usize, comptime length: usize) !*[length]u8 {
    const tail = start +% offset +% (length - 1);
    const is_overflow = tail < start;
    const is_seg_fault = tail >= self.instance.memory.len;
    if (is_overflow or is_seg_fault) {
        return error.OutOfBounds;
    }
    return self.instance.memory[start + offset ..][0..length];
}

const Frame = packed struct {
    func: u32,
    instr: u32,
    stack_begin: usize,
    _pad: std.meta.IntType(false, 128 - @bitSizeOf(usize) - 64) = 0,

    fn terminus() Frame {
        // TODO: why does doing @bitCast(Frame) crash the compiler?
        return @bitCast(u128, @as(u128, 0));
    }

    fn isTerminus(self: Frame) bool {
        return @bitCast(u128, self) == 0;
    }
};

pub fn run(instance: *Instance, stack: []Op.Fixval, func_id: usize, params: []Op.Fixval) !?Op.Fixval {
    var self = Execution{
        .instance = instance,
        .stack = stack,
        .stack_top = 0,
        .current_frame = Frame.terminus(),
    };

    // initCall assumes the params are already pushed onto the stack
    for (params) |param| {
        try self.push(Op.Fixval, param);
    }

    try self.initCall(func_id);

    while (true) {
        const func = self.instance.funcs[self.current_frame.func];
        if (self.current_frame.instr < func.instrs.len) {
            const instr = func.instrs[self.current_frame.instr];
            self.current_frame.instr += 1;

            self.stack_top -= instr.op.pop.len;
            const pop_array: [*]Op.Fixval = self.stack.ptr + self.stack_top;

            const result = try instr.op.step(&self, instr.arg, pop_array);
            if (result) |res| {
                try self.push(@TypeOf(res), res);
            }
        } else {
            const result = self.unwindCall();

            if (self.current_frame.isTerminus()) {
                std.debug.assert(self.stack_top == 0);
                return result;
            } else {
                if (result) |res| {
                    self.push(Op.Fixval, res) catch unreachable;
                }
            }
        }
    }
}

pub fn initCall(self: *Execution, func_id: usize) !void {
    const func = self.instance.funcs[func_id];
    // TODO: validate params on the callstack
    for (func.locals) |local| {
        try self.push(u128, 0);
    }

    try self.push(Frame, self.current_frame);

    self.current_frame = .{
        .func = @intCast(u32, func_id),
        .instr = 0,
        .stack_begin = @intCast(usize, self.stack_top),
    };
}

pub fn unwindCall(self: *Execution) ?Op.Fixval {
    const func = self.instance.funcs[self.current_frame.func];

    const result = if (func.result) |_|
        self.pop(Op.Fixval)
    else
        null;

    self.stack_top = self.current_frame.stack_begin;

    self.current_frame = self.pop(Frame);
    self.dropN(func.locals.len + func.params.len);

    return result;
}

pub fn unwindBlock(self: *Execution, target_idx: u32) void {
    const func = self.instance.funcs[self.current_frame.func];

    var remaining = target_idx;
    var stack_change: isize = 0;
    // TODO: test this...
    while (true) {
        self.current_frame.instr += 1;
        const instr = func.instrs[self.current_frame.instr];

        stack_change -= @intCast(isize, instr.op.pop.len);
        stack_change += @intCast(isize, @boolToInt(instr.op.push != null));

        const swh = util.Swhash(8);
        switch (swh.match(instr.op.name)) {
            swh.case("block"), swh.case("loop"), swh.case("if") => {
                remaining += 1;
            },
            swh.case("end") => {
                if (remaining > 0) {
                    remaining -= 1;
                } else {
                    // TODO: actually find the corresponding opening block
                    const begin = instr;
                    const top_value = self.stack[self.stack_top];

                    std.debug.assert(stack_change <= 0);
                    self.dropN(std.math.absCast(stack_change));

                    const block_type = @intToEnum(Op.Arg.Type, begin.arg.U64);
                    if (block_type != .Void) {
                        self.push(Op.Fixval, top_value) catch unreachable;
                    }

                    if (std.mem.eql(u8, "loop", begin.op.name)) {
                        // Inside loop blocks, br works like "continue" and jumps back to the beginning
                        // self.current_frame.instr = begin_idx + 1;
                    }
                    return;
                }
            },
            else => {},
        }
    }
}

fn dropN(self: *Execution, size: usize) void {
    std.debug.assert(self.stack_top + size <= self.stack.len);
    self.stack_top -= size;
}

fn pop(self: *Execution, comptime T: type) T {
    std.debug.assert(@sizeOf(T) == 16);
    self.stack_top -= 1;
    return @bitCast(T, self.stack[self.stack_top]);
}

fn push(self: *Execution, comptime T: type, value: T) !void {
    std.debug.assert(@sizeOf(T) == 16);
    self.stack[self.stack_top] = @bitCast(Op.Fixval, value);
    self.stack_top = try std.math.add(usize, self.stack_top, 1);
}
