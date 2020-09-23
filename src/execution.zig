const std = @import("std");
const Op = @import("op.zig");
const instance = @import("instance.zig");
const util = @import("util.zig");

pub const Context = struct {
    memory: []u8,
    funcs: []instance.Func,
    allocator: *std.mem.Allocator,

    stack: []Op.Fixval,
    stack_top: usize,

    current_frame: Frame,

    pub fn getLocal(self: Context, idx: usize) Op.Fixval {
        return self.stack[idx + self.localOffset()];
    }

    pub fn setLocal(self: Context, idx: usize, value: Op.Fixval) void {
        self.stack[idx + self.localOffset()] = value;
    }

    fn localOffset(self: Context) usize {
        const func = self.funcs[self.current_frame.func];
        const return_frame = 1;
        return self.current_frame.stack_begin - return_frame - func.params.len - func.locals.len;
    }

    pub fn getGlobal(self: Context, idx: usize) Op.Fixval {
        @panic("TODO");
    }

    pub fn setGlobal(self: Context, idx: usize, value: anytype) void {
        @panic("TODO");
    }

    // TODO: move these memory methods?
    pub fn load(self: Context, comptime T: type, start: usize, offset: usize) !T {
        const Int = std.meta.Int(false, @bitSizeOf(T));
        const raw = std.mem.readIntLittle(Int, try self.memGet(start, offset, @sizeOf(T)));
        return @bitCast(T, raw);
    }

    pub fn store(self: Context, comptime T: type, start: usize, offset: usize, value: T) !void {
        const bytes = try self.memGet(start, offset, @sizeOf(T));
        const Int = std.meta.Int(false, @bitSizeOf(T));
        std.mem.writeIntLittle(Int, bytes, @bitCast(Int, value));
    }

    fn memGet(self: Context, start: usize, offset: usize, comptime length: usize) !*[length]u8 {
        const tail = start +% offset +% (length - 1);
        const is_overflow = tail < start;
        const is_seg_fault = tail >= self.memory.len;
        if (is_overflow or is_seg_fault) {
            return error.OutOfBounds;
        }
        return self.memory[start + offset ..][0..length];
    }

    pub fn initCall(self: *Context, func_id: usize) !void {
        const func = self.funcs[func_id];
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

    pub fn unwindCall(self: *Context) ?Op.Fixval {
        const func = self.funcs[self.current_frame.func];

        const result = if (func.result) |_|
            self.pop(Op.Fixval)
        else
            null;

        self.stack_top = self.current_frame.stack_begin;

        self.current_frame = self.pop(Frame);
        self.dropN(func.locals.len + func.params.len);

        return result;
    }

    pub fn unwindBlock(self: *Context, target_idx: u32) void {
        const func = self.funcs[self.current_frame.func];

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

    fn dropN(self: *Context, size: usize) void {
        std.debug.assert(self.stack_top + size <= self.stack.len);
        self.stack_top -= size;
    }

    fn pop(self: *Context, comptime T: type) T {
        std.debug.assert(@sizeOf(T) == 16);
        self.stack_top -= 1;
        return @bitCast(T, self.stack[self.stack_top]);
    }

    fn push(self: *Context, comptime T: type, value: T) !void {
        std.debug.assert(@sizeOf(T) == 16);
        self.stack[self.stack_top] = @bitCast(Op.Fixval, value);
        self.stack_top = try std.math.add(usize, self.stack_top, 1);
    }
};

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

pub fn run(inst: anytype, stack: []Op.Fixval, func_id: usize, params: []Op.Fixval) !?Op.Fixval {
    var ctx = Context{
        .memory = inst.memory,
        .funcs = inst.funcs,
        .allocator = inst.allocator,

        .stack = stack,
        .stack_top = 0,
        .current_frame = Frame.terminus(),
    };
    // Context may have grown the memory, so we need to copy the new memory in
    // TODO: rearchitect so this copying is unnecessary
    defer inst.memory = ctx.memory;

    // initCall assumes the params are already pushed onto the stack
    for (params) |param| {
        try ctx.push(Op.Fixval, param);
    }

    try ctx.initCall(func_id);

    while (true) {
        const func = ctx.funcs[ctx.current_frame.func];
        if (ctx.current_frame.instr < func.instrs.len) {
            const instr = func.instrs[ctx.current_frame.instr];
            ctx.current_frame.instr += 1;

            ctx.stack_top -= instr.op.pop.len;
            const pop_array: [*]Op.Fixval = ctx.stack.ptr + ctx.stack_top;

            const result = try instr.op.step(&ctx, instr.arg, pop_array);
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
