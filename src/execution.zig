const std = @import("std");
const Op = @import("op.zig");
const Module = @import("module.zig");
const instance = @import("instance.zig");
const util = @import("util.zig");

pub const Context = struct {
    memory: []u8,
    funcs: []instance.Func,
    allocator: *std.mem.Allocator,
    jumps: Module.InstrJumps,

    stack: []Op.Fixval,
    stack_top: usize,
    current_frame: Frame = Frame.terminus(),

    pub fn getLocal(self: Context, idx: usize) Op.Fixval {
        return self.stack[idx + self.localOffset()];
    }

    pub fn getLocals(self: Context, idx: usize, len: usize) []Op.Fixval {
        return self.stack[idx + self.localOffset() ..][0..len];
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

    pub fn unwindCall(self: *Context) ?Op.Fixval {
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

    pub fn jump(self: *Context, target_idx: u32) void {
        const meta = self.jumps.get(.{
            .func = self.current_frame.func,
            .instr = self.current_frame.instr - 1,
        }).?;

        const result = if (meta.return_type) |_|
            self.peek(Op.Fixval)
        else
            null;

        self.dropN(meta.stack_unroll);

        self.current_frame.instr = meta.targets[target_idx];
    }

    pub fn dropN(self: *Context, size: usize) void {
        std.debug.assert(self.stack_top + size <= self.stack.len);
        self.stack_top -= size;
    }

    pub fn peek(self: *Context, comptime T: type) T {
        std.debug.assert(@sizeOf(T) == 16);
        return @bitCast(T, self.stack[self.stack_top - 1]);
    }

    pub fn pop(self: *Context, comptime T: type) T {
        std.debug.assert(@sizeOf(T) == 16);
        self.stack_top -= 1;
        return @bitCast(T, self.stack[self.stack_top]);
    }

    pub fn push(self: *Context, comptime T: type, value: T) !void {
        std.debug.assert(@sizeOf(T) == 16);
        self.stack[self.stack_top] = @bitCast(Op.Fixval, value);
        self.stack_top = try std.math.add(usize, self.stack_top, 1);
    }

    pub fn pushOpaque(self: *Context, comptime len: usize) !*[len]Op.Fixval {
        const start = self.stack_top;
        self.stack_top = try std.math.add(usize, len, 1);
        return self.stack[start..][0..len];
    }
};

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
