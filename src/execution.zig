const std = @import("std");
const Op = @import("op.zig");
const Module = @import("module.zig");

pub const Execution = @This();

instance: *Module.Instance,
stack: []u64,
stack_top: usize,

current_frame: Frame,

pub fn getLocal(self: Execution, idx: usize) Value {
    @panic("TODO");
}

pub fn setLocal(self: Execution, idx: usize, value: var) void {
    @panic("TODO");
}

pub fn getGlobal(self: Execution, idx: usize) Value {
    @panic("TODO");
}

pub fn setGlobal(self: Execution, idx: usize, value: var) void {
    @panic("TODO");
}

pub const Value = packed union {
    I32: i32,
    I64: i64,
    F32: f32,
    F64: f64,
};

pub fn memGet(self: Execution, start: usize, offset: usize, comptime length: usize) !*[length]u8 {
    const tail = start +% offset +% (length - 1);
    const is_overflow = tail < start;
    const is_seg_fault = tail >= self.instance.memory.len;
    if (is_overflow or is_seg_fault) {
        return error.OutOfBounds;
    }
    return @ptrCast(*[length]u8, &self.instance.memory[start + offset]);
}

pub const WasmTrap = error{
    Unreachable,
    Overflow,
    OutOfBounds,
    DivisionByZero,
    InvalidConversionToInteger,
};

const Frame = struct {
    func: usize,
    instr: usize,
    top: usize,

    const Serialized = packed struct {
        func: u20, // "max size" of 1000000
        instr: u22, // "max size" of 7654321 assuming average instruction size of 2 bytes
        top: u22, // 4 million addressable space == 16MB
    };

    fn restore(raw: Serialized) Frame {
        return .{
            .func = @intToEnum(Index.Func, raw.func),
            .instr = @intToEnum(Index.Instr, raw.instr),
            .top = raw.top,
        };
    }

    fn dump(self: Frame) Serialized {
        return .{
            .func = @enumToInt(self.func),
            .instr = @enumToInt(self.instr),
            .top = self.top,
        };
    }

    fn terminus() Frame {
        return .{ .func = 0, .instr = 0, .top = 0 };
    }

    fn isTerminus(self: Frame) bool {
        return self.func == 0 and self.instr == 0 and self.top == 0;
    }
};

fn run(instance: *Instance, stack: []u8, func_name: []const u8, params: []Module.Type) Module.Value {
    var ctx = Execution{
        .instance = instance,
        .stack = @bytesToSlice([]u64, stack),
        .stack_top = stack.len,
        .current_frame = Frame.terminus(),
    };

    // Internal calls assume the arguments already exist
    for (params) |param| {
        ctx.push(param);
    }

    const result = ctx.call(id);
    std.debug.assert(self.stack_top == self.stack.len);
    return result;
}

fn call(self: *Execution, func_id: Index.Function) Value {
    const func = self.instance.funcs[func_id];
    // TODO: validate params on the callstack
    for (func.locals) |local| {
        switch (local) {
            .I32 => self.push(i32, undefined),
            .I64 => self.push(i64, undefined),
            .F32 => self.push(f32, undefined),
            .F64 => self.push(f64, undefined),
        }
    }

    self.push(Frame, self.current_frame);
    self.current_frame = .{
        .func = func_id,
        .instr = 0,
        .top = self.stack_top,
    };

    // TODO: this loop should be in `run()`
    // We should be able to flatten this call stack and have no dynamic stack requirements
    for (func.instrs) |instr, i| {
        self.current_frame.instr = i;
        // Run
    }

    const result = self.pop(func.return_type);
    self.unwindCall(func.return_value, result);
}

fn unwindCall(self: *Execution, func: Func, result: var) void {
    self.stack_top = self.current_frame.top;

    const prev_frame = Frame.restore(self.pop(Frame.Serialized));
    self.dropBytes(func.local_size + func.param_size);

    if (prev_frame.isTerminus()) {
        std.debug.assert(self.stack_top == self.stack.len);
        // THE END!
    }
}

fn dropBytes(self: *Execution, size: usize) void {
    std.debug.assert(self.stack_top + size <= stack.len);
    self.stack_top += size;
}

fn pop(self: *Execution, comptime T: type) T {
    self.curr_size -= @sizeOf(T);
    defer self.top += @sizeOf(T);
    return std.mem.bytesToValue(T, &self.memory[self.top]);
}

fn push(self: *Execution, comptime T: type, value: T) !void {
    self.top = try std.math.sub(self.top, @sizeOf(T));
    self.curr_size += @sizeOf(T);
    std.mem.copy(u8, self.memory[self.top..0], std.mem.toBytes(value));
}
