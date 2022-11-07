const std = @import("std");
const Op = @import("op.zig");
const Module = @import("module.zig");
const Instance = @import("instance.zig");
const Memory = @import("Memory.zig");
const util = @import("util.zig");

const Execution = @This();

memory: *Memory,
funcs: []const Instance.Func,
allocator: std.mem.Allocator,
instance: *const Instance,

stack: []Op.Fixval,
stack_top: usize,
current_frame: Frame = Frame.terminus(),

result: Op.WasmTrap!?Op.Fixval,

pub fn run(instance: *Instance, stack: []Op.Fixval, func_id: usize, params: []Op.Fixval) !?Op.Fixval {
    var ctx = Execution{
        .memory = &instance.memory,
        .funcs = instance.funcs,
        .allocator = instance.allocator,
        .instance = instance,

        .stack = stack,
        .stack_top = 0,

        .result = undefined,
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

    tailDispatch(&ctx, undefined);
    return ctx.result;
}

fn tailDispatch(self: *Execution, arg: Op.Arg) callconv(.C) void {
    const func = self.funcs[self.current_frame.func];
    if (self.current_frame.instr >= func.kind.instrs.len) {
        return @call(.{ .modifier = .always_tail }, tailUnwind, .{ self, arg });
    }

    const instr = func.kind.instrs[self.current_frame.instr];
    self.current_frame.instr += 1;

    const TailCalls = comptime blk: {
        var result: [256]fn (self: *Execution, arg: Op.Arg) callconv(.C) void = undefined;
        @setEvalBranchQuota(10000);
        for (Op.Meta.sparse) |meta| {
            const Tail = TailWrap(meta.code);
            result[@enumToInt(meta.code)] = Tail.call;
        }
        break :blk result;
    };

    return @call(.{ .modifier = .always_tail }, TailCalls[@enumToInt(instr.op)], .{ self, instr.arg });
}

fn tailUnwind(self: *Execution, arg: Op.Arg) callconv(.C) void {
    const result = self.unwindCall();

    if (self.current_frame.isTerminus()) {
        std.debug.assert(self.stack_top == 0);
        self.result = result;
        return;
    } else {
        if (result) |res| {
            self.push(Op.Fixval, res) catch unreachable;
        }
    }
    return @call(.{ .modifier = .always_inline }, tailDispatch, .{ self, arg });
}

fn TailWrap(comptime opcode: std.wasm.Opcode) type {
    const meta = Op.Meta.of(opcode);
    return struct {
        fn call(ctx: *Execution, arg: Op.Arg) callconv(.C) void {
            const pops = ctx.popN(meta.pop.len);
            const result = @call(
                .{ .modifier = .always_inline },
                Op.stepName,
                .{ meta.func_name, ctx, arg, pops.ptr },
            ) catch |err| {
                ctx.result = err;
                return;
            };

            if (result) |res| {
                ctx.push(@TypeOf(res), res) catch |err| {
                    ctx.result = err;
                    return;
                };
            }
            return @call(.{ .modifier = .always_inline }, tailDispatch, .{ ctx, arg });
        }
    };
}

pub fn getLocal(self: Execution, idx: usize) Op.Fixval {
    return self.stack[idx + self.current_frame.locals_begin];
}

pub fn getLocals(self: Execution, idx: usize, len: usize) []Op.Fixval {
    return self.stack[idx + self.current_frame.locals_begin ..][0..len];
}

pub fn setLocal(self: Execution, idx: usize, value: Op.Fixval) void {
    self.stack[idx + self.current_frame.locals_begin] = value;
}

pub fn getGlobal(self: Execution, idx: usize) Op.Fixval {
    return self.instance.globals[idx];
}

pub fn setGlobal(self: Execution, idx: usize, value: Op.Fixval) void {
    self.instance.globals[idx] = value;
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
        const locals_begin = self.stack_top - func.params.len;
        for (func.locals) |local| {
            // TODO: assert params on the callstack are correct
            _ = local;
            try self.push(u128, 0);
        }

        try self.push(Frame, self.current_frame);

        self.current_frame = .{
            .func = @intCast(u32, func_id),
            .instr = 0,
            .stack_begin = @intCast(u32, self.stack_top),
            .locals_begin = @intCast(u32, locals_begin),
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
    locals_begin: u32,

    pub fn terminus() Frame {
        return @bitCast(Frame, @as(u128, 0));
    }

    pub fn isTerminus(self: Frame) bool {
        return @bitCast(u128, self) == 0;
    }
};
