const std = @import("std");
const Execution = @import("execution.zig");

pub const Meta = struct {
    code: std.wasm.Opcode,
    name: []const u8,
    arg_kind: Arg.Kind,
    push: ?Stack.Change,
    pop: []const Stack.Change,

    const sparse = sparse: {
        @setEvalBranchQuota(10000);
        const decls = publicFunctions(Impl);
        var result: [decls.len]Meta = undefined;
        for (decls) |decl, i| {
            const args = @typeInfo(decl.data.Fn.fn_type).Fn.args;
            const ctx_type = args[0].arg_type.?;
            const arg_type = args[1].arg_type.?;
            const pop_type = args[2].arg_type.?;
            if (@typeInfo(pop_type) != .Pointer) @compileError("Pop must be a pointer: " ++ @typeName(pop_type));
            const pop_ref_type = std.meta.Child(pop_type);

            const return_type = decl.data.Fn.return_type;
            const push_type = switch (@typeInfo(decl.data.Fn.return_type)) {
                .ErrorUnion => |eu_info| blk: {
                    for (std.meta.fields(eu_info.error_set)) |err| {
                        if (!errContains(WasmTrap, err.name)) {
                            @compileError("Unhandleable error: " ++ err.name);
                        }
                    }
                    break :blk eu_info.payload;
                },
                else => return_type,
            };

            result[i] = .{
                .code = parseOpcode(decl.name) catch @compileError("Not a known hex: " ++ decl.name[0..4]),
                .name = decl.name[5..],
                .arg_kind = Arg.Kind.init(arg_type),
                .push = Stack.Change.initPush(push_type),
                .pop = switch (pop_ref_type) {
                    Fixval.Void => &[0]Stack.Change{},
                    else => switch (@typeInfo(pop_ref_type)) {
                        .Union => &[1]Stack.Change{Stack.Change.initPop(pop_ref_type)},
                        .Struct => |s_info| blk: {
                            var pop_changes: [s_info.fields.len]Stack.Change = undefined;
                            for (s_info.fields) |field, f| {
                                pop_changes[f] = Stack.Change.initPop(field.field_type);
                            }
                            break :blk &pop_changes;
                        },
                        else => @compileError("Unsupported pop type: " ++ @typeName(pop_type)),
                    },
                },
            };
        }

        break :sparse result;
    };

    pub fn of(code: std.wasm.Opcode) Meta {
        return all[@enumToInt(code)].?;
    }

    pub const all = blk: {
        var result = [_]?Meta{null} ** 256;

        for (sparse) |meta| {
            const raw_code = @enumToInt(meta.code);
            if (result[raw_code] != null) {
                var buf: [100]u8 = undefined;
                @compileError(try std.fmt.bufPrint(&buf, "Collision: '0x{X} {}'", .{ code, meta.name }));
            }
            result[raw_code] = meta;
        }
        break :blk result;
    };
};

/// Generic memory chunk capable of representing any wasm type.
/// Useful for storing stack variables, locals, and globals.
pub const Fixval = extern union {
    I32: i32,
    U32: u32,
    I64: i64,
    U64: u64,
    F32: f32,
    F64: f64,
    V128: i128, // TODO: make this a real vector

    pub const Void = extern struct {
        _pad: u128,
    };

    const I32 = extern union {
        data: i32,
        _pad: u128,
    };

    const U32 = extern union {
        data: u32,
        _pad: u128,
    };

    const I64 = extern union {
        data: i64,
        _pad: u128,
    };

    const U64 = extern union {
        data: u64,
        _pad: u128,
    };

    const F32 = extern union {
        data: f32,
        _pad: u128,
    };

    const F64 = extern union {
        data: f64,
        _pad: u128,
    };
};

test "Fixval subtype sizes" {
    inline for (std.meta.declarations(Fixval)) |decl| {
        if (decl.data == .Type) {
            std.testing.expectEqual(@sizeOf(Fixval), @sizeOf(decl.data.Type));
        }
    }
}

pub const Arg = extern union {
    I32: i32,
    U32: u32,
    I64: i64,
    U64: u64,
    F32: f32,
    F64: f64,
    Type: Type,
    U32z: U32z,
    Mem: Mem,
    Array: Array,

    pub const Kind = enum {
        Void,
        I32,
        U32,
        I64,
        U64,
        F32,
        F64,
        Type,
        U32z,
        Mem,
        Array,

        fn init(comptime T: type) Kind {
            return switch (T) {
                Fixval.Void => .Void,
                Fixval.I32 => .I32,
                Fixval.U32 => .U32,
                Fixval.I64 => .I64,
                Fixval.U64 => .U64,
                Fixval.F32 => .F32,
                Fixval.F64 => .F64,
                Type => .Type,
                U32z => .U32z,
                Mem => .Mem,
                Array => .Array,
                else => @compileError("Unsupported arg type: " ++ @typeName(T)),
            };
        }
    };

    pub const Type = enum(u128) {
        Void = 0x40,
        I32 = 0x7F,
        I64 = 0x7E,
        F32 = 0x7D,
        F64 = 0x7C,
    };

    pub const U32z = extern struct {
        data: u32,
        reserved: u8,
        // Zig bug -- won't pack correctly without manually splitting this
        _pad0: u8 = 0,
        _pad1: u16 = 0,
        _pad2: u64 = 0,
    };

    pub const Mem = extern struct {
        offset: u32,
        align_: u32,
        _pad: u64 = 0,
    };

    // TODO: make this extern
    pub const Array = packed struct {
        ptr: [*]u32,
        len: usize,
        _pad: std.meta.Int(.unsigned, 128 - 2 * @bitSizeOf(usize)) = 0,
    };
};

pub const Stack = struct {
    pub const Change = enum {
        I32,
        I64,
        F32,
        F64,
        Poly,

        fn initPush(comptime T: type) ?Change {
            return switch (T) {
                void => null,
                i32, u32 => Change.I32,
                i64, u64 => Change.I64,
                f32 => Change.F32,
                f64 => Change.F64,
                Fixval => Change.Poly,
                else => @compileError("Unsupported type: " ++ @typeName(T)),
            };
        }

        fn initPop(comptime T: type) Change {
            return switch (T) {
                Fixval.I32, Fixval.U32 => .I32,
                Fixval.I64, Fixval.U64 => .I64,
                Fixval.F32 => .F32,
                Fixval.F64 => .F64,
                Fixval => .Poly,
                else => @compileError("Unsupported type: " ++ @typeName(T)),
            };
        }
    };
};

fn errContains(comptime err_set: type, comptime name: []const u8) bool {
    std.debug.assert(@typeInfo(err_set) == .ErrorSet);
    for (std.meta.fields(err_set)) |err| {
        if (std.mem.eql(u8, err.name, name)) {
            return true;
        }
    }
    return false;
}

fn publicFunctions(comptime T: type) []std.builtin.TypeInfo.Declaration {
    const decls = std.meta.declarations(T);
    var result: [decls.len]std.builtin.TypeInfo.Declaration = undefined;
    var cursor: usize = 0;
    for (decls) |decl| {
        if (decl.is_pub and decl.data == .Fn) {
            result[cursor] = decl;
            cursor += 1;
        }
    }

    return result[0..cursor];
}

test "ops" {
    const nop = Meta.of(.nop);
    std.testing.expectEqual(nop.arg_kind, .Void);
    std.testing.expectEqual(nop.push, null);
    std.testing.expectEqual(nop.pop.len, 0);

    const i32_load = Meta.of(.i32_load);
    std.testing.expectEqual(i32_load.arg_kind, .Mem);
    std.testing.expectEqual(i32_load.push, .I32);

    std.testing.expectEqual(i32_load.pop.len, 1);
    std.testing.expectEqual(i32_load.pop[0], .I32);

    const select = Meta.of(.select);
    std.testing.expectEqual(select.arg_kind, .Void);
    std.testing.expectEqual(select.push, .Poly);

    std.testing.expectEqual(select.pop.len, 3);
    std.testing.expectEqual(select.pop[0], .Poly);
    std.testing.expectEqual(select.pop[1], .Poly);
    std.testing.expectEqual(select.pop[2], .I32);
}

pub const WasmTrap = error{
    Unreachable,
    Overflow,
    OutOfBounds,
    DivisionByZero,
    InvalidConversionToInteger,
    IndirectCalleeAbsent,
    IndirectCallTypeMismatch,
};

const hex = "0123456789ABCDEF";

pub fn step(op: std.wasm.Opcode, ctx: *Execution, arg: Arg, pop: [*]Fixval) WasmTrap!?Fixval {
    const raw_code = @enumToInt(op);
    var prefix_search = [4]u8{ '0', 'x', hex[raw_code / 16], hex[raw_code % 16] };

    // TODO: test out function pointers for performance comparison
    // LLVM optimizes this inline for / mem.eql as a jump table
    // Please benchmark if we try to to optimize this.
    inline for (publicFunctions(Impl)) |decl| {
        if (std.mem.eql(u8, &prefix_search, decl.name[0..4])) {
            const args = @typeInfo(decl.data.Fn.fn_type).Fn.args;
            const result = @field(Impl, decl.name)(
                ctx,
                switch (args[1].arg_type.?) {
                    Arg.Type => arg.Type,
                    else => @bitCast(args[1].arg_type.?, arg),
                },
                @ptrCast(args[2].arg_type.?, pop),
            );

            const result_value = if (@typeInfo(@TypeOf(result)) == .ErrorUnion) try result else result;

            return switch (@TypeOf(result_value)) {
                void => null,
                i32 => Fixval{ .I32 = result_value },
                u32 => Fixval{ .U32 = result_value },
                i64 => Fixval{ .I64 = result_value },
                u64 => Fixval{ .U64 = result_value },
                f32 => Fixval{ .F32 = result_value },
                f64 => Fixval{ .F64 = result_value },
                Fixval => result_value,
                else => @compileError("Op return unimplemented: " ++ @typeName(@TypeOf(result_value))),
            };
        }
    }

    unreachable; // Op parse error
}

fn parseOpcode(name: []const u8) !std.wasm.Opcode {
    if (name[0] != '0' or name[1] != 'x' or name[4] != ' ') {
        return error.InvalidCharacter;
    }

    return @intToEnum(std.wasm.Opcode, try std.fmt.parseInt(u8, name[2..4], 16));
}

const Impl = struct {
    const Void = Fixval.Void;
    const I32 = Fixval.I32;
    const I64 = Fixval.I64;
    const U32 = Fixval.U32;
    const U64 = Fixval.U64;
    const F32 = Fixval.F32;
    const F64 = Fixval.F64;

    // TODO: replace once Zig can define tuple types
    fn Pair(comptime T0: type, comptime T1: type) type {
        return extern struct {
            _0: T0,
            _1: T1,
        };
    }

    // TODO: replace once Zig can define tuple types
    fn Triple(comptime T0: type, comptime T1: type, comptime T2: type) type {
        return extern struct {
            _0: T0,
            _1: T1,
            _2: T2,
        };
    }

    pub fn @"0x00 unreachable"(ctx: *Execution, arg: Void, pop: *Void) !void {
        return error.Unreachable;
    }

    pub fn @"0x01 nop"(ctx: *Execution, arg: Void, pop: *Void) void {}

    pub fn @"0x02 block"(ctx: *Execution, arg: Arg.Type, pop: *Void) void {
        // noop, setup metadata only
    }

    pub fn @"0x03 loop"(ctx: *Execution, arg: Arg.Type, pop: *Void) void {
        // noop, setup metadata only
    }

    pub fn @"0x04 if"(ctx: *Execution, arg: Arg.Type, pop: *I32) void {
        if (pop.data == 0) {
            ctx.jump(null);
        }
    }

    pub fn @"0x05 else"(ctx: *Execution, arg: Void, pop: *Void) void {
        // If we are executing this instruction, it means the `if` fired, so we should skip until the end
        ctx.jump(null);
    }

    pub fn @"0x0B end"(ctx: *Execution, arg: Void, pop: *Void) void {
        // noop, setup metadata only
        // Technically this can return the top value from the stack,
        // but it would be immediately pushed on
    }

    pub fn @"0x0C br"(ctx: *Execution, arg: U32, pop: *Void) void {
        ctx.jump(null);
    }
    pub fn @"0x0D br_if"(ctx: *Execution, arg: U32, pop: *I32) void {
        if (pop.data != 0) {
            ctx.jump(null);
        }
    }
    pub fn @"0x0E br_table"(ctx: *Execution, arg: Arg.Array, pop: *U32) void {
        const idx = std.math.min(pop.data, arg.len - 1); // default to last item. Pretty handy!
        ctx.jump(arg.ptr[idx]);
    }
    pub fn @"0x0F return"(ctx: *Execution, arg: Void, pop: *Void) void {
        // Forces unwindCall()
        ctx.current_frame.instr = std.math.maxInt(u32);
    }

    pub fn @"0x10 call"(ctx: *Execution, arg: U32, pop: *Void) !void {
        try ctx.initCall(arg.data);
    }
    pub fn @"0x11 call_indirect"(ctx: *Execution, arg: Arg.U32z, pop: *U32) !void {
        const func_id = pop.data;
        if (func_id >= ctx.funcs.len) {
            return error.IndirectCalleeAbsent;
        }
        const func = ctx.funcs[func_id];
        if (func.func_type != arg.data) {
            return error.IndirectCallTypeMismatch;
        }
        try ctx.initCall(func_id);
    }
    pub fn @"0x1A drop"(ctx: *Execution, arg: Void, pop: *Fixval) void {
        // Do nothing with the popped value
    }
    pub fn @"0x1B select"(ctx: *Execution, arg: Void, pop: *Triple(Fixval, Fixval, I32)) Fixval {
        return if (pop._2.data != 0) pop._0 else pop._1;
    }

    pub fn @"0x20 local.get"(ctx: *Execution, arg: U32, pop: *Void) Fixval {
        return ctx.getLocal(arg.data);
    }
    pub fn @"0x21 local.set"(ctx: *Execution, arg: U32, pop: *Fixval) void {
        ctx.setLocal(arg.data, pop.*);
    }
    pub fn @"0x22 local.tee"(ctx: *Execution, arg: U32, pop: *Fixval) Fixval {
        ctx.setLocal(arg.data, pop.*);
        return pop.*;
    }
    pub fn @"0x23 global.get"(ctx: *Execution, arg: U32, pop: *Void) Fixval {
        return ctx.getGlobal(arg.data);
    }
    pub fn @"0x24 global.set"(ctx: *Execution, arg: U32, pop: *Fixval) void {
        ctx.setGlobal(arg.data, pop.*);
    }
    pub fn @"0x28 i32.load"(ctx: *Execution, mem: Arg.Mem, pop: *U32) !i32 {
        return try ctx.memory.load(i32, pop.data, mem.offset);
    }
    pub fn @"0x29 i64.load"(ctx: *Execution, mem: Arg.Mem, pop: *U32) !i64 {
        return try ctx.memory.load(i64, pop.data, mem.offset);
    }
    pub fn @"0x2A f32.load"(ctx: *Execution, mem: Arg.Mem, pop: *U32) !f32 {
        return try ctx.memory.load(f32, pop.data, mem.offset);
    }
    pub fn @"0x2B f64.load"(ctx: *Execution, mem: Arg.Mem, pop: *U32) !f64 {
        return try ctx.memory.load(f64, pop.data, mem.offset);
    }
    pub fn @"0x2C i32.load8_s"(ctx: *Execution, mem: Arg.Mem, pop: *U32) !i32 {
        return try ctx.memory.load(i8, pop.data, mem.offset);
    }
    pub fn @"0x2D i32.load8_u"(ctx: *Execution, mem: Arg.Mem, pop: *U32) !u32 {
        return try ctx.memory.load(u8, pop.data, mem.offset);
    }
    pub fn @"0x2E i32.load16_s"(ctx: *Execution, mem: Arg.Mem, pop: *U32) !i32 {
        return try ctx.memory.load(i16, pop.data, mem.offset);
    }
    pub fn @"0x2F i32.load16_u"(ctx: *Execution, mem: Arg.Mem, pop: *U32) !u32 {
        return try ctx.memory.load(u16, pop.data, mem.offset);
    }

    pub fn @"0x30 i64.load8_s"(ctx: *Execution, mem: Arg.Mem, pop: *U32) !i64 {
        return try ctx.memory.load(i8, pop.data, mem.offset);
    }
    pub fn @"0x31 i64.load8_u"(ctx: *Execution, mem: Arg.Mem, pop: *U32) !i64 {
        return try ctx.memory.load(u8, pop.data, mem.offset);
    }
    pub fn @"0x32 i64.load16_s"(ctx: *Execution, mem: Arg.Mem, pop: *U32) !i64 {
        return try ctx.memory.load(i16, pop.data, mem.offset);
    }
    pub fn @"0x33 i64.load16_u"(ctx: *Execution, mem: Arg.Mem, pop: *U32) !i64 {
        return try ctx.memory.load(u16, pop.data, mem.offset);
    }
    pub fn @"0x34 i64.load32_s"(ctx: *Execution, mem: Arg.Mem, pop: *U32) !i64 {
        return try ctx.memory.load(i32, pop.data, mem.offset);
    }
    pub fn @"0x35 i64.load32_u"(ctx: *Execution, mem: Arg.Mem, pop: *U32) !i64 {
        return try ctx.memory.load(u32, pop.data, mem.offset);
    }
    pub fn @"0x36 i32.store"(ctx: *Execution, mem: Arg.Mem, pop: *Pair(U32, I32)) !void {
        return try ctx.memory.store(i32, pop._0.data, mem.offset, pop._1.data);
    }
    pub fn @"0x37 i64.store"(ctx: *Execution, mem: Arg.Mem, pop: *Pair(U32, I64)) !void {
        return try ctx.memory.store(i64, pop._0.data, mem.offset, pop._1.data);
    }
    pub fn @"0x38 f32.store"(ctx: *Execution, mem: Arg.Mem, pop: *Pair(U32, F32)) !void {
        return try ctx.memory.store(f32, pop._0.data, mem.offset, pop._1.data);
    }
    pub fn @"0x39 f64.store"(ctx: *Execution, mem: Arg.Mem, pop: *Pair(U32, F64)) !void {
        return try ctx.memory.store(f64, pop._0.data, mem.offset, pop._1.data);
    }
    pub fn @"0x3A i32.store8"(ctx: *Execution, mem: Arg.Mem, pop: *Pair(U32, I32)) !void {
        return try ctx.memory.store(i8, pop._0.data, mem.offset, @truncate(i8, pop._1.data));
    }
    pub fn @"0x3B i32.store16"(ctx: *Execution, mem: Arg.Mem, pop: *Pair(U32, I32)) !void {
        return try ctx.memory.store(i16, pop._0.data, mem.offset, @truncate(i16, pop._1.data));
    }
    pub fn @"0x3C i64.store8"(ctx: *Execution, mem: Arg.Mem, pop: *Pair(U32, I64)) !void {
        return try ctx.memory.store(i8, pop._0.data, mem.offset, @truncate(i8, pop._1.data));
    }
    pub fn @"0x3D i64.store16"(ctx: *Execution, mem: Arg.Mem, pop: *Pair(U32, I64)) !void {
        return try ctx.memory.store(i16, pop._0.data, mem.offset, @truncate(i16, pop._1.data));
    }
    pub fn @"0x3E i64.store32"(ctx: *Execution, mem: Arg.Mem, pop: *Pair(U32, I64)) !void {
        return try ctx.memory.store(i32, pop._0.data, mem.offset, @truncate(i32, pop._1.data));
    }
    pub fn @"0x3F memory.size"(ctx: *Execution, arg: Void, pop: *Void) u32 {
        return @intCast(u32, ctx.memory.data.len / 65536);
    }

    pub fn @"0x40 memory.grow"(ctx: *Execution, arg: Void, pop: *U32) i32 {
        ctx.memory.grow(@intCast(u16, pop.data)) catch |err| switch (err) {
            error.OutOfMemory => return -1,
        };
        return @as(i32, ctx.memory.pages());
    }
    pub fn @"0x41 i32.const"(ctx: *Execution, arg: I32, pop: *Void) i32 {
        return arg.data;
    }
    pub fn @"0x42 i64.const"(ctx: *Execution, arg: I64, pop: *Void) i64 {
        return arg.data;
    }
    pub fn @"0x43 f32.const"(ctx: *Execution, arg: F32, pop: *Void) f32 {
        return arg.data;
    }
    pub fn @"0x44 f64.const"(ctx: *Execution, arg: F64, pop: *Void) f64 {
        return arg.data;
    }
    pub fn @"0x45 i32.eqz"(ctx: *Execution, arg: Void, pop: *I32) i32 {
        return @boolToInt(pop.data == 0);
    }
    pub fn @"0x46 i32.eq"(ctx: *Execution, arg: Void, pop: *Pair(I32, I32)) i32 {
        return @boolToInt(pop._0.data == pop._1.data);
    }
    pub fn @"0x47 i32.ne"(ctx: *Execution, arg: Void, pop: *Pair(I32, I32)) i32 {
        return @boolToInt(pop._0.data != pop._1.data);
    }
    pub fn @"0x48 i32.lt_s"(ctx: *Execution, arg: Void, pop: *Pair(I32, I32)) i32 {
        return @boolToInt(pop._0.data < pop._1.data);
    }
    pub fn @"0x49 i32.lt_u"(ctx: *Execution, arg: Void, pop: *Pair(U32, U32)) i32 {
        return @boolToInt(pop._0.data < pop._1.data);
    }
    pub fn @"0x4A i32.gt_s"(ctx: *Execution, arg: Void, pop: *Pair(I32, I32)) i32 {
        return @boolToInt(pop._0.data > pop._1.data);
    }
    pub fn @"0x4B i32.gt_u"(ctx: *Execution, arg: Void, pop: *Pair(U32, U32)) i32 {
        return @boolToInt(pop._0.data > pop._1.data);
    }
    pub fn @"0x4C i32.le_s"(ctx: *Execution, arg: Void, pop: *Pair(I32, I32)) i32 {
        return @boolToInt(pop._0.data <= pop._1.data);
    }
    pub fn @"0x4D i32.le_u"(ctx: *Execution, arg: Void, pop: *Pair(U32, U32)) i32 {
        return @boolToInt(pop._0.data <= pop._1.data);
    }
    pub fn @"0x4E i32.ge_s"(ctx: *Execution, arg: Void, pop: *Pair(I32, I32)) i32 {
        return @boolToInt(pop._0.data >= pop._1.data);
    }
    pub fn @"0x4F i32.ge_u"(ctx: *Execution, arg: Void, pop: *Pair(U32, U32)) i32 {
        return @boolToInt(pop._0.data >= pop._1.data);
    }

    pub fn @"0x50 i64.eqz"(ctx: *Execution, arg: Void, pop: *I64) i32 {
        return @boolToInt(pop.data == 0);
    }
    pub fn @"0x51 i64.eq"(ctx: *Execution, arg: Void, pop: *Pair(I64, I64)) i32 {
        return @boolToInt(pop._0.data == pop._1.data);
    }
    pub fn @"0x52 i64.ne"(ctx: *Execution, arg: Void, pop: *Pair(I64, I64)) i32 {
        return @boolToInt(pop._0.data != pop._1.data);
    }
    pub fn @"0x53 i64.lt_s"(ctx: *Execution, arg: Void, pop: *Pair(I64, I64)) i32 {
        return @boolToInt(pop._0.data < pop._1.data);
    }
    pub fn @"0x54 i64.lt_u"(ctx: *Execution, arg: Void, pop: *Pair(U64, U64)) i32 {
        return @boolToInt(pop._0.data < pop._1.data);
    }
    pub fn @"0x55 i64.gt_s"(ctx: *Execution, arg: Void, pop: *Pair(I64, I64)) i32 {
        return @boolToInt(pop._0.data > pop._1.data);
    }
    pub fn @"0x56 i64.gt_u"(ctx: *Execution, arg: Void, pop: *Pair(U64, U64)) i32 {
        return @boolToInt(pop._0.data > pop._1.data);
    }
    pub fn @"0x57 i64.le_s"(ctx: *Execution, arg: Void, pop: *Pair(I64, I64)) i32 {
        return @boolToInt(pop._0.data <= pop._1.data);
    }
    pub fn @"0x58 i64.le_u"(ctx: *Execution, arg: Void, pop: *Pair(U64, U64)) i32 {
        return @boolToInt(pop._0.data <= pop._1.data);
    }
    pub fn @"0x59 i64.ge_s"(ctx: *Execution, arg: Void, pop: *Pair(I64, I64)) i32 {
        return @boolToInt(pop._0.data >= pop._1.data);
    }
    pub fn @"0x5A i64.ge_u"(ctx: *Execution, arg: Void, pop: *Pair(U64, U64)) i32 {
        return @boolToInt(pop._0.data >= pop._1.data);
    }
    pub fn @"0x5B f32.eq"(ctx: *Execution, arg: Void, pop: *Pair(F32, F32)) i32 {
        return @boolToInt(pop._0.data == pop._1.data);
    }
    pub fn @"0x5C f32.ne"(ctx: *Execution, arg: Void, pop: *Pair(F32, F32)) i32 {
        return @boolToInt(pop._0.data != pop._1.data);
    }
    pub fn @"0x5D f32.lt"(ctx: *Execution, arg: Void, pop: *Pair(F32, F32)) i32 {
        return @boolToInt(pop._0.data < pop._1.data);
    }
    pub fn @"0x5E f32.gt"(ctx: *Execution, arg: Void, pop: *Pair(F32, F32)) i32 {
        return @boolToInt(pop._0.data > pop._1.data);
    }
    pub fn @"0x5F f32.le"(ctx: *Execution, arg: Void, pop: *Pair(F32, F32)) i32 {
        return @boolToInt(pop._0.data <= pop._1.data);
    }

    pub fn @"0x60 f32.ge"(ctx: *Execution, arg: Void, pop: *Pair(F32, F32)) i32 {
        return @boolToInt(pop._0.data >= pop._1.data);
    }
    pub fn @"0x61 f64.eq"(ctx: *Execution, arg: Void, pop: *Pair(F64, F64)) i32 {
        return @boolToInt(pop._0.data == pop._1.data);
    }
    pub fn @"0x62 f64.ne"(ctx: *Execution, arg: Void, pop: *Pair(F64, F64)) i32 {
        return @boolToInt(pop._0.data != pop._1.data);
    }
    pub fn @"0x63 f64.lt"(ctx: *Execution, arg: Void, pop: *Pair(F64, F64)) i32 {
        return @boolToInt(pop._0.data < pop._1.data);
    }
    pub fn @"0x64 f64.gt"(ctx: *Execution, arg: Void, pop: *Pair(F64, F64)) i32 {
        return @boolToInt(pop._0.data > pop._1.data);
    }
    pub fn @"0x65 f64.le"(ctx: *Execution, arg: Void, pop: *Pair(F64, F64)) i32 {
        return @boolToInt(pop._0.data <= pop._1.data);
    }
    pub fn @"0x66 f64.ge"(ctx: *Execution, arg: Void, pop: *Pair(F64, F64)) i32 {
        return @boolToInt(pop._0.data >= pop._1.data);
    }
    pub fn @"0x67 i32.clz"(ctx: *Execution, arg: Void, pop: *I32) i32 {
        return @clz(i32, pop.data);
    }
    pub fn @"0x68 i32.ctz"(ctx: *Execution, arg: Void, pop: *I32) i32 {
        return @ctz(i32, pop.data);
    }
    pub fn @"0x69 i32.popcnt"(ctx: *Execution, arg: Void, pop: *I32) i32 {
        return @popCount(i32, pop.data);
    }
    pub fn @"0x6A i32.add"(ctx: *Execution, arg: Void, pop: *Pair(I32, I32)) i32 {
        return pop._0.data +% pop._1.data;
    }
    pub fn @"0x6B i32.sub"(ctx: *Execution, arg: Void, pop: *Pair(I32, I32)) i32 {
        return pop._0.data -% pop._1.data;
    }
    pub fn @"0x6C i32.mul"(ctx: *Execution, arg: Void, pop: *Pair(I32, I32)) i32 {
        return pop._0.data *% pop._1.data;
    }
    pub fn @"0x6D i32.div_s"(ctx: *Execution, arg: Void, pop: *Pair(I32, I32)) !i32 {
        if (pop._1.data == 0) return error.DivisionByZero;
        if (pop._0.data == std.math.minInt(i32) and pop._1.data == -1) return error.Overflow;
        return @divTrunc(pop._0.data, pop._1.data);
    }
    pub fn @"0x6E i32.div_u"(ctx: *Execution, arg: Void, pop: *Pair(U32, U32)) !u32 {
        if (pop._1.data == 0) return error.DivisionByZero;
        return @divFloor(pop._0.data, pop._1.data);
    }
    pub fn @"0x6F i32.rem_s"(ctx: *Execution, arg: Void, pop: *Pair(I32, I32)) !i32 {
        if (pop._1.data == 0) return error.DivisionByZero;
        const abs_0 = std.math.absCast(pop._0.data);
        const abs_1 = std.math.absCast(pop._1.data);
        const val = @intCast(i32, @rem(abs_0, abs_1));
        return if (pop._0.data < 0) -val else val;
    }

    pub fn @"0x70 i32.rem_u"(ctx: *Execution, arg: Void, pop: *Pair(U32, U32)) !u32 {
        if (pop._1.data == 0) return error.DivisionByZero;
        return @mod(pop._0.data, pop._1.data);
    }
    pub fn @"0x71 i32.and"(ctx: *Execution, arg: Void, pop: *Pair(I32, I32)) i32 {
        return pop._0.data & pop._1.data;
    }
    pub fn @"0x72 i32.or"(ctx: *Execution, arg: Void, pop: *Pair(I32, I32)) i32 {
        return pop._0.data | pop._1.data;
    }
    pub fn @"0x73 i32.xor"(ctx: *Execution, arg: Void, pop: *Pair(I32, I32)) i32 {
        return pop._0.data ^ pop._1.data;
    }
    pub fn @"0x74 i32.shl"(ctx: *Execution, arg: Void, pop: *Pair(I32, U32)) i32 {
        return pop._0.data << @truncate(u5, pop._1.data);
    }
    pub fn @"0x75 i32.shr_s"(ctx: *Execution, arg: Void, pop: *Pair(I32, U32)) i32 {
        return pop._0.data >> @truncate(u5, pop._1.data);
    }
    pub fn @"0x76 i32.shr_u"(ctx: *Execution, arg: Void, pop: *Pair(U32, U32)) u32 {
        return pop._0.data >> @truncate(u5, pop._1.data);
    }
    pub fn @"0x77 i32.rotl"(ctx: *Execution, arg: Void, pop: *Pair(U32, U32)) u32 {
        return std.math.rotl(u32, pop._0.data, @truncate(u6, pop._1.data));
    }
    pub fn @"0x78 i32.rotr"(ctx: *Execution, arg: Void, pop: *Pair(U32, U32)) u32 {
        return std.math.rotr(u32, pop._0.data, @truncate(u6, pop._1.data));
    }
    pub fn @"0x79 i64.clz"(ctx: *Execution, arg: Void, pop: *I64) i64 {
        return @clz(i64, pop.data);
    }
    pub fn @"0x7A i64.ctz"(ctx: *Execution, arg: Void, pop: *I64) i64 {
        return @ctz(i64, pop.data);
    }
    pub fn @"0x7B i64.popcnt"(ctx: *Execution, arg: Void, pop: *I64) i64 {
        return @popCount(i64, pop.data);
    }
    pub fn @"0x7C i64.add"(ctx: *Execution, arg: Void, pop: *Pair(I64, I64)) i64 {
        return pop._0.data +% pop._1.data;
    }
    pub fn @"0x7D i64.sub"(ctx: *Execution, arg: Void, pop: *Pair(I64, I64)) i64 {
        return pop._0.data -% pop._1.data;
    }
    pub fn @"0x7E i64.mul"(ctx: *Execution, arg: Void, pop: *Pair(I64, I64)) i64 {
        return pop._0.data *% pop._1.data;
    }
    pub fn @"0x7F i64.div_s"(ctx: *Execution, arg: Void, pop: *Pair(I64, I64)) !i64 {
        if (pop._1.data == 0) return error.DivisionByZero;
        if (pop._0.data == std.math.minInt(i64) and pop._1.data == -1) return error.Overflow;
        return @divTrunc(pop._0.data, pop._1.data);
    }

    pub fn @"0x80 i64.div_u"(ctx: *Execution, arg: Void, pop: *Pair(U64, U64)) !u64 {
        if (pop._1.data == 0) return error.DivisionByZero;
        return @divFloor(pop._0.data, pop._1.data);
    }
    pub fn @"0x81 i64.rem_s"(ctx: *Execution, arg: Void, pop: *Pair(I64, I64)) !i64 {
        if (pop._1.data == 0) return error.DivisionByZero;
        const abs_0 = std.math.absCast(pop._0.data);
        const abs_1 = std.math.absCast(pop._1.data);
        const val = @intCast(i64, @rem(abs_0, abs_1));
        return if (pop._0.data < 0) -val else val;
    }
    pub fn @"0x82 i64.rem_u"(ctx: *Execution, arg: Void, pop: *Pair(U64, U64)) !u64 {
        if (pop._1.data == 0) return error.DivisionByZero;
        return @mod(pop._0.data, pop._1.data);
    }
    pub fn @"0x83 i64.and"(ctx: *Execution, arg: Void, pop: *Pair(I64, I64)) i64 {
        return pop._0.data & pop._1.data;
    }
    pub fn @"0x84 i64.or"(ctx: *Execution, arg: Void, pop: *Pair(I64, I64)) i64 {
        return pop._0.data | pop._1.data;
    }
    pub fn @"0x85 i64.xor"(ctx: *Execution, arg: Void, pop: *Pair(I64, I64)) i64 {
        return pop._0.data ^ pop._1.data;
    }
    pub fn @"0x86 i64.shl"(ctx: *Execution, arg: Void, pop: *Pair(I64, U64)) i64 {
        return pop._0.data << @truncate(u6, pop._1.data);
    }
    pub fn @"0x87 i64.shr_s"(ctx: *Execution, arg: Void, pop: *Pair(I64, U64)) i64 {
        return pop._0.data >> @truncate(u6, pop._1.data);
    }
    pub fn @"0x88 i64.shr_u"(ctx: *Execution, arg: Void, pop: *Pair(U64, U64)) u64 {
        return pop._0.data >> @truncate(u6, pop._1.data);
    }
    pub fn @"0x89 i64.rotl"(ctx: *Execution, arg: Void, pop: *Pair(U64, U64)) u64 {
        return std.math.rotl(u64, pop._0.data, @truncate(u7, pop._1.data));
    }
    pub fn @"0x8A i64.rotr"(ctx: *Execution, arg: Void, pop: *Pair(U64, U64)) u64 {
        return std.math.rotr(u64, pop._0.data, @truncate(u7, pop._1.data));
    }
    pub fn @"0x8B f32.abs"(ctx: *Execution, arg: Void, pop: *F32) f32 {
        return @fabs(pop.data);
    }
    pub fn @"0x8C f32.neg"(ctx: *Execution, arg: Void, pop: *F32) f32 {
        return -pop.data;
    }
    pub fn @"0x8D f32.ceil"(ctx: *Execution, arg: Void, pop: *F32) f32 {
        return @ceil(pop.data);
    }
    pub fn @"0x8E f32.floor"(ctx: *Execution, arg: Void, pop: *F32) f32 {
        return @floor(pop.data);
    }
    pub fn @"0x8F f32.trunc"(ctx: *Execution, arg: Void, pop: *F32) f32 {
        return @trunc(pop.data);
    }

    pub fn @"0x90 f32.nearest"(ctx: *Execution, arg: Void, pop: *F32) f32 {
        return @round(pop.data);
    }
    pub fn @"0x91 f32.sqrt"(ctx: *Execution, arg: Void, pop: *F32) f32 {
        return @sqrt(pop.data);
    }
    pub fn @"0x92 f32.add"(ctx: *Execution, arg: Void, pop: *Pair(F32, F32)) f32 {
        return pop._0.data + pop._1.data;
    }
    pub fn @"0x93 f32.sub"(ctx: *Execution, arg: Void, pop: *Pair(F32, F32)) f32 {
        return pop._0.data - pop._1.data;
    }
    pub fn @"0x94 f32.mul"(ctx: *Execution, arg: Void, pop: *Pair(F32, F32)) f32 {
        return pop._0.data * pop._1.data;
    }
    pub fn @"0x95 f32.div"(ctx: *Execution, arg: Void, pop: *Pair(F32, F32)) f32 {
        return pop._0.data / pop._1.data;
    }
    pub fn @"0x96 f32.min"(ctx: *Execution, arg: Void, pop: *Pair(F32, F32)) f32 {
        return std.math.min(pop._0.data, pop._1.data);
    }
    pub fn @"0x97 f32.max"(ctx: *Execution, arg: Void, pop: *Pair(F32, F32)) f32 {
        return std.math.max(pop._0.data, pop._1.data);
    }
    pub fn @"0x98 f32.copysign"(ctx: *Execution, arg: Void, pop: *Pair(F32, F32)) f32 {
        return std.math.copysign(f32, pop._0.data, pop._1.data);
    }
    pub fn @"0x99 f64.abs"(ctx: *Execution, arg: Void, pop: *F64) f64 {
        return @fabs(pop.data);
    }
    pub fn @"0x9A f64.neg"(ctx: *Execution, arg: Void, pop: *F64) f64 {
        return -pop.data;
    }
    pub fn @"0x9B f64.ceil"(ctx: *Execution, arg: Void, pop: *F64) f64 {
        return @ceil(pop.data);
    }
    pub fn @"0x9C f64.floor"(ctx: *Execution, arg: Void, pop: *F64) f64 {
        return @floor(pop.data);
    }
    pub fn @"0x9D f64.trunc"(ctx: *Execution, arg: Void, pop: *F64) f64 {
        return @trunc(pop.data);
    }
    pub fn @"0x9E f64.nearest"(ctx: *Execution, arg: Void, pop: *F64) f64 {
        return @round(pop.data);
    }
    pub fn @"0x9F f64.sqrt"(ctx: *Execution, arg: Void, pop: *F64) f64 {
        return @sqrt(pop.data);
    }
    pub fn @"0xA0 f64.add"(ctx: *Execution, arg: Void, pop: *Pair(F64, F64)) f64 {
        return pop._0.data + pop._1.data;
    }
    pub fn @"0xA1 f64.sub"(ctx: *Execution, arg: Void, pop: *Pair(F64, F64)) f64 {
        return pop._0.data - pop._1.data;
    }
    pub fn @"0xA2 f64.mul"(ctx: *Execution, arg: Void, pop: *Pair(F64, F64)) f64 {
        return pop._0.data * pop._1.data;
    }
    pub fn @"0xA3 f64.div"(ctx: *Execution, arg: Void, pop: *Pair(F64, F64)) f64 {
        return pop._0.data / pop._1.data;
    }
    pub fn @"0xA4 f64.min"(ctx: *Execution, arg: Void, pop: *Pair(F64, F64)) f64 {
        return std.math.min(pop._0.data, pop._1.data);
    }
    pub fn @"0xA5 f64.max"(ctx: *Execution, arg: Void, pop: *Pair(F64, F64)) f64 {
        return std.math.max(pop._0.data, pop._1.data);
    }
    pub fn @"0xA6 f64.copysign"(ctx: *Execution, arg: Void, pop: *Pair(F64, F64)) f64 {
        return std.math.copysign(f64, pop._0.data, pop._1.data);
    }
    pub fn @"0xA7 i32.wrap_i64"(ctx: *Execution, arg: Void, pop: *U64) u32 {
        return @truncate(u32, std.math.maxInt(u32) & pop.data);
    }
    pub fn @"0xA8 i32.trunc_f32_s"(ctx: *Execution, arg: Void, pop: *F32) !i32 {
        return floatToInt(i32, f32, pop.data);
    }
    pub fn @"0xA9 i32.trunc_f32_u"(ctx: *Execution, arg: Void, pop: *F32) !u32 {
        return floatToInt(u32, f32, pop.data);
    }
    pub fn @"0xAA i32.trunc_f64_s"(ctx: *Execution, arg: Void, pop: *F64) !i32 {
        return floatToInt(i32, f64, pop.data);
    }
    pub fn @"0xAB i32.trunc_f64_u"(ctx: *Execution, arg: Void, pop: *F64) !u32 {
        return floatToInt(u32, f64, pop.data);
    }
    pub fn @"0xAC i64.extend_i32_s"(ctx: *Execution, arg: Void, pop: *I64) i64 {
        return pop.data;
    }
    pub fn @"0xAD i64.extend_i32_u"(ctx: *Execution, arg: Void, pop: *U32) u64 {
        return pop.data;
    }
    pub fn @"0xAE i64.trunc_f32_s"(ctx: *Execution, arg: Void, pop: *F32) !i64 {
        return floatToInt(i64, f32, pop.data);
    }
    pub fn @"0xAF i64.trunc_f32_u"(ctx: *Execution, arg: Void, pop: *F32) !u64 {
        return floatToInt(u64, f32, pop.data);
    }

    pub fn @"0xB0 i64.trunc_f64_s"(ctx: *Execution, arg: Void, pop: *F64) !i64 {
        return floatToInt(i64, f64, pop.data);
    }
    pub fn @"0xB1 i64.trunc_f64_u"(ctx: *Execution, arg: Void, pop: *F64) !u64 {
        return floatToInt(u64, f64, pop.data);
    }
    pub fn @"0xB2 f32.convert_i32_s"(ctx: *Execution, arg: Void, pop: *I32) f32 {
        return @intToFloat(f32, pop.data);
    }
    pub fn @"0xB3 f32.convert_i32_u"(ctx: *Execution, arg: Void, pop: *U32) f32 {
        return @intToFloat(f32, pop.data);
    }
    pub fn @"0xB4 f32.convert_i64_s"(ctx: *Execution, arg: Void, pop: *I64) f32 {
        return @intToFloat(f32, pop.data);
    }
    pub fn @"0xB5 f32.convert_i64_u"(ctx: *Execution, arg: Void, pop: *U64) f32 {
        return @intToFloat(f32, pop.data);
    }
    pub fn @"0xB6 f32.demote_f64"(ctx: *Execution, arg: Void, pop: *F64) f32 {
        return @floatCast(f32, pop.data);
    }
    pub fn @"0xB7 f64.convert_i32_s"(ctx: *Execution, arg: Void, pop: *I32) f64 {
        return @intToFloat(f64, pop.data);
    }
    pub fn @"0xB8 f64.convert_i32_u"(ctx: *Execution, arg: Void, pop: *U32) f64 {
        return @intToFloat(f64, pop.data);
    }
    pub fn @"0xB9 f64.convert_i64_s"(ctx: *Execution, arg: Void, pop: *I64) f64 {
        return @intToFloat(f64, pop.data);
    }
    pub fn @"0xBA f64.convert_i64_u"(ctx: *Execution, arg: Void, pop: *U64) f64 {
        return @intToFloat(f64, pop.data);
    }
    pub fn @"0xBB f64.promote_f32"(ctx: *Execution, arg: Void, pop: *F32) f64 {
        return @floatCast(f64, pop.data);
    }
    pub fn @"0xBC i32.reinterpret_f32"(ctx: *Execution, arg: Void, pop: *F32) i32 {
        return @bitCast(i32, pop.data);
    }
    pub fn @"0xBD i64.reinterpret_f64"(ctx: *Execution, arg: Void, pop: *F64) i64 {
        return @bitCast(i64, pop.data);
    }
    pub fn @"0xBE f32.reinterpret_i32"(ctx: *Execution, arg: Void, pop: *I32) f32 {
        return @bitCast(f32, pop.data);
    }
    pub fn @"0xBF f64.reinterpret_i64"(ctx: *Execution, arg: Void, pop: *I64) f64 {
        return @bitCast(f64, pop.data);
    }

    fn floatToInt(comptime Dst: type, comptime Src: type, val: Src) !Dst {
        if (!std.math.isFinite(val) or val > std.math.maxInt(Dst) or val < std.math.minInt(Dst)) {
            return error.InvalidConversionToInteger;
        }
        return @floatToInt(Dst, val);
    }
};
