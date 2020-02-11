const std = @import("std");
const Op = @import("op.zig");

pub const Module = struct {
    arena: std.heap.ArenaAllocator,
    memory: u32 = 0,
    funcs: []Func,
    exports: []Export,

    pub fn deinit(self: *Module) void {
        self.arena.deinit();
        self.funcs = &[0]Func{};
        self.exports = &[0]Export{};
    }

    pub const Type = enum {
        I32,
        I64,
        F32,
        F64,
    };

    pub const Export = struct {
        name: []const u8,
        value: union(enum) {
            func: usize,
        },
    };

    pub const Func = struct {
        name: ?[]const u8,
        params: []Type,
        result: ?Type,
        locals: []Type,
        instrs: []Instr,
    };

    pub const Instr = struct {
        opcode: u8,
        arg: Op.Arg,
    };
};

pub const WasmTrap = error{
    Unreachable,
    Overflow,
    OutOfBounds,
    DivisionByZero,
    InvalidConversionToInteger,
};

pub const Value = union {
    I32: i32,
    I64: i64,
    F32: f32,
    F64: f64,
};

pub const Instance = struct {
    module: *Module,
    memory: []u8,
    allocator: *std.mem.Allocator,

    // TODO: move these to a function execution context
    locals: StackLookup,
    globals: StackLookup,

    const StackLookup = struct {
        memory: []u8,
        lookup_meta: []struct {
            offset: usize,
            typ: Module.Type,
        },

        pub fn get(self: StackLookup, num: usize) Value {
            const meta = self.lookup_meta[num];
            return switch (meta.typ) {
                .I32 => .{ .I32 = std.mem.readIntLittle(i32, self.ptr32(meta.offset)) },
                .I64 => .{ .I64 = std.mem.readIntLittle(i64, self.ptr64(meta.offset)) },
                .F32 => .{ .F32 = std.mem.readIntLittle(f32, self.ptr32(meta.offset)) },
                .F64 => .{ .F64 = std.mem.readIntLittle(f64, self.ptr64(meta.offset)) },
            };
        }

        pub fn set(self: StackLookup, num: usize, value: Value) void {
            const meta = self.lookup_meta[num];
            switch (meta.typ) {
                .I32 => std.mem.writeIntLittle(i32, self.ptr32(meta.offset), value.I32),
                .I64 => std.mem.writeIntLittle(i64, self.ptr64(meta.offset), value.I64),
                .F32 => std.mem.writeIntLittle(f32, self.ptr32(meta.offset), value.F32),
                .F64 => std.mem.writeIntLittle(f64, self.ptr64(meta.offset), value.F64),
            }
        }

        fn ptr32(self: StackLookup, offset: usize) *[4]u8 {
            return @ptrCast(*[4]u8, &self.memory[offset]);
        }

        fn ptr64(self: StackLookup, offset: usize) *[8]u8 {
            return @ptrCast(*[8]u8, &self.memory[offset]);
        }
    };

    pub fn memGet(self: Instance, start: usize, offset: usize, comptime length: usize) !*[length]u8 {
        const tail = start +% offset +% (length - 1);
        const is_overflow = tail < start;
        const is_seg_fault = tail >= self.memory.len;
        if (is_overflow or is_seg_fault) {
            return error.OutOfBounds;
        }
        return @ptrCast(*[length]u8, &self.memory[start + offset]);
    }
};
