const std = @import("std");
const Op = @import("op.zig");
const Execution = @import("execution.zig");

const Module = @This();

arena: std.heap.ArenaAllocator,
memory: u32 = 0,
funcs: []Func,
exports: std.StringHashMap(Export),

pub fn deinit(self: *Module) void {
    self.memory = 0;
    self.funcs = &[0]Func{};
    self.exports = std.StringHashMap(Export).init(&self.arena.allocator);
    self.arena.deinit();
}

pub const Type = enum {
    I32,
    I64,
    F32,
    F64,
};

pub const Export = union(enum) {
    Func: usize,
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
    arg: Op.Fixed64,
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

    // TODO: revisit if wasm ever becomes multi-threaded
    mutex: std.Mutex,

    fn call(instance: *Instance, name: []const u8, params: []Module.Type) !Value {
        const lock = self.mutex.acquire();
        defer lock.release();

        var stack: [1 << 10]u8 = undefined;
        Execution.run(self, &stack, name, params);
    }
};
