const std = @import("std");
const Bytecode = @import("bytecode.zig");
const Op = @import("op.zig");
const Execution = @import("execution.zig");

const Module = @This();

arena: std.heap.ArenaAllocator,
memory: u32 = 0,
func_types: []FuncType,
funcs: []Func,
exports: std.StringHashMap(Export),

pub fn deinit(self: *Module) void {
    self.arena.deinit();
    self.* = undefined;
}

pub const Type = Bytecode.Type;

pub const Export = union(enum) {
    Func: usize,
};

pub const FuncType = struct {
    params: []Type.Value,
    result: ?Type.Value,
};

pub const Func = struct {
    name: ?[]const u8,
    func_type: usize,
    locals: []Type.Value,
    instrs: []Instr,
};

pub const Instr = struct {
    opcode: u8,
    arg: Op.Fixed64,
};

pub const Value = union(enum) {
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

    fn call(instance: *Instance, name: []const u8, params: []Value) !Value {
        const lock = self.mutex.acquire();
        defer lock.release();

        var stack: [1 << 10]u8 = undefined;
        Execution.run(self, &stack, name, params);
    }
};
