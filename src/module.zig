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
    arg: Op.Fixval,
};

pub const Value = union(Type.Value) {
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

    fn call(self: *Instance, name: []const u8, params: []Value) !?Value {
        const lock = self.mutex.acquire();
        defer lock.release();

        switch (self.module.exports.getValue(name) orelse return error.ExportNotFound) {
            .Func => |func_id| {
                const func = self.module.funcs[func_id];
                const func_type = self.module.func_types[func.func_type];
                if (params.len != func_type.params.len) {
                    return error.TypeSignatureMismatch;
                }

                var converted_params: [20]Op.Fixval = undefined;
                for (params) |param, i| {
                    if (param != func_type.params[i]) return error.TypeSignatureMismatch;

                    converted_params[i] = switch (param) {
                        .I32 => |data| .{ .I32 = data },
                        .I64 => |data| .{ .I64 = data },
                        .F32 => |data| .{ .F32 = data },
                        .F64 => |data| .{ .F64 = data },
                    };
                }

                var stack: [1 << 20]Op.Fixval align(8) = undefined;
                const result = try Execution.run(self, &stack, func_id, converted_params[0..params.len]);
                if (func_type.result) |return_type| {
                    return switch (return_type) {
                        .I32 => Value{ .I32 = result.I32 },
                        .I64 => Value{ .I64 = result.I64 },
                        .F32 => Value{ .F32 = result.F32 },
                        .F64 => Value{ .F64 = result.F64 },
                    };
                } else {
                    return null;
                }
            },
            else => return error.ExportNotAFunction,
        }
    }
};

test "" {
    _ = Instance.call;
}
