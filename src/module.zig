const std = @import("std");
const Bytecode = @import("bytecode.zig");
const Op = @import("op.zig");
const Execution = @import("execution.zig");

const Module = @This();

arena: std.heap.ArenaAllocator,
memory: u32 = 0,
func_types: []FuncType,
funcs: []Func,
imports: []Import,
exports: std.StringHashMap(Export),

pub fn deinit(self: *Module) void {
    self.arena.deinit();
    self.* = undefined;
}

pub fn instantiate(self: *Module, allocator: *std.mem.Allocator, imports: var) !Instance {
    var import_funcs = try std.ArrayList(Instance.ImportFunc).initCapacity(allocator, self.imports.len);
    errdefer import_funcs.deinit();

    for (self.imports) |import| cont: {
        inline for (std.meta.declarations(imports)) |module| {
            if (std.mem.eql(u8, module.name, import.module)) {
                inline for (std.meta.declarations(module)) |field| {
                    if (std.mem.eql(u8, module.name, import.module)) {
                        try import_funcs.append(
                            try Instance.ImportType.init(
                                self.func_types[import.func],
                                @field(module, field.name),
                            ),
                        );
                        break :cont;
                    }
                }
                return error.FieldNotFound;
            }
            return error.ModuleNotFound;
        }
    }

    return Instance{
        .module = self,
        .mutex = std.Mutex.init(),
        .memory = try allocator.alloc(u8, 65536),
        .allocator = allocator,
        .import_funcs = import_funcs.toSliceConst(),
    };
}

pub const Type = Bytecode.Type;

pub const Import = struct {
    module: []const u8,
    field: []const u8,
    kind: union(enum) {
        Func: usize,
    },
};

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
    op: *const Op,
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
    import_funcs: []const ImportFunc,

    fn deinit(self: *Instance) void {
        self.allocator.free(self.memory);
        self.* = undefined;
    }

    const ImportFunc = struct {
        const Func = @OpaqueType();
        ptr: *Func,

        fn init(func_type: FuncType, func: var) !ImportFunc {
            return .{
                // TODO: validate func_type
                .ptr = @ptrCast(*Func, func),
            };
        }
    };

    // TODO: revisit if wasm ever becomes multi-threaded
    mutex: std.Mutex,

    pub fn call(self: *Instance, name: []const u8, params: []Value) !?Value {
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

                var stack: [1 << 10]Op.Fixval align(16) = undefined;
                const result = try Execution.run(self, &stack, func_id, converted_params[0..params.len]);
                if (result) |res| {
                    return switch (func_type.result.?) {
                        .I32 => Value{ .I32 = res.I32 },
                        .I64 => Value{ .I64 = res.I64 },
                        .F32 => Value{ .F32 = res.F32 },
                        .F64 => Value{ .F64 = res.F64 },
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
