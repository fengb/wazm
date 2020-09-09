const std = @import("std");
const Module = @import("module.zig");
const Op = @import("op.zig");
const Execution = @import("execution.zig");

const Instance = @This();

module: *Module,
memory: []u8,
allocator: *std.mem.Allocator,
exports: std.StringHashMap(Export),
funcs: []Func,

// TODO: revisit if wasm ever becomes multi-threaded
mutex: std.Mutex,

pub const Export = union(enum) {
    Func: usize,
    Table: usize,
    Memory: usize,
    Global: usize,
};

pub const Func = struct {
    func_type: usize,
    params: []Module.Type.Value,
    locals: []Module.Type.Value,
    result: ?Module.Type.Value,
    instrs: []Module.Instr,
};

pub fn init(module: *Module, allocator: *std.mem.Allocator, imports: anytype) !Instance {
    //    var import_funcs = try std.ArrayList(Instance.ImportFunc).initCapacity(allocator, module.imports.len);
    //    errdefer import_funcs.deinit();
    //    for (module.imports) |import| cont: {
    //        inline for (std.meta.declarations(imports)) |namespace| {
    //            if (std.mem.eql(u8, namespace.name, import.module)) {
    //                inline for (std.meta.declarations(namespace)) |field| {
    //                    if (std.mem.eql(u8, namespace.name, import.module)) {
    //                        try import_funcs.append(
    //                            try Instance.ImportType.init(
    //                                namespace.func_types[import.func],
    //                                @field(namespace, field.name),
    //                            ),
    //                        );
    //                        break :cont;
    //                    }
    //                }
    //                return error.FieldNotFound;
    //            }
    //            return error.NamespaceNotFound;
    //        }
    //    }
    var exports = std.StringHashMap(Export).init(allocator);
    errdefer exports.deinit();
    for (module.@"export") |exp| {
        try exports.putNoClobber(exp.field, .{ .Func = @enumToInt(exp.index.Function) });
    }

    var funcs = std.ArrayList(Func).init(allocator);
    errdefer funcs.deinit();
    for (module.code) |body, i| {
        const type_idx = @enumToInt(module.function[i]);
        const func_type = module.@"type"[type_idx];
        try funcs.append(.{
            .func_type = type_idx,
            .params = func_type.param_types,
            // FIXME
            .locals = &[0]Module.Type.Value{},
            .result = func_type.return_type,
            .instrs = body.code,
        });
    }

    return Instance{
        .module = module,
        .mutex = std.Mutex{},
        .memory = try allocator.alloc(u8, 65536),
        .exports = exports,
        .funcs = funcs.items,
        .allocator = allocator,
    };
}

pub fn deinit(self: *Instance) void {
    self.allocator.free(self.funcs);
    self.allocator.free(self.memory);
    self.exports.deinit();
    self.* = undefined;
}

pub fn call(self: *Instance, name: []const u8, params: []const Value) !?Value {
    const lock = self.mutex.acquire();
    defer lock.release();

    switch (self.exports.get(name) orelse return error.ExportNotFound) {
        .Func => |func_id| {
            return self.callForTest(func_id, params);
        },
        else => return error.ExportNotAFunction,
    }
}

// TODO: delete me
pub fn callForTest(self: *Instance, func_id: usize, params: []const Value) !?Value {
    const func = self.module.function[func_id];
    const func_type = self.module.@"type"[@enumToInt(func)];
    if (params.len != func_type.param_types.len) {
        return error.TypeSignatureMismatch;
    }

    var converted_params: [20]Op.Fixval = undefined;
    for (params) |param, i| {
        if (param != func_type.param_types[i]) return error.TypeSignatureMismatch;

        converted_params[i] = switch (param) {
            .I32 => |data| .{ .I32 = data },
            .I64 => |data| .{ .I64 = data },
            .F32 => |data| .{ .F32 = data },
            .F64 => |data| .{ .F64 = data },
        };
    }

    var stack: [1 << 10]Op.Fixval = undefined;
    const result = try Execution.run(self, &stack, func_id, converted_params[0..params.len]);
    if (result) |res| {
        return switch (func_type.return_type.?) {
            .I32 => Value{ .I32 = res.I32 },
            .I64 => Value{ .I64 = res.I64 },
            .F32 => Value{ .F32 = res.F32 },
            .F64 => Value{ .F64 = res.F64 },
        };
    } else {
        return null;
    }
}

pub const Value = union(Module.Type.Value) {
    I32: i32,
    I64: i64,
    F32: f32,
    F64: f64,
};

test "" {
    _ = Instance.call;
}
