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

pub fn init(module: *Module, allocator: *std.mem.Allocator, comptime Imports: type) !Instance {
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
        try exports.putNoClobber(exp.field, .{ .Func = exp.index });
    }

    var funcs = std.ArrayList(Func).init(allocator);
    errdefer funcs.deinit();

    for (module.import) |import, i| {
        if (import.kind == .Function) {
            const type_idx = @enumToInt(import.kind.Function);
            const func_type = module.@"type"[type_idx];
            try funcs.append(.{
                .func_type = type_idx,
                .params = func_type.param_types,
                .result = func_type.return_type,
                .locals = &[0]Module.Type.Value{},
                .kind = .{
                    .imported = ImportedFunc.init(Imports, import.module, import.field),
                },
            });
        }
    }

    for (module.code) |body, i| {
        const type_idx = @enumToInt(module.function[i].type_idx);
        const func_type = module.@"type"[type_idx];
        try funcs.append(.{
            .func_type = type_idx,
            .params = func_type.param_types,
            .result = func_type.return_type,
            .locals = body.locals,
            .kind = .{ .instrs = body.code },
        });
    }

    return Instance{
        .module = module,
        .mutex = std.Mutex{},
        .memory = try allocator.alloc(u8, 65536),
        .exports = exports,
        .funcs = funcs.toOwnedSlice(),
        .allocator = allocator,
    };
}

pub fn deinit(self: *Instance) void {
    self.allocator.free(self.funcs);
    self.allocator.free(self.memory);
    self.exports.deinit();
    self.* = undefined;
}

pub fn call(self: *Instance, name: []const u8, params: anytype) !?Value {
    const lock = self.mutex.acquire();
    defer lock.release();

    const exp = self.exports.get(name) orelse return error.ExportNotFound;
    if (exp != .Func) {
        return error.ExportNotAFunction;
    }

    const func_id = exp.Func;
    const func = self.funcs[func_id];
    if (params.len != func.params.len) {
        return error.TypeSignatureMismatch;
    }

    var converted_params: [params.len]Op.Fixval = undefined;
    inline for ([_]void{{}} ** params.len) |_, i| {
        const param_type: Module.Type.Value = switch (@TypeOf(params[i])) {
            i32, u32 => .I32,
            i64, u64 => .I64,
            f32 => .F32,
            f64 => .F64,
            else => @compileError("Unsupported type"),
        };
        if (param_type != func.params[i]) return error.TypeSignatureMismatch;

        converted_params[i] = switch (@TypeOf(params[i])) {
            i32 => .{ .I32 = params[i] },
            i64 => .{ .I64 = params[i] },
            u32 => .{ .U32 = params[i] },
            u64 => .{ .U64 = params[i] },
            f32 => .{ .F32 = params[i] },
            f64 => .{ .F64 = params[i] },
            else => @compileError("Unsupported type"),
        };
    }

    var stack: [1 << 10]Op.Fixval = undefined;
    const result = try self.run(&stack, func_id, converted_params[0..params.len]);
    if (result) |res| {
        return switch (func.result.?) {
            .I32 => Value{ .I32 = res.I32 },
            .I64 => Value{ .I64 = res.I64 },
            .F32 => Value{ .F32 = res.F32 },
            .F64 => Value{ .F64 = res.F64 },
        };
    } else {
        return null;
    }
}

fn run(self: *Instance, stack: []Op.Fixval, func_id: usize, params: []Op.Fixval) !?Op.Fixval {
    var ctx = Execution.Context{
        .memory = self.memory,
        .funcs = self.funcs,
        .allocator = self.allocator,
        .jumps = self.module.jumps,

        .stack = stack,
        .stack_top = 0,
    };
    // Context may have grown the memory, so we need to copy the new memory in
    // TODO: rearchitect so this copying is unnecessary
    defer self.memory = ctx.memory;

    // initCall assumes the params are already pushed onto the stack
    for (params) |param| {
        try ctx.push(Op.Fixval, param);
    }

    try ctx.initCall(func_id);

    while (true) {
        const func = ctx.funcs[ctx.current_frame.func];
        // TODO: investigate imported calling another imported
        if (ctx.current_frame.instr == 0 and func.kind == .imported) {
            const result = try func.kind.imported.func(&ctx, ctx.getLocals(0, func.params.len));

            _ = ctx.unwindCall();

            if (ctx.current_frame.isTerminus()) {
                std.debug.assert(ctx.stack_top == 0);
                return result;
            } else {
                if (result) |res| {
                    ctx.push(Op.Fixval, res) catch unreachable;
                }
            }
        } else if (ctx.current_frame.instr < func.kind.instrs.len) {
            const instr = func.kind.instrs[ctx.current_frame.instr];
            ctx.current_frame.instr += 1;

            ctx.stack_top -= instr.op.pop.len;
            const pop_array: [*]Op.Fixval = ctx.stack.ptr + ctx.stack_top;

            const result = try instr.op.step(&ctx, instr.arg, pop_array);
            if (result) |res| {
                try ctx.push(@TypeOf(res), res);
            }
        } else {
            const result = ctx.unwindCall();

            if (ctx.current_frame.isTerminus()) {
                std.debug.assert(ctx.stack_top == 0);
                return result;
            } else {
                if (result) |res| {
                    ctx.push(Op.Fixval, res) catch unreachable;
                }
            }
        }
    }
}

pub const Value = union(Module.Type.Value) {
    I32: i32,
    I64: i64,
    F32: f32,
    F64: f64,
};

pub const Export = union(enum) {
    Func: usize,
    Table: usize,
    Memory: usize,
    Global: usize,
};

const ImportedFunc = struct {
    func: fn (ctx: *Execution.Context, params: []const Op.Fixval) Op.WasmTrap!?Op.Fixval,
    frame_size: usize,

    fn init(comptime Imports: type, module: []const u8, field: []const u8) ImportedFunc {
        inline for (std.meta.declarations(Imports)) |decl| {
            if (decl.is_pub and std.mem.eql(u8, module, decl.name)) {
                inline for (std.meta.declarations(decl.data.Type)) |decl2| {
                    if (decl2.is_pub and std.mem.eql(u8, field, decl2.name)) {
                        const func = @field(decl.data.Type, decl2.name);
                        comptime const wrapped = wrap(func);
                        return .{
                            .func = wrapped,
                            .frame_size = @frameSize(wrapped),
                        };
                    }
                }

                @panic("Func not found");
            }
        }

        @panic("Module not found");
    }

    fn wrap(comptime func: anytype) fn (self: *Execution.Context, params: []const Op.Fixval) Op.WasmTrap!?Op.Fixval {
        return (struct {
            pub fn wrapped(ctx: *Execution.Context, params: []const Op.Fixval) Op.WasmTrap!?Op.Fixval {
                var args: std.meta.ArgsTuple(@TypeOf(func)) = undefined;
                std.debug.assert(@TypeOf(args[0]) == *Execution.Context);
                args[0] = ctx;
                inline for (std.meta.fields(@TypeOf(args))) |f, i| {
                    if (i == 0) continue;

                    switch (f.field_type) {
                        i32 => args[i] = params[i - 1].I32,
                        i64 => args[i] = params[i - 1].I64,
                        u32 => args[i] = params[i - 1].U32,
                        u64 => args[i] = params[i - 1].U64,
                        f32 => args[i] = params[i - 1].F32,
                        f64 => args[i] = params[i - 1].F64,
                        else => @panic("Signature not supported"),
                    }
                }

                // TODO: move async call to where this is being invoked
                // const fixval_len = std.math.divCeil(comptime_int, @sizeOf(@Frame(func)), @sizeOf(Op.Fixval)) catch unreachable;
                // const frame_loc = ctx.pushOpaque(fixval_len) catch unreachable;
                // const frame = @ptrCast(*@Frame(func), frame_loc);
                // comptime const opts = std.builtin.CallOptions{ .modifier = .async_kw };
                // frame.* = @call(opts, func, args);
                // const result = nosuspend await frame;

                const result = @call(.{}, func, args);
                return switch (@TypeOf(result)) {
                    void => null,
                    i32 => Op.Fixval{ .I32 = result },
                    i64 => Op.Fixval{ .I64 = result },
                    u32 => Op.Fixval{ .U32 = result },
                    u64 => Op.Fixval{ .U64 = result },
                    f32 => Op.Fixval{ .F32 = result },
                    f64 => Op.Fixval{ .F64 = result },
                    else => @panic("Signature not supported"),
                };
            }
        }).wrapped;
    }
};

pub const Func = struct {
    func_type: usize,
    params: []Module.Type.Value,
    result: ?Module.Type.Value,
    locals: []Module.Type.Value,
    kind: union(enum) {
        imported: ImportedFunc,
        instrs: []Module.Instr,
    },
};

test "" {
    _ = call;
}
