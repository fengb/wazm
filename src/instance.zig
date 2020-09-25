const std = @import("std");

const util = @import("util.zig");
const Module = @import("module.zig");
const Op = @import("op.zig");
const Execution = @import("execution.zig");

pub fn init(module: *Module, allocator: *std.mem.Allocator, comptime Imports: type) !Instance(Imports) {
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
                    .imported = .{
                        .module = import.module,
                        .field = import.field,
                    },
                },
            });
        }
    }

    for (module.code) |body, i| {
        const type_idx = @enumToInt(module.function[i]);
        const func_type = module.@"type"[type_idx];
        try funcs.append(.{
            .func_type = type_idx,
            .params = func_type.param_types,
            .result = func_type.return_type,
            .locals = body.locals,
            .kind = .{ .instrs = body.code },
        });
    }

    return Instance(Imports){
        .module = module,
        .mutex = std.Mutex{},
        .memory = try allocator.alloc(u8, 65536),
        .exports = exports,
        .funcs = funcs.toOwnedSlice(),
        .allocator = allocator,
    };
}

pub fn Instance(comptime Imports: type) type {
    return struct {
        const Self = @This();

        module: *Module,
        memory: []u8,
        allocator: *std.mem.Allocator,
        exports: std.StringHashMap(Export),
        funcs: []Func,

        // TODO: revisit if wasm ever becomes multi-threaded
        mutex: std.Mutex,

        pub fn deinit(self: *Self) void {
            self.allocator.free(self.funcs);
            self.allocator.free(self.memory);
            self.exports.deinit();
            self.* = undefined;
        }

        pub fn call(self: *Self, name: []const u8, params: []const Value) !?Value {
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

            var converted_params: [20]Op.Fixval = undefined;
            for (params) |param, i| {
                if (param != func.params[i]) return error.TypeSignatureMismatch;

                converted_params[i] = switch (param) {
                    .I32 => |data| .{ .I32 = data },
                    .I64 => |data| .{ .I64 = data },
                    .F32 => |data| .{ .F32 = data },
                    .F64 => |data| .{ .F64 = data },
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

        fn run(self: *Self, stack: []Op.Fixval, func_id: usize, params: []Op.Fixval) !?Op.Fixval {
            var ctx = Execution.Context{
                .memory = self.memory,
                .funcs = self.funcs,
                .allocator = self.allocator,

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
                    const result = self.importCall(
                        &ctx,
                        func.kind.imported.module,
                        func.kind.imported.field,
                        ctx.getLocals(0, func.params.len),
                    );

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

        fn importCall(self: *Self, ctx: *Execution.Context, module: []const u8, field: []const u8, params: []const Op.Fixval) ?Op.Fixval {
            inline for (std.meta.declarations(Imports)) |decl| {
                if (std.mem.eql(u8, module, decl.name)) {
                    inline for (std.meta.declarations(decl.data.Type)) |decl2| {
                        if (std.mem.eql(u8, field, decl2.name)) {
                            const func = @field(decl.data.Type, decl2.name);
                            var args: util.ArgsTuple(@TypeOf(func)) = undefined;
                            inline for (std.meta.fields(@TypeOf(args))) |f, i| {
                                switch (f.field_type) {
                                    i32 => args[i] = params[i].I32,
                                    i64 => args[i] = params[i].I64,
                                    u32 => args[i] = params[i].U32,
                                    u64 => args[i] = params[i].U64,
                                    f32 => args[i] = params[i].F32,
                                    f64 => args[i] = params[i].F64,
                                    else => @panic("Signature not supported"),
                                }
                            }
                            const fixval_len = std.math.divCeil(comptime_int, @sizeOf(@Frame(func)), @sizeOf(Op.Fixval)) catch unreachable;
                            const frame_loc = ctx.pushOpaque(fixval_len) catch unreachable;
                            const frame = @ptrCast(*@Frame(func), frame_loc);

                            comptime const opts = std.builtin.CallOptions{ .modifier = .async_kw };
                            frame.* = @call(opts, func, args);
                            const result = nosuspend await frame;
                            return switch (@TypeOf(result)) {
                                i32 => Op.Fixval{ .I32 = result },
                                i64 => Op.Fixval{ .I64 = result },
                                u32 => Op.Fixval{ .U32 = result },
                                u64 => Op.Fixval{ .U64 = result },
                                f32 => Op.Fixval{ .F32 = result },
                                f64 => Op.Fixval{ .F64 = result },
                                else => @panic("Signature not supported"),
                            };
                        }
                    }

                    @panic("Func not found");
                }
            }

            @panic("Module not found");
        }
    };
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

pub const Func = struct {
    func_type: usize,
    params: []Module.Type.Value,
    result: ?Module.Type.Value,
    locals: []Module.Type.Value,
    kind: union(enum) {
        imported: struct {
            module: []const u8,
            field: []const u8,
        },
        instrs: []Module.Instr,
    },
};

test "" {
    _ = Instance(struct {}).call;
}
