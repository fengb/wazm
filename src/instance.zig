const std = @import("std");

const Module = @import("module.zig");
const Op = @import("op.zig");
const Execution = @import("execution.zig");
const Memory = @import("Memory.zig");

const Instance = @This();

module: *const Module,
allocator: *std.mem.Allocator,
memory: Memory,
exports: std.StringHashMap(Export),
funcs: []const Func,

// TODO: revisit if wasm ever becomes multi-threaded
mutex: std.Thread.Mutex,

pub fn init(module: *const Module, allocator: *std.mem.Allocator, context: ?*c_void, comptime Imports: type) !Instance {
    var exports = std.StringHashMap(Export).init(allocator);
    errdefer exports.deinit();
    for (module.@"export") |exp| {
        try exports.putNoClobber(exp.field, .{ .Func = exp.index });
    }

    var funcs = std.ArrayList(Func).init(allocator);
    errdefer funcs.deinit();

    const karen = ImportManager(Imports);

    for (module.import) |import, i| {
        switch (import.kind) {
            .Function => {
                const type_idx = @enumToInt(import.kind.Function);
                const func_type = module.@"type"[type_idx];
                const lookup = karen.get(import.module, import.field) orelse return error.ImportNotFound;
                if (!std.meta.eql(lookup.return_type, func_type.return_type)) {
                    return error.ImportSignatureMismatch;
                }
                if (!std.mem.eql(Module.Type.Value, lookup.param_types, func_type.param_types)) {
                    return error.ImportSignatureMismatch;
                }

                try funcs.append(.{
                    .func_type = type_idx,
                    .params = func_type.param_types,
                    .result = func_type.return_type,
                    .locals = &[0]Module.Type.Value{},
                    .kind = .{
                        .imported = .{ .func = lookup.func, .frame_size = lookup.frame_size },
                    },
                });
            },
            else => @panic("Implement me"),
        }
    }

    for (module.code) |code, i| {
        const type_idx = @enumToInt(module.function[i].type_idx);
        const func_type = module.@"type"[type_idx];
        try funcs.append(.{
            .func_type = type_idx,
            .params = func_type.param_types,
            .result = func_type.return_type,
            .locals = code.locals,
            .kind = .{ .instrs = code.body },
        });
    }

    return Instance{
        .module = module,
        .mutex = .{},
        .memory = try Memory.init(allocator, context, 1),
        .exports = exports,
        .funcs = funcs.toOwnedSlice(),
        .allocator = allocator,
    };
}

pub fn deinit(self: *Instance) void {
    self.allocator.free(self.funcs);
    self.memory.deinit();
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
    const result = try Execution.run(self, &stack, func_id, converted_params[0..params.len]);
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

pub fn ImportManager(comptime Imports: type) type {
    const V = struct {
        func: ImportFunc,
        frame_size: usize,
        param_types: []const Module.Type.Value,
        return_type: ?Module.Type.Value,
    };
    const KV = struct {
        @"0": []const u8,
        @"1": V,
    };

    const helpers = struct {
        fn Unwrapped(comptime T: type) type {
            return switch (@typeInfo(T)) {
                .ErrorUnion => |eu_info| Unwrapped(eu_info.payload),
                .Enum => |e_info| if (e_info.is_exhaustive) @compileError("Enum must be exhaustive") else e_info.tag_type,
                .Struct => {
                    return std.meta.Int(.unsigned, @bitSizeOf(T));
                },
                else => T,
            };
        }

        fn shim(comptime func: anytype) ImportFunc {
            return struct {
                fn unwrap(raw: anytype) !Unwrapped(@TypeOf(raw)) {
                    const T = @TypeOf(raw);
                    return switch (@typeInfo(T)) {
                        .ErrorUnion => unwrap(try raw),
                        .Enum => @enumToInt(raw),
                        .Struct => @bitCast(Unwrapped(T), raw),
                        else => raw,
                    };
                }

                pub fn shimmed(ctx: *Execution, params: []const Op.Fixval) Op.WasmTrap!?Op.Fixval {
                    var args: std.meta.ArgsTuple(@TypeOf(func)) = undefined;
                    args[0] = ctx.memory;
                    inline for (std.meta.fields(@TypeOf(args))) |f, i| {
                        if (i == 0) continue;

                        const raw_value = switch (Unwrapped(f.field_type)) {
                            i32 => params[i - 1].I32,
                            i64 => params[i - 1].I64,
                            u32 => params[i - 1].U32,
                            u64 => params[i - 1].U64,
                            f32 => params[i - 1].F32,
                            f64 => params[i - 1].F64,
                            else => @compileError("Signature not supported"),
                        };
                        args[i] = switch (@typeInfo(f.field_type)) {
                            .Enum => @intToEnum(f.field_type, raw_value),
                            .Struct => @bitCast(f.field_type, raw_value),
                            else => raw_value,
                        };
                    }

                    // TODO: move async call to where this is being invoked
                    // const fixval_len = std.math.divCeil(comptime_int, @sizeOf(@Frame(func)), @sizeOf(Op.Fixval)) catch unreachable;
                    // const frame_loc = ctx.pushOpaque(fixval_len) catch unreachable;
                    // const frame = @ptrCast(*@Frame(func), frame_loc);
                    // comptime const opts = std.builtin.CallOptions{ .modifier = .async_kw };
                    // frame.* = @call(opts, func, args);
                    // const result = nosuspend await frame;

                    const result = try unwrap(@call(.{}, func, args));
                    return switch (@TypeOf(result)) {
                        void => null,
                        i32 => Op.Fixval{ .I32 = result },
                        i64 => Op.Fixval{ .I64 = result },
                        u32 => Op.Fixval{ .U32 = result },
                        u64 => Op.Fixval{ .U64 = result },
                        f32 => Op.Fixval{ .F32 = result },
                        f64 => Op.Fixval{ .F64 = result },
                        else => @compileError("Signature not supported"),
                    };
                }
            }.shimmed;
        }

        fn mapType(comptime T: type) ?Module.Type.Value {
            return switch (Unwrapped(T)) {
                void => null,
                i32, u32 => .I32,
                i64, u64 => .I64,
                f32 => .F32,
                f64 => .F64,
                else => @compileError("Type '" ++ @typeName(T) ++ "' not supported"),
            };
        }
    };

    const sep = "\x00\x00";

    var kvs: []const KV = &[0]KV{};
    inline for (std.meta.declarations(Imports)) |decl| {
        if (decl.is_pub) {
            inline for (std.meta.declarations(decl.data.Type)) |decl2| {
                if (decl2.is_pub) {
                    const func = @field(decl.data.Type, decl2.name);
                    const fn_info = @typeInfo(@TypeOf(func)).Fn;
                    const shimmed = helpers.shim(func);
                    kvs = kvs ++ [1]KV{.{
                        .@"0" = decl.name ++ sep ++ decl2.name,
                        .@"1" = .{
                            .func = shimmed,
                            .frame_size = @sizeOf(@Frame(shimmed)),
                            .param_types = params: {
                                var param_types: [fn_info.args.len - 1]Module.Type.Value = undefined;
                                for (param_types) |*param, i| {
                                    param.* = helpers.mapType(fn_info.args[i + 1].arg_type.?).?;
                                }
                                break :params &param_types;
                            },
                            .return_type = helpers.mapType(fn_info.return_type.?),
                        },
                    }};
                }
            }
        }
    }

    const map = if (kvs.len > 0) std.ComptimeStringMap(V, kvs) else {};

    return struct {
        pub fn get(module: []const u8, field: []const u8) ?V {
            if (kvs.len == 0) return null;

            var buffer: [1 << 10]u8 = undefined;
            var fbs = std.io.fixedBufferStream(&buffer);

            fbs.writer().writeAll(module) catch return null;
            fbs.writer().writeAll(sep) catch return null;
            fbs.writer().writeAll(field) catch return null;

            return map.get(fbs.getWritten());
        }
    };
}

const ImportFunc = fn (ctx: *Execution, params: []const Op.Fixval) Op.WasmTrap!?Op.Fixval;

pub const Func = struct {
    func_type: usize,
    params: []const Module.Type.Value,
    result: ?Module.Type.Value,
    locals: []const Module.Type.Value,
    kind: union(enum) {
        imported: struct {
            func: ImportFunc,
            frame_size: usize,
        },
        instrs: []const Module.Instr,
    },
};

test "" {
    _ = call;
}
