const std = @import("std");
const Module = @import("module.zig");
const Op = @import("op.zig");

const magic_number = std.mem.readIntLittle(u32, "\x00asm");

const Bytecode = @This();

arena: std.heap.ArenaAllocator,

/// Code=1
@"type": []struct {
    form: Type.Form, // TODO: why is this called form?
    param_types: []Type.Value,
    return_type: ?Type.Value,
},

/// Code=2
import: []struct {
    module: []const u8,
    field: []const u8,
    kind: ExternalKind,
},

/// Code=3
function: []Index.FuncType,

/// Code=4
table: []struct {
    element_type: Type.Elem,
    limits: ResizableLimits,
},

/// Code=5
memory: []struct {
    limits: ResizableLimits,
},

/// Code=6
global: []struct {
    @"type": struct {
        content_type: Type.Value,
        mutability: bool,
    },
    init: InitExpr,
},

/// Code=7
@"export": []struct {
    field: []const u8,
    index: union(ExternalKind) {
        Table: Index.Table,
        Function: Index.Function,
        Memory: Index.Memory,
        Global: Index.Global,
    },
},

/// Code=8
start: ?struct {
    index: Index.Function,
},

/// Code=9
element: []struct {
    index: Index.Table,
    offset: InitExpr,
    elems: []Index.Function,
},

/// Code=10
code: []struct {
    locals: []struct {
        @"type": []Type.Value,
    },
    code: []Module.Instr,
},

/// Code=11
data: []struct {
    index: Index.Memory,
    offset: InitExpr,
    data: []const u8,
},

/// Code=0
custom: []struct {
    name: []const u8,
    payload: []const u8,
},

fn init(arena: std.heap.ArenaAllocator) Bytecode {
    var result: Bytecode = undefined;
    result.arena = arena;

    inline for (std.meta.fields(Bytecode)) |field| {
        if (comptime !std.mem.eql(u8, field.name, "arena")) {
            @field(result, field.name) = switch (@typeInfo(field.field_type)) {
                .Pointer => |ptr_info| &[0]ptr_info.child{},
                .Optional => null,
                else => @compileError("No idea how to initialize " ++ field.name ++ " " ++ @typeName(field.field_type)),
            };
        }
    }
    return result;
}

const Index = struct {
    const FuncType = enum(u32) { _ };
    const Table = enum(u32) { _ };
    const Function = enum(u32) { _ };
    const Memory = enum(u32) { _ };
    const Global = enum(u32) { _ };
};

pub const Type = struct {
    pub const Value = enum(i7) {
        I32 = -0x01,
        I64 = -0x02,
        F32 = -0x03,
        F64 = -0x04,
    };

    const Block = enum(i7) {
        I32 = -0x01,
        I64 = -0x02,
        F32 = -0x03,
        F64 = -0x04,
        Empty = -0x40,
    };

    const Elem = enum(i7) {
        Anyfunc = -0x10,
    };

    const Form = enum(i7) {
        Func = -0x20,
    };
};

const ExternalKind = enum(u7) {
    Function = 0,
    Table = 1,
    Memory = 2,
    Global = 3,
};

const ResizableLimits = struct {
    initial: u32,
    maximum: ?u32,
};

const InitExpr = struct {};

fn readVarint(comptime T: type, in_stream: var) !T {
    const U = @TypeOf(std.math.absCast(@as(T, 0)));
    const S = std.math.Log2Int(T);

    if (std.meta.bitCount(T) < 8) {
        const byte = try in_stream.readByte();
        return @bitCast(T, try std.math.cast(U, byte));
    }

    var unsigned_result: U = 0;
    var shift: S = 0;
    while (true) : (shift = try std.math.add(S, shift, 7)) {
        const byte = try in_stream.readByte();
        unsigned_result += try std.math.shlExact(U, byte & 0x7F, shift);

        if (byte & 0x80 == 0) {
            if (U == T) {
                return unsigned_result;
            } else if (0x40 != 0 and !@addWithOverflow(S, shift, 7, &shift)) {
                return @bitCast(T, unsigned_result) | @as(T, -1) << shift;
            } else {
                return @bitCast(T, unsigned_result);
            }
        }
    }
}

test "readVarint" {
    {
        var in = std.io.SliceInStream.init("\xE5\x8E\x26");
        std.testing.expectEqual(@as(u32, 624485), try readVarint(u32, &in.stream));
        in.pos = 0;
        std.testing.expectEqual(@as(u21, 624485), try readVarint(u21, &in.stream));
    }
    {
        var in = std.io.SliceInStream.init("\xC0\xBB\x78");
        std.testing.expectEqual(@as(i32, -123456), try readVarint(i32, &in.stream));
        in.pos = 0;
        std.testing.expectEqual(@as(i21, -123456), try readVarint(i21, &in.stream));
    }
    {
        var in = std.io.SliceInStream.init("\x7F");
        std.testing.expectEqual(@as(i7, -1), try readVarint(i7, &in.stream));
        in.pos = 0;
        std.testing.expectEqual(@as(i21, -1), try readVarint(i21, &in.stream));
        in.pos = 0;
        std.testing.expectEqual(@as(i32, -1), try readVarint(i32, &in.stream));
    }
}

fn readVarintEnum(comptime E: type, in_stream: var) !E {
    const raw = try readVarint(std.meta.TagType(E), in_stream);
    return try std.meta.intToEnum(E, raw);
}

fn expectEos(in_stream: var) !void {
    var tmp: [1]u8 = undefined;
    const len = try in_stream.read(&tmp);
    if (len != 0) {
        return error.NotEndOfStream;
    }
}

/// A stream that can only read a fixed number of bytes.
pub fn FixedInStream(comptime Error: type) type {
    return struct {
        const Self = @This();
        pub const Stream = std.io.InStream(Error);

        stream: Stream,

        underlying_stream: *Stream,

        size: usize,
        remaining: usize,

        pub fn init(underlying_stream: *Stream, size: usize) Self {
            return Self{
                .size = size,
                .remaining = size,

                .underlying_stream = underlying_stream,
                .stream = Stream{ .readFn = readFn },
            };
        }

        fn readFn(in_stream: *Stream, dest: []u8) Error!usize {
            const self = @fieldParentPtr(Self, "stream", in_stream);

            const bytes = try self.underlying_stream.read(dest[0..std.math.min(dest.len, self.remaining)]);
            self.remaining -= bytes;
            return bytes;
        }
    };
}

test "FixedInStream" {
    var string = "hello world";
    var slice_in_stream = std.io.SliceInStream.init(string);

    var fixed_in_stream = FixedInStream(std.io.SliceInStream.Error).init(&slice_in_stream.stream, 5);
    std.testing.expectEqual(@as(u8, 'h'), try fixed_in_stream.stream.readByte());
    std.testing.expectEqual(@as(u8, 'e'), try fixed_in_stream.stream.readByte());
    std.testing.expectEqual(@as(u8, 'l'), try fixed_in_stream.stream.readByte());
    std.testing.expectEqual(@as(u8, 'l'), try fixed_in_stream.stream.readByte());
    std.testing.expectEqual(@as(u8, 'o'), try fixed_in_stream.stream.readByte());
    std.testing.expectError(error.EndOfStream, fixed_in_stream.stream.readByte());
}

fn ErrorOf(comptime Func: type) type {
    const R = @typeInfo(Func).Fn.return_type.?;
    return @typeInfo(R).ErrorUnion.error_set;
}

// --- Before ---
// const count = try readVarint(u32, &payload.stream);
// result.field = arena.allocator.alloc(@TypeOf(result.field), count);
// for (result.field) |*item| {
//
// --- After ---
// const count = try readVarint(u32, &payload.stream);
// for (self.allocInto(&result.field, count)) |*item| {
fn allocInto(self: *Bytecode, ptr_to_slice: var, count: usize) !std.meta.Child(@TypeOf(ptr_to_slice)) {
    const Slice = std.meta.Child(@TypeOf(ptr_to_slice));
    std.debug.assert(@typeInfo(Slice).Pointer.size == .Slice);

    ptr_to_slice.* = try self.arena.allocator.alloc(std.meta.Child(Slice), count);
    return ptr_to_slice.*;
}

pub fn parse(allocator: *std.mem.Allocator, in_stream: var) !Bytecode {
    const ReadFn = @TypeOf(in_stream.readFn);
    const ReadError = ErrorOf(ReadFn);

    const signature = try in_stream.readIntLittle(u32);
    if (signature != magic_number) {
        return error.InvalidFormat;
    }

    const version = try in_stream.readIntLittle(u32);
    if (version != 1) {
        return error.InvalidFormat;
    }

    var result = Bytecode.init(std.heap.ArenaAllocator.init(allocator));
    errdefer result.arena.deinit();

    while (true) {
        const id = in_stream.readByte() catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
        const payload_len = try readVarint(u32, in_stream);
        var payload = FixedInStream(ReadError).init(in_stream, payload_len);

        switch (id) {
            0x1 => {
                const count = try readVarint(u32, &payload.stream);
                for (try result.allocInto(&result.@"type", count)) |*t| {
                    t.form = try readVarintEnum(Type.Form, &payload.stream);

                    const param_count = try readVarint(u32, &payload.stream);
                    for (try result.allocInto(&t.param_types, param_count)) |*param_type| {
                        param_type.* = try readVarintEnum(Type.Value, &payload.stream);
                    }

                    const return_count = try readVarint(u1, &payload.stream);
                    t.return_type = if (return_count == 0) null else try readVarintEnum(Type.Value, &payload.stream);
                }
            },
            0x2 => {
                const count = try readVarint(u32, &payload.stream);
                for (try result.allocInto(&result.import, count)) |*i| {
                    const module_len = try readVarint(u32, &payload.stream);
                    const module_data = try result.arena.allocator.alloc(u8, module_len);
                    try payload.stream.readNoEof(module_data);
                    i.module = module_data;

                    const field_len = try readVarint(u32, &payload.stream);
                    const field_data = try result.arena.allocator.alloc(u8, field_len);
                    try payload.stream.readNoEof(field_data);
                    i.field = field_data;

                    i.kind = try readVarintEnum(ExternalKind, &payload.stream);
                }
            },
            0x3 => {
                const count = try readVarint(u32, &payload.stream);
                for (try result.allocInto(&result.function, count)) |*f| {
                    f.* = try readVarintEnum(Index.FuncType, &payload.stream);
                }
            },
            0x4 => {
                const count = try readVarint(u32, &payload.stream);
                for (try result.allocInto(&result.table, count)) |*t| {
                    t.element_type = try readVarintEnum(Type.Elem, &payload.stream);

                    const flags = try readVarint(u1, &payload.stream);
                    t.limits.initial = try readVarint(u32, &payload.stream);
                    t.limits.maximum = if (flags == 0) null else try readVarint(u32, &payload.stream);
                }
            },
            0x5 => {
                const count = try readVarint(u32, &payload.stream);
                for (try result.allocInto(&result.memory, count)) |*m| {
                    const flags = try readVarint(u1, &payload.stream);
                    m.limits.initial = try readVarint(u32, &payload.stream);
                    m.limits.maximum = if (flags == 0) null else try readVarint(u32, &payload.stream);
                }
            },
            0x6 => {
                const count = try readVarint(u32, &payload.stream);
                for (try result.allocInto(&result.global, count)) |*g| {
                    g.@"type".content_type = try readVarintEnum(Type.Value, &payload.stream);
                    g.@"type".mutability = (try readVarint(u1, &payload.stream)) == 1;
                    g.init = .{}; // FIXME
                }
            },
            0x7 => {
                const count = try readVarint(u32, &payload.stream);
                for (try result.allocInto(&result.@"export", count)) |*e| {
                    const field_len = try readVarint(u32, &payload.stream);
                    const field_data = try result.arena.allocator.alloc(u8, field_len);
                    try payload.stream.readNoEof(field_data);
                    e.field = field_data;

                    const kind = try readVarintEnum(ExternalKind, &payload.stream);
                    const index = try readVarint(u32, &payload.stream);
                    e.index = switch (kind) {
                        .Table => .{ .Table = @intToEnum(Index.Table, index) },
                        .Function => .{ .Function = @intToEnum(Index.Function, index) },
                        .Memory => .{ .Memory = @intToEnum(Index.Memory, index) },
                        .Global => .{ .Global = @intToEnum(Index.Global, index) },
                    };
                }
            },
            0x8 => {
                const index = try readVarint(u32, &payload.stream);
                result.start = .{
                    .index = @intToEnum(Index.Function, index),
                };
            },
            0x9 => {
                const count = try readVarint(u32, &payload.stream);
                for (try result.allocInto(&result.element, count)) |*e| {
                    const index = try readVarint(u32, &payload.stream);
                    e.index = @intToEnum(Index.Table, index);
                    e.offset = .{}; // FIXME

                    const num_elem = try readVarint(u32, &payload.stream);
                    for (try result.allocInto(&e.elems, count)) |*func| {
                        const func_index = try readVarint(u32, &payload.stream);
                        func.* = @intToEnum(Index.Function, func_index);
                    }
                }
            },
            0x10 => {
                const count = try readVarint(u32, &payload.stream);
                for (try result.allocInto(&result.code, count)) |*c| {
                    const body_size = try readVarint(u32, &payload.stream);
                    const local_count = try readVarint(u32, &payload.stream);
                    for (try result.allocInto(&c.locals, local_count)) |*l| {
                        const var_count = try readVarint(u32, &payload.stream);
                        for (try result.allocInto(&l.@"type", local_count)) |*t| {
                            t.* = try readVarintEnum(Type.Value, &payload.stream);
                        }
                    }
                    // FIXME: this is probably the wrong size
                    if (body_size != payload.remaining) {
                        return error.ComeUpWithABetterName;
                    }
                    var code = std.ArrayList(Module.Instr).init(&result.arena.allocator);
                    while (payload.stream.readByte()) |opcode| {
                        if (Op.all[opcode]) |*op| {
                            try code.append(.{
                                .op = op,
                                .arg = switch (op.arg_kind) {
                                    .Void => .{ .I64 = 0 },
                                    .I32 => .{ .I32 = try readVarint(i32, &payload.stream) },
                                    .U32 => .{ .U32 = try readVarint(u32, &payload.stream) },
                                    .I64 => .{ .I64 = try readVarint(i64, &payload.stream) },
                                    .U64 => .{ .U64 = try readVarint(u64, &payload.stream) },
                                    .F32 => .{ .F64 = try payload.stream.readIntLittle(f32) },
                                    .F64 => .{ .F64 = try payload.stream.readIntLittle(f64) },
                                    .Type => .{ .I64 = try readVarint(u7, &payload.stream) },
                                    .U32z => Op.Fixval.init(Op.Arg.U32z{
                                        .data = try readVarint(u32, &payload.stream),
                                        .reserved = try payload.stream.readByte(),
                                    }),
                                    .Mem => Op.Fixval.init(Op.Arg.Mem{
                                        .offset = try readVarint(u32, &payload.stream),
                                        .align_ = try readVarint(u32, &payload.stream),
                                    }),
                                    .Array => blk: {
                                        const target_count = try readVarint(u32, &payload.stream);
                                        const size = target_count + 1; // Implementation detail: we shove the default into the last element of the array
                                        const data = try result.arena.allocator.alloc(u32, size);

                                        var array = Op.Arg.Array{
                                            .data = data.ptr,
                                            .len = data.len,
                                        };
                                        for (data) |*item| {
                                            item.* = try readVarint(u32, &payload.stream);
                                        }
                                        break :blk Op.Fixval.init(array);
                                    },
                                },
                            });
                        } else {
                            return error.InvalidOpCode;
                        }
                    } else |err| switch (err) {
                        error.EndOfStream => {},
                        else => return err,
                    }
                    c.code = code.toOwnedSlice();
                }
            },
            0x11 => {
                const count = try readVarint(u32, &payload.stream);
                for (try result.allocInto(&result.data, count)) |*d| {
                    const index = try readVarint(u32, &payload.stream);
                    d.index = @intToEnum(Index.Memory, index);
                    d.offset = .{}; // FIXME

                    const size = try readVarint(u32, &payload.stream);
                    const data = try result.arena.allocator.alloc(u8, size);
                    try payload.stream.readNoEof(data);
                    d.data = data;
                }
            },
            0x0 => @panic("TODO"),
            else => return error.InvalidFormat,
        }
        try expectEos(&payload.stream);
    }

    return result;
}

pub fn deinit(self: *Bytecode) void {
    self.arena.deinit();
    self.* = undefined;
}

fn clone(comptime T: type, allocator: *std.mem.Allocator, data: []T) ![]T {
    const result = try allocator.alloc(T, data.len);
    std.mem.copy(T, result, data);
    return result;
}

pub fn toModule(self: Bytecode, allocator: *std.mem.Allocator) !Module {
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();

    return Module{
        .memory = 0,
        .func_types = blk: {
            var result = try arena.allocator.alloc(Module.FuncType, self.@"type".len);
            for (self.@"type") |t, i| {
                result[i] = .{
                    .params = try clone(Type.Value, &arena.allocator, t.param_types),
                    .result = t.return_type,
                };
            }
            break :blk result;
        },
        .funcs = &[0]Module.Func{},
        .exports = std.StringHashMap(Module.Export).init(&arena.allocator),
        .arena = arena,
    };
}

pub fn load(allocator: *std.mem.Allocator, in_stream: var) !Module {
    var bytecode = try Bytecode.parse(allocator, in_stream);
    defer bytecode.deinit();

    return bytecode.toModule(allocator);
}

const empty_raw_bytes = &[_]u8{ 0, 'a', 's', 'm', 1, 0, 0, 0 };

test "empty module" {
    var ios = std.io.SliceInStream.init(empty_raw_bytes);
    var module = try Bytecode.load(std.testing.allocator, &ios.stream);
    defer module.deinit();

    std.testing.expectEqual(@as(usize, 0), module.memory);
    std.testing.expectEqual(@as(usize, 0), module.func_types.len);
    std.testing.expectEqual(@as(usize, 0), module.funcs.len);
    std.testing.expectEqual(@as(usize, 0), module.exports.count());
}

test "module with only type" {
    const raw_bytes = empty_raw_bytes ++ "\x01\x04\x01\x60\x00\x00";
    var ios = std.io.SliceInStream.init(raw_bytes);
    var module = try Bytecode.load(std.testing.allocator, &ios.stream);
    defer module.deinit();

    std.testing.expectEqual(@as(usize, 1), module.func_types.len);
}
