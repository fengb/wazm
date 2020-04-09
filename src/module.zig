const std = @import("std");
const Instance = @import("instance.zig");
const Op = @import("op.zig");

const magic_number = std.mem.readIntLittle(u32, "\x00asm");

const Module = @This();

arena: std.heap.ArenaAllocator,

/// Code=0
custom: []struct {
    name: []const u8,
    payload: []const u8,
},

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
    locals: []Type.Value,
    code: []Module.Instr,
},

/// Code=11
data: []struct {
    index: Index.Memory,
    offset: InitExpr,
    data: []const u8,
},

pub fn init(arena: std.heap.ArenaAllocator) Module {
    var result: Module = undefined;
    result.arena = arena;

    inline for (std.meta.fields(Module)) |field| {
        if (comptime !std.mem.eql(u8, field.name, "arena")) {
            @field(result, field.name) = std.mem.zeroes(field.field_type);
        }
    }
    return result;
}

pub fn deinit(self: *Module) void {
    self.arena.deinit();
    self.* = undefined;
}

pub fn sectionType(comptime section: Section) type {
    const fields = std.meta.fields(Module);
    const num = @enumToInt(section) + 1; // 0 == allocator, 1 == custom, etc.
    return std.meta.Child(fields[num].field_type);
}

const Section = enum {
    Custom = 0,
    Type = 1,
    Import = 2,
    Function = 3,
    Table = 4,
    Memory = 5,
    Global = 6,
    Export = 7,
    Start = 8,
    Element = 9,
    Code = 10,
    Data = 11,
};

pub const Index = struct {
    pub const FuncType = enum(u32) { _ };
    pub const Table = enum(u32) { _ };
    pub const Function = enum(u32) { _ };
    pub const Memory = enum(u32) { _ };
    pub const Global = enum(u32) { _ };
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

pub const Instr = struct {
    op: *const Op,
    arg: Op.Fixval,
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
            } else if (byte & 0x40 != 0 and !@addWithOverflow(S, shift, 6, &shift)) {
                return @bitCast(T, unsigned_result) | @as(T, -1) << shift;
            } else {
                return @bitCast(T, unsigned_result);
            }
        }
    }
}

test "readVarint" {
    {
        var ios = std.io.fixedBufferStream("\xE5\x8E\x26");
        std.testing.expectEqual(@as(u32, 624485), try readVarint(u32, ios.inStream()));
        ios.pos = 0;
        std.testing.expectEqual(@as(u21, 624485), try readVarint(u21, ios.inStream()));
    }
    {
        var ios = std.io.fixedBufferStream("\xC0\xBB\x78");
        std.testing.expectEqual(@as(i32, -123456), try readVarint(i32, ios.inStream()));
        ios.pos = 0;
        std.testing.expectEqual(@as(i21, -123456), try readVarint(i21, ios.inStream()));
    }
    {
        var ios = std.io.fixedBufferStream("\x7F");
        std.testing.expectEqual(@as(i7, -1), try readVarint(i7, ios.inStream()));
        ios.pos = 0;
        std.testing.expectEqual(@as(i21, -1), try readVarint(i21, ios.inStream()));
        ios.pos = 0;
        std.testing.expectEqual(@as(i32, -1), try readVarint(i32, ios.inStream()));
    }
    {
        var ios = std.io.fixedBufferStream("\xa4\x03");
        std.testing.expectEqual(@as(i21, 420), try readVarint(i21, ios.inStream()));
        ios.pos = 0;
        std.testing.expectEqual(@as(i32, 420), try readVarint(i32, ios.inStream()));
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

/// A stream that can only read a maximum number of bytes.
pub fn ClampedInStream(comptime InStreamType: type) type {
    return struct {
        const Self = @This();
        pub const Error = InStreamType.Error;
        pub const InStream = std.io.InStream(*Self, Error, read);

        underlying_stream: InStreamType,

        size: usize,
        remaining: usize,

        pub fn inStream(self: *Self) InStream {
            return .{ .context = self };
        }

        fn read(self: *Self, dest: []u8) Error!usize {
            const bytes = try self.underlying_stream.read(dest[0..std.math.min(dest.len, self.remaining)]);
            self.remaining -= bytes;
            return bytes;
        }
    };
}

pub fn clampedInStream(underlying_stream: var, size: usize) ClampedInStream(@TypeOf(underlying_stream)) {
    return .{
        .underlying_stream = underlying_stream,

        .size = size,
        .remaining = size,
    };
}

test "ClampedInStream" {
    var string = "hello world";
    var fixed_buffer_stream = std.io.fixedBufferStream(string);

    var clamped_in_stream = clampedInStream(fixed_buffer_stream.inStream(), 5);
    std.testing.expectEqual(@as(u8, 'h'), try clamped_in_stream.inStream().readByte());
    std.testing.expectEqual(@as(u8, 'e'), try clamped_in_stream.inStream().readByte());
    std.testing.expectEqual(@as(u8, 'l'), try clamped_in_stream.inStream().readByte());
    std.testing.expectEqual(@as(u8, 'l'), try clamped_in_stream.inStream().readByte());
    std.testing.expectEqual(@as(u8, 'o'), try clamped_in_stream.inStream().readByte());
    std.testing.expectError(error.EndOfStream, clamped_in_stream.inStream().readByte());
}

fn ErrorOf(comptime Func: type) type {
    const R = @typeInfo(Func).Fn.return_type.?;
    return @typeInfo(R).ErrorUnion.error_set;
}

// --- Before ---
// const count = try readVarint(u32, payload.inStream());
// result.field = arena.allocator.alloc(@TypeOf(result.field), count);
// for (result.field) |*item| {
//
// --- After ---
// const count = try readVarint(u32, payload.inStream());
// for (self.allocInto(&result.field, count)) |*item| {
fn allocInto(self: *Module, ptr_to_slice: var, count: usize) !std.meta.Child(@TypeOf(ptr_to_slice)) {
    const Slice = std.meta.Child(@TypeOf(ptr_to_slice));
    std.debug.assert(@typeInfo(Slice).Pointer.size == .Slice);

    ptr_to_slice.* = try self.arena.allocator.alloc(std.meta.Child(Slice), count);
    return ptr_to_slice.*;
}

pub fn parse(allocator: *std.mem.Allocator, in_stream: var) !Module {
    const signature = try in_stream.readIntLittle(u32);
    if (signature != magic_number) {
        return error.InvalidFormat;
    }

    const version = try in_stream.readIntLittle(u32);
    if (version != 1) {
        return error.InvalidFormat;
    }

    var result = Module.init(std.heap.ArenaAllocator.init(allocator));
    errdefer result.arena.deinit();

    while (true) {
        const id = in_stream.readByte() catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
        const payload_len = try readVarint(u32, in_stream);
        var payload = clampedInStream(in_stream, payload_len);

        switch (id) {
            0x1 => {
                const count = try readVarint(u32, payload.inStream());
                for (try result.allocInto(&result.@"type", count)) |*t| {
                    t.form = try readVarintEnum(Type.Form, payload.inStream());

                    const param_count = try readVarint(u32, payload.inStream());
                    for (try result.allocInto(&t.param_types, param_count)) |*param_type| {
                        param_type.* = try readVarintEnum(Type.Value, payload.inStream());
                    }

                    const return_count = try readVarint(u1, payload.inStream());
                    t.return_type = if (return_count == 0) null else try readVarintEnum(Type.Value, payload.inStream());
                }
            },
            0x2 => {
                const count = try readVarint(u32, payload.inStream());
                for (try result.allocInto(&result.import, count)) |*i| {
                    const module_len = try readVarint(u32, payload.inStream());
                    const module_data = try result.arena.allocator.alloc(u8, module_len);
                    try payload.inStream().readNoEof(module_data);
                    i.module = module_data;

                    const field_len = try readVarint(u32, payload.inStream());
                    const field_data = try result.arena.allocator.alloc(u8, field_len);
                    try payload.inStream().readNoEof(field_data);
                    i.field = field_data;

                    i.kind = try readVarintEnum(ExternalKind, payload.inStream());
                }
            },
            0x3 => {
                const count = try readVarint(u32, payload.inStream());
                for (try result.allocInto(&result.function, count)) |*f| {
                    const index = try readVarint(u32, payload.inStream());
                    f.* = @intToEnum(Index.FuncType, index);
                }
            },
            0x4 => {
                const count = try readVarint(u32, payload.inStream());
                for (try result.allocInto(&result.table, count)) |*t| {
                    t.element_type = try readVarintEnum(Type.Elem, payload.inStream());

                    const flags = try readVarint(u1, payload.inStream());
                    t.limits.initial = try readVarint(u32, payload.inStream());
                    t.limits.maximum = if (flags == 0) null else try readVarint(u32, payload.inStream());
                }
            },
            0x5 => {
                const count = try readVarint(u32, payload.inStream());
                for (try result.allocInto(&result.memory, count)) |*m| {
                    const flags = try readVarint(u1, payload.inStream());
                    m.limits.initial = try readVarint(u32, payload.inStream());
                    m.limits.maximum = if (flags == 0) null else try readVarint(u32, payload.inStream());
                }
            },
            0x6 => {
                const count = try readVarint(u32, payload.inStream());
                for (try result.allocInto(&result.global, count)) |*g| {
                    g.@"type".content_type = try readVarintEnum(Type.Value, payload.inStream());
                    g.@"type".mutability = (try readVarint(u1, payload.inStream())) == 1;
                    g.init = .{}; // FIXME
                }
            },
            0x7 => {
                const count = try readVarint(u32, payload.inStream());
                for (try result.allocInto(&result.@"export", count)) |*e| {
                    const field_len = try readVarint(u32, payload.inStream());
                    const field_data = try result.arena.allocator.alloc(u8, field_len);
                    try payload.inStream().readNoEof(field_data);
                    e.field = field_data;

                    const kind = try readVarintEnum(ExternalKind, payload.inStream());
                    const index = try readVarint(u32, payload.inStream());
                    e.index = switch (kind) {
                        .Table => .{ .Table = @intToEnum(Index.Table, index) },
                        .Function => .{ .Function = @intToEnum(Index.Function, index) },
                        .Memory => .{ .Memory = @intToEnum(Index.Memory, index) },
                        .Global => .{ .Global = @intToEnum(Index.Global, index) },
                    };
                }
            },
            0x8 => {
                const index = try readVarint(u32, payload.inStream());
                result.start = .{
                    .index = @intToEnum(Index.Function, index),
                };
            },
            0x9 => {
                const count = try readVarint(u32, payload.inStream());
                for (try result.allocInto(&result.element, count)) |*e| {
                    const index = try readVarint(u32, payload.inStream());
                    e.index = @intToEnum(Index.Table, index);
                    e.offset = .{}; // FIXME

                    const num_elem = try readVarint(u32, payload.inStream());
                    for (try result.allocInto(&e.elems, count)) |*func| {
                        const func_index = try readVarint(u32, payload.inStream());
                        func.* = @intToEnum(Index.Function, func_index);
                    }
                }
            },
            0xA => {
                const count = try readVarint(u32, payload.inStream());
                for (try result.allocInto(&result.code, count)) |*c| {
                    const body_size = try readVarint(u32, payload.inStream());
                    if (body_size != payload.remaining) {
                        // FIXME: this is probably the wrong size
                        return error.BodySizeMismatch;
                    }

                    c.locals = blk: {
                        // TODO: double pass here to preallocate the exact array size
                        var list = std.ArrayList(Type.Value).init(&result.arena.allocator);
                        var local_count = try readVarint(u32, payload.inStream());
                        while (local_count > 0) : (local_count -= 1) {
                            var current_count = try readVarint(u32, payload.inStream());
                            const typ = try readVarintEnum(Type.Value, payload.inStream());
                            while (current_count > 0) : (current_count -= 1) {
                                try list.append(typ);
                            }
                        }
                        break :blk list.toOwnedSlice();
                    };

                    var code = std.ArrayList(Module.Instr).init(&result.arena.allocator);
                    while (payload.inStream().readByte()) |opcode| {
                        if (Op.all[opcode]) |*op| {
                            try code.append(.{
                                .op = op,
                                .arg = switch (op.arg_kind) {
                                    .Void => .{ .I64 = 0 },
                                    .I32 => .{ .I32 = try readVarint(i32, payload.inStream()) },
                                    .U32 => .{ .U32 = try readVarint(u32, payload.inStream()) },
                                    .I64 => .{ .I64 = try readVarint(i64, payload.inStream()) },
                                    .U64 => .{ .U64 = try readVarint(u64, payload.inStream()) },
                                    .F32 => .{ .F64 = try payload.inStream().readIntLittle(f32) },
                                    .F64 => .{ .F64 = try payload.inStream().readIntLittle(f64) },
                                    .Type => .{ .I64 = try readVarint(u7, payload.inStream()) },
                                    .U32z => Op.Fixval.init(Op.Arg.U32z{
                                        .data = try readVarint(u32, payload.inStream()),
                                        .reserved = try payload.inStream().readByte(),
                                    }),
                                    .Mem => Op.Fixval.init(Op.Arg.Mem{
                                        .offset = try readVarint(u32, payload.inStream()),
                                        .align_ = try readVarint(u32, payload.inStream()),
                                    }),
                                    .Array => blk: {
                                        const target_count = try readVarint(u32, payload.inStream());
                                        const size = target_count + 1; // Implementation detail: we shove the default into the last element of the array
                                        const data = try result.arena.allocator.alloc(u32, size);

                                        var array = Op.Arg.Array{
                                            .data = data.ptr,
                                            .len = data.len,
                                        };
                                        for (data) |*item| {
                                            item.* = try readVarint(u32, payload.inStream());
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
            0xB => {
                const count = try readVarint(u32, payload.inStream());
                for (try result.allocInto(&result.data, count)) |*d| {
                    const index = try readVarint(u32, payload.inStream());
                    d.index = @intToEnum(Index.Memory, index);
                    d.offset = .{}; // FIXME

                    const size = try readVarint(u32, payload.inStream());
                    const data = try result.arena.allocator.alloc(u8, size);
                    try payload.inStream().readNoEof(data);
                    d.data = data;
                }
            },
            0x0 => @panic("TODO"),
            else => return error.InvalidFormat,
        }
        try expectEos(payload.inStream());
    }

    return result;
}

pub const instantiate = Instance.init;

const empty_raw_bytes = &[_]u8{ 0, 'a', 's', 'm', 1, 0, 0, 0 };

test "empty module" {
    var ios = std.io.fixedBufferStream(empty_raw_bytes);
    var module = try Module.parse(std.testing.allocator, ios.inStream());
    defer module.deinit();

    std.testing.expectEqual(@as(usize, 0), module.memory.len);
    std.testing.expectEqual(@as(usize, 0), module.@"type".len);
    std.testing.expectEqual(@as(usize, 0), module.function.len);
    std.testing.expectEqual(@as(usize, 0), module.@"export".len);
}

test "module with only type" {
    const raw_bytes = empty_raw_bytes ++ // (module
        "\x01\x04\x01\x60\x00\x00" ++ //      (type (func)))
        "";
    var ios = std.io.fixedBufferStream(raw_bytes);
    var module = try Module.parse(std.testing.allocator, ios.inStream());
    defer module.deinit();

    std.testing.expectEqual(@as(usize, 1), module.@"type".len);
    std.testing.expectEqual(@as(usize, 0), module.@"type"[0].param_types.len);
    std.testing.expectEqual(@as(?Type.Value, null), module.@"type"[0].return_type);
}

test "module with function body" {
    // TODO: resurrect WAT so we can write readable tests

    // (module
    //   (type (;0;) (func (result i32)))
    //   (func (;0;) (type 0) (result i32)
    //     i32.const 420)
    //   (export "a" (func 0)))
    const raw_bytes = empty_raw_bytes ++ //          (module
        "\x01\x05\x01\x60\x00\x01\x7f" ++ //           (type (;0;) (func (result i32)))
        "\x03\x02\x01\x00" ++ //                       (func (;0;) (type 0)
        "\x07\x05\x01\x01\x61\x00\x00" ++ //           (export "a" (func 0))
        "\x0a\x07\x01\x05\x00\x41\xa4\x03\x0b" ++ //     i32.const 420
        "";

    var ios = std.io.fixedBufferStream(raw_bytes);
    var module = try Module.parse(std.testing.allocator, ios.inStream());
    defer module.deinit();

    std.testing.expectEqual(@as(usize, 1), module.@"type".len);
    std.testing.expectEqual(@as(usize, 0), module.@"type"[0].param_types.len);
    std.testing.expectEqual(Type.Value.I32, module.@"type"[0].return_type.?);

    std.testing.expectEqual(@as(usize, 1), module.@"export".len);

    std.testing.expectEqual(@as(usize, 1), module.function.len);
    std.testing.expectEqual(@as(usize, 1), module.code.len);
    std.testing.expectEqual(@as(usize, 2), module.code[0].code.len);
    std.testing.expectEqualSlices(u8, "i32.const", module.code[0].code[0].op.name);
    std.testing.expectEqualSlices(u8, "end", module.code[0].code[1].op.name);

    var instance = try module.instantiate(std.testing.allocator, struct {});
    defer instance.deinit();

    const result = try instance.call("a", &[0]Instance.Value{});
    std.testing.expectEqual(@as(isize, 420), result.?.I32);
}
