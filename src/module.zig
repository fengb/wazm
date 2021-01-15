const std = @import("std");
const Instance = @import("instance.zig");
const Op = @import("op.zig");
pub const post_process = @import("module/post_process.zig").post_process;

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
    kind: union(ExternalKind) {
        Function: Index.FuncType,
        // TODO: add these types
        Table: void,
        Memory: void,
        Global: void,
    },
},

/// Code=3
function: []struct {
    type_idx: Index.FuncType,
},

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
    kind: ExternalKind,
    index: u32,
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

jumps: InstrJumps = .{},

pub const InstrJumps = std.AutoHashMapUnmanaged(struct { func: u32, instr: u32 }, struct {
    return_type: ?Type.Value,
    stack_unroll: u32,
    targets: [*]u32, // len = 1, except br_table where len = args.len
});

pub fn init(arena: std.heap.ArenaAllocator) Module {
    var result: Module = undefined;
    result.arena = arena;
    result.jumps = .{};

    inline for (std.meta.fields(Module)) |field| {
        comptime const needs_zero = !std.mem.eql(u8, field.name, "arena") and !std.mem.eql(u8, field.name, "jumps");

        if (needs_zero) {
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

test "sectionType" {
    const module: Module = undefined;
    std.testing.expectEqual(std.meta.Child(@TypeOf(module.custom)), sectionType(.Custom));
    std.testing.expectEqual(std.meta.Child(@TypeOf(module.memory)), sectionType(.Memory));
    std.testing.expectEqual(std.meta.Child(@TypeOf(module.data)), sectionType(.Data));
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

    pub const Block = enum(i7) {
        I32 = -0x01,
        I64 = -0x02,
        F32 = -0x03,
        F64 = -0x04,
        Empty = -0x40,
    };

    pub const Elem = enum(i7) {
        Anyfunc = -0x10,
    };

    pub const Form = enum(i7) {
        Func = -0x20,
    };
};

pub const ExternalKind = enum(u7) {
    Function = 0,
    Table = 1,
    Memory = 2,
    Global = 3,
};

pub const ResizableLimits = struct {
    initial: u32,
    maximum: ?u32,
};

pub const Instr = struct {
    op: Op.Code,
    pop_len: u8,
    arg: Op.Fixval,
};

const InitExpr = struct {};

fn readVarint(comptime T: type, reader: anytype) !T {
    const readFn = switch (@typeInfo(T).Int.signedness) {
        .signed => std.leb.readILEB128,
        .unsigned => std.leb.readULEB128,
    };
    return try readFn(T, reader);
}

test "readVarint" {
    {
        var ios = std.io.fixedBufferStream("\xE5\x8E\x26");
        std.testing.expectEqual(@as(u32, 624485), try readVarint(u32, ios.reader()));
        ios.pos = 0;
        std.testing.expectEqual(@as(u21, 624485), try readVarint(u21, ios.reader()));
    }
    {
        var ios = std.io.fixedBufferStream("\xC0\xBB\x78");
        std.testing.expectEqual(@as(i32, -123456), try readVarint(i32, ios.reader()));
        ios.pos = 0;
        std.testing.expectEqual(@as(i21, -123456), try readVarint(i21, ios.reader()));
    }
    {
        var ios = std.io.fixedBufferStream("\x7F");
        std.testing.expectEqual(@as(i7, -1), try readVarint(i7, ios.reader()));
        ios.pos = 0;
        std.testing.expectEqual(@as(i21, -1), try readVarint(i21, ios.reader()));
        ios.pos = 0;
        std.testing.expectEqual(@as(i32, -1), try readVarint(i32, ios.reader()));
    }
    {
        var ios = std.io.fixedBufferStream("\xa4\x03");
        std.testing.expectEqual(@as(i21, 420), try readVarint(i21, ios.reader()));
        ios.pos = 0;
        std.testing.expectEqual(@as(i32, 420), try readVarint(i32, ios.reader()));
    }
}

fn readVarintEnum(comptime E: type, reader: anytype) !E {
    const raw = try readVarint(std.meta.TagType(E), reader);
    return try std.meta.intToEnum(E, raw);
}

fn expectEos(reader: anytype) !void {
    var tmp: [1]u8 = undefined;
    const len = try reader.read(&tmp);
    if (len != 0) {
        return error.NotEndOfStream;
    }
}

/// A stream that can only read a maximum number of bytes.
pub fn ClampedReader(comptime ReaderType: type) type {
    return struct {
        const Self = @This();
        pub const Error = ReaderType.Error;
        pub const Reader = std.io.Reader(*Self, Error, read);

        underlying_stream: ReaderType,

        size: usize,
        remaining: usize,

        pub fn reader(self: *Self) Reader {
            return .{ .context = self };
        }

        fn read(self: *Self, dest: []u8) Error!usize {
            const bytes = try self.underlying_stream.read(dest[0..std.math.min(dest.len, self.remaining)]);
            self.remaining -= bytes;
            return bytes;
        }
    };
}

pub fn clampedReader(underlying_stream: anytype, size: usize) ClampedReader(@TypeOf(underlying_stream)) {
    return .{
        .underlying_stream = underlying_stream,

        .size = size,
        .remaining = size,
    };
}

test "ClampedReader" {
    var string = "hello world";
    var fixed_buffer_stream = std.io.fixedBufferStream(string);

    var clamped_reader = clampedReader(fixed_buffer_stream.reader(), 5);
    std.testing.expectEqual(@as(u8, 'h'), try clamped_reader.reader().readByte());
    std.testing.expectEqual(@as(u8, 'e'), try clamped_reader.reader().readByte());
    std.testing.expectEqual(@as(u8, 'l'), try clamped_reader.reader().readByte());
    std.testing.expectEqual(@as(u8, 'l'), try clamped_reader.reader().readByte());
    std.testing.expectEqual(@as(u8, 'o'), try clamped_reader.reader().readByte());
    std.testing.expectError(error.EndOfStream, clamped_reader.reader().readByte());
}

fn ErrorOf(comptime Func: type) type {
    const R = @typeInfo(Func).Fn.return_type.?;
    return @typeInfo(R).ErrorUnion.error_set;
}

// --- Before ---
// const count = try readVarint(u32, payload.reader());
// result.field = arena.allocator.alloc(@TypeOf(result.field), count);
// for (result.field) |*item| {
//
// --- After ---
// const count = try readVarint(u32, payload.reader());
// for (self.allocInto(&result.field, count)) |*item| {
fn allocInto(self: *Module, ptr_to_slice: anytype, count: usize) !std.meta.Child(@TypeOf(ptr_to_slice)) {
    const Slice = std.meta.Child(@TypeOf(ptr_to_slice));
    std.debug.assert(@typeInfo(Slice).Pointer.size == .Slice);

    ptr_to_slice.* = try self.arena.allocator.alloc(std.meta.Child(Slice), count);
    return ptr_to_slice.*;
}

pub fn parse(allocator: *std.mem.Allocator, reader: anytype) !Module {
    const signature = try reader.readIntLittle(u32);
    if (signature != magic_number) {
        return error.InvalidFormat;
    }

    const version = try reader.readIntLittle(u32);
    if (version != 1) {
        return error.InvalidFormat;
    }

    var result = Module.init(std.heap.ArenaAllocator.init(allocator));
    errdefer result.arena.deinit();

    while (true) {
        const id = reader.readByte() catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
        const payload_len = try readVarint(u32, reader);
        var payload = clampedReader(reader, payload_len);

        switch (try std.meta.intToEnum(Section, id)) {
            .Type => {
                const count = try readVarint(u32, payload.reader());
                for (try result.allocInto(&result.@"type", count)) |*t| {
                    t.form = try readVarintEnum(Type.Form, payload.reader());

                    const param_count = try readVarint(u32, payload.reader());
                    for (try result.allocInto(&t.param_types, param_count)) |*param_type| {
                        param_type.* = try readVarintEnum(Type.Value, payload.reader());
                    }

                    const return_count = try readVarint(u1, payload.reader());
                    t.return_type = if (return_count == 0) null else try readVarintEnum(Type.Value, payload.reader());
                }
            },
            .Import => {
                const count = try readVarint(u32, payload.reader());
                for (try result.allocInto(&result.import, count)) |*i| {
                    const module_len = try readVarint(u32, payload.reader());
                    const module_data = try result.arena.allocator.alloc(u8, module_len);
                    try payload.reader().readNoEof(module_data);
                    i.module = module_data;

                    const field_len = try readVarint(u32, payload.reader());
                    const field_data = try result.arena.allocator.alloc(u8, field_len);
                    try payload.reader().readNoEof(field_data);
                    i.field = field_data;

                    // TODO: actually test import parsing
                    const kind = try readVarintEnum(ExternalKind, payload.reader());
                    i.kind = switch (kind) {
                        .Function => .{ .Function = try readVarintEnum(Index.FuncType, payload.reader()) },
                        .Table => @panic("TODO"),
                        .Memory => @panic("TODO"),
                        .Global => @panic("TODO"),
                    };
                }
            },
            .Function => {
                const count = try readVarint(u32, payload.reader());
                for (try result.allocInto(&result.function, count)) |*f| {
                    const index = try readVarint(u32, payload.reader());
                    f.type_idx = @intToEnum(Index.FuncType, index);
                }
            },
            .Table => {
                const count = try readVarint(u32, payload.reader());
                for (try result.allocInto(&result.table, count)) |*t| {
                    t.element_type = try readVarintEnum(Type.Elem, payload.reader());

                    const flags = try readVarint(u1, payload.reader());
                    t.limits.initial = try readVarint(u32, payload.reader());
                    t.limits.maximum = if (flags == 0) null else try readVarint(u32, payload.reader());
                }
            },
            .Memory => {
                const count = try readVarint(u32, payload.reader());
                for (try result.allocInto(&result.memory, count)) |*m| {
                    const flags = try readVarint(u1, payload.reader());
                    m.limits.initial = try readVarint(u32, payload.reader());
                    m.limits.maximum = if (flags == 0) null else try readVarint(u32, payload.reader());
                }
            },
            .Global => {
                const count = try readVarint(u32, payload.reader());
                for (try result.allocInto(&result.global, count)) |*g| {
                    g.@"type".content_type = try readVarintEnum(Type.Value, payload.reader());
                    g.@"type".mutability = (try readVarint(u1, payload.reader())) == 1;
                    g.init = .{}; // FIXME
                }
            },
            .Export => {
                const count = try readVarint(u32, payload.reader());
                for (try result.allocInto(&result.@"export", count)) |*e| {
                    const field_len = try readVarint(u32, payload.reader());
                    const field_data = try result.arena.allocator.alloc(u8, field_len);
                    try payload.reader().readNoEof(field_data);
                    e.field = field_data;
                    e.kind = try readVarintEnum(ExternalKind, payload.reader());
                    e.index = try readVarint(u32, payload.reader());
                }
            },
            .Start => {
                const index = try readVarint(u32, payload.reader());
                result.start = .{
                    .index = @intToEnum(Index.Function, index),
                };
            },
            .Element => {
                const count = try readVarint(u32, payload.reader());
                for (try result.allocInto(&result.element, count)) |*e| {
                    const index = try readVarint(u32, payload.reader());
                    e.index = @intToEnum(Index.Table, index);
                    e.offset = .{}; // FIXME

                    const num_elem = try readVarint(u32, payload.reader());
                    for (try result.allocInto(&e.elems, count)) |*func| {
                        const func_index = try readVarint(u32, payload.reader());
                        func.* = @intToEnum(Index.Function, func_index);
                    }
                }
            },
            .Code => {
                const count = try readVarint(u32, payload.reader());
                for (try result.allocInto(&result.code, count)) |*c| {
                    const body_size = try readVarint(u32, payload.reader());
                    if (body_size != payload.remaining) {
                        // FIXME: this is probably the wrong size
                        return error.BodySizeMismatch;
                    }

                    c.locals = blk: {
                        // TODO: double pass here to preallocate the exact array size
                        var list = std.ArrayList(Type.Value).init(&result.arena.allocator);
                        var local_count = try readVarint(u32, payload.reader());
                        while (local_count > 0) : (local_count -= 1) {
                            var current_count = try readVarint(u32, payload.reader());
                            const typ = try readVarintEnum(Type.Value, payload.reader());
                            while (current_count > 0) : (current_count -= 1) {
                                try list.append(typ);
                            }
                        }
                        break :blk list.items;
                    };

                    c.code = code: {
                        var list = std.ArrayList(Module.Instr).init(&result.arena.allocator);
                        while (true) {
                            const opcode = payload.reader().readByte() catch |err| switch (err) {
                                error.EndOfStream => {
                                    const last = list.popOrNull() orelse return error.MissingFunctionEnd;
                                    if (last.op != .end) {
                                        return error.MissingFunctionEnd;
                                    }
                                    break :code list.items;
                                },
                                else => return err,
                            };

                            const op_meta = Op.Meta.all[opcode] orelse return error.InvalidOpCode;

                            try list.append(.{
                                .op = @intToEnum(Op.Code, opcode),
                                .pop_len = @intCast(u8, op_meta.pop.len),
                                .arg = switch (op_meta.arg_kind) {
                                    .Void => .{ .I64 = 0 },
                                    .I32 => .{ .I32 = try readVarint(i32, payload.reader()) },
                                    .U32 => .{ .U32 = try readVarint(u32, payload.reader()) },
                                    .I64 => .{ .I64 = try readVarint(i64, payload.reader()) },
                                    .U64 => .{ .U64 = try readVarint(u64, payload.reader()) },
                                    .F32 => .{ .F64 = @bitCast(f32, try payload.reader().readIntLittle(i32)) },
                                    .F64 => .{ .F64 = @bitCast(f64, try payload.reader().readIntLittle(i64)) },
                                    .Type => .{ .I64 = try readVarint(u7, payload.reader()) },
                                    .U32z => Op.Fixval.init(Op.Arg.U32z{
                                        .data = try readVarint(u32, payload.reader()),
                                        .reserved = try payload.reader().readByte(),
                                    }),
                                    .Mem => Op.Fixval.init(Op.Arg.Mem{
                                        .offset = try readVarint(u32, payload.reader()),
                                        .align_ = try readVarint(u32, payload.reader()),
                                    }),
                                    .Array => blk: {
                                        const target_count = try readVarint(u32, payload.reader());
                                        const size = target_count + 1; // Implementation detail: we shove the default into the last element of the array

                                        const data = try result.arena.allocator.alloc(u32, size);
                                        for (data) |*item| {
                                            item.* = try readVarint(u32, payload.reader());
                                        }
                                        break :blk Op.Fixval.init(
                                            Op.Arg.Array{
                                                .data = data.ptr,
                                                .len = data.len,
                                            },
                                        );
                                    },
                                },
                            });
                        }
                    };
                }
            },
            .Data => {
                const count = try readVarint(u32, payload.reader());
                for (try result.allocInto(&result.data, count)) |*d| {
                    const index = try readVarint(u32, payload.reader());
                    d.index = @intToEnum(Index.Memory, index);
                    d.offset = .{}; // FIXME

                    const size = try readVarint(u32, payload.reader());
                    const data = try result.arena.allocator.alloc(u8, size);
                    try payload.reader().readNoEof(data);
                    d.data = data;
                }
            },
            .Custom => @panic("TODO"),
        }
        try expectEos(payload.reader());
    }

    try result.post_process();

    return result;
}

pub const instantiate = Instance.init;

const empty_raw_bytes = &[_]u8{ 0, 'a', 's', 'm', 1, 0, 0, 0 };

test "empty module" {
    var ios = std.io.fixedBufferStream(empty_raw_bytes);
    var module = try Module.parse(std.testing.allocator, ios.reader());
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
    var module = try Module.parse(std.testing.allocator, ios.reader());
    defer module.deinit();

    std.testing.expectEqual(@as(usize, 1), module.@"type".len);
    std.testing.expectEqual(@as(usize, 0), module.@"type"[0].param_types.len);
    std.testing.expectEqual(@as(?Type.Value, null), module.@"type"[0].return_type);
}

test "module with function body" {
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
    var module = try Module.parse(std.testing.allocator, ios.reader());
    defer module.deinit();

    std.testing.expectEqual(@as(usize, 1), module.@"type".len);
    std.testing.expectEqual(@as(usize, 0), module.@"type"[0].param_types.len);
    std.testing.expectEqual(Type.Value.I32, module.@"type"[0].return_type.?);

    std.testing.expectEqual(@as(usize, 1), module.@"export".len);

    std.testing.expectEqual(@as(usize, 1), module.function.len);
    std.testing.expectEqual(@as(usize, 1), module.code.len);
    std.testing.expectEqual(@as(usize, 1), module.code[0].code.len);
    std.testing.expectEqual(Op.Code.@"i32.const", module.code[0].code[0].op);

    var instance = try module.instantiate(std.testing.allocator, struct {});
    defer instance.deinit();

    const result = try instance.call("a", &[0]Instance.Value{});
    std.testing.expectEqual(@as(isize, 420), result.?.I32);
}
