const std = @import("std");
const Instance = @import("instance.zig");
const Op = @import("op.zig");
pub const PostProcess = @import("module/post_process.zig");

const log = std.log.scoped(.wazm);
const magic_number = std.mem.readIntLittle(u32, "\x00asm");

const Module = @This();

arena: std.heap.ArenaAllocator,

/// Code=0
custom: []const struct {
    name: []const u8,
    payload: []const u8,
} = &.{},

/// Code=1
@"type": []const struct {
    form: Type.Form, // TODO: why is this called form?
    param_types: []const Type.Value,
    return_type: ?Type.Value,
} = &.{},

/// Code=2
import: []const struct {
    module: []const u8,
    field: []const u8,
    kind: union(ExternalKind) {
        Function: Index.FuncType,
        // TODO: add these types
        Table: void,
        Memory: void,
        Global: void,
    },
} = &.{},

/// Code=3
function: []const struct {
    type_idx: Index.FuncType,
} = &.{},

/// Code=4
table: []const struct {
    element_type: Type.Elem,
    limits: ResizableLimits,
} = &.{},

/// Code=5
memory: []const struct {
    limits: ResizableLimits,
} = &.{},

/// Code=6
global: []const struct {
    @"type": struct {
        content_type: Type.Value,
        mutability: bool,
    },
    init: InitExpr,
} = &.{},

/// Code=7
@"export": []const struct {
    field: []const u8,
    kind: ExternalKind,
    index: u32,
} = &.{},

/// Code=8
start: ?struct {
    index: Index.Function,
} = null,

/// Code=9
element: []const struct {
    index: Index.Table,
    offset: InitExpr,
    elems: []const Index.Function,
} = &.{},

/// Code=10
code: []const struct {
    locals: []const Type.Value,
    body: []const Module.Instr,
} = &.{},

/// Code=11
data: []const struct {
    index: Index.Memory,
    offset: InitExpr,
    data: []const u8,
} = &.{},

post_process: ?PostProcess = null,

pub fn init(arena: std.heap.ArenaAllocator) Module {
    return Module{ .arena = arena };
}

pub fn deinit(self: *Module) void {
    self.arena.deinit();
    self.* = undefined;
}

pub fn Section(comptime section: std.wasm.Section) type {
    const fields = std.meta.fields(Module);
    const num = @enumToInt(section) + 1; // 0 == allocator, 1 == custom, etc.
    return std.meta.Child(fields[num].field_type);
}

test "Section" {
    const module: Module = undefined;
    try std.testing.expectEqual(std.meta.Child(@TypeOf(module.custom)), Section(.custom));
    try std.testing.expectEqual(std.meta.Child(@TypeOf(module.memory)), Section(.memory));
    try std.testing.expectEqual(std.meta.Child(@TypeOf(module.data)), Section(.data));
}

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
    op: std.wasm.Opcode,
    pop_len: u8,
    arg: Op.Arg,
};

pub const InitExpr = union(enum) {
    i32_const: i32,
    i64_const: i64,
    f32_const: f32,
    f64_const: f64,
    global_get: u32,

    fn parse(reader: anytype) !InitExpr {
        const opcode = @intToEnum(std.wasm.Opcode, try reader.readByte());
        const result: InitExpr = switch (opcode) {
            .i32_const => .{ .i32_const = try readVarint(i32, reader) },
            .i64_const => .{ .i64_const = try readVarint(i64, reader) },
            .f32_const => .{ .f32_const = @bitCast(f32, try reader.readIntLittle(i32)) },
            .f64_const => .{ .f64_const = @bitCast(f64, try reader.readIntLittle(i64)) },
            .global_get => .{ .global_get = try readVarint(u32, reader) },
            else => return error.UnsupportedInitExpr,
        };
        if (std.wasm.opcode(.end) != try reader.readByte()) {
            return error.InitExprTerminationError;
        }
        return result;
    }
};

pub fn postProcess(self: *Module) !void {
    if (self.post_process == null) {
        self.post_process = try PostProcess.init(self);
    }
}

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
        try std.testing.expectEqual(@as(u32, 624485), try readVarint(u32, ios.reader()));
        ios.pos = 0;
        try std.testing.expectEqual(@as(u21, 624485), try readVarint(u21, ios.reader()));
    }
    {
        var ios = std.io.fixedBufferStream("\xC0\xBB\x78");
        try std.testing.expectEqual(@as(i32, -123456), try readVarint(i32, ios.reader()));
        ios.pos = 0;
        try std.testing.expectEqual(@as(i21, -123456), try readVarint(i21, ios.reader()));
    }
    {
        var ios = std.io.fixedBufferStream("\x7F");
        try std.testing.expectEqual(@as(i7, -1), try readVarint(i7, ios.reader()));
        ios.pos = 0;
        try std.testing.expectEqual(@as(i21, -1), try readVarint(i21, ios.reader()));
        ios.pos = 0;
        try std.testing.expectEqual(@as(i32, -1), try readVarint(i32, ios.reader()));
    }
    {
        var ios = std.io.fixedBufferStream("\xa4\x03");
        try std.testing.expectEqual(@as(i21, 420), try readVarint(i21, ios.reader()));
        ios.pos = 0;
        try std.testing.expectEqual(@as(i32, 420), try readVarint(i32, ios.reader()));
    }
}

fn readVarintEnum(comptime E: type, reader: anytype) !E {
    const raw = try readVarint(std.meta.TagType(E), reader);
    if (@typeInfo(E).Enum.is_exhaustive) {
        return try std.meta.intToEnum(E, raw);
    } else {
        return @intToEnum(E, raw);
    }
}

fn expectEos(reader: anytype) !void {
    var tmp: [1]u8 = undefined;
    const len = try reader.read(&tmp);
    if (len != 0) {
        return error.NotEndOfStream;
    }
}

fn Mut(comptime T: type) type {
    var ptr_info = @typeInfo(T).Pointer;
    ptr_info.is_const = false;
    return @Type(.{ .Pointer = ptr_info });
}

// --- Before ---
// const count = try readVarint(u32, section.reader());
// result.field = arena.allocator.alloc(@TypeOf(result.field), count);
// for (result.field) |*item| {
//
// --- After ---
// const count = try readVarint(u32, section.reader());
// for (self.allocInto(&result.field, count)) |*item| {
fn allocInto(self: *Module, ptr_to_slice: anytype, count: usize) !Mut(std.meta.Child(@TypeOf(ptr_to_slice))) {
    const Slice = Mut(std.meta.Child(@TypeOf(ptr_to_slice)));
    std.debug.assert(@typeInfo(Slice).Pointer.size == .Slice);

    var result = try self.arena.allocator.alloc(std.meta.Child(Slice), count);
    ptr_to_slice.* = result;
    return result;
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

    var customs = std.ArrayList(Module.Section(.custom)).init(&result.arena.allocator);
    errdefer customs.deinit();

    while (true) {
        const id = reader.readByte() catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
        const section_len = try readVarint(u32, reader);
        var section = std.io.limitedReader(reader, section_len);

        switch (try std.meta.intToEnum(std.wasm.Section, id)) {
            .type => {
                const count = try readVarint(u32, section.reader());
                for (try result.allocInto(&result.@"type", count)) |*t| {
                    t.form = try readVarintEnum(Type.Form, section.reader());

                    const param_count = try readVarint(u32, section.reader());
                    for (try result.allocInto(&t.param_types, param_count)) |*param_type| {
                        param_type.* = try readVarintEnum(Type.Value, section.reader());
                    }

                    const return_count = try readVarint(u1, section.reader());
                    t.return_type = if (return_count == 0) null else try readVarintEnum(Type.Value, section.reader());
                }
                try expectEos(section.reader());
            },
            .import => {
                const count = try readVarint(u32, section.reader());
                for (try result.allocInto(&result.import, count)) |*i| {
                    const module_len = try readVarint(u32, section.reader());
                    const module_data = try result.arena.allocator.alloc(u8, module_len);
                    try section.reader().readNoEof(module_data);
                    i.module = module_data;

                    const field_len = try readVarint(u32, section.reader());
                    const field_data = try result.arena.allocator.alloc(u8, field_len);
                    try section.reader().readNoEof(field_data);
                    i.field = field_data;

                    // TODO: actually test import parsing
                    const kind = try readVarintEnum(ExternalKind, section.reader());
                    i.kind = switch (kind) {
                        .Function => .{ .Function = try readVarintEnum(Index.FuncType, section.reader()) },
                        .Table => @panic("TODO"),
                        .Memory => @panic("TODO"),
                        .Global => @panic("TODO"),
                    };
                }
                try expectEos(section.reader());
            },
            .function => {
                const count = try readVarint(u32, section.reader());
                for (try result.allocInto(&result.function, count)) |*f| {
                    f.type_idx = try readVarintEnum(Index.FuncType, section.reader());
                }
                try expectEos(section.reader());
            },
            .table => {
                const count = try readVarint(u32, section.reader());
                for (try result.allocInto(&result.table, count)) |*t| {
                    t.element_type = try readVarintEnum(Type.Elem, section.reader());

                    const flags = try readVarint(u1, section.reader());
                    t.limits.initial = try readVarint(u32, section.reader());
                    t.limits.maximum = if (flags == 0) null else try readVarint(u32, section.reader());
                }
                try expectEos(section.reader());
            },
            .memory => {
                const count = try readVarint(u32, section.reader());
                for (try result.allocInto(&result.memory, count)) |*m| {
                    const flags = try readVarint(u1, section.reader());
                    m.limits.initial = try readVarint(u32, section.reader());
                    m.limits.maximum = if (flags == 0) null else try readVarint(u32, section.reader());
                }
                try expectEos(section.reader());
            },
            .global => {
                const count = try readVarint(u32, section.reader());
                for (try result.allocInto(&result.global, count)) |*g| {
                    g.@"type".content_type = try readVarintEnum(Type.Value, section.reader());
                    g.@"type".mutability = (try readVarint(u1, section.reader())) == 1;
                    g.init = try InitExpr.parse(section.reader());
                }
                try expectEos(section.reader());
            },
            .@"export" => {
                const count = try readVarint(u32, section.reader());
                for (try result.allocInto(&result.@"export", count)) |*e| {
                    const field_len = try readVarint(u32, section.reader());
                    const field_data = try result.arena.allocator.alloc(u8, field_len);
                    try section.reader().readNoEof(field_data);
                    e.field = field_data;
                    e.kind = try readVarintEnum(ExternalKind, section.reader());
                    e.index = try readVarint(u32, section.reader());
                }
                try expectEos(section.reader());
            },
            .start => {
                const index = try readVarint(u32, section.reader());
                result.start = .{
                    .index = try readVarintEnum(Index.Function, section.reader()),
                };
                try expectEos(section.reader());
            },
            .element => {
                const count = try readVarint(u32, section.reader());
                for (try result.allocInto(&result.element, count)) |*e| {
                    e.index = try readVarintEnum(Index.Table, section.reader());
                    e.offset = try InitExpr.parse(section.reader());

                    const num_elem = try readVarint(u32, section.reader());
                    for (try result.allocInto(&e.elems, count)) |*func| {
                        func.* = try readVarintEnum(Index.Function, section.reader());
                    }
                }
                try expectEos(section.reader());
            },
            .code => {
                const count = try readVarint(u32, section.reader());
                for (try result.allocInto(&result.code, count)) |*c| {
                    const body_size = try readVarint(u32, section.reader());
                    if (body_size != section.bytes_left) {
                        // FIXME: this is probably the wrong size
                        return error.BodySizeMismatch;
                    }

                    c.locals = blk: {
                        // TODO: double pass here to preallocate the exact array size
                        var list = std.ArrayList(Type.Value).init(&result.arena.allocator);
                        var local_count = try readVarint(u32, section.reader());
                        while (local_count > 0) : (local_count -= 1) {
                            var current_count = try readVarint(u32, section.reader());
                            const typ = try readVarintEnum(Type.Value, section.reader());
                            while (current_count > 0) : (current_count -= 1) {
                                try list.append(typ);
                            }
                        }
                        break :blk list.items;
                    };

                    c.body = body: {
                        var list = std.ArrayList(Module.Instr).init(&result.arena.allocator);
                        while (true) {
                            const opcode = section.reader().readByte() catch |err| switch (err) {
                                error.EndOfStream => {
                                    const last = list.popOrNull() orelse return error.MissingFunctionEnd;
                                    if (last.op != .end) {
                                        return error.MissingFunctionEnd;
                                    }
                                    break :body list.items;
                                },
                                else => return err,
                            };

                            const op_meta = Op.Meta.all[opcode] orelse return error.InvalidOpCode;

                            try list.append(.{
                                .op = @intToEnum(std.wasm.Opcode, opcode),
                                .pop_len = @intCast(u8, op_meta.pop.len),
                                .arg = switch (op_meta.arg_kind) {
                                    .Void => undefined,
                                    .I32 => .{ .I32 = try readVarint(i32, section.reader()) },
                                    .U32 => .{ .U32 = try readVarint(u32, section.reader()) },
                                    .I64 => .{ .I64 = try readVarint(i64, section.reader()) },
                                    .U64 => .{ .U64 = try readVarint(u64, section.reader()) },
                                    .F32 => .{ .F64 = @bitCast(f32, try section.reader().readIntLittle(i32)) },
                                    .F64 => .{ .F64 = @bitCast(f64, try section.reader().readIntLittle(i64)) },
                                    .Type => .{ .I64 = try readVarint(u7, section.reader()) },
                                    .U32z => .{
                                        .U32z = .{
                                            .data = try readVarint(u32, section.reader()),
                                            .reserved = try section.reader().readByte(),
                                        },
                                    },
                                    .Mem => .{
                                        .Mem = .{
                                            .align_ = try readVarint(u32, section.reader()),
                                            .offset = try readVarint(u32, section.reader()),
                                        },
                                    },
                                    .Array => blk: {
                                        const target_count = try readVarint(u32, section.reader());
                                        const size = target_count + 1; // Implementation detail: we shove the default into the last element of the array

                                        const data = try result.arena.allocator.alloc(u32, size);
                                        for (data) |*item| {
                                            item.* = try readVarint(u32, section.reader());
                                        }
                                        break :blk .{
                                            .Array = .{
                                                .ptr = data.ptr,
                                                .len = data.len,
                                            },
                                        };
                                    },
                                },
                            });
                        }
                    };
                }
                try expectEos(section.reader());
            },
            .data => {
                const count = try readVarint(u32, section.reader());
                for (try result.allocInto(&result.data, count)) |*d| {
                    d.index = try readVarintEnum(Index.Memory, section.reader());
                    d.offset = try InitExpr.parse(section.reader());

                    const size = try readVarint(u32, section.reader());
                    const data = try result.arena.allocator.alloc(u8, size);
                    try section.reader().readNoEof(data);
                    d.data = data;
                }
                try expectEos(section.reader());
            },
            .custom => {
                const custom_section = try customs.addOne();

                const name_len = try readVarint(u32, section.reader());
                const name = try result.arena.allocator.alloc(u8, name_len);
                try section.reader().readNoEof(name);
                custom_section.name = name;

                const payload = try result.arena.allocator.alloc(u8, section.bytes_left);
                try section.reader().readNoEof(payload);
                custom_section.payload = payload;

                try expectEos(section.reader());
            },
        }

        // Putting this in all the switch paths makes debugging much easier
        // Leaving an extra one here in case one of the paths is missing
        if (std.builtin.mode == .Debug) {
            try expectEos(section.reader());
        }
    }

    result.custom = customs.toOwnedSlice();

    result.post_process = try PostProcess.init(&result);

    return result;
}

pub const instantiate = Instance.init;

const empty_raw_bytes = &[_]u8{ 0, 'a', 's', 'm', 1, 0, 0, 0 };

test "empty module" {
    var ios = std.io.fixedBufferStream(empty_raw_bytes);
    var module = try Module.parse(std.testing.allocator, ios.reader());
    defer module.deinit();

    try std.testing.expectEqual(@as(usize, 0), module.memory.len);
    try std.testing.expectEqual(@as(usize, 0), module.@"type".len);
    try std.testing.expectEqual(@as(usize, 0), module.function.len);
    try std.testing.expectEqual(@as(usize, 0), module.@"export".len);
}

test "module with only type" {
    const raw_bytes = empty_raw_bytes ++ // (module
        "\x01\x04\x01\x60\x00\x00" ++ //      (type (func)))
        "";
    var ios = std.io.fixedBufferStream(raw_bytes);
    var module = try Module.parse(std.testing.allocator, ios.reader());
    defer module.deinit();

    try std.testing.expectEqual(@as(usize, 1), module.@"type".len);
    try std.testing.expectEqual(@as(usize, 0), module.@"type"[0].param_types.len);
    try std.testing.expectEqual(@as(?Type.Value, null), module.@"type"[0].return_type);
}

test "module with function body" {
    const raw_bytes = empty_raw_bytes ++ //          (module
        "\x01\x05\x01\x60\x00\x01\x7f" ++ //           (type (;0;) (func (result i32)))
        "\x03\x02\x01\x00" ++ //                       (func (;0;) (type 0)
        "\x07\x05\x01\x01\x61\x00\x00" ++ //           (export "a" (func 0))
        "\x0a\x07\x01\x05\x00\x41\xa4\x03\x0b" ++ //     i32.const 420
        "";

    var ios = std.io.fixedBufferStream(raw_bytes);
    var module = try Module.parse(std.testing.allocator, ios.reader());
    defer module.deinit();

    try std.testing.expectEqual(@as(usize, 1), module.@"type".len);
    try std.testing.expectEqual(@as(usize, 0), module.@"type"[0].param_types.len);
    try std.testing.expectEqual(Type.Value.I32, module.@"type"[0].return_type.?);

    try std.testing.expectEqual(@as(usize, 1), module.@"export".len);

    try std.testing.expectEqual(@as(usize, 1), module.function.len);
    try std.testing.expectEqual(@as(usize, 1), module.code.len);
    try std.testing.expectEqual(@as(usize, 1), module.code[0].body.len);
    try std.testing.expectEqual(std.wasm.Opcode.i32_const, module.code[0].body[0].op);
}

test "global definitions" {
    const raw_bytes = empty_raw_bytes ++ //                  (module
        "\x06\x09\x01\x7f\x01\x41\x80\x80\xc0\x00\x0b" ++ //   (global (mut i32) (i32.const 1048576)))
        "";
    var ios = std.io.fixedBufferStream(raw_bytes);
    var module = try Module.parse(std.testing.allocator, ios.reader());
    defer module.deinit();

    try std.testing.expectEqual(@as(usize, 1), module.global.len);
    try std.testing.expectEqual(Type.Value.I32, module.global[0].type.content_type);
    try std.testing.expectEqual(true, module.global[0].type.mutability);
}
