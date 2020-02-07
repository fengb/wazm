const std = @import("std");
const core = @import("core.zig");
const Op = @import("op.zig");

const magic_number = std.mem.readIntLittle("\x00asm");
const version = 1;

const Bytecode = @This();

arena: std.heap.ArenaAllocator,

/// Code=1
@"type": []struct {
    form: i7,
    param_types: []Type.Value,
    return_type: Type.Value,
} = .{},

/// Code=2
import: []struct {
    module: []const u8,
    field: []const u8,
    kind: ExternalKind,
} = .{},

/// Code=3
function: []Index.FuncType,

/// Code=4
table: []struct {
    element_type: Type.Elem,
    limits: ResizableLimits,
} = .{},

/// Code=5
memory: []struct {
    limits: ResizableLimits,
} = .{},

/// Code=6
global: []struct {
    @"type": struct {
        content_type: Type.Value,
        mutability: bool,
    },
    init: InitExpr,
} = .{},

/// Code=7
@"export": []struct {
    field: []const u8,
    index: union(ExternalKind) {
        Table: Index.Table,
        Function: Index.Function,
        Memory: Index.Memory,
        Global: Index.Global,
    },
} = .{},

/// Code=8
start: ?struct {
    index: Index.Function,
} = null,

/// Code=9
element: []struct {
    index: Index.Table,
    offset: InitExpr,
    elems: []Index.Function,
} = .{},

/// Code=10
code: []struct {
    locals: []struct {
        @"type": []Type.Value,
    },
    code: []const u8,
} = .{},

/// Code=11
data: []struct {
    index: Index.Memory,
    offset: InitExpr,
    data: []const u8,
} = .{},

/// Code=0
custom: []struct {
    name: []const u8,
    payload: []const u8,
} = .{},

const Index = struct {
    const FuncType = enum(u32) { _ };
    const Table = enum(u32) { _ };
    const Function = enum(u32) { _ };
    const Memory = enum(u32) { _ };
    const Global = enum(u32) { _ };
};

const Type = struct {
    const Value = enum(i7) {
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
};

const ExternalKind = enum(u8) {
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

    var unsigned_result: U = 0;
    var shift: S = 0;
    while (true) : (shift = try std.math.add(S, shift, 7)) {
        const byte = try in_stream.readByte();
        unsigned_result += try std.math.shlExact(U, 0x7F & byte, shift);

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
}

fn expectEos(in_stream: var) !void {
    var tmp: [1]u8 = undefined;
    const len = try self.read(&result);
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

fn ErrorOf(func: var) type {
    const R = @typeInfo(@TypeOf(func)).Fn.return_type;
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
fn allocInto(self: Bytecode, ptr_to_slice: var, count: usize) std.meta.Child(@TypeOf(ptr_to_slice)) {
    const Slice = std.meta.Child(@TypeOf(ptr_to_slice));
    std.debug.assert(@typeInfo(Slice).Pointer.size == .Slice);

    ptr_to_slice.* = self.arena.allocator.alloc(std.meta.Child(Slice), count);
    return ptr_to_slice.*;
}

pub fn parse(allocator: *std.mem.Allocator, in_stream: var) !Bytecode {
    const signature = try in_stream.readIntLittle(u32);
    if (signature != magic_number) {
        return error.InvalidFormat;
    }

    const version = try in_stream.readIntLittle(u32);
    if (version != 1) {
        return error.InvalidFormat;
    }

    var result = Bytecode{
        .arena = std.heap.ArenaAllocator.init(allocator),
    };
    errdefer result.arena.deinit();

    while (true) {
        const id = in_stream.readByte() catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
        const payload_len = try readVarint(u32, in_stream);
        const payload = FixedInStream(in_stream.readFn).init(in_stream, payload_len);

        switch (id) {
            0x1 => {
                const count = try readVarint(u32, &payload.stream);
                for (result.allocInto(&result.@"type", count)) |*t| {
                    t.form = try readVarint(i7, &payload.stream);

                    const param_count = try readVarint(u32, &payload.stream);
                    for (result.allocInto(&t.param_types, count)) |*param_type| {
                        param_type.* = try payload.stream.readEnum(Type.Value);
                    }

                    const return_count = try readVarint(u1, &payload.stream);
                    t.return_type = if (return_count == 0) null else try payload.stream.readEnum(Type.Value);
                }
            },
            0x2 => {
                const count = try readVarint(u32, &payload.stream);
                for (result.allocInto(&result.import, count)) |*i| {
                    const module_len = try readVarint(u32, &payload.stream);
                    try payload.stream.readNoEof(result.allocInto(&i.module, module_len));

                    const field_len = try readVarint(u32, &payload.stream);
                    try payload.stream.readNoEof(result.allocInto(&i.field, field_len));

                    i.kind = try payload.stream.readEnum(ExternalKind);
                }
            },
            0x3 => {
                const count = try readVarint(u32, &payload.stream);
                for (result.allocInto(&result.function, count)) |*f| {
                    const index = try readVarint(u32, &payload.stream);
                    f.* = @intToEnum(Index.FuncType, index);
                }
            },
            0x4 => {
                const count = try readVarint(u32, &payload.stream);
                for (result.allocInto(&result.table, count)) |*t| {
                    t.element_type = try payload.stream.readEnum(Type.Elem);

                    const flags = try readVarint(u1, &payload.stream);
                    t.limits.initial = try readVarint(u32, &payload.stream);
                    t.limits.maximum = if (flags == 0) null else try readVarint(u32, &payload.stream);
                }
            },
            0x5 => {
                const count = try readVarint(u32, &payload.stream);
                for (result.allocInto(&result.memory, count)) |*m| {
                    const flags = try readVarint(u1, &payload.stream);
                    m.limits.initial = try readVarint(u32, &payload.stream);
                    m.limits.maximum = if (flags == 0) null else try readVarint(u32, &payload.stream);
                }
            },
            0x6 => {
                const count = try readVarint(u32, &payload.stream);
                for (result.allocInto(&result.global, count)) |*g| {
                    g.@"type".content_type = try payload.stream.readEnum(Type.Value);
                    g.@"type".mutability = try readVarint(u1, Type.Value) == 1;
                    g.init = .{}; // FIXME
                }
            },
            0x7 => {
                const count = try readVarint(u32, &payload.stream);
                for (result.allocInto(&result.@"export", count)) |*e| {
                    const field_len = try readVarint(u32, &payload.stream);
                    try payload.stream.readNoEof(result.allocInto(&e.field, field_len));

                    const kind = try payload.stream.readEnum(ExternalKind);
                    const index = try readVarint(u32, &payload.stream);
                    e.index = switch (kind) {
                        .Table => .{ .Table = @intToEnum(Index.Table) },
                        .Function => .{ .Function = @intToEnum(Index.Function) },
                        .Memory => .{ .Memory = @intToEnum(Index.Memory) },
                        .Global => .{ .Global = @intToEnum(Index.Global) },
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
                for (result.allocInto(&result.element, count)) |*e| {
                    const index = try readVarint(u32, &payload.stream);
                    e.index = @intToEnum(Index.Table, index);
                    e.offset = .{}; // FIXME

                    const num_elem = try readVarint(u32, &payload.stream);
                    for (result.allocInto(&e.elems, count)) |*func| {
                        const func_index = try readVarint(u32, &payload.stream);
                        func.* = @intToEnum(Index.Function, func_index);
                    }
                }
            },
            0x10 => {
                const count = try readVarint(u32, &payload.stream);
                for (result.allocInto(&result.code, count)) |*c| {
                    const body_size = try readVarint(u32, &payload.stream);
                    const local_count = try readVarint(u32, &payload.stream);
                    for (result.allocInto(&c.locals, local_count)) |*l| {
                        const var_count = try readVarint(u32, &payload.stream);
                        for (result.allocInto(&l.@"type", local_count)) |*t| {
                            t.* = try payload.stream.readEnum(Type.Value);
                        }
                    }
                    // FIXME: this is probably the wrong size
                    try payload.stream.readNoEof(result.allocInto(&c.code, body_size));
                }
            },
            0x11 => {
                const count = try readVarint(u32, &payload.stream);
                for (result.allocInto(&result.data, count)) |*d| {
                    const index = try readVarint(u32, &payload.stream);
                    d.index = @intToEnum(Index.Memory, index);
                    d.offset = .{}; // FIXME

                    const size = try readVarint(u32, &payload.stream);
                    try payload.stream.readNoEof(result.allocInto(&d.data, body_size));
                }
            },
            0x0 => @panic("TODO"),
            else => return error.InvalidFormat,
        }
        try expectEos(&payload.stream);
    }

    return result;
}

pub fn deinit(self: *Bytecode, allocator: *std.heap.Allocator) void {
    self.arena.deinit();
    self.* = .{ .arena = self.arena };
}

pub fn toModule(self: Bytecode, allocator: *std.heap.Allocator) !core.Module {
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();

    return .{
        .memory = @intCast(u32, memory),
        .funcs = funcs.toOwnedSlice(),
        .exports = exports.toOwnedSlice(),
        .arena = arena,
    };
}

pub fn load(allocator: *std.mem.Allocator, in_stream: var) !core.Module {
    const bytecode = try Bytecode.parse(allocator, in_stream);
    defer bytecode.deinit();

    return bytecode.toModule(allocator);
}
