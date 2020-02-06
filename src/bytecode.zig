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
},

/// Code=2
import: []struct {
    module: []const u8,
    field: []const u8,
    kind: ExternalKind,
},

/// Code=3
function: []Index.Type,

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
start: struct {
    index: Index.Function,
},

/// Code=9
element: []struct {
    index: Index.Table,
    offset: i32,
    elems: []Index.Function,
},

/// Code=10
code: []struct {
    locals: []struct {
        count: u32,
        @"type": Type.Value,
    },
    code: []const u8,
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

const Index = struct {
    const Type = enum(u32) { _ };
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

pub fn parse(allocator: *std.mem.Allocator, in_stream: var) !Bytecode {
    const signature = try in_stream.readIntLittle(u32);
    if (signature != magic_number) {
        return error.InvalidFormat;
    }

    const version = try in_stream.readIntLittle(u32);
    if (version != 1) {
        return error.InvalidFormat;
    }

    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();

    var funcs = std.ArrayList(core.Module.Func).init(&arena.allocator);
    var exports = std.ArrayList(core.Module.Export).init(&arena.allocator);

    while (true) {
        const id = try in_stream.readByte();
        const payload_len = try in_stream.readIntLittle(u32);

        switch (id) {
            0x0 => Custom,
            0x1 => FuncType,
            0x2 => Import,
            0x3 => Function,
            0x4 => Table,
            0x5 => Memory,
            0x6 => Global,
            0x7 => Export,
            0x8 => Start,
            0x9 => Element,
            0xA => Code,
            0xB => Data,
            else => return error.InvalidFormat,
        }
    }

    return error.Nop;
}

pub fn deinit(self: Bytecode, allocator: *std.heap.Allocator) void {
    self.arena.deinit();
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
