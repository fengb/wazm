const std = @import("std");

pub const Module = struct {
    arena: *std.heap.ArenaAllocator,
    nodes: []Node,

    pub fn deinit(self: *Module) void {
        self.arena.deinit();
        self.nodes = &[0]Node{};
    }

    pub const Node = union(enum) {
        memory: usize,
        func: Func,
    };

    pub const Type = enum {
        I32,
        I64,
        F32,
        F64,
    };

    pub const Export = struct {
        name: []const u8,
        value: union(enum) {
            func: []const n8,
        },
    };

    pub const Func = struct {
        name: []const u8,
        params: []Decl,
        result: Type,
        locals: []Decl,
        instrs: []Op, // TODO: fill with actual instructions

        const Decl = struct {
            name: []const u8,
            typ: Type,
        };
    };
};

pub const Op = enum(u8) {
    Unreachable = 0x00,
    Nop = 0x01,
    Block = 0x02,
    Loop = 0x03,
    If = 0x04,
    Else = 0x05,
    // Try = 0x06,
    // Catch = 0x07,
    // Throw = 0x08,
    // Rethrow = 0x09,
    // BrOnExn = 0x0A,
    End = 0x0B,
    Br = 0x0C,
    BrIf = 0x0D,
    BrTable = 0x0E,
    BrReturn = 0x0F,

    Call = 0x10,
    CallIndirect = 0x11,
    // ReturnCall = 0x12,
    // ReturnCallIndirect = 0x13,
    // 0x14
    // 0x15
    // 0x16
    // 0x17
    // 0x18
    // 0x19
    Drop = 0x1A,
    Select = 0x1B,
    // SelectT = 0x1C,
    // 0x1D
    // 0x1E
    // 0x1F

    LocalGet = 0x20,
    LocalSet = 0x21,
    LocalTee = 0x22,
    GlobalGet = 0x23,
    GlobalSet = 0x24,
    // TableGet = 0x25,
    // TableSet = 0x26,
    // 0x27
    I32Load = 0x28,
    I64Load = 0x29,
    F32Load = 0x2A,
    F64Load = 0x2B,
    I32Load8S = 0x2C,
    I32Load8U = 0x2D,
    I32Load16S = 0x2E,

    I64Load8S = 0x30,
    I64Load8U = 0x31,
    I64Load16S = 0x32,
    I64Load16U = 0x33,
    I64Load32S = 0x34,
    I64Load32U = 0x35,
    I32Store = 0x36,
    I64Store = 0x37,
    F32Store = 0x38,
    F64Store = 0x39,
    I32Store8 = 0x3A,
    I32Store16 = 0x3B,
    I64Store8 = 0x3C,
    I64Store16 = 0x3D,
    I64Store32 = 0x3E,
    MemorySize = 0x3F,

    _,
};
