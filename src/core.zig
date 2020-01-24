const std = @import("std");
const Op = @import("op.zig");

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
        params: []Type,
        result: ?Type,
        locals: []Type,
        instrs: []Instr,
    };

    pub const Instr = struct {
        op: u8,
        arg: Op.Arg,
    };
};
