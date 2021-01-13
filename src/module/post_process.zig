const std = @import("std");

const Module = @import("../module.zig");

pub fn post_process(self: *Module) !void {
    var temp_arena = std.heap.ArenaAllocator.init(self.arena.child_allocator);
    defer temp_arena.deinit();

    var stack_types = std.ArrayList(Module.Type.Value).init(&temp_arena.allocator);

    const import_funcs = 0;

    for (self.code) |body, i| {
        const func = self.function[i];
        const func_type = self.@"type"[@enumToInt(func.type_idx)];
        const func_idx = i + import_funcs;
        for (body.code) |instr| {
            for (instr.op.pop) |pop| {
                const top = stack_types.popOrNull() orelse return error.StackMismatch;
                const expected: Module.Type.Value = switch (pop) {
                    .I32 => .I32,
                    .I64 => .I64,
                    .F32 => .F32,
                    .F64 => .F64,
                    .Poly => switch (instr.op.code) {
                        0x1A => continue, // Drops *any* value, no comparison needed
                        0x21, 0x22 => local_type(instr.arg.U32, func_type.param_types, body.locals),
                        else => @panic("TODO"),
                    },
                };
                if (expected != top) {
                    return error.StackMismatch;
                }
            }

            if (instr.op.push) |push| {
                try stack_types.append(switch (push) {
                    .I32 => .I32,
                    .I64 => .I64,
                    .F32 => .F32,
                    .F64 => .F64,
                    .Poly => switch (instr.op.code) {
                        0x20, 0x22 => local_type(instr.arg.U32, func_type.param_types, body.locals),
                        else => @panic("TODO"),
                    },
                });
            }
        }

        if (func_type.return_type) |return_type| {
            if (stack_types.items.len != 1 or stack_types.pop() != return_type) {
                return error.StackMismatch;
            }
        } else {
            if (stack_types.items.len != 0) {
                return error.StackMismatch;
            }
        }
    }
}

fn local_type(local_idx: u32, params: []Module.Type.Value, locals: []Module.Type.Value) Module.Type.Value {
    if (local_idx < params.len) {
        return params[local_idx];
    } else {
        return locals[local_idx - params.len];
    }
}
