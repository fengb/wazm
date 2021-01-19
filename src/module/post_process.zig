const std = @import("std");

const Module = @import("../module.zig");
const Op = @import("../op.zig");
const Wat = @import("../wat.zig");

const StackCheck = struct {
    top: ?*Node,
    list: std.ArrayList(?Node),

    const Node = struct {
        @"type": Module.Type.Value,
        prev: ?*Node,
    };

    pub fn init(allocator: *std.mem.Allocator) StackCheck {
        return .{
            .top = null,
            .list = std.ArrayList(?Node).init(allocator),
        };
    }

    pub fn reset(self: *StackCheck, size: usize) !void {
        self.top = null;
        self.list.shrinkRetainingCapacity(0);
        try self.list.ensureCapacity(size);
    }

    pub fn setPush(self: *StackCheck, idx: usize, typ: ?Module.Type.Value) !void {
        std.debug.assert(idx == self.list.items.len);
        if (typ) |typ_| {
            self.list.appendAssumeCapacity(Node{ .@"type" = typ_, .prev = self.top });
            self.top = &self.list.items[idx].?;
        } else {
            self.list.appendAssumeCapacity(if (self.top) |top| top.* else null);
        }
    }

    pub fn popType(self: *StackCheck) !Module.Type.Value {
        if (self.top) |top| {
            self.top = top.prev;
            return top.@"type";
        } else {
            return error.StackMismatch;
        }
    }

    pub fn popTypes(self: *StackCheck, many: []const Module.Type.Value) !void {
        var i: usize = many.len;
        while (i > 0) {
            i -= 1;
            const param = many[i];
            if (param != try self.popType()) {
                return error.StackMismatch;
            }
        }
    }
};

pub fn post_process(self: *Module) !void {
    var temp_arena = std.heap.ArenaAllocator.init(self.arena.child_allocator);
    defer temp_arena.deinit();

    var import_funcs: usize = 0;
    for (self.import) |import| {
        if (import.kind == .Function) {
            import_funcs += 1;
        }
    }

    var stack_check = StackCheck.init(&temp_arena.allocator);

    var stack_blocks = std.ArrayList(usize).init(&temp_arena.allocator);
    var block_metas = std.AutoHashMap(usize, struct { op: Op.Code, block_type: Module.Type.Block, jump_target: usize }).init(&temp_arena.allocator);
    var jump_matches = std.ArrayList(struct { instr_idx: usize, block_instr: usize }).init(&temp_arena.allocator);

    for (self.code) |body, f| {
        const func = self.function[f];
        const func_type = self.@"type"[@enumToInt(func.type_idx)];
        const func_idx = f + import_funcs;

        std.debug.assert(stack_check.top == null);
        try stack_check.reset(body.code.len);

        for (body.code) |instr, instr_idx| {
            const op_meta = Op.Meta.of(instr.op);
            switch (instr.op) {
                .call => {
                    const call_func = self.function[instr.arg.U32];
                    const call_type = self.@"type"[@enumToInt(call_func.type_idx)];
                    try stack_check.popTypes(call_type.param_types);
                    try stack_check.setPush(instr_idx, call_type.return_type);
                },
                .call_indirect => {
                    const call_type = self.@"type"[instr.arg.U32];
                    try stack_check.popTypes(call_type.param_types);
                    try stack_check.setPush(instr_idx, call_type.return_type);
                },
                .@"else" => @panic("TODO: handle if blockvalue else"),
                // Drops *any* value, no comparison needed
                .drop => _ = try stack_check.popType(),
                else => {
                    for (op_meta.pop) |pop| {
                        const expected: Module.Type.Value = switch (pop) {
                            .I32 => .I32,
                            .I64 => .I64,
                            .F32 => .F32,
                            .F64 => .F64,
                            .Poly => switch (instr.op) {
                                .@"local.set", .@"local.tee" => localType(instr.arg.U32, func_type.param_types, body.locals),
                                else => @panic("TODO"),
                            },
                        };
                        if (expected != try stack_check.popType()) {
                            return error.StackMismatch;
                        }
                    }

                    if (op_meta.push) |push| {
                        try stack_check.setPush(instr_idx, switch (push) {
                            .I32 => .I32,
                            .I64 => .I64,
                            .F32 => .F32,
                            .F64 => .F64,
                            .Poly => switch (instr.op) {
                                .@"local.get", .@"local.tee" => localType(instr.arg.U32, func_type.param_types, body.locals),
                                else => @panic("TODO"),
                            },
                        });
                    } else {
                        try stack_check.setPush(instr_idx, null);
                    }
                },
            }
        }

        std.debug.assert(stack_check.list.items.len == body.code.len);
        if (func_type.return_type) |return_type| {
            if (return_type != try stack_check.popType()) {
                return error.StackMismatch;
            }
        }

        if (stack_check.top != null) {
            return error.StackMismatch;
        }

        // Block checks

        stack_blocks.shrinkRetainingCapacity(0);
        block_metas.clearRetainingCapacity();
        jump_matches.shrinkRetainingCapacity(0);

        for (body.code) |instr, instr_idx| {
            const op_meta = Op.Meta.of(instr.op);
            switch (instr.op) {
                .br, .br_if => {
                    const block_stack_idx = std.math.sub(usize, stack_blocks.items.len, 1 + instr.arg.U32) catch return error.JumpExceedsBlock;
                    const target_block = stack_blocks.items[block_stack_idx];
                    try jump_matches.append(.{ .instr_idx = instr_idx, .block_instr = target_block });
                },
                .br_table => @panic("TODO"),
                .block, .loop, .@"if" => {
                    if (instr.op == .@"if") {
                        // "if" is its own jump
                        try jump_matches.append(.{ .instr_idx = instr_idx, .block_instr = instr_idx });
                    }
                    const result_type = @intToEnum(Op.Arg.Type, instr.arg.V128);
                    const converted_type: Module.Type.Block = switch (result_type) {
                        .Void => .Empty,
                        .I32 => .I32,
                        .I64 => .I64,
                        .F32 => .F32,
                        .F64 => .F64,
                    };
                    try stack_blocks.append(instr_idx);
                    try block_metas.putNoClobber(instr_idx, .{
                        .op = instr.op,
                        .block_type = converted_type,
                        .jump_target = undefined,
                    });
                },
                .end, .@"else" => {
                    const block_instr = stack_blocks.popOrNull() orelse return error.BlockMismatch;
                    var block_meta = block_metas.get(block_instr).?;

                    if (block_meta.block_type != .Empty) {
                        const top = stack_check.list.items[instr_idx].?;
                        if (@enumToInt(block_meta.block_type) != @enumToInt(top.@"type")) {
                            return error.StackMismatch;
                        }
                    }

                    block_meta.jump_target = switch (block_meta.op) {
                        .loop => block_instr,
                        .@"else", .@"if", .block => instr_idx,
                        else => unreachable,
                    };
                    block_metas.putAssumeCapacity(block_instr, block_meta);

                    if (instr.op == .@"else") {
                        if (block_meta.op != .@"if") {
                            return error.ElseWithoutIf;
                        }

                        try stack_blocks.append(instr_idx);
                        try block_metas.putNoClobber(instr_idx, .{
                            .op = instr.op,
                            .block_type = block_meta.block_type,
                            .jump_target = undefined,
                        });
                    }
                },
                else => {},
            }
        }

        for (jump_matches.items) |jump| {
            const block_meta = block_metas.get(jump.block_instr).?;
            try self.jumps.putNoClobber(
                &self.arena.allocator,
                .{ .func = @intCast(u32, func_idx), .instr = @intCast(u32, jump.instr_idx) },
                .{
                    .has_value = block_meta.block_type != .Empty,
                    .stack_unroll = undefined,
                    .target = .{ .single = @intCast(u32, block_meta.jump_target) },
                },
            );
        }

        if (stack_blocks.items.len != 0) {
            return error.BlockMismatch;
        }
    }
}

fn localType(local_idx: u32, params: []const Module.Type.Value, locals: []const Module.Type.Value) Module.Type.Value {
    if (local_idx < params.len) {
        return params[local_idx];
    } else {
        return locals[local_idx - params.len];
    }
}

test "smoke" {
    var fbs = std.io.fixedBufferStream(
        \\(module
        \\  (func (result i32)
        \\    i32.const 40
        \\    i32.const 2
        \\    i32.add))
    );
    var module = try Wat.parseNoValidate(std.testing.allocator, fbs.reader());
    defer module.deinit();

    try module.post_process();
}

test "add nothing" {
    var fbs = std.io.fixedBufferStream(
        \\(module
        \\  (func (result i32)
        \\    i32.add))
    );
    var module = try Wat.parseNoValidate(std.testing.allocator, fbs.reader());
    defer module.deinit();

    std.testing.expectError(error.StackMismatch, module.post_process());
}

test "add wrong types" {
    var fbs = std.io.fixedBufferStream(
        \\(module
        \\  (func (result i32)
        \\    i32.const 40
        \\    i64.const 2
        \\    i32.add))
    );
    var module = try Wat.parseNoValidate(std.testing.allocator, fbs.reader());
    defer module.deinit();

    std.testing.expectError(error.StackMismatch, module.post_process());
}

test "return nothing" {
    var fbs = std.io.fixedBufferStream(
        \\(module
        \\  (func (result i32)))
    );
    var module = try Wat.parseNoValidate(std.testing.allocator, fbs.reader());
    defer module.deinit();

    std.testing.expectError(error.StackMismatch, module.post_process());
}

test "return wrong type" {
    var fbs = std.io.fixedBufferStream(
        \\(module
        \\  (func (result i32)
        \\    i64.const 40))
    );
    var module = try Wat.parseNoValidate(std.testing.allocator, fbs.reader());
    defer module.deinit();

    std.testing.expectError(error.StackMismatch, module.post_process());
}

test "jump locations" {
    var fbs = std.io.fixedBufferStream(
        \\(module
        \\  (func
        \\    block
        \\      loop
        \\        br 0
        \\        br 1
        \\      end
        \\    end))
    );
    var module = try Wat.parseNoValidate(std.testing.allocator, fbs.reader());
    defer module.deinit();

    try module.post_process();

    const jump_0 = module.jumps.get(.{ .func = 0, .instr = 2 }) orelse return error.JumpNotFound;
    std.testing.expectEqual(@as(usize, 1), jump_0.target.single);

    const jump_1 = module.jumps.get(.{ .func = 0, .instr = 3 }) orelse return error.JumpNotFound;
    std.testing.expectEqual(@as(usize, 5), jump_1.target.single);
}
