const std = @import("std");

const Module = @import("../module.zig");
const Op = @import("../op.zig");
const Wat = @import("../wat.zig");

pub fn post_process(self: *Module) !void {
    var temp_arena = std.heap.ArenaAllocator.init(self.arena.child_allocator);
    defer temp_arena.deinit();

    var import_funcs: usize = 0;
    for (self.import) |import| {
        if (import.kind == .Function) {
            import_funcs += 1;
        }
    }

    var stack_checker = StackChecker.init(&temp_arena.allocator);

    var stack_blocks = std.ArrayList(usize).init(&temp_arena.allocator);
    var block_metas = std.AutoHashMap(usize, struct { op: Op.Code, block_type: Module.Type.Block, jump_target: usize }).init(&temp_arena.allocator);
    var jump_matches = std.ArrayList(struct { instr_idx: usize, block_instr: usize }).init(&temp_arena.allocator);

    for (self.code) |body, f| {
        const func_idx = f + import_funcs;

        try stack_checker.process(self, f);

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
                        const top = stack_checker.list.items[instr_idx].?;
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

const StackChecker = struct {
    top: ?*Node,
    list: std.ArrayList(?Node),

    const Node = struct {
        @"type": Module.Type.Value,
        prev: ?*Node,
    };

    pub fn init(allocator: *std.mem.Allocator) StackChecker {
        return .{
            .top = null,
            .list = std.ArrayList(?Node).init(allocator),
        };
    }

    pub fn process(self: *StackChecker, module: *const Module, body_idx: usize) !void {
        const func = module.function[body_idx];
        const func_type = module.@"type"[@enumToInt(func.type_idx)];
        const body = module.code[body_idx];

        self.top = null;
        self.list.shrinkRetainingCapacity(0);
        try self.list.ensureCapacity(body.code.len);

        for (body.code) |instr, instr_idx| {
            const op_meta = Op.Meta.of(instr.op);
            switch (instr.op) {
                .call => {
                    const call_func = module.function[instr.arg.U32];
                    const call_type = module.@"type"[@enumToInt(call_func.type_idx)];
                    try self.popTypesCheck(call_type.param_types);
                    try self.setPush(instr_idx, call_type.return_type);
                },
                .call_indirect => {
                    const call_type = module.@"type"[instr.arg.U32];
                    try self.popTypesCheck(call_type.param_types);
                    try self.setPush(instr_idx, call_type.return_type);
                },

                .@"else" => @panic("TODO: handle if blockvalue else"),

                .@"local.tee" => try self.topCheck(localType(instr.arg.U32, func_type.param_types, body.locals)),
                .@"local.set" => try self.popTypesCheck(&.{localType(instr.arg.U32, func_type.param_types, body.locals)}),
                .@"local.get" => try self.setPush(instr_idx, localType(instr.arg.U32, func_type.param_types, body.locals)),

                // Technically pops off 2 elements, makes sure they're the same, and pushes 1 back on
                // But we can just pop 1 off and compare it to the remaining top
                .select => {
                    const prev_top = try self.popType();
                    try self.topCheck(prev_top);
                },

                // Drops *any* value, no check needed
                .drop => _ = try self.popType(),

                else => {
                    for (op_meta.pop) |pop| {
                        try self.popTypesCheck(&.{asValue(pop)});
                    }

                    if (op_meta.push) |push| {
                        try self.setPush(instr_idx, asValue(push));
                    }
                },
            }
            // Didn't push anything on -- copy the existing top over
            if (self.list.items.len == instr_idx) {
                try self.setPush(instr_idx, null);
            }
        }

        if (func_type.return_type) |return_type| {
            try self.popTypesCheck(&.{return_type});
        }

        if (self.top != null) {
            return error.StackMismatch;
        }
    }

    fn asValue(change: Op.Stack.Change) Module.Type.Value {
        return switch (change) {
            .I32 => .I32,
            .I64 => .I64,
            .F32 => .F32,
            .F64 => .F64,
            .Poly => unreachable,
        };
    }

    fn setPush(self: *StackChecker, idx: usize, typ: ?Module.Type.Value) !void {
        std.debug.assert(idx == self.list.items.len);
        if (typ) |typ_| {
            self.list.appendAssumeCapacity(Node{ .@"type" = typ_, .prev = self.top });
            self.top = &self.list.items[idx].?;
        } else {
            self.list.appendAssumeCapacity(if (self.top) |top| top.* else null);
        }
    }

    fn popType(self: *StackChecker) !Module.Type.Value {
        const top = self.top orelse return error.StackMismatch;
        self.top = top.prev;
        return top.@"type";
    }

    fn topCheck(self: StackChecker, typ: Module.Type.Value) !void {
        if (self.top == null or self.top.?.@"type" != typ) {
            return error.StackMismatch;
        }
    }

    fn popTypesCheck(self: *StackChecker, checks: []const Module.Type.Value) !void {
        var i: usize = checks.len;
        while (i > 0) {
            i -= 1;
            if (checks[i] != try self.popType()) {
                return error.StackMismatch;
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
};

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
