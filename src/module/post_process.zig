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

    var stack_validator = StackValidator.init(&temp_arena.allocator);

    var jump_matches = std.ArrayList(struct { instr_idx: usize, block_instr: usize }).init(&temp_arena.allocator);

    for (self.code) |body, f| {
        const func_idx = f + import_funcs;

        try stack_validator.process(self, f);

        // Fill in jump targets

        jump_matches.shrinkRetainingCapacity(0);

        for (body.code) |instr, instr_idx| {
            const op_meta = Op.Meta.of(instr.op);
            switch (instr.op) {
                .br, .br_if => {
                    var block = &(stack_validator.blocks.list.items[instr_idx] orelse return error.JumpExceedsBlock);

                    var b = instr.arg.U32;
                    while (b > 0) {
                        b -= 1;
                        block = block.prev orelse return error.JumpExceedsBlock;
                    }

                    try jump_matches.append(.{ .instr_idx = instr_idx, .block_instr = block.start_idx });
                },
                .br_table => @panic("TODO"),
                // "if" and "else" are their own jump
                .@"if", .@"else" => try jump_matches.append(.{ .instr_idx = instr_idx, .block_instr = instr_idx }),
                else => {},
            }
        }

        for (jump_matches.items) |jump| {
            const block_meta = stack_validator.blocks.list.items[jump.block_instr].?;
            const block_op = body.code[jump.block_instr].op;
            try self.jumps.putNoClobber(
                &self.arena.allocator,
                .{ .func = @intCast(u32, func_idx), .instr = @intCast(u32, jump.instr_idx) },
                .{
                    .has_value = block_meta.data != .Empty,
                    .stack_unroll = undefined,
                    .target = .{ .single = @intCast(u32, if (block_op == .loop) block_meta.start_idx else block_meta.end_idx) },
                },
            );
        }
    }
}

pub fn StackLedger(comptime T: type) type {
    return struct {
        const Self = @This();
        const Node = struct {
            data: T,
            start_idx: usize,
            end_idx: usize,
            prev: ?*Node,
        };

        top: ?*Node,
        list: std.ArrayList(?Node),

        pub fn init(allocator: *std.mem.Allocator) Self {
            return .{
                .top = null,
                .list = std.ArrayList(?Node).init(allocator),
            };
        }

        pub fn reset(self: *Self, size: usize) !void {
            self.top = null;
            self.list.shrinkRetainingCapacity(0);
            try self.list.ensureCapacity(size);
        }

        pub fn pushAt(self: *Self, idx: usize, data: T) void {
            std.debug.assert(idx == self.list.items.len);
            self.list.appendAssumeCapacity(Node{ .data = data, .start_idx = idx, .end_idx = undefined, .prev = self.top });
            self.top = &self.list.items[idx].?;
        }

        pub fn seal(self: *Self, idx: usize) void {
            if (self.list.items.len == idx) {
                self.list.appendAssumeCapacity(if (self.top) |top| top.* else null);
            }
        }

        pub fn pop(self: *Self, idx: usize) !T {
            const top = self.top orelse return error.StackMismatch;
            self.top = top.prev;
            top.end_idx = idx;
            return top.data;
        }

        pub fn checkPops(self: *Self, idx: usize, datas: []const T) !void {
            var i: usize = datas.len;
            while (i > 0) {
                i -= 1;
                if (datas[i] != try self.pop(idx)) {
                    return error.StackMismatch;
                }
            }
        }
    };
}

const StackValidator = struct {
    types: StackLedger(Module.Type.Value),
    blocks: StackLedger(Module.Type.Block),

    pub fn init(allocator: *std.mem.Allocator) StackValidator {
        return .{
            .types = StackLedger(Module.Type.Value).init(allocator),
            .blocks = StackLedger(Module.Type.Block).init(allocator),
        };
    }

    pub fn process(self: *StackValidator, module: *const Module, body_idx: usize) !void {
        const func = module.function[body_idx];
        const func_type = module.@"type"[@enumToInt(func.type_idx)];
        const body = module.code[body_idx];

        try self.types.reset(body.code.len);
        try self.blocks.reset(body.code.len);

        for (body.code) |instr, instr_idx| {
            const op_meta = Op.Meta.of(instr.op);
            switch (instr.op) {
                // Block operations
                .block, .loop, .@"if" => {
                    const result_type = @intToEnum(Op.Arg.Type, instr.arg.V128);
                    self.blocks.pushAt(instr_idx, switch (result_type) {
                        .Void => .Empty,
                        .I32 => .I32,
                        .I64 => .I64,
                        .F32 => .F32,
                        .F64 => .F64,
                    });
                },
                .@"else" => {
                    const top = try self.blocks.pop(instr_idx);
                    // This is the reason blocks and types must be interlaced. :(
                    if (top != .Empty) {
                        _ = try self.types.pop(instr_idx);
                    }
                    self.blocks.pushAt(instr_idx, top);
                },
                .end => _ = try self.blocks.pop(instr_idx),

                // Type operations
                .call => {
                    const call_func = module.function[instr.arg.U32];
                    const call_type = module.@"type"[@enumToInt(call_func.type_idx)];
                    try self.types.checkPops(instr_idx, call_type.param_types);
                    if (call_type.return_type) |typ| {
                        self.types.pushAt(instr_idx, typ);
                    }
                },
                .call_indirect => {
                    const call_type = module.@"type"[instr.arg.U32];
                    try self.types.checkPops(instr_idx, call_type.param_types);
                    if (call_type.return_type) |typ| {
                        self.types.pushAt(instr_idx, typ);
                    }
                },

                .@"local.set" => try self.types.checkPops(instr_idx, &.{localType(instr.arg.U32, func_type.param_types, body.locals)}),
                .@"local.get" => self.types.pushAt(instr_idx, localType(instr.arg.U32, func_type.param_types, body.locals)),
                .@"local.tee" => {
                    const typ = localType(instr.arg.U32, func_type.param_types, body.locals);
                    try self.types.checkPops(instr_idx, &.{typ});
                    self.types.pushAt(instr_idx, typ);
                },

                .select => {
                    const top1 = try self.types.pop(instr_idx);
                    const top2 = try self.types.pop(instr_idx);
                    if (top1 != top2) {
                        return error.StackMismatch;
                    }
                    self.types.pushAt(instr_idx, top1);
                },

                // Drops *any* value, no check needed
                .drop => _ = try self.types.pop(instr_idx),

                else => {
                    for (op_meta.pop) |pop| {
                        try self.types.checkPops(instr_idx, &.{asValue(pop)});
                    }

                    if (op_meta.push) |push| {
                        self.types.pushAt(instr_idx, asValue(push));
                    }
                },
            }

            self.types.seal(instr_idx);
            self.blocks.seal(instr_idx);
        }

        if (func_type.return_type) |return_type| {
            try self.types.checkPops(body.code.len, &.{return_type});
        }

        if (self.types.top != null) {
            return error.StackMismatch;
        }

        if (self.blocks.top != null) {
            return error.BlockMismatch;
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
