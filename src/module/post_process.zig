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

    for (self.code) |body, f| {
        try stack_validator.process(self, f);

        // Fill in jump targets
        const jump_targeter = JumpTargeter{ .module = self, .func_idx = f, .types = stack_validator.types.list.items };

        for (body.code) |instr, instr_idx| {
            switch (instr.op) {
                .br, .br_if => {
                    const block = stack_validator.blocks.upFrom(instr_idx, instr.arg.U32) orelse return error.JumpExceedsBlock;
                    const block_instr = body.code[block.start_idx];
                    try jump_targeter.add(block.data, .{
                        .from = instr_idx,
                        .target = if (block_instr.op == .loop) block.start_idx else block.end_idx,
                    });
                },
                .br_table => {
                    const targets = try self.arena.allocator.alloc(Module.JumpTarget, instr.arg.Array.len);
                    for (targets) |*target, t| {
                        const block_level = instr.arg.Array.ptr[t];
                        const block = stack_validator.blocks.upFrom(instr_idx, block_level) orelse return error.JumpExceedsBlock;
                        const block_instr = body.code[block.start_idx];
                        const target_idx = if (block_instr.op == .loop) block.start_idx else block.end_idx;
                        target.addr = @intCast(u32, if (block_instr.op == .loop) block.start_idx else block.end_idx);
                        target.has_value = block.data != .Empty;
                    }
                    try jump_targeter.addMany(instr_idx, targets);
                },
                .@"else" => {
                    const block = stack_validator.blocks.list.items[instr_idx].?;
                    try jump_targeter.add(block.data, .{
                        .from = instr_idx,
                        .target = block.end_idx,
                        // When the "if" block has a value, it is left on the stack at
                        // the "else", which needs to carry it forward
                        // This is either off-by-one during stack analysis or jumping... :(
                        .stack_adjust = @boolToInt(block.data != .Empty),
                    });
                },
                .@"if" => {
                    const block = stack_validator.blocks.list.items[instr_idx].?;
                    try jump_targeter.add(block.data, .{
                        .from = instr_idx,
                        // "if" jumps to *after* the corresponding else
                        .target = block.end_idx + 1,
                    });
                },
                else => {},
            }
        }
    }
}

const JumpTargeter = struct {
    module: *Module,
    func_idx: usize,
    types: []const ?StackLedger(Module.Type.Value).Node,

    fn add(self: JumpTargeter, block_type: Module.Type.Block, args: struct {
        from: usize,
        target: usize,
        stack_adjust: u32 = 0,
    }) !void {
        // stackDepth reflects the status *after* execution
        // and we're jumping to right *before* the instruction
        const target_depth = stackDepth(self.types[args.target - 1]);
        try self.module.jumps.putNoClobber(
            &self.module.arena.allocator,
            .{ .func = @intCast(u32, self.func_idx), .instr = @intCast(u32, args.from) },
            .{
                .one = .{
                    .has_value = block_type != .Empty,
                    .addr = @intCast(u32, args.target),
                    .stack_unroll = stackDepth(self.types[args.from]) + args.stack_adjust - target_depth,
                },
            },
        );
    }

    fn addMany(self: JumpTargeter, from_idx: usize, targets: []Module.JumpTarget) !void {
        for (targets) |*target| {
            target.stack_unroll = stackDepth(self.types[from_idx]) - stackDepth(self.types[target.addr]);
        }
        try self.module.jumps.putNoClobber(
            &self.module.arena.allocator,
            .{ .func = @intCast(u32, self.func_idx), .instr = @intCast(u32, from_idx) },
            .{ .many = targets.ptr },
        );
    }

    fn stackDepth(node: ?StackLedger(Module.Type.Value).Node) u32 {
        var iter = &(node orelse return 0);
        var result: u32 = 1;
        while (iter.prev) |prev| {
            result += 1;
            iter = prev;
        }
        return result;
    }
};

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

        pub fn upFrom(self: Self, start_idx: usize, levels: usize) ?*const Node {
            var node = &(self.list.items[start_idx] orelse return null);
            var l = levels;
            while (l > 0) {
                l -= 1;
                node = node.prev orelse return null;
            }
            return node;
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
                    if (instr.op == .@"if") {
                        try self.types.checkPops(instr_idx, &.{Module.Type.Value.I32});
                    }
                    const result_type = instr.arg.Type;
                    self.blocks.pushAt(instr_idx, switch (result_type) {
                        .Void => .Empty,
                        .I32 => .I32,
                        .I64 => .I64,
                        .F32 => .F32,
                        .F64 => .F64,
                    });
                },
                .@"else" => {
                    const block_idx = (self.blocks.top orelse return error.StackMismatch).start_idx;
                    const top = try self.blocks.pop(instr_idx);
                    if (body.code[block_idx].op != .@"if") {
                        return error.MismatchElseWithoutIf;
                    }
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

                .br_table => try self.types.checkPops(instr_idx, &.{Module.Type.Value.I32}),

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
        \\    block     ;; 0
        \\      loop    ;; 1
        \\        br 0  ;; 2
        \\        br 1  ;; 3
        \\      end     ;; 4
        \\    end       ;; 5
        \\  ))
    );
    var module = try Wat.parseNoValidate(std.testing.allocator, fbs.reader());
    defer module.deinit();

    try module.post_process();

    const br_0 = module.jumps.get(.{ .func = 0, .instr = 2 }) orelse return error.JumpNotFound;
    std.testing.expectEqual(@as(usize, 1), br_0.one.addr);

    const br_1 = module.jumps.get(.{ .func = 0, .instr = 3 }) orelse return error.JumpNotFound;
    std.testing.expectEqual(@as(usize, 5), br_1.one.addr);
}

test "if/else locations" {
    var fbs = std.io.fixedBufferStream(
        \\(module
        \\  (func (result i32)
        \\    i32.const 0     ;; 0
        \\    if (result i32) ;; 1
        \\      i32.const 1   ;; 2
        \\    else            ;; 3
        \\      i32.const 0   ;; 4
        \\    end             ;; 5
        \\  ))
    );
    var module = try Wat.parseNoValidate(std.testing.allocator, fbs.reader());
    defer module.deinit();

    try module.post_process();

    const jump_if = module.jumps.get(.{ .func = 0, .instr = 1 }) orelse return error.JumpNotFound;
    // Note that if's jump target is *after* the else instruction
    std.testing.expectEqual(@as(usize, 4), jump_if.one.addr);
    std.testing.expectEqual(@as(usize, 0), jump_if.one.stack_unroll);

    const jump_else = module.jumps.get(.{ .func = 0, .instr = 3 }) orelse return error.JumpNotFound;
    std.testing.expectEqual(@as(usize, 5), jump_else.one.addr);
    std.testing.expectEqual(@as(usize, 0), jump_else.one.stack_unroll);
}
