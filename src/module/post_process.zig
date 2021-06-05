const std = @import("std");

const Module = @import("../module.zig");
const Op = @import("../op.zig");
const Wat = @import("../wat.zig");

const PostProcess = @This();

import_funcs: []const ImportFunc,
jumps: InstrJumps,

pub const ImportFunc = struct {
    module: []const u8,
    field: []const u8,
    type_idx: Module.Index.FuncType,
};

pub const InstrJumps = std.AutoHashMap(struct { func: u32, instr: u32 }, union {
    one: JumpTarget,
    many: [*]const JumpTarget, // len = args.len
});

pub const JumpTarget = struct {
    has_value: bool,
    addr: u32,
    stack_unroll: u32,
};

pub fn init(module: *Module) !PostProcess {
    var temp_arena = std.heap.ArenaAllocator.init(module.arena.child_allocator);
    defer temp_arena.deinit();

    var import_funcs = std.ArrayList(ImportFunc).init(&module.arena.allocator);
    for (module.import) |import| {
        switch (import.kind) {
            .Function => |type_idx| {
                try import_funcs.append(.{
                    .module = import.module,
                    .field = import.field,
                    .type_idx = type_idx,
                });
            },
            else => @panic("TODO"),
        }
    }

    var stack_validator = StackValidator.init(&temp_arena.allocator);
    var jumps = InstrJumps.init(&module.arena.allocator);

    for (module.code) |code, f| {
        try stack_validator.process(import_funcs.items, module, f);

        // Fill in jump targets
        const jump_targeter = JumpTargeter{ .jumps = &jumps, .func_idx = f + import_funcs.items.len, .types = stack_validator.types };

        for (code.body) |instr, instr_idx| {
            switch (instr.op) {
                .br, .br_if => {
                    const block = stack_validator.blocks.upFrom(instr_idx, instr.arg.U32) orelse return error.JumpExceedsBlock;
                    const block_instr = code.body[block.start_idx];
                    try jump_targeter.add(block.data, .{
                        .from = instr_idx,
                        .target = if (block_instr.op == .loop) block.start_idx else block.end_idx,
                    });
                },
                .br_table => {
                    const targets = try module.arena.allocator.alloc(JumpTarget, instr.arg.Array.len);
                    for (targets) |*target, t| {
                        const block_level = instr.arg.Array.ptr[t];
                        const block = stack_validator.blocks.upFrom(instr_idx, block_level) orelse return error.JumpExceedsBlock;
                        const block_instr = code.body[block.start_idx];
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

    return PostProcess{
        .jumps = jumps,
        .import_funcs = import_funcs.toOwnedSlice(),
    };
}

const JumpTargeter = struct {
    jumps: *InstrJumps,
    func_idx: usize,
    types: StackLedger(Module.Type.Value),

    fn add(self: JumpTargeter, block_type: Module.Type.Block, args: struct {
        from: usize,
        target: usize,
        stack_adjust: u32 = 0,
    }) !void {
        // stackDepth reflects the status *after* execution
        // and we're jumping to right *before* the instruction
        const target_depth = self.types.depthOf(args.target - 1);
        try self.jumps.putNoClobber(
            .{ .func = @intCast(u32, self.func_idx), .instr = @intCast(u32, args.from) },
            .{
                .one = .{
                    .has_value = block_type != .Empty,
                    .addr = @intCast(u32, args.target),
                    .stack_unroll = self.types.depthOf(args.from) + args.stack_adjust - target_depth,
                },
            },
        );
    }

    fn addMany(self: JumpTargeter, from_idx: usize, targets: []JumpTarget) !void {
        for (targets) |*target| {
            target.stack_unroll = self.types.depthOf(from_idx) - self.types.depthOf(target.addr);
        }
        try self.jumps.putNoClobber(
            .{ .func = @intCast(u32, self.func_idx), .instr = @intCast(u32, from_idx) },
            .{ .many = targets.ptr },
        );
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

        pub fn depthOf(self: Self, idx: usize) u32 {
            var iter = &(self.list.items[idx] orelse return 0);
            var result: u32 = 1;
            while (iter.prev) |prev| {
                result += 1;
                iter = prev;
            }
            return result;
        }

        pub fn format(self: Self, comptime fmt: []const u8, opts: std.fmt.FormatOptions, writer: anytype) !void {
            try writer.writeAll("StackLedger(");
            var iter = self.top;
            while (iter) |node| {
                try writer.print(", {}", .{node.data});
                iter = node.prev;
            }
            try writer.writeAll(")");
        }

        pub fn reset(self: *Self, size: usize) !void {
            self.top = null;
            self.list.shrinkRetainingCapacity(0);
            try self.list.ensureCapacity(size);
        }

        pub fn upFrom(self: Self, start_idx: usize, levels: usize) ?*const Node {
            var node = &(self.list.items[start_idx] orelse return null);
            if (levels == 0) {
                return &(self.list.items[node.start_idx].?);
            }

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

    pub fn process(self: *StackValidator, import_funcs: []const ImportFunc, module: *const Module, code_idx: usize) !void {
        const func = module.function[code_idx];
        const func_type = module.@"type"[@enumToInt(func.type_idx)];
        const code = module.code[code_idx];

        try self.blocks.reset(code.body.len);
        for (code.body) |instr, instr_idx| {
            defer self.blocks.seal(instr_idx);

            switch (instr.op) {
                // Block operations
                .block, .loop, .@"if" => {
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
                    if (code.body[block_idx].op != .@"if") {
                        return error.MismatchElseWithoutIf;
                    }
                    self.blocks.pushAt(instr_idx, top);
                },
                .end => _ = try self.blocks.pop(instr_idx),
                else => {},
            }
        }
        if (self.blocks.top != null) {
            return error.BlockMismatch;
        }

        try self.types.reset(code.body.len);
        var terminating_block: ?StackLedger(Module.Type.Block).Node = null;
        for (code.body) |instr, instr_idx| {
            defer self.types.seal(instr_idx);

            if (terminating_block) |block| {
                if (instr.op == .end) {
                    const unroll_amount = self.types.depthOf(instr_idx - 1) - self.types.depthOf(block.start_idx);

                    var i: usize = 0;
                    while (i < unroll_amount) : (i += 1) {
                        _ = self.types.pop(instr_idx) catch unreachable;
                    }

                    terminating_block = null;
                }
                // TODO: do I need to detect valid instruction
                continue;
            }

            switch (instr.op) {
                .@"return", .br, .br_table, .@"unreachable" => {
                    if (instr.op == .br_table) {
                        try self.types.checkPops(instr_idx, &.{Module.Type.Value.I32});
                    }
                    terminating_block = self.blocks.list.items[instr_idx];
                },

                .@"if" => try self.types.checkPops(instr_idx, &.{Module.Type.Value.I32}),
                .@"else" => {
                    const if_block = self.blocks.list.items[instr_idx - 1].?;
                    if (if_block.data != .Empty) {
                        _ = try self.types.pop(instr_idx);
                    }
                },

                .call => {
                    // TODO: validate these indexes
                    const func_idx = instr.arg.U32;
                    if (func_idx < import_funcs.len) {
                        // import
                        const call_func = import_funcs[func_idx];
                        const call_type = module.@"type"[@enumToInt(call_func.type_idx)];
                        try self.types.checkPops(instr_idx, call_type.param_types);
                        if (call_type.return_type) |typ| {
                            self.types.pushAt(instr_idx, typ);
                        }
                    } else {
                        const call_func = module.function[func_idx - import_funcs.len];
                        const call_type = module.@"type"[@enumToInt(call_func.type_idx)];
                        try self.types.checkPops(instr_idx, call_type.param_types);
                        if (call_type.return_type) |typ| {
                            self.types.pushAt(instr_idx, typ);
                        }
                    }
                },
                .call_indirect => {
                    const call_type = module.@"type"[instr.arg.U32];
                    try self.types.checkPops(instr_idx, call_type.param_types);
                    if (call_type.return_type) |typ| {
                        self.types.pushAt(instr_idx, typ);
                    }
                },

                .local_set => try self.types.checkPops(instr_idx, &.{try localType(instr.arg.U32, func_type.param_types, code.locals)}),
                .local_get => self.types.pushAt(instr_idx, try localType(instr.arg.U32, func_type.param_types, code.locals)),
                .local_tee => {
                    const typ = try localType(instr.arg.U32, func_type.param_types, code.locals);
                    try self.types.checkPops(instr_idx, &.{typ});
                    self.types.pushAt(instr_idx, typ);
                },
                .global_set => {
                    const idx = instr.arg.U32;
                    if (idx >= module.global.len) return error.GlobalIndexOutOfBounds;
                    try self.types.checkPops(instr_idx, &.{module.global[idx].@"type".content_type});
                },
                .global_get => {
                    const idx = instr.arg.U32;
                    if (idx >= module.global.len) return error.GlobalIndexOutOfBounds;
                    self.types.pushAt(instr_idx, module.global[idx].@"type".content_type);
                },

                .select => {
                    try self.types.checkPops(instr_idx, &.{.I32});
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
                    const op_meta = Op.Meta.of(instr.op);
                    for (op_meta.pop) |pop| {
                        try self.types.checkPops(instr_idx, &.{asValue(pop)});
                    }

                    if (op_meta.push) |push| {
                        self.types.pushAt(instr_idx, asValue(push));
                    }
                },
            }
        }

        if (func_type.return_type) |return_type| {
            try self.types.checkPops(code.body.len, &.{return_type});
        }

        if (self.types.top != null) {
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

    fn localType(local_idx: u32, params: []const Module.Type.Value, locals: []const Module.Type.Value) !Module.Type.Value {
        if (local_idx >= params.len + locals.len) return error.LocalIndexOutOfBounds;
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

    _ = try PostProcess.init(&module);
}

test "add nothing" {
    var fbs = std.io.fixedBufferStream(
        \\(module
        \\  (func (result i32)
        \\    i32.add))
    );
    var module = try Wat.parseNoValidate(std.testing.allocator, fbs.reader());
    defer module.deinit();

    try std.testing.expectError(error.StackMismatch, PostProcess.init(&module));
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

    try std.testing.expectError(error.StackMismatch, PostProcess.init(&module));
}

test "return nothing" {
    var fbs = std.io.fixedBufferStream(
        \\(module
        \\  (func (result i32)))
    );
    var module = try Wat.parseNoValidate(std.testing.allocator, fbs.reader());
    defer module.deinit();

    try std.testing.expectError(error.StackMismatch, PostProcess.init(&module));
}

test "return wrong type" {
    var fbs = std.io.fixedBufferStream(
        \\(module
        \\  (func (result i32)
        \\    i64.const 40))
    );
    var module = try Wat.parseNoValidate(std.testing.allocator, fbs.reader());
    defer module.deinit();

    try std.testing.expectError(error.StackMismatch, PostProcess.init(&module));
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

    const process = try PostProcess.init(&module);

    const br_0 = process.jumps.get(.{ .func = 0, .instr = 2 }) orelse return error.JumpNotFound;
    try std.testing.expectEqual(@as(usize, 1), br_0.one.addr);

    const br_1 = process.jumps.get(.{ .func = 0, .instr = 3 }) orelse return error.JumpNotFound;
    try std.testing.expectEqual(@as(usize, 5), br_1.one.addr);
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

    const process = try PostProcess.init(&module);

    const jump_if = process.jumps.get(.{ .func = 0, .instr = 1 }) orelse return error.JumpNotFound;
    // Note that if's jump target is *after* the else instruction
    try std.testing.expectEqual(@as(usize, 4), jump_if.one.addr);
    try std.testing.expectEqual(@as(usize, 0), jump_if.one.stack_unroll);

    const jump_else = process.jumps.get(.{ .func = 0, .instr = 3 }) orelse return error.JumpNotFound;
    try std.testing.expectEqual(@as(usize, 5), jump_else.one.addr);
    try std.testing.expectEqual(@as(usize, 0), jump_else.one.stack_unroll);
}

test "invalid global idx" {
    var fbs = std.io.fixedBufferStream(
        \\(module
        \\  (global $x i32 (i32.const -5))
        \\  (func (result i32)
        \\  global.get 1))
    );
    var module = try Wat.parseNoValidate(std.testing.allocator, fbs.reader());
    defer module.deinit();
    try std.testing.expectError(error.GlobalIndexOutOfBounds, PostProcess.init(&module));
}

test "valid global idx" {
    var fbs = std.io.fixedBufferStream(
        \\(module
        \\  (global $x i32 (i32.const -5))
        \\  (func (result i32)
        \\  global.get 0))
    );
    var module = try Wat.parseNoValidate(std.testing.allocator, fbs.reader());
    defer module.deinit();
    _ = try PostProcess.init(&module);
}

test "invalid local idx" {
    var fbs = std.io.fixedBufferStream(
        \\(module
        \\  (func (result i32)
        \\  local.get 0))
    );
    var module = try Wat.parseNoValidate(std.testing.allocator, fbs.reader());
    defer module.deinit();
    try std.testing.expectError(error.LocalIndexOutOfBounds, PostProcess.init(&module));
}

test "valid local idx" {
    var fbs = std.io.fixedBufferStream(
        \\(module
        \\  (func (param i32) (result i32)
        \\  local.get 0))
    );
    var module = try Wat.parseNoValidate(std.testing.allocator, fbs.reader());
    defer module.deinit();
    _ = try PostProcess.init(&module);
}

test "valid br flushing the stack" {
    var fbs = std.io.fixedBufferStream(
        \\(module
        \\  (func
        \\    block         ;; 0
        \\      i32.const 1 ;; 1
        \\      br 0        ;; 2
        \\      i32.const 2 ;; 3
        \\    end))         ;; 4
    );
    var module = try Wat.parseNoValidate(std.testing.allocator, fbs.reader());
    defer module.deinit();
    _ = try PostProcess.init(&module);
}
