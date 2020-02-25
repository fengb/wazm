const std = @import("std");
const Module = @import("module.zig");
const Op = @import("op.zig");

fn swhash(string: []const u8) u128 {
    if (string.len >= 16) return std.math.maxInt(u128);
    var tmp = [_]u8{0} ** 16;
    std.mem.copy(u8, &tmp, string);
    return std.mem.readIntLittle(u128, &tmp);
}

const ParseContext = struct {
    string: []const u8,
    err: ?struct {
        location: usize,
        message: ?[]const u8,
    },

    pub fn init(string: []const u8) ParseContext {
        return .{ .string = string, .err = null };
    }

    pub fn format(
        self: ParseContext,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        context: var,
        comptime Errors: type,
        comptime output: fn (@TypeOf(context), []const u8) Errors!void,
    ) Errors!void {
        if (self.err) |err| {
            if (err.location >= self.string.len) {
                try output(context, "ParseError @ EOF");
            } else {
                try std.fmt.format(context, Errors, output, "ParseError @ {}", .{err.location});
            }
            if (err.message) |msg| {
                try output(context, ": '");
                try output(context, msg);
                try output(context, "'");
            }

            try output(context, "\n# ");
            if (err.location >= self.string.len) {
                const start = std.math.min(self.string.len -% 20, 0);
                try output(context, self.string[start..]);
                try output(context, "$");
            } else {
                try output(context, self.string[err.location..std.math.min(err.location + 20, self.string.len)]);
                try output(context, "\n  ^");
            }
            try output(context, "\n");
        }
    }

    fn eof(self: ParseContext) usize {
        return self.string.len;
    }

    fn validate(self: *ParseContext, truthiness: bool, location: usize) !void {
        if (!truthiness) {
            return self.fail(location);
        }
    }

    fn fail(self: *ParseContext, location: usize) error{ParseError} {
        self.err = .{ .location = location, .message = null };
        if (std.builtin.is_test) {
            std.debug.warn("#Debug\n{}\n", .{self});
        }
        return error.ParseError;
    }
};

const Sexpr = struct {
    arena: std.heap.ArenaAllocator,
    root: []Elem,

    const Elem = struct {
        token: Token,
        data: Data,

        const Data = union(enum) {
            list: []Elem,
            keyword: []const u8,
            id: []const u8,
            string: []const u8,
            integer: usize,
            float: f64,
        };
    };

    const Token = struct {
        source: usize,
        raw: []const u8,
        kind: Kind,

        const Kind = enum {
            OpenParen,
            CloseParen,
            Newline,
            OpenParenSemicolon,
            SemicolonCloseParen,
            SemicolonSemicolon,
            Literal,
        };

        fn init(kind: Kind, string: []const u8, start: usize, end: usize) Token {
            return .{
                .kind = kind,
                .source = start,
                .raw = string[start..end],
            };
        }
    };

    pub fn deinit(self: *Sexpr) void {
        self.arena.deinit();
    }

    pub fn parse(ctx: *ParseContext, allocator: *std.mem.Allocator) !Sexpr {
        var arena = std.heap.ArenaAllocator.init(allocator);
        errdefer arena.deinit();

        var tokenizer = Tokenizer.init(ctx.string);
        if (tokenizer.next()) |start| {
            try ctx.validate(start.kind == .OpenParen, start.source);
        } else {
            return ctx.fail(ctx.eof());
        }

        return Sexpr{
            .root = try parseList(ctx, &arena.allocator, &tokenizer),
            .arena = arena,
        };
    }

    fn parseList(ctx: *ParseContext, arena: *std.mem.Allocator, tokenizer: *Tokenizer) error{
        OutOfMemory,
        ParseError,
    }![]Elem {
        var list = std.ArrayList(Elem).init(arena);
        while (tokenizer.next()) |token| {
            switch (token.kind) {
                .OpenParen => try list.append(.{
                    .token = token,
                    .data = .{ .list = try parseList(ctx, arena, tokenizer) },
                }),
                .Literal => {
                    try list.append(.{
                        .token = token,
                        .data = switch (token.raw[0]) {
                            '"' => .{ .string = token.raw },
                            '$' => .{ .id = token.raw },
                            'a'...'z' => .{ .keyword = token.raw },
                            '+', '-', '0'...'9' => .{
                                .integer = std.fmt.parseInt(usize, token.raw, 10) catch {
                                    return ctx.fail(token.source);
                                },
                            },
                            else => return ctx.fail(token.source),
                        },
                    });
                },
                .CloseParen => return list.toOwnedSlice(),
                .Newline => {},
                .OpenParenSemicolon => {
                    while (tokenizer.next()) |comment| {
                        if (comment.kind == .SemicolonCloseParen) {
                            break;
                        }
                    }
                    return ctx.fail(token.source);
                },
                .SemicolonCloseParen => return ctx.fail(token.source),
                .SemicolonSemicolon => {
                    while (tokenizer.next()) |comment| {
                        if (comment.kind == .Newline) {
                            break;
                        }
                    }
                },
            }
        }

        return ctx.fail(ctx.eof());
    }

    const Tokenizer = struct {
        raw: []const u8,
        cursor: usize,

        fn init(raw: []const u8) Tokenizer {
            return .{ .raw = raw, .cursor = 0 };
        }

        fn next(self: *Tokenizer) ?Token {
            if (self.cursor >= self.raw.len) {
                return null;
            }

            const start = self.cursor;
            self.cursor += 1;
            switch (self.raw[start]) {
                0, ' ', '\t' => return self.next(),
                '(' => {
                    if (self.cursor <= self.raw.len and self.raw[self.cursor] == ';') {
                        self.cursor += 1;
                        return Token.init(.OpenParenSemicolon, self.raw, start, self.cursor);
                    } else {
                        return Token.init(.OpenParen, self.raw, start, self.cursor);
                    }
                },
                ')' => return Token.init(.CloseParen, self.raw, start, self.cursor),
                '\n' => return Token.init(.Newline, self.raw, start, self.cursor),
                ';' => {
                    if (self.cursor > self.raw.len) {
                        return Token.init(.Literal, self.raw, start, self.cursor);
                    } else if (self.raw[self.cursor] == ';') {
                        self.cursor += 1;
                        return Token.init(.SemicolonSemicolon, self.raw, start, self.cursor);
                    } else if (self.raw[self.cursor] == ')') {
                        self.cursor += 1;
                        return Token.init(.SemicolonCloseParen, self.raw, start, self.cursor);
                    } else {
                        // "fallthrough"
                    }
                },
                else => {},
            }

            while (self.cursor < self.raw.len) : (self.cursor += 1) {
                switch (self.raw[self.cursor]) {
                    ' ', '\t', '(', ')', '\n', ';' => break,
                    else => {},
                }
            }

            return Token.init(.Literal, self.raw, start, self.cursor);
        }
    };
};

test "Tokenizer" {
    {
        var tokenizer = Sexpr.Tokenizer.init("(type (func (param i32 i32)");
        std.testing.expectEqual(Sexpr.Token.Kind.OpenParen, tokenizer.next().?.kind);
        std.testing.expectEqualSlices(u8, "type", tokenizer.next().?.raw);

        std.testing.expectEqual(Sexpr.Token.Kind.OpenParen, tokenizer.next().?.kind);
        std.testing.expectEqualSlices(u8, "func", tokenizer.next().?.raw);

        std.testing.expectEqual(Sexpr.Token.Kind.OpenParen, tokenizer.next().?.kind);
        std.testing.expectEqualSlices(u8, "param", tokenizer.next().?.raw);
        std.testing.expectEqualSlices(u8, "i32", tokenizer.next().?.raw);
        std.testing.expectEqualSlices(u8, "i32", tokenizer.next().?.raw);
        std.testing.expectEqual(Sexpr.Token.Kind.CloseParen, tokenizer.next().?.kind);

        std.testing.expectEqual(@as(?Sexpr.Token, null), tokenizer.next());
    }
    {
        var tokenizer = Sexpr.Tokenizer.init("block  ;; label = @1\n  local.get 4");
        std.testing.expectEqualSlices(u8, "block", tokenizer.next().?.raw);

        std.testing.expectEqual(Sexpr.Token.Kind.SemicolonSemicolon, tokenizer.next().?.kind);
        std.testing.expectEqualSlices(u8, "label", tokenizer.next().?.raw);
        std.testing.expectEqualSlices(u8, "=", tokenizer.next().?.raw);
        std.testing.expectEqualSlices(u8, "@1", tokenizer.next().?.raw);

        std.testing.expectEqual(Sexpr.Token.Kind.Newline, tokenizer.next().?.kind);
        std.testing.expectEqualSlices(u8, "local.get", tokenizer.next().?.raw);
        std.testing.expectEqualSlices(u8, "4", tokenizer.next().?.raw);

        std.testing.expectEqual(@as(?Sexpr.Token, null), tokenizer.next());
    }
    {
        var tokenizer = Sexpr.Tokenizer.init("foo (;0;)");
        std.testing.expectEqualSlices(u8, "foo", tokenizer.next().?.raw);

        std.testing.expectEqual(Sexpr.Token.Kind.OpenParenSemicolon, tokenizer.next().?.kind);
        std.testing.expectEqualSlices(u8, "0", tokenizer.next().?.raw);
        std.testing.expectEqual(Sexpr.Token.Kind.SemicolonCloseParen, tokenizer.next().?.kind);

        std.testing.expectEqual(@as(?Sexpr.Token, null), tokenizer.next());
    }
}

test "Sexpr.parse" {
    {
        var sexpr = try Sexpr.parse(&ParseContext.init("(a bc 42)"), std.testing.allocator);
        defer sexpr.deinit();

        std.testing.expectEqual(@as(usize, 3), sexpr.root.len);
        std.testing.expectEqualSlices(u8, "a", sexpr.root[0].data.keyword);
        std.testing.expectEqualSlices(u8, "bc", sexpr.root[1].data.keyword);
        std.testing.expectEqual(@as(usize, 42), sexpr.root[2].data.integer);
    }
    {
        var sexpr = try Sexpr.parse(&ParseContext.init("(() ())"), std.testing.allocator);
        defer sexpr.deinit();

        std.testing.expectEqual(@as(usize, 2), sexpr.root.len);
        std.testing.expectEqual(@TagType(Sexpr.Elem.Data).list, sexpr.root[0].data);
        std.testing.expectEqual(@TagType(Sexpr.Elem.Data).list, sexpr.root[1].data);
    }
    {
        var sexpr = try Sexpr.parse(&ParseContext.init("( ( ( ())))"), std.testing.allocator);
        defer sexpr.deinit();

        std.testing.expectEqual(@TagType(Sexpr.Elem.Data).list, sexpr.root[0].data);
        std.testing.expectEqual(@TagType(Sexpr.Elem.Data).list, sexpr.root[0].data.list[0].data);
        std.testing.expectEqual(@TagType(Sexpr.Elem.Data).list, sexpr.root[0].data.list[0].data.list[0].data);
    }
    {
        var sexpr = try Sexpr.parse(&ParseContext.init("(block  ;; label = @1\n  local.get 4)"), std.testing.allocator);
        defer sexpr.deinit();

        std.testing.expectEqual(@as(usize, 3), sexpr.root.len);
        std.testing.expectEqualSlices(u8, "block", sexpr.root[0].data.keyword);
        std.testing.expectEqualSlices(u8, "local.get", sexpr.root[1].data.keyword);
        std.testing.expectEqual(@as(usize, 4), sexpr.root[2].data.integer);
    }
}

fn pop(list: []Sexpr.Elem, i: *usize) ?Sexpr.Elem {
    if (i.* >= list.len) return null;
    defer i.* += 1;
    return list[i.*];
}

pub fn parse(allocator: *std.mem.Allocator, string: []const u8) !Module {
    var ctx = ParseContext.init(string);
    var sexpr = try Sexpr.parse(&ctx, allocator);
    defer sexpr.deinit();

    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();

    try ctx.validate(sexpr.root.len > 0, ctx.eof());
    try ctx.validate(std.mem.eql(u8, sexpr.root[0].data.keyword, "module"), sexpr.root[0].token.source);

    var memory: usize = 0;
    var func_types = std.ArrayList(Module.FuncType).init(&arena.allocator);
    var funcs = std.ArrayList(Module.Func).init(&arena.allocator);
    var exports = std.StringHashMap(Module.Export).init(&arena.allocator);

    for (sexpr.root[1..]) |elem| {
        try ctx.validate(elem.data == .list, elem.token.source);

        const list = elem.data.list;
        try ctx.validate(list.len > 0, elem.token.source);
        try ctx.validate(list[0].data == .keyword, list[0].token.source);

        switch (swhash(list[0].data.keyword)) {
            swhash("memory") => {
                try ctx.validate(list.len == 2, elem.token.source);
                try ctx.validate(list[1].data == .integer, list[1].token.source);

                memory = list[1].data.integer;
            },
            swhash("func") => {
                var params = std.ArrayList(Module.Type.Value).init(&arena.allocator);
                var locals = std.ArrayList(Module.Type.Value).init(&arena.allocator);
                var result: ?Module.Type.Value = null;

                var i: usize = 1;
                while (i < list.len and list[i].data == .list) : (i += 1) {
                    const pair = list[i].data.list;
                    try ctx.validate(pair.len == 2, list[i].token.source);
                    try ctx.validate(pair[1].data == .keyword, pair[1].token.source);
                    const typ: Module.Type.Value = switch (swhash(pair[1].data.keyword)) {
                        swhash("i32") => .I32,
                        swhash("i64") => .I64,
                        swhash("f32") => .F32,
                        swhash("f64") => .F64,
                        else => return ctx.fail(pair[1].token.source),
                    };

                    try ctx.validate(pair[0].data == .keyword, pair[0].token.source);
                    switch (swhash(pair[0].data.keyword)) {
                        swhash("param") => try params.append(typ),
                        swhash("local") => try locals.append(typ),
                        swhash("result") => result = typ,
                        else => return ctx.fail(pair[0].token.source),
                    }
                }

                var instrs = std.ArrayList(Module.Instr).init(&arena.allocator);
                while (pop(list, &i)) |val| {
                    try ctx.validate(val.data == .keyword, val.token.source);

                    const op = Op.byName(val.data.keyword) orelse return ctx.fail(val.token.source);
                    try instrs.append(.{
                        .opcode = op.code,
                        .arg = switch (op.arg_kind) {
                            .Void => .{ .I64 = 0 },
                            .Type => blk: {
                                const next = pop(list, &i) orelse return ctx.fail(ctx.eof());
                                try ctx.validate(next.data == .keyword, next.token.source);
                                break :blk Op.Fixval.init(
                                    @as(Op.Arg.Type, switch (swhash(next.data.keyword)) {
                                        swhash("void") => .Void,
                                        swhash("i32") => .I32,
                                        swhash("i64") => .I64,
                                        swhash("f32") => .F32,
                                        swhash("f64") => .F64,
                                        else => return ctx.fail(next.token.source),
                                    }),
                                );
                            },
                            .I32 => blk: {
                                const next = pop(list, &i) orelse return ctx.fail(ctx.eof());
                                try ctx.validate(next.data == .integer, next.token.source);
                                break :blk .{ .I32 = @intCast(i32, next.data.integer) };
                            },
                            .U32 => blk: {
                                const next = pop(list, &i) orelse return ctx.fail(ctx.eof());
                                try ctx.validate(next.data == .integer, next.token.source);
                                break :blk .{ .U32 = @intCast(u32, next.data.integer) };
                            },
                            .I64 => blk: {
                                const next = pop(list, &i) orelse return ctx.fail(ctx.eof());
                                try ctx.validate(next.data == .integer, next.token.source);
                                break :blk .{ .I64 = @intCast(i64, next.data.integer) };
                            },
                            .U64 => blk: {
                                const next = pop(list, &i) orelse return ctx.fail(ctx.eof());
                                try ctx.validate(next.data == .integer, next.token.source);
                                break :blk .{ .U64 = @intCast(u64, next.data.integer) };
                            },
                            .F32 => blk: {
                                const next = pop(list, &i) orelse return ctx.fail(ctx.eof());
                                try ctx.validate(next.data == .float, next.token.source);
                                break :blk .{ .F64 = @floatCast(f32, next.data.float) };
                            },
                            .F64 => blk: {
                                const next = pop(list, &i) orelse return ctx.fail(ctx.eof());
                                try ctx.validate(next.data == .float, next.token.source);
                                break :blk .{ .F64 = @floatCast(f64, next.data.float) };
                            },
                            .U32z, .Mem, .Array => {
                                @panic(list[i].data.keyword);
                            },
                        },
                    });
                }

                try func_types.append(.{
                    .params = params.toOwnedSlice(),
                    .result = result,
                });

                try funcs.append(.{
                    .name = null,
                    .func_type = func_types.len - 1,
                    .locals = locals.toOwnedSlice(),
                    .instrs = instrs.toOwnedSlice(),
                });
            },
            else => return ctx.fail(list[0].token.source),
        }
    }

    return Module{
        .memory = @intCast(u32, memory),
        .func_types = func_types.toOwnedSlice(),
        .funcs = funcs.toOwnedSlice(),
        .exports = exports,
        .arena = arena,
    };
}

test "parse" {
    {
        var module = try parse(std.testing.allocator, "(module)");
        defer module.deinit();

        std.testing.expectEqual(@as(u32, 0), module.memory);
        std.testing.expectEqual(@as(usize, 0), module.funcs.len);
        std.testing.expectEqual(@as(usize, 0), module.exports.count());
    }
    {
        var module = try parse(std.testing.allocator, "(module (memory 42))");
        defer module.deinit();

        std.testing.expectEqual(@as(usize, 42), module.memory);
    }
    {
        var module = try parse(std.testing.allocator,
            \\(module
            \\  (func (param i32) (param f32) (result i64) (local f64)
            \\    local.get 0
            \\    local.get 1
            \\    local.get 2))
        );
        defer module.deinit();

        std.testing.expectEqual(@as(usize, 1), module.funcs.len);

        const func_type = module.func_types[0];
        std.testing.expectEqual(@as(usize, 2), func_type.params.len);
        std.testing.expectEqual(Module.Type.Value.I32, func_type.params[0]);
        std.testing.expectEqual(Module.Type.Value.F32, func_type.params[1]);
        std.testing.expectEqual(Module.Type.Value.I64, func_type.result.?);

        const func = module.funcs[0];
        std.testing.expectEqual(@as(?[]const u8, null), func.name);

        std.testing.expectEqual(@as(usize, 1), func.locals.len);
        std.testing.expectEqual(Module.Type.Value.F64, func.locals[0]);

        std.testing.expectEqual(@as(usize, 3), func.instrs.len);
    }
}
