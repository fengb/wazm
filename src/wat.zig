const std = @import("std");
const builtin = @import("builtin");
const core = @import("core.zig");
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
        output: fn (@TypeOf(context), []const u8) Errors!void,
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
        if (builtin.is_test) {
            std.debug.warn("#Debug\n{}\n", .{self});
        }
        return error.ParseError;
    }
};

const Sexpr = struct {
    arena: *std.heap.ArenaAllocator,
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
        const arena = try allocator.create(std.heap.ArenaAllocator);
        errdefer allocator.destroy(arena);
        arena.* = std.heap.ArenaAllocator.init(allocator);
        errdefer arena.deinit();

        var tokenizer = Tokenizer.init(ctx.string);
        if (tokenizer.next()) |start| {
            try ctx.validate(start.kind == .OpenParen, start.source);
        } else {
            return ctx.fail(ctx.eof());
        }

        return Sexpr{
            .arena = arena,
            .root = try parseList(ctx, &arena.allocator, &tokenizer),
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
        var sexpr = try Sexpr.parse(&ParseContext.init("(a bc 42)"), std.heap.page_allocator);
        defer sexpr.deinit();

        std.testing.expectEqual(@as(usize, 3), sexpr.root.len);
        std.testing.expectEqualSlices(u8, "a", sexpr.root[0].data.keyword);
        std.testing.expectEqualSlices(u8, "bc", sexpr.root[1].data.keyword);
        std.testing.expectEqual(@as(usize, 42), sexpr.root[2].data.integer);
    }
    {
        var sexpr = try Sexpr.parse(&ParseContext.init("(() ())"), std.heap.page_allocator);
        defer sexpr.deinit();

        std.testing.expectEqual(@as(usize, 2), sexpr.root.len);
        std.testing.expectEqual(@TagType(Sexpr.Elem.Data).list, sexpr.root[0].data);
        std.testing.expectEqual(@TagType(Sexpr.Elem.Data).list, sexpr.root[1].data);
    }
    {
        var sexpr = try Sexpr.parse(&ParseContext.init("( ( ( ())))"), std.heap.page_allocator);
        defer sexpr.deinit();

        std.testing.expectEqual(@TagType(Sexpr.Elem.Data).list, sexpr.root[0].data);
        std.testing.expectEqual(@TagType(Sexpr.Elem.Data).list, sexpr.root[0].data.list[0].data);
        std.testing.expectEqual(@TagType(Sexpr.Elem.Data).list, sexpr.root[0].data.list[0].data.list[0].data);
    }
    {
        var sexpr = try Sexpr.parse(&ParseContext.init("(block  ;; label = @1\n  local.get 4)"), std.heap.page_allocator);
        defer sexpr.deinit();

        std.testing.expectEqual(@as(usize, 3), sexpr.root.len);
        std.testing.expectEqualSlices(u8, "block", sexpr.root[0].data.keyword);
        std.testing.expectEqualSlices(u8, "local.get", sexpr.root[1].data.keyword);
        std.testing.expectEqual(@as(usize, 4), sexpr.root[2].data.integer);
    }
}

pub fn parse(allocator: *std.mem.Allocator, string: []const u8) !core.Module {
    var ctx = ParseContext.init(string);
    var sexpr = try Sexpr.parse(&ctx, allocator);
    defer sexpr.deinit();

    const arena = try allocator.create(std.heap.ArenaAllocator);
    errdefer allocator.destroy(arena);
    arena.* = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();

    try ctx.validate(sexpr.root.len > 0, ctx.eof());
    try ctx.validate(std.mem.eql(u8, sexpr.root[0].data.keyword, "module"), sexpr.root[0].token.source);

    var list = std.ArrayList(core.Module.Node).init(&arena.allocator);
    for (sexpr.root[1..]) |elem| {
        try list.append(try parseNode(&ctx, &arena.allocator, elem));
    }

    return core.Module{
        .arena = arena,
        .nodes = list.toOwnedSlice(),
    };
}

fn pop(list: []Sexpr.Elem, i: *usize) ?Sexpr.Elem {
    if (i.* >= list.len) return null;
    defer i.* += 1;
    return list[i.*];
}

fn parseNode(ctx: *ParseContext, arena: *std.mem.Allocator, elem: Sexpr.Elem) !core.Module.Node {
    try ctx.validate(elem.data == .list, elem.token.source);

    const list = elem.data.list;
    try ctx.validate(list.len > 0, elem.token.source);
    try ctx.validate(list[0].data == .keyword, list[0].token.source);

    switch (swhash(list[0].data.keyword)) {
        swhash("memory") => {
            try ctx.validate(list.len == 2, elem.token.source);
            try ctx.validate(list[1].data == .integer, list[1].token.source);

            return core.Module.Node{
                .memory = list[1].data.integer,
            };
        },
        swhash("func") => {
            var params = std.ArrayList(core.Module.Type).init(arena);
            var locals = std.ArrayList(core.Module.Type).init(arena);
            var result: ?core.Module.Type = null;

            var i: usize = 1;
            while (i < list.len and list[i].data == .list) : (i += 1) {
                const pair = list[i].data.list;
                try ctx.validate(pair.len == 2, list[i].token.source);
                try ctx.validate(pair[1].data == .keyword, pair[1].token.source);
                const typ = switch (swhash(pair[1].data.keyword)) {
                    swhash("i32") => core.Module.Type.I32,
                    swhash("i64") => core.Module.Type.I64,
                    swhash("f32") => core.Module.Type.F32,
                    swhash("f64") => core.Module.Type.F64,
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

            var instrs = std.ArrayList(core.Module.Instr).init(arena);
            while (pop(list, &i)) |val| {
                try ctx.validate(val.data == .keyword, val.token.source);

                const op = Op.byName(val.data.keyword) orelse return ctx.fail(val.token.source);
                try instrs.append(.{
                    .opcode = op.code,
                    .arg = switch (op.arg.kind) {
                        .None => Op.Arg{},
                        .Type => blk: {
                            const next = pop(list, &i) orelse return ctx.fail(ctx.eof());
                            try ctx.validate(next.data == .keyword, next.token.source);
                            break :blk Op.Arg.init(
                                switch (swhash(next.data.keyword)) {
                                    swhash("void") => Op.Arg.Type.Void,
                                    swhash("i32") => Op.Arg.Type.I32,
                                    swhash("i64") => Op.Arg.Type.I64,
                                    swhash("f32") => Op.Arg.Type.F32,
                                    swhash("f64") => Op.Arg.Type.F64,
                                    else => return ctx.fail(next.token.source),
                                },
                            );
                        },
                        .I32 => blk: {
                            const next = pop(list, &i) orelse return ctx.fail(ctx.eof());
                            try ctx.validate(next.data == .integer, next.token.source);
                            break :blk Op.Arg.init(next.data.integer);
                        },
                        .I32z, .Mem => {
                            @panic(list[i].data.keyword);
                        },
                    },
                });
            }

            return core.Module.Node{
                .func = .{
                    .name = null,
                    .params = params.toOwnedSlice(),
                    .result = result,
                    .locals = locals.toOwnedSlice(),
                    .instrs = instrs.toOwnedSlice(),
                },
            };
        },
        else => return ctx.fail(list[0].token.source),
    }
}

test "parse" {
    {
        var module = try parse(std.heap.page_allocator, "(module)");
        defer module.deinit();

        std.testing.expectEqual(@as(usize, 0), module.nodes.len);
    }
    {
        var module = try parse(std.heap.page_allocator, "(module (memory 42))");
        defer module.deinit();

        std.testing.expectEqual(@as(usize, 1), module.nodes.len);
        std.testing.expectEqual(@as(usize, 42), module.nodes[0].memory);
    }
}

test "parseNode" {
    {
        var ctx = ParseContext.init(
            \\(func (param i32) (param f32) (result i64) (local f64)
            \\  local.get 0
            \\  local.get 1
            \\  local.get 2)
        );
        var sexpr = try Sexpr.parse(&ctx, std.heap.page_allocator);
        defer sexpr.deinit();

        const wrapped = Sexpr.Elem{
            .token = .{ .source = 0, .raw = "(", .kind = .OpenParen },
            .data = .{ .list = sexpr.root },
        };
        var node = try parseNode(&ctx, &sexpr.arena.allocator, wrapped);
        std.testing.expectEqual(@TagType(core.Module.Node).func, node);
        std.testing.expectEqual(@as(?[]const u8, null), node.func.name);

        std.testing.expectEqual(@as(usize, 2), node.func.params.len);
        std.testing.expectEqual(core.Module.Type.I32, node.func.params[0]);
        std.testing.expectEqual(core.Module.Type.F32, node.func.params[1]);

        std.testing.expectEqual(@as(usize, 1), node.func.locals.len);
        std.testing.expectEqual(core.Module.Type.F64, node.func.locals[0]);

        std.testing.expectEqual(core.Module.Type.I64, node.func.result.?);

        std.testing.expectEqual(@as(usize, 3), node.func.instrs.len);
    }
}
