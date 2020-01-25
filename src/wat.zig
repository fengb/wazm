const std = @import("std");
const builtin = @import("builtin");
const core = @import("core.zig");
const Op = @import("op.zig");

const ParseContext = struct {
    allocator: *std.mem.Allocator,
    string: []const u8,
    err: ?struct {
        location: usize,
        message: ?[]const u8,
    } = null,

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

    const Elem = union(enum) {
        list: []Elem,
        keyword: []const u8,
        id: []const u8,
        string: []const u8,
        integer: usize,
        float: f64,
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

    pub fn parse(ctx: *ParseContext) !Sexpr {
        const arena = try ctx.allocator.create(std.heap.ArenaAllocator);
        arena.* = std.heap.ArenaAllocator.init(ctx.allocator);
        errdefer {
            arena.deinit();
            ctx.allocator.destroy(arena);
        }

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
        Overflow,
        InvalidCharacter,
    }![]Elem {
        var list = std.ArrayList(Elem).init(arena);
        while (tokenizer.next()) |token| {
            switch (token.kind) {
                .OpenParen => try list.append(.{ .list = try parseList(ctx, arena, tokenizer) }),
                .Literal => {
                    try list.append(switch (token.raw[0]) {
                        '"' => .{ .string = token.raw },
                        '$' => .{ .id = token.raw },
                        '+', '-', '0'...'9' => .{ .integer = try std.fmt.parseInt(usize, token.raw, 10) },
                        'a'...'z' => .{ .keyword = token.raw },
                        else => return ctx.fail(token.source),
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
                    try ctx.validate(false, token.source);
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
        var sexpr = try Sexpr.parse(&ParseContext{ .string = "(a bc 42)", .allocator = std.heap.page_allocator });
        defer sexpr.deinit();

        std.testing.expectEqual(@as(usize, 3), sexpr.root.len);
        std.testing.expectEqualSlices(u8, "a", sexpr.root[0].keyword);
        std.testing.expectEqualSlices(u8, "bc", sexpr.root[1].keyword);
        std.testing.expectEqual(@as(usize, 42), sexpr.root[2].integer);
    }
    {
        var sexpr = try Sexpr.parse(&ParseContext{ .string = "(() ())", .allocator = std.heap.page_allocator });
        defer sexpr.deinit();

        std.testing.expectEqual(@as(usize, 2), sexpr.root.len);
        std.testing.expectEqual(@TagType(Sexpr.Elem).list, sexpr.root[0]);
        std.testing.expectEqual(@TagType(Sexpr.Elem).list, sexpr.root[1]);
    }
    {
        var sexpr = try Sexpr.parse(&ParseContext{ .string = "( ( ( ())))", .allocator = std.heap.page_allocator });
        defer sexpr.deinit();

        std.testing.expectEqual(@TagType(Sexpr.Elem).list, sexpr.root[0]);
        std.testing.expectEqual(@TagType(Sexpr.Elem).list, sexpr.root[0].list[0]);
        std.testing.expectEqual(@TagType(Sexpr.Elem).list, sexpr.root[0].list[0].list[0]);
    }
    {
        var sexpr = try Sexpr.parse(&ParseContext{ .string = "(block  ;; label = @1\n  local.get 4)", .allocator = std.heap.page_allocator });
        defer sexpr.deinit();

        std.testing.expectEqual(@as(usize, 3), sexpr.root.len);
        std.testing.expectEqualSlices(u8, "block", sexpr.root[0].keyword);
        std.testing.expectEqualSlices(u8, "local.get", sexpr.root[1].keyword);
        std.testing.expectEqual(@as(usize, 4), sexpr.root[2].integer);
    }
}

pub fn parse(allocator: *std.mem.Allocator, string: []const u8) !core.Module {
    var sexpr = try Sexpr.parse(&ParseContext{ .string = string, .allocator = allocator });
    defer sexpr.deinit();

    const arena = try allocator.create(std.heap.ArenaAllocator);
    arena.* = std.heap.ArenaAllocator.init(allocator);
    errdefer {
        arena.deinit();
        allocator.destroy(arena);
    }

    if (sexpr.root.len == 0) {
        return error.ParseError;
    }

    if (!std.mem.eql(u8, sexpr.root[0].keyword, "module")) {
        return error.ParseError;
    }

    var list = std.ArrayList(core.Module.Node).init(&arena.allocator);
    for (sexpr.root[1..]) |elem| {
        if (elem != .list) {
            return error.ParseError;
        }
        try list.append(try parseNode(&arena.allocator, elem.list));
    }

    return core.Module{
        .arena = arena,
        .nodes = list.toOwnedSlice(),
    };
}

fn parseNode(arena: *std.mem.Allocator, list: []Sexpr.Elem) !core.Module.Node {
    if (list.len == 0) {
        return error.ParseError;
    }

    if (list[0] != .keyword) {
        return error.ParseError;
    }

    if (std.mem.eql(u8, list[0].keyword, "memory")) {
        if (list.len != 2) {
            return error.ParseError;
        }

        return core.Module.Node{
            .memory = list[1].integer,
        };
    } else if (std.mem.eql(u8, list[0].keyword, "func")) {
        var params = std.ArrayList(core.Module.Type).init(arena);
        var locals = std.ArrayList(core.Module.Type).init(arena);
        var result: ?core.Module.Type = null;

        var i: usize = 1;
        while (i < list.len and list[i] == .list) : (i += 1) {
            const pair = list[i].list;
            if (pair.len != 2) {
                return error.ParseError;
            }
            if (pair[1] != .keyword) {
                return error.ParseError;
            }
            const typ = if (std.mem.eql(u8, pair[1].keyword, "i32"))
                core.Module.Type.I32
            else if (std.mem.eql(u8, pair[1].keyword, "i64"))
                core.Module.Type.I64
            else if (std.mem.eql(u8, pair[1].keyword, "f32"))
                core.Module.Type.F32
            else if (std.mem.eql(u8, pair[1].keyword, "f64"))
                core.Module.Type.F64
            else
                return error.ParseError;

            if (pair[0] != .keyword) {
                return error.ParseError;
            }
            if (std.mem.eql(u8, pair[0].keyword, "param")) {
                try params.append(typ);
            } else if (std.mem.eql(u8, pair[0].keyword, "local")) {
                try locals.append(typ);
            } else if (std.mem.eql(u8, pair[0].keyword, "result")) {
                result = typ;
            } else {
                return error.ParseError;
            }
        }

        var instrs = std.ArrayList(core.Module.Instr).init(arena);
        while (i < list.len) : (i += 1) {
            if (list[i] != .keyword) {
                return error.ParseError;
            }
            const op = try Op.byName(list[i].keyword);
            const arg = if (op.arg.kind == .None)
                Op.Arg{ ._pad = 0 }
            else blk: {
                i += 1;
                const next = list[i];
                switch (op.arg.kind) {
                    .None => unreachable,
                    .Type => {
                        if (next != .keyword) {
                            return error.ParseError;
                        }
                        const t = if (std.mem.eql(u8, next.keyword, "void"))
                            Op.Arg.Type.Void
                        else if (std.mem.eql(u8, next.keyword, "i32"))
                            Op.Arg.Type.I32
                        else if (std.mem.eql(u8, next.keyword, "i64"))
                            Op.Arg.Type.I64
                        else if (std.mem.eql(u8, next.keyword, "f32"))
                            Op.Arg.Type.F32
                        else if (std.mem.eql(u8, next.keyword, "f64"))
                            Op.Arg.Type.F64
                        else
                            return error.ParseError;

                        break :blk Op.Arg{ .b1 = @intCast(u8, @enumToInt(t)) };
                    },
                    .I32 => {
                        if (next != .integer) {
                            return error.ParseError;
                        }
                        var raw: [4]u8 = undefined;
                        std.mem.writeIntLittle(u32, &raw, @intCast(u32, next.integer));
                        break :blk Op.Arg{ .b4 = raw };
                    },
                    .I32z, .Mem => {
                        @panic(list[i].keyword);
                    },
                }
            };
            try instrs.append(.{ .opcode = op.code, .arg = arg });
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
    }

    return error.ParseError;
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
        var sexpr = try Sexpr.parse(&ParseContext{
            .allocator = std.heap.page_allocator,
            .string =
                \\(func (param i32) (param f32) (result i64) (local f64)
                \\  local.get 0
                \\  local.get 1
                \\  local.get 2)
                    });
        defer sexpr.deinit();

        var node = try parseNode(&sexpr.arena.allocator, sexpr.root);
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
