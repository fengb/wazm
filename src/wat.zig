const std = @import("std");
const Module = @import("module.zig");
const Op = @import("op.zig");
const util = @import("util.zig");

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
        out_stream: anytype,
    ) !void {
        if (self.err) |err| {
            if (err.location >= self.string.len) {
                try out_stream.writeAll("ParseError @ EOF");
            } else {
                try std.fmt.format(out_stream, "ParseError @ {}", .{err.location});
            }
            if (err.message) |msg| {
                try out_stream.writeAll(": '");
                try out_stream.writeAll(msg);
                try out_stream.writeAll("'");
            }

            try out_stream.writeAll("\n# ");
            if (err.location >= self.string.len) {
                const start = std.math.min(self.string.len -% 20, 0);
                try out_stream.writeAll(self.string[start..]);
                try out_stream.writeAll("$");
            } else {
                try out_stream.writeAll(self.string[err.location..std.math.min(err.location + 20, self.string.len)]);
                try out_stream.writeAll("\n  ^");
            }
            try out_stream.writeAll("\n");
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

    fn coerceElem(self: *ParseContext, elem: Sexpr.Elem, comptime T: type) !T {
        switch (@typeInfo(T)) {
            .Int => {
                try self.validate(elem.data == .integer, elem.token.source);
                return @intCast(T, elem.data.integer);
            },
            .Float => {
                try self.validate(elem.data == .float, elem.token.source);
                return @floatCast(T, elem.data.float);
            },
            else => @compileLog("Coerce failure: " ++ @typeName(T) ++ " not supported"),
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

fn sexpr(reader: anytype) Sexpr(@TypeOf(reader)) {
    return .{ .reader = reader };
}

fn Sexpr(comptime Reader: type) type {
    return struct {
        const Self = @This();

        reader: Reader,
        stack: u8 = 0,
        peek: ?u8 = null,

        const Token = enum {
            OpenParen,
            CloseParen,
            Atom,
        };

        const List = struct {
            ctx: *Self,

            const Next = union { Atom: []const u8, List: List };

            pub fn next(self: Element, buffer: []const u8) !?Next {
                return switch ((try self.scan(byte)).?) {
                    .OpenParen => Next.List{ .ctx = self.ctx },
                    .CloseParen => null,
                    else => self.loadIntoBuffer(buffer),
                };
            }

            pub fn nextAtom(self: Element, buffer: []const u8) !?[]const u8 {
                return switch ((try self.scan(byte)).?) {
                    .OpenParen => error.ExpectedAtom,
                    .CloseParen => null,
                    else => self.loadIntoBuffer(buffer),
                };
            }

            pub fn nextList(self: Element) !?List {
                return switch ((try self.scan(byte)).?) {
                    .OpenParen => Next.List{ .ctx = self.ctx },
                    .CloseParen => null,
                    else => return error.ExpectedList,
                };
            }

            fn loadIntoBuffer(self: Element, buffer: []const u8) ![]const u8 {
                var fbs = std.io.fixedBufferStream(buffer);

                const first = try self.ctx.readByte();
                try fbs.writeByte(first);
                const is_string = start == '"';

                while (true) {
                    const byte = try self.ctx.readByte();
                    if (is_string) {
                        fbs.writeByte(byte);

                        // TODO: handle escape sequences?
                        if (byte == '"') {
                            return fbs.getWritten();
                        }
                    } else {
                        switch (byte) {
                            0, ' ', '\t', '\n', '(', ')' => {
                                self.ctx.putBack(byte);
                                return fbs.getWritten();
                            },
                            else => try fbs.writeByte(byte),
                        }
                    }
                }
            }
        };

        pub fn root(self: *Self) !List {
            const token = try self.scan();
            self.assert(token == .OpenParen);
            return List{ .ctx = self };
        }

        fn skipPast(self: *Self, seq: []const u8) !void {
            std.debug.assert(seq.len > 0);

            var matched = 0;
            while (self.readByte()) |byte| {
                if (byte == seq[matched]) {
                    matched += 1;
                    if (matched >= seq.len) {
                        return;
                    }
                } else {
                    matched = 0;
                }
            }
        }

        fn readByte(self: *Self) !u8 {
            if (self.peek) |p| {
                self.peek = null;
                return p;
            } else {
                return self.reader.readByte();
            }
        }

        fn peek(self: *Self) !u8 {
            return self.peek orelse {
                self.peek = try self.readByte();
                return self.peek;
            };
        }

        fn scan(self: *Self) !Token {
            while (true) {
                const byte = try self.readByte();
                switch (byte) {
                    0, ' ', '\t', '\n' => {},
                    '(' => {
                        if (self.peek() == ';') {
                            // Comment block -- skip to next segment
                            try self.skipPast(";)");
                        } else {
                            self.stack = try std.math.add(self.stack, 1);
                            return Token.OpenParen;
                        }
                    },
                    ')' => {
                        self.stack = try std.math.sub(self.stack, 1);
                        return Token.CloseParen;
                    },
                    ';' => try self.skipPast("\n"),
                    else => {
                        self.putBack(byte);
                        return Token.Atom;
                    },
                }
            }
        }
    };
}

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
                .CloseParen => return list.items,
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

fn next(list: []Sexpr.Elem, i: *usize) ?Sexpr.Elem {
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

    var customs = std.ArrayList(Module.sectionType(.Custom)).init(&arena.allocator);
    var types = std.ArrayList(Module.sectionType(.Type)).init(&arena.allocator);
    var imports = std.ArrayList(Module.sectionType(.Import)).init(&arena.allocator);
    var functions = std.ArrayList(Module.sectionType(.Function)).init(&arena.allocator);
    var tables = std.ArrayList(Module.sectionType(.Table)).init(&arena.allocator);
    var memories = std.ArrayList(Module.sectionType(.Memory)).init(&arena.allocator);
    var globals = std.ArrayList(Module.sectionType(.Global)).init(&arena.allocator);
    var exports = std.ArrayList(Module.sectionType(.Export)).init(&arena.allocator);
    var start: ?Module.sectionType(.Start) = null;
    var elements = std.ArrayList(Module.sectionType(.Element)).init(&arena.allocator);
    var codes = std.ArrayList(Module.sectionType(.Code)).init(&arena.allocator);
    var data = std.ArrayList(Module.sectionType(.Data)).init(&arena.allocator);

    for (sexpr.root[1..]) |elem| {
        try ctx.validate(elem.data == .list, elem.token.source);

        const list = elem.data.list;
        try ctx.validate(list.len > 0, elem.token.source);
        try ctx.validate(list[0].data == .keyword, list[0].token.source);

        const swhash = util.Swhash(8);
        switch (swhash.match(list[0].data.keyword)) {
            swhash.case("memory") => {
                try ctx.validate(list.len == 2, elem.token.source);
                try ctx.validate(list[1].data == .integer, list[1].token.source);

                try memories.append(.{
                    .limits = .{
                        .initial = @intCast(u32, list[1].data.integer),
                        .maximum = if (list.len == 2) null else @intCast(u32, list[2].data.integer),
                    },
                });
            },
            swhash.case("func") => {
                var params = std.ArrayList(Module.Type.Value).init(&arena.allocator);
                var locals = std.ArrayList(Module.Type.Value).init(&arena.allocator);
                var result: ?Module.Type.Value = null;

                var i: usize = 1;
                while (i < list.len and list[i].data == .list) : (i += 1) {
                    const pair = list[i].data.list;
                    try ctx.validate(pair.len == 2, list[i].token.source);
                    try ctx.validate(pair[1].data == .keyword, pair[1].token.source);
                    const typ: Module.Type.Value = switch (swhash.match(pair[1].data.keyword)) {
                        swhash.case("i32") => .I32,
                        swhash.case("i64") => .I64,
                        swhash.case("f32") => .F32,
                        swhash.case("f64") => .F64,
                        else => return ctx.fail(pair[1].token.source),
                    };

                    try ctx.validate(pair[0].data == .keyword, pair[0].token.source);
                    switch (swhash.match(pair[0].data.keyword)) {
                        swhash.case("param") => try params.append(typ),
                        swhash.case("local") => try locals.append(typ),
                        swhash.case("result") => result = typ,
                        else => return ctx.fail(pair[0].token.source),
                    }
                }

                var code = std.ArrayList(Module.Instr).init(&arena.allocator);
                while (next(list, &i)) |val| {
                    try ctx.validate(val.data == .keyword, val.token.source);

                    if (Op.byName(val.data.keyword)) |op| {
                        try code.append(.{
                            .op = op,
                            .arg = blk: {
                                if (op.arg_kind == .Void) break :blk .{ .I64 = 0 };

                                const arg = next(list, &i) orelse return ctx.fail(ctx.eof());
                                break :blk @as(Op.Fixval, switch (op.arg_kind) {
                                    .Void => unreachable,
                                    .Type => {
                                        try ctx.validate(arg.data == .keyword, arg.token.source);
                                        break :blk Op.Fixval.init(
                                            @as(Op.Arg.Type, switch (swhash.match(arg.data.keyword)) {
                                                swhash.case("void") => .Void,
                                                swhash.case("i32") => .I32,
                                                swhash.case("i64") => .I64,
                                                swhash.case("f32") => .F32,
                                                swhash.case("f64") => .F64,
                                                else => return ctx.fail(arg.token.source),
                                            }),
                                        );
                                    },
                                    .I32 => .{ .I32 = try ctx.coerceElem(arg, i32) },
                                    .U32 => .{ .U32 = try ctx.coerceElem(arg, u32) },
                                    .I64 => .{ .I64 = try ctx.coerceElem(arg, i64) },
                                    .U64 => .{ .U64 = try ctx.coerceElem(arg, u64) },
                                    .F32 => .{ .F32 = try ctx.coerceElem(arg, f32) },
                                    .F64 => .{ .F64 = try ctx.coerceElem(arg, f64) },
                                    .U32z, .Mem, .Array => @panic(list[i].data.keyword),
                                });
                            },
                        });
                    } else {
                        return ctx.fail(val.token.source);
                    }
                }

                try functions.append(@intToEnum(Module.Index.FuncType, @intCast(u32, types.items.len)));

                try codes.append(.{
                    .locals = locals.items,
                    .code = code.items,
                });

                try types.append(.{
                    .form = .Func,
                    .param_types = params.items,
                    .return_type = result,
                });
            },
            else => return ctx.fail(list[0].token.source),
        }
    }

    return Module{
        .custom = customs.items,
        .@"type" = types.items,
        .import = imports.items,
        .function = functions.items,
        .table = tables.items,
        .memory = memories.items,
        .global = globals.items,
        .@"export" = exports.items,
        .start = start,
        .element = elements.items,
        .code = codes.items,
        .data = data.items,

        .arena = arena,
    };
}

test "parse" {
    {
        var module = try parse(std.testing.allocator, "(module)");
        defer module.deinit();

        std.testing.expectEqual(@as(usize, 0), module.memory.len);
        std.testing.expectEqual(@as(usize, 0), module.function.len);
        std.testing.expectEqual(@as(usize, 0), module.@"export".len);
    }
    {
        var module = try parse(std.testing.allocator, "(module (memory 42))");
        defer module.deinit();

        std.testing.expectEqual(@as(usize, 1), module.memory.len);
        std.testing.expectEqual(@as(u32, 42), module.memory[0].limits.initial);
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

        std.testing.expectEqual(@as(usize, 1), module.function.len);

        const func_type = module.@"type"[0];
        std.testing.expectEqual(@as(usize, 2), func_type.param_types.len);
        std.testing.expectEqual(Module.Type.Value.I32, func_type.param_types[0]);
        std.testing.expectEqual(Module.Type.Value.F32, func_type.param_types[1]);
        std.testing.expectEqual(Module.Type.Value.I64, func_type.return_type.?);

        const code = module.code[0];

        std.testing.expectEqual(@as(usize, 1), code.locals.len);
        std.testing.expectEqual(Module.Type.Value.F64, code.locals[0]);

        std.testing.expectEqual(@as(usize, 3), code.code.len);
    }
}
