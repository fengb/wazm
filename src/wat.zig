const std = @import("std");
const core = @import("core.zig");

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

    const Token = union(enum) {
        OpenParen: void,
        CloseParen: void,
        Newline: void,
        OpenParenSemicolon: void,
        SemicolonCloseParen: void,
        SemicolonSemicolon: void,
        Literal: []const u8,
    };

    pub fn deinit(self: *Sexpr) void {
        self.arena.deinit();
    }

    pub fn parse(allocator: *std.mem.Allocator, string: []const u8) !Sexpr {
        const arena = try allocator.create(std.heap.ArenaAllocator);
        arena.* = std.heap.ArenaAllocator.init(allocator);
        errdefer {
            arena.deinit();
            allocator.destroy(arena);
        }

        var tokenizer = Tokenizer.init(string);
        if (tokenizer.next()) |token| {
            if (token != .OpenParen) {
                return error.ParseError;
            }
        } else {
            return error.ParseError;
        }

        return Sexpr{
            .arena = arena,
            .root = try parseList(&arena.allocator, &tokenizer),
        };
    }

    fn parseList(arena: *std.mem.Allocator, tokenizer: *Tokenizer) error{
        OutOfMemory,
        ParseError,
        Overflow,
        InvalidCharacter,
    }![]Elem {
        var list = std.ArrayList(Elem).init(arena);
        while (tokenizer.next()) |token| {
            switch (token) {
                .OpenParen => try list.append(.{ .list = try parseList(arena, tokenizer) }),
                .Literal => |literal| {
                    try list.append(switch (literal[0]) {
                        '"' => .{ .string = literal },
                        '$' => .{ .id = literal },
                        '+', '-', '0'...'9' => .{ .integer = try std.fmt.parseInt(usize, literal, 10) },
                        else => .{ .keyword = literal },
                    });
                },
                .CloseParen => return list.toOwnedSlice(),
                .Newline => {},
                .OpenParenSemicolon => {
                    while (tokenizer.next()) |comment| {
                        if (comment == .SemicolonCloseParen) {
                            break;
                        }
                    }
                    return error.ParseError;
                },
                .SemicolonCloseParen => return error.ParseError,
                .SemicolonSemicolon => {
                    while (tokenizer.next()) |comment| {
                        if (comment == .Newline) {
                            break;
                        }
                    }
                },
            }
        }

        return error.ParseError;
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
                        return Token{ .OpenParenSemicolon = {} };
                    } else {
                        return Token{ .OpenParen = {} };
                    }
                },
                ')' => return Token{ .CloseParen = {} },
                '\n' => return Token{ .Newline = {} },
                ';' => {
                    if (self.cursor > self.raw.len) {
                        return Token{ .Literal = ";" };
                    } else if (self.raw[self.cursor] == ';') {
                        self.cursor += 1;
                        return Token{ .SemicolonSemicolon = {} };
                    } else if (self.raw[self.cursor] == ')') {
                        self.cursor += 1;
                        return Token{ .SemicolonCloseParen = {} };
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

            return Token{ .Literal = self.raw[start..self.cursor] };
        }
    };
};

test "Tokenizer" {
    {
        var tokenizer = Sexpr.Tokenizer.init("(type (func (param i32 i32)");
        std.testing.expectEqual(@TagType(Sexpr.Token).OpenParen, tokenizer.next().?);
        std.testing.expectEqualSlices(u8, "type", tokenizer.next().?.Literal);

        std.testing.expectEqual(@TagType(Sexpr.Token).OpenParen, tokenizer.next().?);
        std.testing.expectEqualSlices(u8, "func", tokenizer.next().?.Literal);

        std.testing.expectEqual(@TagType(Sexpr.Token).OpenParen, tokenizer.next().?);
        std.testing.expectEqualSlices(u8, "param", tokenizer.next().?.Literal);
        std.testing.expectEqualSlices(u8, "i32", tokenizer.next().?.Literal);
        std.testing.expectEqualSlices(u8, "i32", tokenizer.next().?.Literal);
        std.testing.expectEqual(@TagType(Sexpr.Token).CloseParen, tokenizer.next().?);

        std.testing.expectEqual(@as(?Sexpr.Token, null), tokenizer.next());
    }
    {
        var tokenizer = Sexpr.Tokenizer.init("block  ;; label = @1\n  local.get 4");
        std.testing.expectEqualSlices(u8, "block", tokenizer.next().?.Literal);

        std.testing.expectEqual(@TagType(Sexpr.Token).SemicolonSemicolon, tokenizer.next().?);
        std.testing.expectEqualSlices(u8, "label", tokenizer.next().?.Literal);
        std.testing.expectEqualSlices(u8, "=", tokenizer.next().?.Literal);
        std.testing.expectEqualSlices(u8, "@1", tokenizer.next().?.Literal);

        std.testing.expectEqual(@TagType(Sexpr.Token).Newline, tokenizer.next().?);
        std.testing.expectEqualSlices(u8, "local.get", tokenizer.next().?.Literal);
        std.testing.expectEqualSlices(u8, "4", tokenizer.next().?.Literal);

        std.testing.expectEqual(@as(?Sexpr.Token, null), tokenizer.next());
    }
    {
        var tokenizer = Sexpr.Tokenizer.init("foo (;0;)");
        std.testing.expectEqualSlices(u8, "foo", tokenizer.next().?.Literal);

        std.testing.expectEqual(@TagType(Sexpr.Token).OpenParenSemicolon, tokenizer.next().?);
        std.testing.expectEqualSlices(u8, "0", tokenizer.next().?.Literal);
        std.testing.expectEqual(@TagType(Sexpr.Token).SemicolonCloseParen, tokenizer.next().?);

        std.testing.expectEqual(@as(?Sexpr.Token, null), tokenizer.next());
    }
}

test "Sexpr.parse" {
    {
        var sexpr = try Sexpr.parse(std.heap.page_allocator, "(a bc 42)");
        defer sexpr.deinit();

        std.testing.expectEqual(@as(usize, 3), sexpr.root.len);
        std.testing.expectEqualSlices(u8, "a", sexpr.root[0].keyword);
        std.testing.expectEqualSlices(u8, "bc", sexpr.root[1].keyword);
        std.testing.expectEqual(@as(usize, 42), sexpr.root[2].integer);
    }
    {
        var sexpr = try Sexpr.parse(std.heap.page_allocator, "(() ())");
        defer sexpr.deinit();

        std.testing.expectEqual(@as(usize, 2), sexpr.root.len);
        std.testing.expectEqual(@TagType(Sexpr.Elem).list, sexpr.root[0]);
        std.testing.expectEqual(@TagType(Sexpr.Elem).list, sexpr.root[1]);
    }
    {
        var sexpr = try Sexpr.parse(std.heap.page_allocator, "( ( ( ())))");
        defer sexpr.deinit();

        std.testing.expectEqual(@TagType(Sexpr.Elem).list, sexpr.root[0]);
        std.testing.expectEqual(@TagType(Sexpr.Elem).list, sexpr.root[0].list[0]);
        std.testing.expectEqual(@TagType(Sexpr.Elem).list, sexpr.root[0].list[0].list[0]);
    }
    {
        var sexpr = try Sexpr.parse(std.heap.page_allocator, "(block  ;; label = @1\n  local.get 4)");
        defer sexpr.deinit();

        std.testing.expectEqual(@as(usize, 3), sexpr.root.len);
        std.testing.expectEqualSlices(u8, "block", sexpr.root[0].keyword);
        std.testing.expectEqualSlices(u8, "local.get", sexpr.root[1].keyword);
        std.testing.expectEqual(@as(usize, 4), sexpr.root[2].integer);
    }
}

pub fn parse(allocator: *std.mem.Allocator, string: []const u8) !core.Module {
    var sexpr = try Sexpr.parse(allocator, string);
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
        try list.append(try parseNode(&arena.allocator, elem));
    }

    return core.Module{
        .arena = arena,
        .nodes = list.toOwnedSlice(),
    };
}

fn parseNode(arena: *std.mem.Allocator, elem: Sexpr.Elem) !core.Module.Node {
    if (elem != .list) return error.ParseError;

    const list = elem.list;
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
    }

    @panic("Nope");
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
