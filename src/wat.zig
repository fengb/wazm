const std = @import("std");
const core = @import("core.zig");

const Sexpr = struct {
    arena: *std.heap.ArenaAllocator,
    root: []Elem,

    const Elem = union(enum) {
        List: []Elem,
        Symbol: []const u8,
    };

    const Token = union(enum) {
        OpenBrace: void,
        CloseBrace: void,
        Newline: void,
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
            if (token != .OpenBrace) {
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
    }![]Elem {
        var list = std.ArrayList(Elem).init(arena);
        while (tokenizer.next()) |token| {
            switch (token) {
                .OpenBrace => try list.append(.{ .List = try parseList(arena, tokenizer) }),
                .Literal => |literal| try list.append(.{ .Symbol = literal }),
                .CloseBrace => return list.toOwnedSlice(),
                .Newline => {},
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
                '(' => return Token{ .OpenBrace = {} },
                ')' => return Token{ .CloseBrace = {} },
                '\n' => return Token{ .Newline = {} },
                ';' => {
                    if (self.cursor > self.raw.len) {
                        return Token{ .Literal = ";" };
                    } else if (self.raw[self.cursor] == ';') {
                        self.cursor += 1;
                        return Token{ .SemicolonSemicolon = {} };
                    } else {
                        // "fallthrough"
                    }
                },
                else => {},
            }

            while (self.cursor < self.raw.len) : (self.cursor += 1) {
                switch (self.raw[self.cursor]) {
                    ' ', '\t', '(', ')', '\n' => break,
                    else => {},
                }
            }

            return Token{ .Literal = self.raw[start..self.cursor] };
        }
    };
};

test "Tokenizer" {
    {
        var tokenizer = Sexpr.Tokenizer.init("(type (;1;) (func (param i32 i32)");
        std.testing.expectEqual(@TagType(Sexpr.Token).OpenBrace, tokenizer.next().?);
        std.testing.expectEqualSlices(u8, "type", tokenizer.next().?.Literal);

        std.testing.expectEqual(@TagType(Sexpr.Token).OpenBrace, tokenizer.next().?);
        std.testing.expectEqualSlices(u8, ";1;", tokenizer.next().?.Literal);
        std.testing.expectEqual(@TagType(Sexpr.Token).CloseBrace, tokenizer.next().?);

        std.testing.expectEqual(@TagType(Sexpr.Token).OpenBrace, tokenizer.next().?);
        std.testing.expectEqualSlices(u8, "func", tokenizer.next().?.Literal);

        std.testing.expectEqual(@TagType(Sexpr.Token).OpenBrace, tokenizer.next().?);
        std.testing.expectEqualSlices(u8, "param", tokenizer.next().?.Literal);
        std.testing.expectEqualSlices(u8, "i32", tokenizer.next().?.Literal);
        std.testing.expectEqualSlices(u8, "i32", tokenizer.next().?.Literal);
        std.testing.expectEqual(@TagType(Sexpr.Token).CloseBrace, tokenizer.next().?);

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
}

test "Sexpr.parse" {
    {
        var sexpr = try Sexpr.parse(std.heap.page_allocator, "(a bc)");
        defer sexpr.deinit();

        std.testing.expectEqual(@as(usize, 2), sexpr.root.len);
        std.testing.expectEqualSlices(u8, "a", sexpr.root[0].Symbol);
        std.testing.expectEqualSlices(u8, "bc", sexpr.root[1].Symbol);
    }
    {
        var sexpr = try Sexpr.parse(std.heap.page_allocator, "(() ())");
        defer sexpr.deinit();

        std.testing.expectEqual(@as(usize, 2), sexpr.root.len);
        std.testing.expectEqual(@TagType(Sexpr.Elem).List, sexpr.root[0]);
        std.testing.expectEqual(@TagType(Sexpr.Elem).List, sexpr.root[1]);
    }
    {
        var sexpr = try Sexpr.parse(std.heap.page_allocator, "( ( ( ())))");
        defer sexpr.deinit();

        std.testing.expectEqual(@TagType(Sexpr.Elem).List, sexpr.root[0]);
        std.testing.expectEqual(@TagType(Sexpr.Elem).List, sexpr.root[0].List[0]);
        std.testing.expectEqual(@TagType(Sexpr.Elem).List, sexpr.root[0].List[0].List[0]);
    }
    {
        var sexpr = try Sexpr.parse(std.heap.page_allocator, "(block  ;; label = @1\n  local.get 4)");
        defer sexpr.deinit();

        std.testing.expectEqual(@as(usize, 3), sexpr.root.len);
        std.testing.expectEqualSlices(u8, "block", sexpr.root[0].Symbol);
        std.testing.expectEqualSlices(u8, "local.get", sexpr.root[1].Symbol);
        std.testing.expectEqualSlices(u8, "4", sexpr.root[2].Symbol);
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

    if (!std.mem.eql(u8, sexpr.root[0].Symbol, "module")) {
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
    switch (elem) {
        .Symbol => return error.ParseError,
        .List => |list| {
            if (list.len == 0) {
                return error.ParseError;
            }

            if (list[0] != .Symbol) {
                return error.ParseError;
            }

            if (std.mem.eql(u8, list[0].Symbol, "memory")) {
                if (list.len != 2) {
                    return error.ParseError;
                }

                return core.Module.Node{
                    .memory = 42,
                };
            }
        },
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
