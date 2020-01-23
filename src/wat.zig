const std = @import("std");

const Sexpr = struct {
    arena: *std.heap.ArenaAllocator,
    root: []Elem,

    const Elem = union {
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

    pub fn parse(allocator: *std.mem.Allocator, string: []const u8) !Sexpr {
        const arena = allocator.create(std.heap.ArenaAllocator);
        errdefer {
            arena.deinit();
            allocator.destroy(arena);
        }

        var tokenizer = Tokenizer.init(string);
        if (tokenizer.next()) |token| {
            if (token.typ != .OpenBrace) {
                return error.ParseError;
            }
        } else {
            return error.ParseError;
        }

        return .{
            .arena = arena,
            .root = try parseList(arena, &tokenizer),
        };
    }

    fn parseList(arena: *std.mem.Allocator, tokenizer: *Tokenizer) !SexprElem {
        while (tokenizer.next()) |token| {
            switch (token) {}
        }

        return error.ParseError;
    }
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
