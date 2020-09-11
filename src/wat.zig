const std = @import("std");
const Module = @import("module.zig");
const Op = @import("op.zig");
const util = @import("util.zig");

fn sexpr(reader: anytype) Sexpr(@TypeOf(reader)) {
    return .{ .reader = reader };
}

fn Sexpr(comptime Reader: type) type {
    return struct {
        const Self = @This();

        reader: Reader,
        stack: u8 = 0,
        _peek: ?u8 = null,

        const Token = enum {
            OpenParen,
            CloseParen,
            Atom,
        };

        pub const List = struct {
            ctx: *Self,

            const Next = union { Atom: []const u8, List: List };

            pub fn next(self: List, buffer: []u8) !?Next {
                return switch (try self.ctx.scan()) {
                    .OpenParen => Next{ .List = .{ .ctx = self.ctx } },
                    .CloseParen => null,
                    else => try self.loadIntoBuffer(buffer),
                };
            }

            pub fn obtainAtom(self: List, buffer: []u8) ![]const u8 {
                return (try self.nextAtom(buffer)) orelse error.ExpectedAtomGotNull;
            }

            pub fn obtainList(self: List) !List {
                return (try self.nextList()) orelse error.ExpectedListGotNull;
            }

            pub fn nextAtom(self: List, buffer: []u8) !?[]const u8 {
                return switch (try self.ctx.scan()) {
                    .OpenParen => error.ExpectedAtomGotList,
                    .CloseParen => null,
                    else => try self.loadIntoBuffer(buffer),
                };
            }

            pub fn nextList(self: List) !?List {
                return switch (try self.ctx.scan()) {
                    .OpenParen => List{ .ctx = self.ctx },
                    .CloseParen => null,
                    else => error.ExpectedListGotAtom,
                };
            }

            pub fn expectEnd(self: List) !void {
                switch (try self.ctx.scan()) {
                    .CloseParen => {},
                    else => return error.ExpectedEndOfList,
                }
            }

            fn loadIntoBuffer(self: List, buffer: []u8) ![]const u8 {
                var fbs = std.io.fixedBufferStream(buffer);
                const writer = fbs.writer();

                const first = try self.ctx.readByte();
                try writer.writeByte(first);
                const is_string = first == '"';

                while (true) {
                    const byte = try self.ctx.readByte();
                    if (is_string) {
                        try writer.writeByte(byte);

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
                            else => try writer.writeByte(byte),
                        }
                    }
                }
            }
        };

        pub fn root(self: *Self) !List {
            const token = try self.scan();
            std.debug.assert(token == .OpenParen);
            return List{ .ctx = self };
        }

        fn skipPast(self: *Self, seq: []const u8) !void {
            std.debug.assert(seq.len > 0);

            var matched: usize = 0;
            while (true) {
                const byte = try self.readByte();
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
            if (self._peek) |p| {
                self._peek = null;
                return p;
            } else {
                return self.reader.readByte();
            }
        }

        fn peek(self: *Self) !u8 {
            return self._peek orelse {
                const byte = try self.readByte();
                self._peek = byte;
                return byte;
            };
        }

        fn putBack(self: *Self, byte: u8) void {
            std.debug.assert(self._peek == null);
            self._peek = byte;
        }

        fn scan(self: *Self) !Token {
            while (true) {
                const byte = try self.readByte();
                switch (byte) {
                    0, ' ', '\t', '\n' => {},
                    '(' => {
                        if ((try self.peek()) == ';') {
                            // Comment block -- skip to next segment
                            try self.skipPast(";)");
                        } else {
                            self.stack = try std.math.add(u8, self.stack, 1);
                            return Token.OpenParen;
                        }
                    },
                    ')' => {
                        self.stack = try std.math.sub(u8, self.stack, 1);
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

test "sexpr" {
    {
        var fbs = std.io.fixedBufferStream("(a bc 42)");
        var s = sexpr(fbs.reader());

        const root = try s.root();

        var buf: [0x100]u8 = undefined;
        std.testing.expectEqualSlices(u8, "a", try root.obtainAtom(&buf));
        std.testing.expectEqualSlices(u8, "bc", try root.obtainAtom(&buf));
        std.testing.expectEqualSlices(u8, "42", try root.obtainAtom(&buf));
        try root.expectEnd();
    }
    {
        var fbs = std.io.fixedBufferStream("(() ())");
        var s = sexpr(fbs.reader());

        const root = try s.root();

        const first = try root.obtainList();
        std.testing.expectEqual(@as(?@TypeOf(root), null), try first.nextList());

        const second = try root.obtainList();
        std.testing.expectEqual(@as(?@TypeOf(root), null), try second.nextList());
    }
    {
        var fbs = std.io.fixedBufferStream("( ( ( ())))");
        var s = sexpr(fbs.reader());

        const root = try s.root();

        const first = try root.obtainList();
        const second = try first.obtainList();
        const third = try second.obtainList();
        try third.expectEnd();
        try second.expectEnd();
        try first.expectEnd();
    }
    {
        var fbs = std.io.fixedBufferStream("(block (; ; ; ;) ;; label = @1\n  local.get 4)");
        var s = sexpr(fbs.reader());

        const root = try s.root();

        var buf: [0x100]u8 = undefined;
        std.testing.expectEqualSlices(u8, "block", try root.obtainAtom(&buf));
        std.testing.expectEqualSlices(u8, "local.get", try root.obtainAtom(&buf));
        std.testing.expectEqualSlices(u8, "4", try root.obtainAtom(&buf));
        try root.expectEnd();
    }
}

pub fn parse(allocator: *std.mem.Allocator, reader: anytype) !Module {
    var ctx = sexpr(reader);
    const root = try ctx.root();

    var module_buf: [0x10]u8 = undefined;
    if (!std.mem.eql(u8, try root.obtainAtom(&module_buf), "module")) {
        return error.ExpectModule;
    }

    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();

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

    while (try root.nextList()) |command| {
        const swhash = util.Swhash(8);

        var cmdname_buf: [0x10]u8 = undefined;
        switch (swhash.match(try command.obtainAtom(&cmdname_buf))) {
            swhash.case("memory") => {
                var tmp_buf: [0x10]u8 = undefined;
                try memories.append(.{
                    .limits = .{
                        .initial = try std.fmt.parseInt(u32, try command.obtainAtom(&tmp_buf), 10),
                        .maximum = if (try command.nextAtom(&tmp_buf)) |value|
                            try std.fmt.parseInt(u32, value, 10)
                        else
                            null,
                    },
                });
                // TODO: this is broken
                // try command.expectEnd();
            },
            swhash.case("func") => {
                var params = std.ArrayList(Module.Type.Value).init(&arena.allocator);
                var locals = std.ArrayList(Module.Type.Value).init(&arena.allocator);
                var result: ?Module.Type.Value = null;

                while (command.obtainList()) |pair| {
                    var loc_buf: [0x10]u8 = undefined;
                    const loc = try pair.obtainAtom(&loc_buf);

                    var typ_buf: [0x10]u8 = undefined;
                    const typ: Module.Type.Value = switch (swhash.match(try pair.obtainAtom(&typ_buf))) {
                        swhash.case("i32") => .I32,
                        swhash.case("i64") => .I64,
                        swhash.case("f32") => .F32,
                        swhash.case("f64") => .F64,
                        else => return error.ExpectedType,
                    };

                    switch (swhash.match(loc)) {
                        swhash.case("param") => try params.append(typ),
                        swhash.case("local") => try locals.append(typ),
                        swhash.case("result") => result = typ,
                        else => return error.ExpectedLoc,
                    }

                    try pair.expectEnd();
                } else |err| switch (err) {
                    error.ExpectedListGotNull, error.ExpectedListGotAtom => {},
                    else => return err,
                }

                var code = std.ArrayList(Module.Instr).init(&arena.allocator);
                var val_buf: [0x100]u8 = undefined;
                while (try command.nextAtom(&val_buf)) |val| {
                    const op = Op.byName(val) orelse {
                        return error.OpNotFound;
                    };

                    try code.append(.{
                        .op = op,
                        .arg = blk: {
                            if (op.arg_kind == .Void) break :blk .{ .I64 = 0 };

                            var arg_buf: [0x10]u8 = undefined;
                            const arg = try command.obtainAtom(&arg_buf);
                            break :blk @as(Op.Fixval, switch (op.arg_kind) {
                                .Void => unreachable,
                                .Type => {
                                    break :blk Op.Fixval.init(
                                        @as(Op.Arg.Type, switch (swhash.match(arg)) {
                                            swhash.case("void") => .Void,
                                            swhash.case("i32") => .I32,
                                            swhash.case("i64") => .I64,
                                            swhash.case("f32") => .F32,
                                            swhash.case("f64") => .F64,
                                            else => return error.ExpectedType,
                                        }),
                                    );
                                },
                                .I32 => .{ .I32 = try std.fmt.parseInt(i32, arg, 10) },
                                .U32 => .{ .U32 = try std.fmt.parseInt(u32, arg, 10) },
                                .I64 => .{ .I64 = try std.fmt.parseInt(i64, arg, 10) },
                                .U64 => .{ .U64 = try std.fmt.parseInt(u64, arg, 10) },
                                .F32 => .{ .F32 = try std.fmt.parseFloat(f32, arg) },
                                .F64 => .{ .F64 = try std.fmt.parseFloat(f64, arg) },
                                .U32z, .Mem, .Array => @panic(arg),
                            });
                        },
                    });
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
            swhash.case("export") => {
                var export_name_buf: [0x100]u8 = undefined;
                const export_name = try command.obtainAtom(&export_name_buf);
                if (export_name[0] != '"') {
                    return error.ExpectString;
                }
                std.debug.assert(export_name[export_name.len - 1] == '"');

                const pair = try command.obtainList();

                var kind_buf: [0x10]u8 = undefined;
                const kind = try pair.obtainAtom(&kind_buf);

                var index_buf: [0x10]u8 = undefined;
                const index = try pair.obtainAtom(&index_buf);

                try exports.append(.{
                    .field = try arena.allocator.dupe(u8, export_name[1 .. export_name.len - 1]),
                    .kind = switch (swhash.match(kind)) {
                        swhash.case("func") => .Function,
                        swhash.case("table") => .Table,
                        swhash.case("memory") => .Memory,
                        swhash.case("global") => .Global,
                        else => return error.ExpectExternalKind,
                    },
                    .index = try std.fmt.parseInt(u32, index, 10),
                });

                try pair.expectEnd();
            },
            else => return error.Fail,
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
        var fbs = std.io.fixedBufferStream("(module)");
        var module = try parse(std.testing.allocator, fbs.reader());
        defer module.deinit();

        std.testing.expectEqual(@as(usize, 0), module.memory.len);
        std.testing.expectEqual(@as(usize, 0), module.function.len);
        std.testing.expectEqual(@as(usize, 0), module.@"export".len);
    }
    {
        var fbs = std.io.fixedBufferStream("(module (memory 42))");
        var module = try parse(std.testing.allocator, fbs.reader());
        defer module.deinit();

        std.testing.expectEqual(@as(usize, 1), module.memory.len);
        std.testing.expectEqual(@as(u32, 42), module.memory[0].limits.initial);
    }
    {
        var fbs = std.io.fixedBufferStream(
            \\(module
            \\  (func (param i32) (param f32) (result i64) (local f64)
            \\    local.get 0
            \\    local.get 1
            \\    local.get 2))
        );
        var module = try parse(std.testing.allocator, fbs.reader());
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
    {
        var fbs = std.io.fixedBufferStream(
            \\(module
            \\  (func (param i32) local.get 0)
            \\  (export "foo" (func 0)))
        );
        var module = try parse(std.testing.allocator, fbs.reader());
        defer module.deinit();

        std.testing.expectEqual(@as(usize, 1), module.function.len);

        std.testing.expectEqual(@as(usize, 1), module.@"export".len);
        std.testing.expectEqualSlices(u8, "foo", module.@"export"[0].field);
        std.testing.expectEqual(Module.ExternalKind.Function, module.@"export"[0].kind);
        std.testing.expectEqual(@as(u32, 0), module.@"export"[0].index);
    }
}
