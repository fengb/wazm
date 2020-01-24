const std = @import("std");
const builtin = @import("builtin");

pub const Type = enum {
    I32,
    I64,
    F32,
    F64,

    fn fromRaw(comptime T: type) ?Type {
        return switch (T) {
            i32 => Type.I32,
            i64 => Type.I64,
            f32 => Type.F32,
            f64 => Type.F64,
            void => null,
            else => @compileError("Unsupported type:" ++ @typeName(T)),
        };
    }
};

const Meta = struct {
    code: u8,
    name: []const u8,
    push: ?Type,
    pop: [2]?Type,

    pub fn format(
        self: Meta,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        context: var,
        comptime Errors: type,
        output: fn (@TypeOf(context), []const u8) Errors!void,
    ) Errors!void {
        return std.fmt.format(
            context,
            Errors,
            output,
            "Op( 0x{x} {} [{},{}] -> [{}] )",
            .{ self.code, self.name, self.pop[0], self.pop[1], self.push },
        );
    }
};

pub const sparse = blk: {
    const decls = publicFunctions(Impl);
    var result: [decls.len]Meta = undefined;
    for (decls) |decl, i| {
        std.debug.assert(decl.name[0] == '0');
        std.debug.assert(decl.name[1] == 'x');
        std.debug.assert(decl.name[4] == ' ');

        const args = @typeInfo(decl.data.Fn.fn_type).Fn.args;
        const arg_ctx = args[0];
        const arg_arg = args[1];
        const arg_pop = args[2];

        result[i] = .{
            .code = std.fmt.parseInt(u8, decl.name[2..4], 16) catch unreachable,
            .name = decl.name[5..],
            .push = Type.fromRaw(decl.data.Fn.return_type),
            .pop = switch (@typeInfo(arg_pop.arg_type.?)) {
                .Void, .Int, .Float => .{ Type.fromRaw(arg_pop.arg_type.?), null },
                else => @compileError("Unsupported pop type: " ++ @typeName(arg_pop.arg_type.?)),
            },
        };
    }

    break :blk result;
};

pub const all = blk: {
    const uninit = Meta{ .code = 0xAA, .name = "ILLEGAL", .pop = .{ null, null }, .push = null };
    var result = [_]Meta{uninit} ** 256;
    for (result) |*meta, i| {
        meta.code = i;
    }

    for (sparse) |meta| {
        result[meta.code] = meta;
    }
    break :blk result;
};

pub fn byName(needle: []const u8) ?Meta {
    for (all) |meta| {
        if (std.mem.eql(u8, meta.name, needle)) {
            return meta;
        }
    }
    return null;
}

fn publicFunctions(comptime T: type) []builtin.TypeInfo.Declaration {
    const decls = std.meta.declarations(T);
    var result: [decls.len]builtin.TypeInfo.Declaration = undefined;
    var cursor: usize = 0;
    for (decls) |decl| {
        if (decl.is_pub and decl.data == .Fn) {
            result[cursor] = decl;
            cursor += 1;
        }
    }

    return result[0..cursor];
}

test "ops" {
    const nop = byName("nop").?;
    std.testing.expectEqual(nop.push, null);
    std.testing.expectEqual(nop.pop[0], null);
    std.testing.expectEqual(nop.pop[1], null);

    const i32_load = byName("i32.load").?;
    std.testing.expectEqual(i32_load.push, Type.I32);
    std.testing.expectEqual(i32_load.pop[0], Type.I32);
    std.testing.expectEqual(i32_load.pop[1], null);
}

const Impl = struct {
    const Context = struct {};
    pub fn @"0x00 unreachable"(ctx: Context, arg: void, pop: void) void {}

    pub fn @"0x01 nop"(ctx: Context, arg: void, pop: void) void {}

    pub fn @"0x02 block"(ctx: Context, arg: ?Type, pop: void) void {}

    pub fn @"0x03 loop"(ctx: Context, arg: ?Type, pop: void) void {}

    pub fn @"0x04 if"(ctx: Context, arg: ?Type, pop: i32) void {}

    pub fn @"0x05 else"(ctx: Context, arg: void, pop: void) void {}

    pub fn @"0x0B end"(ctx: Context, arg: void, pop: void) void {}

    pub fn @"0x0C br"(ctx: Context, arg: void, pop: void) void {}

    pub fn @"0x0D br_if"(ctx: Context, arg: u32, pop: void) void {}

    pub fn @"0x0E br_table"(ctx: Context, arg: [2]u32, pop: void) void {}

    pub fn @"0x0F return"(ctx: Context, arg: void, pop: void) void {}

    pub fn @"0x28 i32.load"(ctx: Context, arg: [2]u32, pop: i32) i32 {
        return 0;
    }
};
