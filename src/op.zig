const std = @import("std");
const builtin = @import("builtin");
const core = @import("core.zig");

pub const StackChange = enum {
    Void,
    I32,
    I64,
    F32,
    F64,

    fn from(comptime T: type) StackChange {
        return switch (T) {
            void => .Void,
            i32, u32 => .I32,
            i64, u64 => .I64,
            f32 => .F32,
            f64 => .F64,
            else => switch (@typeInfo(T)) {
                .ErrorUnion => |eu_info| from(eu_info.payload),
                else => @compileError("Unsupported type:" ++ @typeName(T)),
            },
        };
    }
};

pub const Arg = packed struct {
    raw: [8]u8 = [_]u8{0} ** 8,

    pub fn init(data: var) Arg {
        const T = @TypeOf(data);
        var result = Arg{};
        const bytes = @ptrCast(*const [@sizeOf(T)]u8, &data);
        std.mem.copy(u8, &result.raw, bytes);
        return result;
    }

    pub const None = packed union {
        const bytes = 0;
        _pad: u64,
    };
    // TODO: this only works in LittleEndian
    pub const Type = enum(u64) {
        const bytes = 1;
        Void = 0x40,
        I32 = 0x7F,
        I64 = 0x7E,
        F32 = 0x7D,
        F64 = 0x7C,
    };
    pub const I32 = packed union {
        const bytes = 4;
        data: u32,
        _pad: u64,
    };
    pub const I32z = packed union {
        const bytes = 5;
        data: u32,
        _pad: u64,
    };
    pub const Mem = packed struct {
        const bytes = 8;
        offset: u32,
        align_: u32,
    };
};
pub const ArgKind = enum {
    None,
    Type,
    I32,
    I32z,
    Mem,

    fn from(comptime T: type) ArgKind {
        return switch (T) {
            Arg.None => .None,
            Arg.Type => .Type,
            Arg.I32 => .I32,
            Arg.I32z => .I32z,
            Arg.Mem => .Mem,
            else => @compileError("Unsupported type: " ++ @typeName(T)),
        };
    }
};

test "Arg smoke" {
    const size = @sizeOf(Arg);
    inline for (std.meta.declarations(Arg)) |decl| {
        if (decl.data == .Type) {
            _ = decl.data.Type.bytes;
            std.testing.expectEqual(size, @sizeOf(decl.data.Type));
        }
    }
}

const Meta = struct {
    code: u8,
    name: []const u8,
    can_error: bool,
    arg: struct {
        kind: ArgKind,
        bytes: u8,
    },
    push: StackChange,
    pop: [2]StackChange,

    fn lessThan(lhs: Meta, rhs: Meta) bool {
        return std.mem.lessThan(u8, lhs.name, rhs.name);
    }

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
            "Op( 0x{x} \"{}\" {{{} {}b}} [{},{}]->[{}] )",
            .{ self.code, self.name, @tagName(self.arg.kind), self.arg.bytes, @tagName(self.pop[0]), @tagName(self.pop[1]), @tagName(self.push) },
        );
    }
};

pub const sparse = blk: {
    @setEvalBranchQuota(10000);
    const decls = publicFunctions(Impl);
    var result: [decls.len]Meta = undefined;
    for (decls) |decl, i| {
        std.debug.assert(decl.name[0] == '0');
        std.debug.assert(decl.name[1] == 'x');
        std.debug.assert(decl.name[4] == ' ');

        const args = @typeInfo(decl.data.Fn.fn_type).Fn.args;
        const ctx_type = args[0].arg_type.?;
        const arg_type = args[1].arg_type.?;
        const pop_type = args[2].arg_type.?;
        const return_type = decl.data.Fn.return_type;

        result[i] = .{
            .code = std.fmt.parseInt(u8, decl.name[2..4], 16) catch unreachable,
            .name = decl.name[5..],
            .can_error = switch (@typeInfo(return_type)) {
                .ErrorUnion => |eu_info| blk: {
                    std.debug.assert(eu_info.error_set == core.WasmTrap);
                    break :blk true;
                },
                else => false,
            },
            .arg = .{ .bytes = arg_type.bytes, .kind = ArgKind.from(arg_type) },
            .push = StackChange.from(return_type),
            .pop = switch (@typeInfo(pop_type)) {
                .Void, .Int, .Float => .{ StackChange.from(pop_type), .Void },
                .Struct => |s_info| blk: {
                    std.debug.assert(s_info.fields.len == 2);
                    std.debug.assert(std.mem.eql(u8, s_info.fields[0].name, "_0"));
                    std.debug.assert(std.mem.eql(u8, s_info.fields[1].name, "_1"));
                    break :blk .{
                        StackChange.from(s_info.fields[0].field_type),
                        StackChange.from(s_info.fields[1].field_type),
                    };
                },
                else => @compileError("Unsupported pop type: " ++ @typeName(pop_type)),
            },
        };
    }

    std.sort.sort(Meta, &result, Meta.lessThan);

    break :blk result;
};

pub const all = blk: {
    var result = [_]?Meta{null} ** 256;

    for (sparse) |meta| {
        result[meta.code] = meta;
    }
    break :blk result;
};

pub fn byName(needle: []const u8) ?Meta {
    var curr: usize = 0;
    var size = sparse.len;
    while (size > 0) {
        const offset = size % 2;

        size /= 2;
        const meta = sparse[curr + size];
        switch (std.mem.order(u8, needle, meta.name)) {
            .lt => {},
            .eq => return meta,
            .gt => curr += size + offset,
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
    std.testing.expectEqual(nop.arg.bytes, 0);
    std.testing.expectEqual(nop.push, .Void);
    std.testing.expectEqual(nop.pop[0], .Void);
    std.testing.expectEqual(nop.pop[1], .Void);

    const i32_load = byName("i32.load").?;
    std.testing.expectEqual(i32_load.arg.bytes, 8);
    std.testing.expectEqual(i32_load.push, .I32);
    std.testing.expectEqual(i32_load.pop[0], .I32);
    std.testing.expectEqual(i32_load.pop[1], .Void);
}

const Impl = struct {
    const WasmTrap = core.WasmTrap;

    // TODO: replace once Zig can define tuple types
    fn Pair(comptime T0: type, comptime T1: type) type {
        return struct {
            _0: T0,
            _1: T1,
        };
    }

    pub fn @"0x00 unreachable"(self: *core.Instance, arg: Arg.None, pop: void) WasmTrap!void {
        return error.WasmTrap;
    }

    pub fn @"0x01 nop"(self: *core.Instance, arg: Arg.None, pop: void) void {}

    pub fn @"0x02 block"(self: *core.Instance, arg: Arg.Type, pop: void) void {
        @panic("TODO");
    }

    pub fn @"0x03 loop"(self: *core.Instance, arg: Arg.Type, pop: void) void {
        @panic("TODO");
    }

    pub fn @"0x04 if"(self: *core.Instance, arg: Arg.Type, pop: i32) void {
        @panic("TODO");
    }

    pub fn @"0x05 else"(self: *core.Instance, arg: Arg.None, pop: void) void {
        @panic("TODO");
    }

    pub fn @"0x0B end"(self: *core.Instance, arg: Arg.None, pop: void) void {
        @panic("TODO");
    }

    pub fn @"0x0C br"(self: *core.Instance, arg: Arg.None, pop: void) void {
        @panic("TODO");
    }

    pub fn @"0x0D br_if"(self: *core.Instance, arg: Arg.I32, pop: void) void {
        @panic("TODO");
    }

    pub fn @"0x0E br_table"(self: *core.Instance, arg: Arg.Mem, pop: void) void {
        @panic("TODO");
    }

    pub fn @"0x0F return"(self: *core.Instance, arg: Arg.None, pop: void) void {
        @panic("TODO");
    }

    pub fn @"0x20 local.get"(self: *core.Instance, arg: Arg.I32, pop: i32) i32 {
        @panic("TODO");
    }

    pub fn @"0x28 i32.load"(self: *core.Instance, mem: Arg.Mem, pop: u32) WasmTrap!i32 {
        return std.mem.readIntLittle(i32, try self.memGet(pop, mem.offset, 4));
    }
    pub fn @"0x29 i64.load"(self: *core.Instance, mem: Arg.Mem, pop: u32) WasmTrap!i64 {
        return std.mem.readIntLittle(i64, try self.memGet(pop, mem.offset, 8));
    }
    pub fn @"0x2A f32.load"(self: *core.Instance, mem: Arg.Mem, pop: u32) WasmTrap!f32 {
        return std.mem.readIntLittle(f32, try self.memGet(pop, mem.offset, 4));
    }
    pub fn @"0x2B f64.load"(self: *core.Instance, mem: Arg.Mem, pop: u32) WasmTrap!f64 {
        return std.mem.readIntLittle(f64, try self.memGet(pop, mem.offset, 8));
    }
    pub fn @"0x2C i32.load8_s"(self: *core.Instance, mem: Arg.Mem, pop: u32) WasmTrap!i32 {
        return std.mem.readIntLittle(i8, try self.memGet(pop, mem.offset, 1));
    }
    pub fn @"0x2D i32.load8_u"(self: *core.Instance, mem: Arg.Mem, pop: u32) WasmTrap!u32 {
        return std.mem.readIntLittle(u8, try self.memGet(pop, mem.offset, 1));
    }
    pub fn @"0x2E i32.load16_s"(self: *core.Instance, mem: Arg.Mem, pop: u32) WasmTrap!i32 {
        return std.mem.readIntLittle(i16, try self.memGet(pop, mem.offset, 2));
    }
    pub fn @"0x2F i32.load16_u"(self: *core.Instance, mem: Arg.Mem, pop: u32) WasmTrap!u32 {
        return std.mem.readIntLittle(u16, try self.memGet(pop, mem.offset, 2));
    }

    pub fn @"0x30 i64.load8_s"(self: *core.Instance, mem: Arg.Mem, pop: u32) WasmTrap!i64 {
        return std.mem.readIntLittle(i8, try self.memGet(pop, mem.offset, 1));
    }
    pub fn @"0x31 i64.load8_u"(self: *core.Instance, mem: Arg.Mem, pop: u32) WasmTrap!i64 {
        return std.mem.readIntLittle(u8, try self.memGet(pop, mem.offset, 1));
    }
    pub fn @"0x32 i64.load16_s"(self: *core.Instance, mem: Arg.Mem, pop: u32) WasmTrap!i64 {
        return std.mem.readIntLittle(i16, try self.memGet(pop, mem.offset, 2));
    }
    pub fn @"0x33 i64.load16_u"(self: *core.Instance, mem: Arg.Mem, pop: u32) WasmTrap!i64 {
        return std.mem.readIntLittle(u16, try self.memGet(pop, mem.offset, 2));
    }
    pub fn @"0x34 i64.load32_s"(self: *core.Instance, mem: Arg.Mem, pop: u32) WasmTrap!i64 {
        return std.mem.readIntLittle(i32, try self.memGet(pop, mem.offset, 4));
    }
    pub fn @"0x35 i64.load32_u"(self: *core.Instance, mem: Arg.Mem, pop: u32) WasmTrap!i64 {
        return std.mem.readIntLittle(u32, try self.memGet(pop, mem.offset, 4));
    }
    pub fn @"0x36 i32.store"(self: *core.Instance, mem: Arg.Mem, pop: Pair(u32, i32)) WasmTrap!void {
        const bytes = try self.memGet(pop._0, mem.offset, 4);
        std.mem.writeIntLittle(i32, bytes, pop._1);
    }
    pub fn @"0x37 i64.store"(self: *core.Instance, mem: Arg.Mem, pop: Pair(u32, i64)) WasmTrap!void {
        const bytes = try self.memGet(pop._0, mem.offset, 8);
        std.mem.writeIntLittle(i64, bytes, pop._1);
    }
    pub fn @"0x38 f32.store"(self: *core.Instance, mem: Arg.Mem, pop: Pair(u32, f32)) WasmTrap!void {
        const bytes = try self.memGet(pop._0, mem.offset, 4);
        std.mem.writeIntLittle(f32, bytes, pop._1);
    }
    pub fn @"0x39 f64.store"(self: *core.Instance, mem: Arg.Mem, pop: Pair(u32, f64)) WasmTrap!void {
        const bytes = try self.memGet(pop._0, mem.offset, 8);
        std.mem.writeIntLittle(f64, bytes, pop._1);
    }
    pub fn @"0x3A i32.store8"(self: *core.Instance, mem: Arg.Mem, pop: Pair(u32, i32)) WasmTrap!void {
        const bytes = try self.memGet(pop._0, mem.offset, 1);
        std.mem.writeIntLittle(i8, bytes, @truncate(i8, pop._1));
    }
    pub fn @"0x3B i32.store16"(self: *core.Instance, mem: Arg.Mem, pop: Pair(u32, i32)) WasmTrap!void {
        const bytes = try self.memGet(pop._0, mem.offset, 2);
        std.mem.writeIntLittle(i16, bytes, @truncate(i16, pop._1));
    }
    pub fn @"0x3C i64.store8"(self: *core.Instance, mem: Arg.Mem, pop: Pair(u32, i64)) WasmTrap!void {
        const bytes = try self.memGet(pop._0, mem.offset, 1);
        std.mem.writeIntLittle(i8, bytes, @truncate(i8, pop._1));
    }
    pub fn @"0x3B i64.store16"(self: *core.Instance, mem: Arg.Mem, pop: Pair(u32, i64)) WasmTrap!void {
        const bytes = try self.memGet(pop._0, mem.offset, 2);
        std.mem.writeIntLittle(i16, bytes, @truncate(i16, pop._1));
    }
    pub fn @"0x3A i64.store32"(self: *core.Instance, mem: Arg.Mem, pop: Pair(u32, i64)) WasmTrap!void {
        const bytes = try self.memGet(pop._0, mem.offset, 4);
        std.mem.writeIntLittle(i32, bytes, @truncate(i32, pop._1));
    }
    pub fn @"0x3F memory.size"(self: *core.Instance, arg: Arg.None, pop: void) u32 {
        return @intCast(u32, self.memory.len % 65536);
    }

    pub fn @"0x40 memory.grow"(self: *core.Instance, arg: Arg.None, pop: u32) i32 {
        const page_overflow = 65536; // 65536 * 65536 = 4294967296 -> beyond addressable
        const current = self.memory.len % 65536;
        if (current + pop > page_overflow) {
            return -1;
        }
        self.memory = self.allocator.realloc(self.memory, current + pop) catch |err| switch (err) {
            error.OutOfMemory => return -1,
        };
        return @intCast(i32, current);
    }
};
