const std = @import("std");
const builtin = @import("builtin");
const core = @import("core.zig");
const Op = @This();

code: u8,
name: []const u8,
can_error: bool,
arg_kind: @TagType(Arg),
push: StackChange,
pop: [3]StackChange,

pub const sparse = blk: {
    @setEvalBranchQuota(100000);
    const decls = publicFunctions(Impl);
    var result: [decls.len]Op = undefined;
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
            .code = std.fmt.parseInt(u8, decl.name[2..4], 16) catch @compileError("Not a known hex: " ++ decl.name[0..4]),
            .name = decl.name[5..],
            .can_error = switch (@typeInfo(return_type)) {
                .ErrorUnion => |eu_info| blk: {
                    for (std.meta.fields(eu_info.error_set)) |err| {
                        if (!errContains(core.WasmTrap, err.value)) {
                            @compileError("Unhandleable error: " ++ err.name);
                        }
                    }
                    break :blk true;
                },
                else => false,
            },
            .arg_kind = switch (arg_type) {
                void => .Void,
                i32, u32 => .I32,
                i64, u64 => .I64,
                f32 => .F32,
                f64 => .F64,
                Arg.Type => .Type,
                Arg.I32z => .I32z,
                Arg.Mem => .Mem,
                else => @compileError("Unsupported arg type: " ++ @typeName(arg_type)),
            },
            .push = StackChange.from(return_type),
            .pop = switch (@typeInfo(pop_type)) {
                .Void, .Int, .Float, .Union => .{ StackChange.from(pop_type), .Void, .Void },
                .Struct => |s_info| blk: {
                    std.debug.assert(s_info.fields.len == 3);
                    std.debug.assert(std.mem.eql(u8, s_info.fields[0].name, "_0"));
                    std.debug.assert(std.mem.eql(u8, s_info.fields[1].name, "_1"));
                    std.debug.assert(std.mem.eql(u8, s_info.fields[2].name, "_2"));
                    break :blk .{
                        StackChange.from(s_info.fields[0].field_type),
                        StackChange.from(s_info.fields[1].field_type),
                        StackChange.from(s_info.fields[2].field_type),
                    };
                },
                else => @compileError("Unsupported pop type: " ++ @typeName(pop_type)),
            },
        };
    }

    std.sort.sort(Op, &result, Op.lessThan);

    break :blk result;
};

pub const all = blk: {
    var result = [_]?Op{null} ** 256;

    for (sparse) |meta| {
        if (result[meta.code] != null) {
            var buf: [100]u8 = undefined;
            @compileError(try std.fmt.bufPrint(&buf, "Collision: '0x{X} {}'", .{ meta.code, meta.name }));
        }
        result[meta.code] = meta;
    }
    break :blk result;
};

pub fn byName(needle: []const u8) ?Op {
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

pub const StackChange = enum {
    Void,
    I32,
    I64,
    F32,
    F64,
    Poly,

    fn from(comptime T: type) StackChange {
        return switch (T) {
            void => .Void,
            i32, u32 => .I32,
            i64, u64 => .I64,
            f32 => .F32,
            f64 => .F64,
            core.Value => .Poly,
            else => switch (@typeInfo(T)) {
                .ErrorUnion => |eu_info| from(eu_info.payload),
                else => @compileError("Unsupported type: " ++ @typeName(T)),
            },
        };
    }
};

pub const Arg = union(enum) {
    Void: void,
    I32: i32,
    I64: i64,
    F32: f32,
    F64: f64,
    Type: Type,
    I32z: I32z,
    Mem: Mem,

    pub const Type = enum(u8) {
        Void = 0x40,
        I32 = 0x7F,
        I64 = 0x7E,
        F32 = 0x7D,
        F64 = 0x7C,
    };

    pub const I32z = packed struct {
        data: i32,
        reserved: u8,
    };

    pub const Mem = packed struct {
        offset: u32,
        align_: u32,
    };
};

fn errContains(comptime err_set: type, val: comptime_int) bool {
    std.debug.assert(@typeInfo(err_set) == .ErrorSet);
    const lookup = comptime blk: {
        const error_count = 1 << @bitSizeOf(anyerror);
        var result = [_]bool{false} ** error_count;
        for (std.meta.fields(err_set)) |err| {
            result[err.value] = true;
        }
        break :blk result;
    };
    return lookup[val];
}

fn sortKey(self: Op) u128 {
    var bytes = [_]u8{0} ** 16;
    if (bytes[4] == '.') {
        std.mem.copy(u8, bytes[0..3], self.name[0..3]);
        std.mem.copy(u8, bytes[3..], self.name[5..std.math.min(self.name.len, 18)]);
    } else {
        std.mem.copy(u8, &bytes, self.name[0..std.math.min(self.name.len, 16)]);
    }
    return std.mem.readIntBig(u128, &bytes);
}

fn lessThan(lhs: Op, rhs: Op) bool {
    return lhs.sortKey() < rhs.sortKey();
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
    std.testing.expectEqual(nop.arg_kind, .Void);
    std.testing.expectEqual(nop.push, .Void);
    std.testing.expectEqual(nop.pop[0], .Void);
    std.testing.expectEqual(nop.pop[1], .Void);
    std.testing.expectEqual(nop.pop[2], .Void);

    const i32_load = byName("i32.load").?;
    std.testing.expectEqual(i32_load.arg_kind, .Mem);
    std.testing.expectEqual(i32_load.push, .I32);
    std.testing.expectEqual(i32_load.pop[0], .I32);
    std.testing.expectEqual(i32_load.pop[1], .Void);
    std.testing.expectEqual(i32_load.pop[2], .Void);

    const select = byName("select").?;
    std.testing.expectEqual(select.arg_kind, .Void);
    std.testing.expectEqual(select.push, .Poly);
    std.testing.expectEqual(select.pop[0], .Poly);
    std.testing.expectEqual(select.pop[1], .Poly);
    std.testing.expectEqual(select.pop[2], .I32);
}

const Impl = struct {
    // TODO: replace once Zig can define tuple types
    fn Pair(comptime T0: type, comptime T1: type) type {
        return struct {
            _0: T0,
            _1: T1,
            _2: void,
        };
    }

    // TODO: replace once Zig can define tuple types
    fn Triple(comptime T0: type, comptime T1: type, comptime T2: type) type {
        return struct {
            _0: T0,
            _1: T1,
            _2: T2,
        };
    }

    pub fn @"0x00 unreachable"(self: *core.Instance, arg: void, pop: void) !void {
        return error.Unreachable;
    }

    pub fn @"0x01 nop"(self: *core.Instance, arg: void, pop: void) void {}

    pub fn @"0x02 block"(self: *core.Instance, arg: Arg.Type, pop: void) void {
        @panic("TODO");
    }

    pub fn @"0x03 loop"(self: *core.Instance, arg: Arg.Type, pop: void) void {
        @panic("TODO");
    }

    pub fn @"0x04 if"(self: *core.Instance, arg: Arg.Type, pop: i32) void {
        @panic("TODO");
    }

    pub fn @"0x05 else"(self: *core.Instance, arg: void, pop: void) void {
        @panic("TODO");
    }

    pub fn @"0x0B end"(self: *core.Instance, arg: void, pop: void) void {
        @panic("TODO");
    }

    pub fn @"0x0C br"(self: *core.Instance, arg: void, pop: void) void {
        @panic("TODO");
    }

    pub fn @"0x0D br_if"(self: *core.Instance, arg: i32, pop: void) void {
        @panic("TODO");
    }

    pub fn @"0x0E br_table"(self: *core.Instance, arg: Arg.Mem, pop: void) void {
        @panic("TODO");
    }

    pub fn @"0x0F return"(self: *core.Instance, arg: void, pop: void) void {
        @panic("TODO");
    }

    pub fn @"0x1A drop"(self: *core.Instance, arg: void, pop: core.Value) void {
        // Do nothing with the popped value
    }
    pub fn @"0x1B select"(self: *core.Instance, arg: void, pop: Triple(core.Value, core.Value, i32)) core.Value {
        return if (pop._2 == 0) pop._0 else pop._1;
    }

    pub fn @"0x20 local.get"(self: *core.Instance, arg: u32, pop: void) core.Value {
        return self.locals.get(arg);
    }
    pub fn @"0x21 local.set"(self: *core.Instance, arg: u32, pop: core.Value) void {
        self.locals.set(arg, pop);
    }
    pub fn @"0x22 local.tee"(self: *core.Instance, arg: u32, pop: core.Value) core.Value {
        self.locals.set(arg, pop);
        return pop;
    }
    pub fn @"0x23 global.get"(self: *core.Instance, arg: u32, pop: void) core.Value {
        return self.globals.get(arg);
    }
    pub fn @"0x24 global.set"(self: *core.Instance, arg: u32, pop: core.Value) void {
        self.globals.set(arg, pop);
    }
    pub fn @"0x28 i32.load"(self: *core.Instance, mem: Arg.Mem, pop: u32) !i32 {
        return std.mem.readIntLittle(i32, try self.memGet(pop, mem.offset, 4));
    }
    pub fn @"0x29 i64.load"(self: *core.Instance, mem: Arg.Mem, pop: u32) !i64 {
        return std.mem.readIntLittle(i64, try self.memGet(pop, mem.offset, 8));
    }
    pub fn @"0x2A f32.load"(self: *core.Instance, mem: Arg.Mem, pop: u32) !f32 {
        return std.mem.readIntLittle(f32, try self.memGet(pop, mem.offset, 4));
    }
    pub fn @"0x2B f64.load"(self: *core.Instance, mem: Arg.Mem, pop: u32) !f64 {
        return std.mem.readIntLittle(f64, try self.memGet(pop, mem.offset, 8));
    }
    pub fn @"0x2C i32.load8_s"(self: *core.Instance, mem: Arg.Mem, pop: u32) !i32 {
        return std.mem.readIntLittle(i8, try self.memGet(pop, mem.offset, 1));
    }
    pub fn @"0x2D i32.load8_u"(self: *core.Instance, mem: Arg.Mem, pop: u32) !u32 {
        return std.mem.readIntLittle(u8, try self.memGet(pop, mem.offset, 1));
    }
    pub fn @"0x2E i32.load16_s"(self: *core.Instance, mem: Arg.Mem, pop: u32) !i32 {
        return std.mem.readIntLittle(i16, try self.memGet(pop, mem.offset, 2));
    }
    pub fn @"0x2F i32.load16_u"(self: *core.Instance, mem: Arg.Mem, pop: u32) !u32 {
        return std.mem.readIntLittle(u16, try self.memGet(pop, mem.offset, 2));
    }

    pub fn @"0x30 i64.load8_s"(self: *core.Instance, mem: Arg.Mem, pop: u32) !i64 {
        return std.mem.readIntLittle(i8, try self.memGet(pop, mem.offset, 1));
    }
    pub fn @"0x31 i64.load8_u"(self: *core.Instance, mem: Arg.Mem, pop: u32) !i64 {
        return std.mem.readIntLittle(u8, try self.memGet(pop, mem.offset, 1));
    }
    pub fn @"0x32 i64.load16_s"(self: *core.Instance, mem: Arg.Mem, pop: u32) !i64 {
        return std.mem.readIntLittle(i16, try self.memGet(pop, mem.offset, 2));
    }
    pub fn @"0x33 i64.load16_u"(self: *core.Instance, mem: Arg.Mem, pop: u32) !i64 {
        return std.mem.readIntLittle(u16, try self.memGet(pop, mem.offset, 2));
    }
    pub fn @"0x34 i64.load32_s"(self: *core.Instance, mem: Arg.Mem, pop: u32) !i64 {
        return std.mem.readIntLittle(i32, try self.memGet(pop, mem.offset, 4));
    }
    pub fn @"0x35 i64.load32_u"(self: *core.Instance, mem: Arg.Mem, pop: u32) !i64 {
        return std.mem.readIntLittle(u32, try self.memGet(pop, mem.offset, 4));
    }
    pub fn @"0x36 i32.store"(self: *core.Instance, mem: Arg.Mem, pop: Pair(u32, i32)) !void {
        const bytes = try self.memGet(pop._0, mem.offset, 4);
        std.mem.writeIntLittle(i32, bytes, pop._1);
    }
    pub fn @"0x37 i64.store"(self: *core.Instance, mem: Arg.Mem, pop: Pair(u32, i64)) !void {
        const bytes = try self.memGet(pop._0, mem.offset, 8);
        std.mem.writeIntLittle(i64, bytes, pop._1);
    }
    pub fn @"0x38 f32.store"(self: *core.Instance, mem: Arg.Mem, pop: Pair(u32, f32)) !void {
        const bytes = try self.memGet(pop._0, mem.offset, 4);
        std.mem.writeIntLittle(f32, bytes, pop._1);
    }
    pub fn @"0x39 f64.store"(self: *core.Instance, mem: Arg.Mem, pop: Pair(u32, f64)) !void {
        const bytes = try self.memGet(pop._0, mem.offset, 8);
        std.mem.writeIntLittle(f64, bytes, pop._1);
    }
    pub fn @"0x3A i32.store8"(self: *core.Instance, mem: Arg.Mem, pop: Pair(u32, i32)) !void {
        const bytes = try self.memGet(pop._0, mem.offset, 1);
        std.mem.writeIntLittle(i8, bytes, @truncate(i8, pop._1));
    }
    pub fn @"0x3B i32.store16"(self: *core.Instance, mem: Arg.Mem, pop: Pair(u32, i32)) !void {
        const bytes = try self.memGet(pop._0, mem.offset, 2);
        std.mem.writeIntLittle(i16, bytes, @truncate(i16, pop._1));
    }
    pub fn @"0x3C i64.store8"(self: *core.Instance, mem: Arg.Mem, pop: Pair(u32, i64)) !void {
        const bytes = try self.memGet(pop._0, mem.offset, 1);
        std.mem.writeIntLittle(i8, bytes, @truncate(i8, pop._1));
    }
    pub fn @"0x3D i64.store16"(self: *core.Instance, mem: Arg.Mem, pop: Pair(u32, i64)) !void {
        const bytes = try self.memGet(pop._0, mem.offset, 2);
        std.mem.writeIntLittle(i16, bytes, @truncate(i16, pop._1));
    }
    pub fn @"0x3E i64.store32"(self: *core.Instance, mem: Arg.Mem, pop: Pair(u32, i64)) !void {
        const bytes = try self.memGet(pop._0, mem.offset, 4);
        std.mem.writeIntLittle(i32, bytes, @truncate(i32, pop._1));
    }
    pub fn @"0x3F memory.size"(self: *core.Instance, arg: void, pop: void) u32 {
        return @intCast(u32, self.memory.len % 65536);
    }

    pub fn @"0x40 memory.grow"(self: *core.Instance, arg: void, pop: u32) i32 {
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
    pub fn @"0x41 i32.const"(self: *core.Instance, arg: i32, pop: void) i32 {
        return arg;
    }
    pub fn @"0x42 i64.const"(self: *core.Instance, arg: i64, pop: void) i64 {
        return arg;
    }
    pub fn @"0x43 f32.const"(self: *core.Instance, arg: f32, pop: void) f32 {
        return arg;
    }
    pub fn @"0x44 f64.const"(self: *core.Instance, arg: f64, pop: void) f64 {
        return arg;
    }
    pub fn @"0x45 i32.eqz"(self: *core.Instance, arg: void, pop: i32) i32 {
        return @boolToInt(pop == 0);
    }
    pub fn @"0x46 i32.eq"(self: *core.Instance, arg: void, pop: Pair(i32, i32)) i32 {
        return @boolToInt(pop._0 == pop._1);
    }
    pub fn @"0x47 i32.ne"(self: *core.Instance, arg: void, pop: Pair(i32, i32)) i32 {
        return @boolToInt(pop._0 != pop._1);
    }
    pub fn @"0x48 i32.lt_s"(self: *core.Instance, arg: void, pop: Pair(i32, i32)) i32 {
        return @boolToInt(pop._0 < pop._1);
    }
    pub fn @"0x49 i32.lt_u"(self: *core.Instance, arg: void, pop: Pair(u32, u32)) i32 {
        return @boolToInt(pop._0 < pop._1);
    }
    pub fn @"0x4A i32.gt_s"(self: *core.Instance, arg: void, pop: Pair(i32, i32)) i32 {
        return @boolToInt(pop._0 > pop._1);
    }
    pub fn @"0x4B i32.gt_u"(self: *core.Instance, arg: void, pop: Pair(u32, u32)) i32 {
        return @boolToInt(pop._0 > pop._1);
    }
    pub fn @"0x4C i32.le_s"(self: *core.Instance, arg: void, pop: Pair(i32, i32)) i32 {
        return @boolToInt(pop._0 <= pop._1);
    }
    pub fn @"0x4D i32.le_u"(self: *core.Instance, arg: void, pop: Pair(u32, u32)) i32 {
        return @boolToInt(pop._0 <= pop._1);
    }
    pub fn @"0x4E i32.ge_s"(self: *core.Instance, arg: void, pop: Pair(i32, i32)) i32 {
        return @boolToInt(pop._0 >= pop._1);
    }
    pub fn @"0x4F i32.ge_u"(self: *core.Instance, arg: void, pop: Pair(u32, u32)) i32 {
        return @boolToInt(pop._0 >= pop._1);
    }

    pub fn @"0x50 i64.eqz"(self: *core.Instance, arg: void, pop: i64) i32 {
        return @boolToInt(pop == 0);
    }
    pub fn @"0x51 i64.eq"(self: *core.Instance, arg: void, pop: Pair(i64, i64)) i32 {
        return @boolToInt(pop._0 == pop._1);
    }
    pub fn @"0x52 i64.ne"(self: *core.Instance, arg: void, pop: Pair(i64, i64)) i32 {
        return @boolToInt(pop._0 != pop._1);
    }
    pub fn @"0x53 i64.lt_s"(self: *core.Instance, arg: void, pop: Pair(i64, i64)) i32 {
        return @boolToInt(pop._0 < pop._1);
    }
    pub fn @"0x54 i64.lt_u"(self: *core.Instance, arg: void, pop: Pair(u64, u64)) i32 {
        return @boolToInt(pop._0 < pop._1);
    }
    pub fn @"0x55 i64.gt_s"(self: *core.Instance, arg: void, pop: Pair(i64, i64)) i32 {
        return @boolToInt(pop._0 > pop._1);
    }
    pub fn @"0x56 i64.gt_u"(self: *core.Instance, arg: void, pop: Pair(u64, u64)) i32 {
        return @boolToInt(pop._0 > pop._1);
    }
    pub fn @"0x57 i64.le_s"(self: *core.Instance, arg: void, pop: Pair(i64, i64)) i32 {
        return @boolToInt(pop._0 <= pop._1);
    }
    pub fn @"0x58 i64.le_u"(self: *core.Instance, arg: void, pop: Pair(u64, u64)) i32 {
        return @boolToInt(pop._0 <= pop._1);
    }
    pub fn @"0x59 i64.ge_s"(self: *core.Instance, arg: void, pop: Pair(i64, i64)) i32 {
        return @boolToInt(pop._0 >= pop._1);
    }
    pub fn @"0x5A i64.ge_u"(self: *core.Instance, arg: void, pop: Pair(u64, u64)) i32 {
        return @boolToInt(pop._0 >= pop._1);
    }
    pub fn @"0x5B f32.eq"(self: *core.Instance, arg: void, pop: Pair(f32, f32)) i32 {
        return @boolToInt(pop._0 == pop._1);
    }
    pub fn @"0x5C f32.ne"(self: *core.Instance, arg: void, pop: Pair(f32, f32)) i32 {
        return @boolToInt(pop._0 != pop._1);
    }
    pub fn @"0x5D f32.lt"(self: *core.Instance, arg: void, pop: Pair(f32, f32)) i32 {
        return @boolToInt(pop._0 < pop._1);
    }
    pub fn @"0x5E f32.gt"(self: *core.Instance, arg: void, pop: Pair(f32, f32)) i32 {
        return @boolToInt(pop._0 > pop._1);
    }
    pub fn @"0x5F f32.le"(self: *core.Instance, arg: void, pop: Pair(f32, f32)) i32 {
        return @boolToInt(pop._0 <= pop._1);
    }

    pub fn @"0x60 f32.ge"(self: *core.Instance, arg: void, pop: Pair(f32, f32)) i32 {
        return @boolToInt(pop._0 >= pop._1);
    }
    pub fn @"0x61 f64.eq"(self: *core.Instance, arg: void, pop: Pair(f64, f64)) i32 {
        return @boolToInt(pop._0 == pop._1);
    }
    pub fn @"0x62 f64.ne"(self: *core.Instance, arg: void, pop: Pair(f64, f64)) i32 {
        return @boolToInt(pop._0 != pop._1);
    }
    pub fn @"0x63 f64.lt"(self: *core.Instance, arg: void, pop: Pair(f64, f64)) i32 {
        return @boolToInt(pop._0 < pop._1);
    }
    pub fn @"0x64 f64.gt"(self: *core.Instance, arg: void, pop: Pair(f64, f64)) i32 {
        return @boolToInt(pop._0 > pop._1);
    }
    pub fn @"0x65 f64.le"(self: *core.Instance, arg: void, pop: Pair(f64, f64)) i32 {
        return @boolToInt(pop._0 <= pop._1);
    }
    pub fn @"0x66 f64.ge"(self: *core.Instance, arg: void, pop: Pair(f64, f64)) i32 {
        return @boolToInt(pop._0 >= pop._1);
    }
    pub fn @"0x67 i32.clz"(self: *core.Instance, arg: void, pop: i32) i32 {
        return @clz(i32, pop);
    }
    pub fn @"0x68 i32.ctz"(self: *core.Instance, arg: void, pop: i32) i32 {
        return @ctz(i32, pop);
    }
    pub fn @"0x69 i32.popcnt"(self: *core.Instance, arg: void, pop: i32) i32 {
        return @popCount(i32, pop);
    }
    pub fn @"0x6A i32.add"(self: *core.Instance, arg: void, pop: Pair(i32, i32)) i32 {
        return pop._0 +% pop._1;
    }
    pub fn @"0x6B i32.sub"(self: *core.Instance, arg: void, pop: Pair(i32, i32)) i32 {
        return pop._0 -% pop._1;
    }
    pub fn @"0x6C i32.mul"(self: *core.Instance, arg: void, pop: Pair(i32, i32)) i32 {
        return pop._0 *% pop._1;
    }
    pub fn @"0x6D i32.div_s"(self: *core.Instance, arg: void, pop: Pair(i32, i32)) !i32 {
        if (pop._1 == 0) return error.DivisionByZero;
        if (pop._0 == std.math.minInt(i32) and pop._1 == -1) return error.Overflow;
        return @divTrunc(pop._0, pop._1);
    }
    pub fn @"0x6E i32.div_u"(self: *core.Instance, arg: void, pop: Pair(u32, u32)) !u32 {
        if (pop._1 == 0) return error.DivisionByZero;
        return @divFloor(pop._0, pop._1);
    }
    pub fn @"0x6F i32.rem_s"(self: *core.Instance, arg: void, pop: Pair(i32, i32)) !i32 {
        if (pop._1 == 0) return error.DivisionByZero;
        const abs_0 = std.math.absCast(pop._0);
        const abs_1 = std.math.absCast(pop._1);
        const val = @intCast(i32, @rem(abs_0, abs_1));
        return if (pop._0 < 0) -val else val;
    }

    pub fn @"0x70 i32.rem_u"(self: *core.Instance, arg: void, pop: Pair(u32, u32)) !u32 {
        if (pop._1 == 0) return error.DivisionByZero;
        return @mod(pop._0, pop._1);
    }
    pub fn @"0x71 i32.and"(self: *core.Instance, arg: void, pop: Pair(i32, i32)) i32 {
        return pop._0 & pop._1;
    }
    pub fn @"0x72 i32.or"(self: *core.Instance, arg: void, pop: Pair(i32, i32)) i32 {
        return pop._0 | pop._1;
    }
    pub fn @"0x73 i32.xor"(self: *core.Instance, arg: void, pop: Pair(i32, i32)) i32 {
        return pop._0 ^ pop._1;
    }
    pub fn @"0x74 i32.shl"(self: *core.Instance, arg: void, pop: Pair(i32, u32)) i32 {
        return pop._0 << @truncate(u5, pop._1);
    }
    pub fn @"0x75 i32.shr_s"(self: *core.Instance, arg: void, pop: Pair(i32, u32)) i32 {
        return pop._0 >> @truncate(u5, pop._1);
    }
    pub fn @"0x76 i32.shr_u"(self: *core.Instance, arg: void, pop: Pair(u32, u32)) u32 {
        return pop._0 >> @truncate(u5, pop._1);
    }
    pub fn @"0x77 i32.rotl"(self: *core.Instance, arg: void, pop: Pair(u32, u32)) u32 {
        return std.math.rotl(u32, pop._0, @truncate(u6, pop._1));
    }
    pub fn @"0x78 i32.rotr"(self: *core.Instance, arg: void, pop: Pair(u32, u32)) u32 {
        return std.math.rotr(u32, pop._0, @truncate(u6, pop._1));
    }
    pub fn @"0x79 i64.clz"(self: *core.Instance, arg: void, pop: i64) i64 {
        return @clz(i64, pop);
    }
    pub fn @"0x7A i64.ctz"(self: *core.Instance, arg: void, pop: i64) i64 {
        return @ctz(i64, pop);
    }
    pub fn @"0x7B i64.popcnt"(self: *core.Instance, arg: void, pop: i64) i64 {
        return @popCount(i64, pop);
    }
    pub fn @"0x7C i64.add"(self: *core.Instance, arg: void, pop: Pair(i64, i64)) i64 {
        return pop._0 +% pop._1;
    }
    pub fn @"0x7D i64.sub"(self: *core.Instance, arg: void, pop: Pair(i64, i64)) i64 {
        return pop._0 -% pop._1;
    }
    pub fn @"0x7E i64.mul"(self: *core.Instance, arg: void, pop: Pair(i64, i64)) i64 {
        return pop._0 *% pop._1;
    }
    pub fn @"0x7F i64.div_s"(self: *core.Instance, arg: void, pop: Pair(i64, i64)) !i64 {
        if (pop._1 == 0) return error.DivisionByZero;
        if (pop._0 == std.math.minInt(i64) and pop._1 == -1) return error.Overflow;
        return @divTrunc(pop._0, pop._1);
    }

    pub fn @"0x80 i64.div_u"(self: *core.Instance, arg: void, pop: Pair(u64, u64)) !u64 {
        if (pop._1 == 0) return error.DivisionByZero;
        return @divFloor(pop._0, pop._1);
    }
    pub fn @"0x81 i64.rem_s"(self: *core.Instance, arg: void, pop: Pair(i64, i64)) !i64 {
        if (pop._1 == 0) return error.DivisionByZero;
        const abs_0 = std.math.absCast(pop._0);
        const abs_1 = std.math.absCast(pop._1);
        const val = @intCast(i64, @rem(abs_0, abs_1));
        return if (pop._0 < 0) -val else val;
    }
    pub fn @"0x82 i64.rem_u"(self: *core.Instance, arg: void, pop: Pair(u64, u64)) !u64 {
        if (pop._1 == 0) return error.DivisionByZero;
        return @mod(pop._0, pop._1);
    }
    pub fn @"0x83 i64.and"(self: *core.Instance, arg: void, pop: Pair(i64, i64)) i64 {
        return pop._0 & pop._1;
    }
    pub fn @"0x84 i64.or"(self: *core.Instance, arg: void, pop: Pair(i64, i64)) i64 {
        return pop._0 | pop._1;
    }
    pub fn @"0x85 i64.xor"(self: *core.Instance, arg: void, pop: Pair(i64, i64)) i64 {
        return pop._0 ^ pop._1;
    }
    pub fn @"0x86 i64.shl"(self: *core.Instance, arg: void, pop: Pair(i64, u64)) i64 {
        return pop._0 << @truncate(u6, pop._1);
    }
    pub fn @"0x87 i64.shr_s"(self: *core.Instance, arg: void, pop: Pair(i64, u64)) i64 {
        return pop._0 >> @truncate(u6, pop._1);
    }
    pub fn @"0x88 i64.shr_u"(self: *core.Instance, arg: void, pop: Pair(u64, u64)) u64 {
        return pop._0 >> @truncate(u6, pop._1);
    }
    pub fn @"0x89 i64.rotl"(self: *core.Instance, arg: void, pop: Pair(u64, u64)) u64 {
        return std.math.rotl(u64, pop._0, @truncate(u7, pop._1));
    }
    pub fn @"0x8A i64.rotr"(self: *core.Instance, arg: void, pop: Pair(u64, u64)) u64 {
        return std.math.rotr(u64, pop._0, @truncate(u7, pop._1));
    }
    pub fn @"0x8B f32.abs"(self: *core.Instance, arg: void, pop: f32) f32 {
        return @fabs(pop);
    }
    pub fn @"0x8C f32.neg"(self: *core.Instance, arg: void, pop: f32) f32 {
        return -pop;
    }
    pub fn @"0x8D f32.ceil"(self: *core.Instance, arg: void, pop: f32) f32 {
        return @ceil(pop);
    }
    pub fn @"0x8E f32.floor"(self: *core.Instance, arg: void, pop: f32) f32 {
        return @floor(pop);
    }
    pub fn @"0x8F f32.trunc"(self: *core.Instance, arg: void, pop: f32) f32 {
        return @trunc(pop);
    }

    pub fn @"0x90 f32.nearest"(self: *core.Instance, arg: void, pop: f32) f32 {
        return @round(pop);
    }
    pub fn @"0x91 f32.sqrt"(self: *core.Instance, arg: void, pop: f32) f32 {
        return @sqrt(pop);
    }
    pub fn @"0x92 f32.add"(self: *core.Instance, arg: void, pop: Pair(f32, f32)) f32 {
        return pop._0 + pop._1;
    }
    pub fn @"0x93 f32.sub"(self: *core.Instance, arg: void, pop: Pair(f32, f32)) f32 {
        return pop._0 - pop._1;
    }
    pub fn @"0x94 f32.mul"(self: *core.Instance, arg: void, pop: Pair(f32, f32)) f32 {
        return pop._0 * pop._1;
    }
    pub fn @"0x95 f32.div"(self: *core.Instance, arg: void, pop: Pair(f32, f32)) f32 {
        return pop._0 / pop._1;
    }
    pub fn @"0x96 f32.min"(self: *core.Instance, arg: void, pop: Pair(f32, f32)) f32 {
        return std.math.min(pop._0, pop._1);
    }
    pub fn @"0x97 f32.max"(self: *core.Instance, arg: void, pop: Pair(f32, f32)) f32 {
        return std.math.max(pop._0, pop._1);
    }
    pub fn @"0x98 f32.copysign"(self: *core.Instance, arg: void, pop: Pair(f32, f32)) f32 {
        return std.math.copysign(f32, pop._0, pop._1);
    }
    pub fn @"0x99 f64.abs"(self: *core.Instance, arg: void, pop: f64) f64 {
        return @fabs(pop);
    }
    pub fn @"0x9A f64.neg"(self: *core.Instance, arg: void, pop: f64) f64 {
        return -pop;
    }
    pub fn @"0x9B f64.ceil"(self: *core.Instance, arg: void, pop: f64) f64 {
        return @ceil(pop);
    }
    pub fn @"0x9C f64.floor"(self: *core.Instance, arg: void, pop: f64) f64 {
        return @floor(pop);
    }
    pub fn @"0x9D f64.trunc"(self: *core.Instance, arg: void, pop: f64) f64 {
        return @trunc(pop);
    }
    pub fn @"0x9E f64.nearest"(self: *core.Instance, arg: void, pop: f64) f64 {
        return @round(pop);
    }
    pub fn @"0x9F f64.sqrt"(self: *core.Instance, arg: void, pop: f64) f64 {
        return @sqrt(pop);
    }
    pub fn @"0xA0 f64.add"(self: *core.Instance, arg: void, pop: Pair(f64, f64)) f64 {
        return pop._0 + pop._1;
    }
    pub fn @"0xA1 f64.sub"(self: *core.Instance, arg: void, pop: Pair(f64, f64)) f64 {
        return pop._0 - pop._1;
    }
    pub fn @"0xA2 f64.mul"(self: *core.Instance, arg: void, pop: Pair(f64, f64)) f64 {
        return pop._0 * pop._1;
    }
    pub fn @"0xA3 f64.div"(self: *core.Instance, arg: void, pop: Pair(f64, f64)) f64 {
        return pop._0 / pop._1;
    }
    pub fn @"0xA4 f64.min"(self: *core.Instance, arg: void, pop: Pair(f64, f64)) f64 {
        return std.math.min(pop._0, pop._1);
    }
    pub fn @"0xA5 f64.max"(self: *core.Instance, arg: void, pop: Pair(f64, f64)) f64 {
        return std.math.max(pop._0, pop._1);
    }
    pub fn @"0xA6 f64.copysign"(self: *core.Instance, arg: void, pop: Pair(f64, f64)) f64 {
        return std.math.copysign(f64, pop._0, pop._1);
    }
    pub fn @"0xA7 i32.wrap_i64"(self: *core.Instance, arg: void, pop: u64) u32 {
        return @truncate(u32, std.math.maxInt(u32) & pop);
    }
    pub fn @"0xA8 i32.trunc_f32_s"(self: *core.Instance, arg: void, pop: f32) !i32 {
        return floatToInt(i32, f32, pop);
    }
    pub fn @"0xA9 i32.trunc_f32_u"(self: *core.Instance, arg: void, pop: f32) !u32 {
        return floatToInt(u32, f32, pop);
    }
    pub fn @"0xAA i32.trunc_f64_s"(self: *core.Instance, arg: void, pop: f64) !i32 {
        return floatToInt(i32, f64, pop);
    }
    pub fn @"0xAB i32.trunc_f64_u"(self: *core.Instance, arg: void, pop: f64) !u32 {
        return floatToInt(u32, f64, pop);
    }
    pub fn @"0xAC i64.extend_i32_s"(self: *core.Instance, arg: void, pop: i64) i64 {
        return pop;
    }
    pub fn @"0xAD i64.extend_i32_u"(self: *core.Instance, arg: void, pop: u32) u64 {
        return pop;
    }
    pub fn @"0xAE i64.trunc_f32_s"(self: *core.Instance, arg: void, pop: f32) !i64 {
        return floatToInt(i64, f32, pop);
    }
    pub fn @"0xAF i64.trunc_f32_u"(self: *core.Instance, arg: void, pop: f32) !u64 {
        return floatToInt(u64, f32, pop);
    }

    pub fn @"0xB0 i64.trunc_f64_s"(self: *core.Instance, arg: void, pop: f64) !i64 {
        return floatToInt(i64, f64, pop);
    }
    pub fn @"0xB1 i64.trunc_f64_u"(self: *core.Instance, arg: void, pop: f64) !u64 {
        return floatToInt(u64, f64, pop);
    }
    pub fn @"0xB2 f32.convert_i32_s"(self: *core.Instance, arg: void, pop: i32) f32 {
        return @intToFloat(f32, pop);
    }
    pub fn @"0xB3 f32.convert_i32_u"(self: *core.Instance, arg: void, pop: u32) f32 {
        return @intToFloat(f32, pop);
    }
    pub fn @"0xB4 f32.convert_i64_s"(self: *core.Instance, arg: void, pop: i64) f32 {
        return @intToFloat(f32, pop);
    }
    pub fn @"0xB5 f32.convert_i64_u"(self: *core.Instance, arg: void, pop: u64) f32 {
        return @intToFloat(f32, pop);
    }
    pub fn @"0xB6 f32.demote_f64"(self: *core.Instance, arg: void, pop: f64) f32 {
        return @floatCast(f32, pop);
    }
    pub fn @"0xB7 f64.convert_i32_s"(self: *core.Instance, arg: void, pop: i32) f64 {
        return @intToFloat(f64, pop);
    }
    pub fn @"0xB8 f64.convert_i32_u"(self: *core.Instance, arg: void, pop: u32) f64 {
        return @intToFloat(f64, pop);
    }
    pub fn @"0xB9 f64.convert_i64_s"(self: *core.Instance, arg: void, pop: i64) f64 {
        return @intToFloat(f64, pop);
    }
    pub fn @"0xBA f64.convert_i64_u"(self: *core.Instance, arg: void, pop: u64) f64 {
        return @intToFloat(f64, pop);
    }
    pub fn @"0xBB f64.promote_f32"(self: *core.Instance, arg: void, pop: f32) f64 {
        return @floatCast(f64, pop);
    }
    pub fn @"0xBC i32.reinterpret_f32"(self: *core.Instance, arg: void, pop: f32) i32 {
        return @bitCast(i32, pop);
    }
    pub fn @"0xBD i64.reinterpret_f64"(self: *core.Instance, arg: void, pop: f64) i64 {
        return @bitCast(i64, pop);
    }
    pub fn @"0xBE f32.reinterpret_i32"(self: *core.Instance, arg: void, pop: i32) f32 {
        return @bitCast(f32, pop);
    }
    pub fn @"0xBF f64.reinterpret_i64"(self: *core.Instance, arg: void, pop: i64) f64 {
        return @bitCast(f64, pop);
    }

    fn floatToInt(comptime Dst: type, comptime Src: type, val: Src) !Dst {
        if (!std.math.isFinite(val) or val > std.math.maxInt(Dst) or val < std.math.minInt(Dst)) {
            return error.InvalidConversionToInteger;
        }
        return @floatToInt(Dst, val);
    }
};
