const std = @import("std");
/// Super simple "perfect hash" algorithm
/// Only really useful for switching on strings
// TODO: can we auto detect and promote the underlying type?
pub fn Swhash(comptime max_bytes: comptime_int) type {
    const T = std.meta.IntType(false, max_bytes * 8);

    return struct {
        pub fn match(string: []const u8) T {
            return hash(string) orelse std.math.maxInt(T);
        }

        pub fn case(comptime string: []const u8) T {
            return hash(string) orelse @compileError("Cannot hash '" ++ string ++ "'");
        }

        fn hash(string: []const u8) ?T {
            if (string.len > max_bytes) return null;
            var tmp = [_]u8{0} ** max_bytes;
            std.mem.copy(u8, &tmp, string);
            return std.mem.readIntNative(T, &tmp);
        }
    };
}

pub fn ArgsTuple(comptime Fn: type) type {
    const function_info = @typeInfo(Fn).Fn;
    var argument_field_list: [function_info.args.len]std.builtin.TypeInfo.StructField = undefined;
    inline for (function_info.args) |arg, i| {
        @setEvalBranchQuota(10_000);
        var num_buf: [128]u8 = undefined;
        argument_field_list[i] = std.builtin.TypeInfo.StructField{
            .name = std.fmt.bufPrint(&num_buf, "{d}", .{i}) catch unreachable,
            .field_type = arg.arg_type.?,
            .default_value = @as(?(arg.arg_type.?), null),
            .is_comptime = false,
        };
    }

    return @Type(std.builtin.TypeInfo{
        .Struct = std.builtin.TypeInfo.Struct{
            .is_tuple = true,
            .layout = .Auto,
            .decls = &[_]std.builtin.TypeInfo.Declaration{},
            .fields = &argument_field_list,
        },
    });
}
