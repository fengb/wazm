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
