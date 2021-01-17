const std = @import("std");
const Module = @import("module.zig");
const Instance = @import("instance.zig");
const Execution = @import("execution.zig");

/// Timestamp in nanoseconds.
pub const timestamp = u64;

pub fn Context(cache_bust: anytype) type {
    return struct {
        // (clock_id: clockid_t, resolution: *timestamp_t) -> errno_t
        pub fn clock_res_get(ctx: *Execution, clock_id: u32, resolution: u32) timestamp {
            const clk: i32 = switch (clock_id) {
                0 => std.os.CLOCK_REALTIME,
                1 => std.os.CLOCK_MONOTONIC,
                else => return 666,
            };

            var result: std.os.timespec = undefined;
            std.os.clock_getres(clk, &result) catch |err| return 666;
            return @intCast(timestamp, std.time.ns_per_s * result.tv_sec + result.tv_nsec);
        }

        // (clock_id: clockid_t, precision: timestamp_t, timestamp: *timestamp_t) -> errno_t
        pub fn clock_time_get(ctx: *Execution, clock_id: u32, precision: u32, resolution: u32) timestamp {
            const clk: i32 = switch (clock_id) {
                0 => std.os.CLOCK_REALTIME,
                1 => std.os.CLOCK_MONOTONIC,
                else => return 666,
            };

            var result: std.os.timespec = undefined;
            std.os.clock_gettime(clk, &result) catch |err| return 666;
            return @intCast(timestamp, std.time.ns_per_s * result.tv_sec + result.tv_nsec);
        }
    };
}

test "smoke" {
    _ = Instance.ImportManager(struct {
        pub const wasi = Context(null);
    });
}
