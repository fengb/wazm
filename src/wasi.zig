const std = @import("std");
const Module = @import("module.zig");
const Instance = @import("instance.zig");
const Execution = @import("execution.zig");

/// Timestamp in nanoseconds.
pub const Timestamp = u64;

/// Identifiers for clocks.
pub const ClockId = enum(u32) {
    /// The clock measuring real time. Time value zero corresponds with 1970-01-01T00:00:00Z.
    realtime = 0,

    /// The store-wide monotonic clock, which is defined as a clock measuring real time, whose value cannot be adjusted and which cannot have negative clock jumps. The epoch of this clock is undefined. The absolute time value of this clock therefore has no meaning.
    monotonic = 1,

    /// The CPU-time clock associated with the current process.
    process_cputime_id = 2,

    /// The CPU-time clock associated with the current thread.
    thread_cputime_id = 3,
    _,
};

/// Error codes returned by functions. Not all of these error codes are returned by the functions provided by this API; some are used in higher-level library layers, and others are provided merely for alignment with POSIX.
pub const Errno = enum(u32) {
    success = 0,
    inval = 28,
    unexpected = 0xAAAA,
    _,
};

pub fn P(comptime T: type) type {
    return enum(u32) {
        _,

        pub const Pointee = T;
    };
}

pub fn Context(cache_bust: anytype) type {
    return struct {
        pub fn clock_res_get(ctx: *Execution, clock_id: ClockId, resolution: P(Timestamp)) Errno {
            const clk: i32 = switch (clock_id) {
                .realtime => std.os.CLOCK_REALTIME,
                .monotonic => std.os.CLOCK_MONOTONIC,
                .process_cputime_id => std.os.CLOCK_PROCESS_CPUTIME_ID,
                .thread_cputime_id => std.os.CLOCK_THREAD_CPUTIME_ID,
                else => return Errno.inval,
            };

            var result: std.os.timespec = undefined;
            std.os.clock_getres(clk, &result) catch |err| switch (err) {
                error.UnsupportedClock => return Errno.inval,
                error.Unexpected => return Errno.unexpected,
            };
            std.mem.writeIntSliceLittle(
                Timestamp,
                ctx.memory[@enumToInt(resolution)..],
                @intCast(Timestamp, std.time.ns_per_s * result.tv_sec + result.tv_nsec),
            );
            return Errno.success;
        }

        pub fn clock_time_get(ctx: *Execution, clock_id: ClockId, precision: Timestamp, time: P(Timestamp)) Errno {
            const clk: i32 = switch (clock_id) {
                .realtime => std.os.CLOCK_REALTIME,
                .monotonic => std.os.CLOCK_MONOTONIC,
                .process_cputime_id => std.os.CLOCK_PROCESS_CPUTIME_ID,
                .thread_cputime_id => std.os.CLOCK_THREAD_CPUTIME_ID,
                else => return Errno.inval,
            };

            var result: std.os.timespec = undefined;
            std.os.clock_gettime(clk, &result) catch |err| switch (err) {
                error.UnsupportedClock => return Errno.inval,
                error.Unexpected => return Errno.unexpected,
            };
            std.mem.writeIntSliceLittle(
                Timestamp,
                ctx.memory[@enumToInt(time)..],
                @intCast(Timestamp, std.time.ns_per_s * result.tv_sec + result.tv_nsec),
            );
            return Errno.success;
        }
    };
}

test "smoke" {
    _ = Instance.ImportManager(struct {
        pub const wasi = Context(null);
    });
}
