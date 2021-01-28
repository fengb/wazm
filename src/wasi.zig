const std = @import("std");
const Module = @import("module.zig");
const Instance = @import("instance.zig");
const Execution = @import("execution.zig");

const Wasi = @This();

argv: [][]u8,
environ: [][]u8 = &.{},

pub fn run(self: *Wasi, allocator: *std.mem.Allocator, reader: anytype) !void {
    var module = try Module.parse(allocator, reader);
    defer module.deinit();

    var instance = try module.instantiate(allocator, self, struct {
        pub const wasi = imports;
    });
    defer instance.deinit();

    _ = try instance.call("_start", .{});
}

pub const Size = u32;

/// Non-negative file size or length of a region within a file.
pub const Filesize: u64;

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

/// A file descriptor handle.
const Fd = enum(u32) {
    stdin = 0,
    stdout = 1,
    stderr = 2,
    _,
};

const Iovec = extern struct {
    buf: P(u8),
    len: Size,
};

/// Error codes returned by functions. Not all of these error codes are returned by the functions provided by this API; some are used in higher-level library layers, and others are provided merely for alignment with POSIX.
pub const Errno = enum(u32) {
    /// No error occurred. System call completed successfully.
    success = 0,

    /// Permission denied.
    acces = 2,

    /// Resource unavailable, or operation would block.
    again = 6,

    /// Bad file descriptor.
    badf = 8,

    /// Reserved.
    dquot = 19,

    /// File too large.
    fbig = 22,

    /// Invalid argument.
    inval = 28,

    /// I/O error.
    io = 29,

    /// No buffer space available.
    nobufs = 42,

    /// No space left on device.
    nospc = 51,

    /// Broken pipe.
    pipe = 64,

    unexpected = 0xAAAA,
    _,
};

/// File descriptor rights, determining which actions may be performed.
pub const Rights = packed struct {
    fd_datasync: bool,
    fd_read: bool,
    fd_seek: bool,
    fd_fdstat_set_flags: bool,
    fd_sync: bool,
    fd_tell: bool,
    fd_write: bool,
    fd_advise: bool,
    fd_allocate: bool,
    path_create_directory: bool,
    path_create_file: bool,
    path_link_source: bool,
    path_link_target: bool,
    path_open: bool,
    fd_readdir: bool,
    path_readlink: bool,
    path_rename_source: bool,
    path_rename_target: bool,
    path_filestat_get: bool,
    path_filestat_set_size: bool,
    path_filestat_set_times: bool,
    fd_filestat_get: bool,
    fd_filestat_set_size: bool,
    fd_filestat_set_times: bool,
    path_symlink: bool,
    path_remove_directory: bool,
    path_unlink_file: bool,
    poll_fd_readwrite: bool,
    sock_shutdown: bool,
    _pad: u3,
    _pad1: u32,
};

pub fn P(comptime T: type) type {
    return extern struct {
        value: u32,

        const Self = @This();
        pub const Pointee = T;

        // TODO: handle overflow
        // TODO: handle endianness
        fn get(self: Self, memory: []const u8) !T {
            return @bitCast(T, memory[self.value..][0..@sizeOf(T)].*);
        }

        // TODO: handle overflow
        // TODO: handle endianness
        fn getOffset(self: Self, memory: []const u8, offset: Size) !T {
            const size = @sizeOf(T);
            return @bitCast(T, memory[self.value + offset * size ..][0..size].*);
        }

        fn getMany(self: Self, memory: []u8, size: Size) ![]u8 {
            return memory[self.value..][0..size];
        }

        // TODO: handle overflow
        // TODO: handle endianness
        fn set(self: Self, memory: []u8, value: T) !void {
            std.mem.copy(u8, memory[self.value..], std.mem.asBytes(&value));
        }

        // TODO: handle overflow
        // TODO: handle endianness
        fn setMany(self: Self, memory: []u8, value: []const T) !void {
            std.mem.copy(u8, memory[self.value..], std.mem.sliceAsBytes(value));
        }
    };
}

const imports = struct {
    pub fn args_get(exec: *Execution, argv: P(P(u8)), argv_buf: P(u8)) !Errno {
        const wasi = @ptrCast(*Wasi, @alignCast(@alignOf(Wasi), exec.context));
        return strings_get(exec, wasi.argv, argv, argv_buf);
    }

    pub fn args_sizes_get(exec: *Execution, argc: P(Size), argv_buf_size: P(Size)) !Errno {
        const wasi = @ptrCast(*Wasi, @alignCast(@alignOf(Wasi), exec.context));
        return strings_sizes_get(exec, wasi.argv, argc, argv_buf_size);
    }

    pub fn environ_get(exec: *Execution, environ: P(P(u8)), environ_buf: P(u8)) !Errno {
        const wasi = @ptrCast(*Wasi, @alignCast(@alignOf(Wasi), exec.context));
        return strings_get(exec, wasi.environ, environ, environ_buf);
    }

    pub fn environ_sizes_get(exec: *Execution, environc: P(Size), environ_buf_size: P(Size)) !Errno {
        const wasi = @ptrCast(*Wasi, @alignCast(@alignOf(Wasi), exec.context));
        return strings_sizes_get(exec, wasi.environ, environc, environ_buf_size);
    }

    pub fn fd_write(exec: *Execution, fd: Fd, iovs: P(Iovec), iovs_len: Size, nread: P(Size)) !Errno {
        var os_vec: [128]std.os.iovec_const = undefined;
        var i: u32 = 0;
        while (i < iovs_len) : (i += 1) {
            const iov = try iovs.getOffset(exec.memory, i);
            const slice = try iov.buf.getMany(exec.memory, iov.len);
            os_vec[i] = .{ .iov_base = slice.ptr, .iov_len = slice.len };
        }

        const handle = switch (fd) {
            .stdin => unreachable,
            .stdout => std.io.getStdOut().handle,
            .stderr => std.io.getStdErr().handle,
            else => unreachable,
        };
        var written = std.os.writev(handle, os_vec[0..iovs_len]) catch |err| return switch (err) {
            error.DiskQuota => Errno.dquot,
            error.FileTooBig => Errno.fbig,
            error.InputOutput => Errno.io,
            error.NoSpaceLeft => Errno.nospc,
            error.AccessDenied => Errno.acces,
            error.BrokenPipe => Errno.pipe,
            error.SystemResources => Errno.nobufs,
            error.OperationAborted => unreachable,
            error.NotOpenForWriting => Errno.badf,
            error.WouldBlock => Errno.again,
            error.Unexpected => Errno.unexpected,
        };
        try nread.set(exec.memory, @intCast(u32, written));
        return Errno.success;
    }

    fn strings_get(exec: *Execution, strings: [][]u8, target: P(P(u8)), target_buf: P(u8)) !Errno {
        var target_ = target;
        var target_buf_ = target_buf;

        for (strings) |string| {
            try target_.set(exec.memory, target_buf_);

            try target_buf_.setMany(exec.memory, string);
            target_buf_.value += @intCast(u32, string.len);
            try target_buf_.set(exec.memory, 0);
            target_buf_.value += 1;
        }
        return Errno.success;
    }

    fn strings_sizes_get(exec: *Execution, strings: [][]u8, targetc: P(Size), target_buf_size: P(Size)) !Errno {
        try targetc.set(exec.memory, @intCast(Size, strings.len));

        var buf_size: usize = 0;
        for (strings) |string| {
            buf_size += string.len + 1;
        }
        try target_buf_size.set(exec.memory, @intCast(Size, buf_size));
        return Errno.success;
    }

    pub fn clock_res_get(exec: *Execution, clock_id: ClockId, resolution: P(Timestamp)) Errno {
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
        try resolution.set(exec.memory, @intCast(Timestamp, std.time.ns_per_s * result.tv_sec + result.tv_nsec));
        return Errno.success;
    }

    pub fn clock_time_get(exec: *Execution, clock_id: ClockId, precision: Timestamp, time: P(Timestamp)) Errno {
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
        try time.set(exec.memory, @intCast(Timestamp, std.time.ns_per_s * result.tv_sec + result.tv_nsec));
        return Errno.success;
    }
};

test "smoke" {
    _ = Instance.ImportManager(struct {
        pub const wasi = imports;
    });
}
