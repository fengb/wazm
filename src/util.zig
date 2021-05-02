const std = @import("std");
/// Super simple "perfect hash" algorithm
/// Only really useful for switching on strings
// TODO: can we auto detect and promote the underlying type?
pub fn Swhash(comptime max_bytes: comptime_int) type {
    const T = std.meta.Int(.unsigned, max_bytes * 8);

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

pub const RingAllocator = struct {
    buffer: []u8,
    alignment: u29,
    max_alloc_size: usize,
    curr_index: usize = 0,
    allocator: std.mem.Allocator = .{
        .allocFn = alloc,
        .resizeFn = resize,
    },

    pub fn init(buffer: []u8, max_alloc_size: usize) RingAllocator {
        std.debug.assert(@popCount(usize, max_alloc_size) == 1);
        std.debug.assert(buffer.len % max_alloc_size == 0);
        return .{
            .buffer = buffer,
            .alignment = @as(u29, 1) << @intCast(std.math.Log2Int(u29), @ctz(usize, max_alloc_size | @ptrToInt(buffer.ptr))),
            .max_alloc_size = max_alloc_size,
        };
    }

    const ShiftSize = std.math.Log2Int(usize);
    fn shiftSize(self: RingAllocator) ShiftSize {
        return @intCast(ShiftSize, @ctz(usize, self.max_alloc_size));
    }

    fn totalSlots(self: RingAllocator) usize {
        return self.buffer.len >> self.shiftSize();
    }

    pub fn ownsSlice(self: *const RingAllocator, slice: []u8) bool {
        return @ptrToInt(slice.ptr) >= @ptrToInt(self.buffer.ptr) and
            (@ptrToInt(slice.ptr) + slice.len) <= (@ptrToInt(self.buffer.ptr) + self.buffer.len);
    }

    fn alloc(allocator: *std.mem.Allocator, n: usize, ptr_align: u29, len_align: u29, return_address: usize) error{OutOfMemory}![]u8 {
        const self = @fieldParentPtr(RingAllocator, "allocator", allocator);
        std.debug.assert(n <= self.max_alloc_size);
        std.debug.assert(ptr_align <= self.alignment);

        const start = self.curr_index << self.shiftSize();
        self.curr_index += 1;
        if (self.curr_index >= self.totalSlots()) {
            // Wrap around the ring
            self.curr_index = 0;
        }

        return self.buffer[start..][0..self.max_alloc_size];
    }

    fn resize(allocator: *std.mem.Allocator, buf: []u8, buf_align: u29, new_size: usize, len_align: u29, return_address: usize) error{OutOfMemory}!usize {
        const self = @fieldParentPtr(RingAllocator, "allocator", allocator);
        std.debug.assert(self.ownsSlice(buf)); // sanity check
        std.debug.assert(buf_align == 1);

        if (new_size >= self.max_alloc_size) {
            return error.OutOfMemory;
        }

        return new_size;
    }
};
