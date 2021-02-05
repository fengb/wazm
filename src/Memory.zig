const std = @import("std");

const Memory = @This();

allocator: *std.mem.Allocator,
data: []u8,

const page_size = 65536;

pub fn init(allocator: *std.mem.Allocator, initial_pages: u16) !Memory {
    var result = Memory{ .allocator = allocator, .data = &.{} };
    _ = try result.grow(initial_pages);
    return result;
}

pub fn deinit(self: *Memory) void {
    self.allocator.free(self.data);
    self.* = undefined;
}

pub fn grow(self: *Memory, additional_pages: u16) !u16 {
    const existing_pages = self.data.len / page_size;
    const new_size = existing_pages + additional_pages;
    if (new_size > 65536) {
        return error.OutOfMemory;
    }
    self.data = try self.allocator.realloc(self.data, existing_pages + additional_pages);
    return @intCast(u16, new_size);
}

// TODO: move these memory methods?
pub fn load(self: Memory, comptime T: type, start: usize, offset: usize) !T {
    const Int = std.meta.Int(.unsigned, @bitSizeOf(T));
    const raw = std.mem.readIntLittle(Int, try self.ptr(start, offset, @sizeOf(T)));
    return @bitCast(T, raw);
}

pub fn store(self: Memory, comptime T: type, start: usize, offset: usize, value: T) !void {
    const bytes = try self.ptr(start, offset, @sizeOf(T));
    const Int = std.meta.Int(.unsigned, @bitSizeOf(T));
    std.mem.writeIntLittle(Int, bytes, @bitCast(Int, value));
}

fn ptr(self: Memory, start: usize, offset: usize, comptime length: usize) !*[length]u8 {
    const tail = start +% offset +% (length - 1);
    const is_overflow = tail < start;
    const is_seg_fault = tail >= self.data.len;
    if (is_overflow or is_seg_fault) {
        return error.OutOfBounds;
    }
    return self.data[start + offset ..][0..length];
}
