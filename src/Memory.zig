const std = @import("std");

const Memory = @This();

allocator: *std.mem.Allocator,
data: []u8,
context: ?*c_void,

const page_size = 65536;

pub fn init(allocator: *std.mem.Allocator, context: ?*c_void, initial_pages: u16) !Memory {
    var result = Memory{ .allocator = allocator, .data = &.{}, .context = context };
    _ = try result.grow(initial_pages);
    return result;
}

pub fn deinit(self: *Memory) void {
    self.allocator.free(self.data);
    self.* = undefined;
}

pub fn ext(self: Memory, comptime T: type) *T {
    return @ptrCast(*T, @alignCast(@alignOf(T), self.context));
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

pub fn load(self: Memory, comptime T: type, start: u32, offset: u32) !T {
    const Int = std.meta.Int(.unsigned, @bitSizeOf(T));
    const idx = try std.math.add(u32, start, offset);
    const bytes = try self.chunk(idx, @sizeOf(T));
    return @bitCast(T, std.mem.readIntLittle(Int, bytes));
}

pub fn store(self: Memory, comptime T: type, start: u32, offset: u32, value: T) !void {
    const Int = std.meta.Int(.unsigned, @bitSizeOf(T));
    const idx = try std.math.add(u32, start, offset);
    const bytes = try self.chunk(idx, @sizeOf(T));
    std.mem.writeIntLittle(Int, bytes, @bitCast(Int, value));
}

fn chunk(self: Memory, idx: u32, comptime size: u32) !*[size]u8 {
    const end = try std.math.add(u32, idx, size - 1);
    if (end >= self.data.len) {
        return error.OutOfBounds;
    }
    return self.data[idx..][0..size];
}

pub fn get(self: Memory, ptr: anytype) !@TypeOf(ptr).Pointee {
    return self.load(@TypeOf(ptr).Pointee, ptr.addr, 0);
}

pub fn getMany(self: Memory, ptr: anytype, size: u32) ![]u8 {
    return self.data[ptr.addr..][0..size];
}

pub fn set(self: Memory, ptr: anytype, value: @TypeOf(ptr).Pointee) !void {
    return self.store(@TypeOf(ptr).Pointee, ptr.addr, 0, value);
}

pub fn setMany(self: Memory, ptr: anytype, values: []const @TypeOf(ptr).Pointee) !void {
    for (values) |value, i| {
        try self.set(try ptr.offset(@intCast(u32, i)), value);
    }
}

pub fn P(comptime T: type) type {
    return extern struct {
        addr: u32,

        pub const Pointee = T;

        pub fn init(addr: u32) @This() {
            return .{ .addr = addr };
        }

        pub fn offset(self: @This(), change: u32) !@This() {
            return @This(){ .addr = try std.math.add(u32, self.addr, change) };
        }
    };
}
