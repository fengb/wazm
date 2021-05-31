const std = @import("std");

const Memory = @This();

pages: std.ArrayListUnmanaged(*[65536]u8),
allocator: *std.mem.Allocator,
context: ?*c_void,

const page_size = 65536;

pub fn init(allocator: *std.mem.Allocator, context: ?*c_void, initial_pages: u16) !Memory {
    var result = Memory{ .allocator = allocator, .pages = .{}, .context = context };
    try result.grow(initial_pages);
    return result;
}

pub fn deinit(self: *Memory) void {
    for (self.pages.items) |page| {
        self.allocator.destroy(page);
    }
    self.pages.deinit(self.allocator);
    self.* = undefined;
}

pub fn pageCount(self: Memory) u16 {
    return @intCast(u16, self.pages.items.len);
}

pub fn ext(self: Memory, comptime T: type) *T {
    return @ptrCast(*T, @alignCast(@alignOf(T), self.context));
}

pub fn grow(self: *Memory, additional_pages: u16) !void {
    const new_page_count = self.pageCount() + additional_pages;
    if (new_page_count > 65536) {
        return error.OutOfMemory;
    }
    try self.pages.ensureCapacity(self.allocator, new_page_count);

    var i: u16 = 0;
    while (i < additional_pages) : (i += 1) {
        const page = try self.allocator.alloc(u8, page_size);
        self.pages.appendAssumeCapacity(@ptrCast(*[page_size]u8, page.ptr));
    }
}

pub fn load(self: Memory, comptime T: type, start: u32, offset: u32) !T {
    const Int = std.meta.Int(.unsigned, @bitSizeOf(T));
    const idx = try std.math.add(u32, start, offset);
    const bytes = try self.pageChunk(idx);
    // TODO: handle split byte boundary
    return @bitCast(T, std.mem.readIntLittle(Int, bytes[0..@sizeOf(T)]));
}

pub fn store(self: Memory, comptime T: type, start: u32, offset: u32, value: T) !void {
    const Int = std.meta.Int(.unsigned, @bitSizeOf(T));
    const idx = try std.math.add(u32, start, offset);
    const bytes = try self.pageChunk(idx);
    // TODO: handle split byte boundary
    std.mem.writeIntLittle(Int, bytes[0..@sizeOf(T)], @bitCast(Int, value));
}

fn pageChunk(self: Memory, idx: u32) ![]u8 {
    const page_num = idx / page_size;
    const offset = idx % page_size;
    if (page_num >= self.pageCount()) {
        std.log.info("{} > {}", .{ page_num, self.pageCount() });
        return error.OutOfBounds;
    }
    const page = self.pages.items[page_num];
    return page[offset..];
}

pub fn get(self: Memory, ptr: anytype) !@TypeOf(ptr).Pointee {
    return self.load(@TypeOf(ptr).Pointee, ptr.addr, 0);
}

pub fn iterBytes(self: Memory, ptr: P(u8), size: u32) ByteIterator {
    return .{
        .memory = self,
        .ptr = ptr,
        .remaining = size,
    };
}

const ByteIterator = struct {
    memory: Memory,
    ptr: P(u8),
    remaining: u32,

    pub fn next(iter: *ByteIterator) !?[]u8 {
        if (iter.remaining == 0) {
            return null;
        }

        const bytes = try iter.memory.pageChunk(iter.ptr.addr);

        const size = @intCast(u17, bytes.len);
        if (size >= iter.remaining) {
            defer iter.remaining = 0;
            return bytes[0..iter.remaining];
        } else {
            iter.remaining -= size;
            iter.ptr = try iter.ptr.offset(size);
            return bytes;
        }
    }
};

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

test "grow" {
    var mem = try Memory.init(std.testing.allocator, null, 1);
    defer mem.deinit();

    try std.testing.expectEqual(@as(u16, 1), mem.pageCount());

    try mem.grow(1);
    try std.testing.expectEqual(@as(u16, 2), mem.pageCount());
}

test "get/set" {
    var mem = try Memory.init(std.testing.allocator, null, 1);
    defer mem.deinit();

    try std.testing.expectEqual(@as(u16, 1), mem.pageCount());

    const ptr1 = P(u32){ .addr = 1234 };
    const ptr2 = P(u32){ .addr = 4321 };
    try mem.set(ptr1, 69);
    try mem.set(ptr2, 420);

    try std.testing.expectEqual(@as(u32, 69), try mem.get(ptr1));
    try std.testing.expectEqual(@as(u32, 420), try mem.get(ptr2));
}
