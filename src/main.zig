pub const Instance = @import("instance.zig");
pub const Module = @import("module.zig");
pub const Op = @import("op.zig");
pub const Wat = @import("wat.zig");

test "" {
    _ = Instance;
    _ = Module;
    _ = Op;
    _ = Wat;
    _ = @import("func/basic.zig");
    _ = @import("func/imports.zig");
    _ = @import("wasi.zig");
}
