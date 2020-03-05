pub const Instance = @import("instance.zig");
pub const Module = @import("module.zig");
pub const Op = @import("op.zig");
pub const wat = @import("wat.zig");

test "" {
    _ = Instance;
    _ = Module;
    _ = Op;
    //_ = wat;
}
