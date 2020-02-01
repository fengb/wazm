pub const core = @import("core.zig");
pub const op = @import("op.zig");
pub const wat = @import("wat.zig");

test "" {
    _ = core;
    _ = op;
    _ = wat;
}
