pub const Bytecode = @import("bytecode.zig");
pub const core = @import("core.zig");
pub const Op = @import("op.zig");
pub const wat = @import("wat.zig");

test "" {
    _ = Bytecode;
    _ = core;
    _ = Op;
    _ = wat;
}
