pub const Bytecode = @import("bytecode.zig");
pub const Module = @import("module.zig");
pub const Op = @import("op.zig");
pub const wat = @import("wat.zig");

test "" {
    _ = Bytecode;
    _ = Module;
    _ = Op;
    _ = wat;
}
