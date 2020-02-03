const std = @import("std");
const self = @import("self");

pub fn main() !void {
    const stdout = std.io.getStdOut();
    try outputHtml(&stdout.outStream());
}

fn outputConsole(file: *std.fs.File.OutStream) !void {
    var os = file.outStream();
    for (self.op.all) |op, i| {
        var buf = [_]u8{' '} ** 13;
        if (op) |o| {
            std.mem.copy(u8, &buf, o.name);
        }
        try fos.stream.print("{}", .{buf});

        if (i % 0x10 == 0xF) {
            try fos.stream.print("\n", .{});
        }
    }
}

fn outputHtml(fos: *std.fs.File.OutStream) !void {
    try fos.stream.print("<html>\n<body>\n<table>\n", .{});

    try fos.stream.print("<tr>\n<th></th>\n", .{});
    for ([_]u8{0} ** 16) |_, i| {
        try fos.stream.print("<th>_{X}</th>\n", .{i});
    }
    try fos.stream.print("</tr>\n", .{});

    for (self.op.all) |op, i| {
        if (i % 0x10 == 0x0) {
            try fos.stream.print("<tr>\n<th>{X}_</th>\n", .{i / 16});
        }
        const name = if (op) |o| o.name else "";
        try fos.stream.print("<td>{}</td>\n", .{name});

        if (i % 0x10 == 0xF) {
            try fos.stream.print("</tr>\n", .{});
        }
    }
    try fos.stream.print("</table>\n</body>\n</html>\n", .{});
}
