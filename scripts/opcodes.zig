const std = @import("std");
const self = @import("self");

pub fn main() !void {
    const stdout = std.io.getStdOut();
    try outputHtml(stdout.writer());
}

fn outputConsole(writer: anytype) !void {
    for (self.Op.Meta.all) |op, i| {
        var buf = [_]u8{' '} ** 13;
        if (op) |o| {
            std.mem.copy(u8, &buf, o.name);
        }
        try writer.print("{}", .{buf});

        if (i % 0x10 == 0xF) {
            try writer.print("\n", .{});
        }
    }
}

fn outputHtml(writer: anytype) !void {
    try writer.print("<html>\n<body>\n<table>\n", .{});

    try writer.print("<tr>\n<th></th>\n", .{});
    for ([_]u8{0} ** 16) |_, i| {
        try writer.print("<th>_{X}</th>\n", .{i});
    }
    try writer.print("</tr>\n", .{});

    for (self.Op.Meta.all) |op, i| {
        if (i % 0x10 == 0x0) {
            try writer.print("<tr>\n<th>{X}_</th>\n", .{i / 16});
        }
        try writer.print("<td style='white-space: nowrap; font-family: monospace'>\n", .{});
        if (op) |o| {
            try writer.print("<strong>{s}</strong><br />\n", .{o.name});
            try writer.print("(", .{});
            if (o.pop.len > 0) {
                for (o.pop) |change| {
                    try writer.print("{s} ", .{@tagName(change)});
                }
            }
            try writer.print(") ", .{});
            try writer.print("&rarr; ({s})\n", .{if (o.push) |change| @tagName(change) else ""});
        }
        try writer.print("</td>", .{});

        if (i % 0x10 == 0xF) {
            try writer.print("</tr>\n", .{});
        }
    }
    try writer.print("</table>\n</body>\n</html>\n", .{});
}
