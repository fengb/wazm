const std = @import("std");
const self = @import("self");

pub fn main() !void {
    const stdout = std.io.getStdOut();
    try outputHtml(stdout.outStream());
}

fn outputConsole(outstream: anytype) !void {
    for (self.Op.all) |op, i| {
        var buf = [_]u8{' '} ** 13;
        if (op) |o| {
            std.mem.copy(u8, &buf, o.name);
        }
        try outstream.print("{}", .{buf});

        if (i % 0x10 == 0xF) {
            try outstream.print("\n", .{});
        }
    }
}

fn outputHtml(outstream: anytype) !void {
    try outstream.print("<html>\n<body>\n<table>\n", .{});

    try outstream.print("<tr>\n<th></th>\n", .{});
    for ([_]u8{0} ** 16) |_, i| {
        try outstream.print("<th>_{X}</th>\n", .{i});
    }
    try outstream.print("</tr>\n", .{});

    for (self.Op.all) |op, i| {
        if (i % 0x10 == 0x0) {
            try outstream.print("<tr>\n<th>{X}_</th>\n", .{i / 16});
        }
        try outstream.print("<td style='white-space: nowrap; font-family: monospace'>\n", .{});
        if (op) |o| {
            try outstream.print("<strong>{}</strong><br />\n", .{o.name});
            try outstream.print("(", .{});
            if (o.pop.len > 1) {
                for (o.pop) |change| {
                    try outstream.print("{} ", .{@tagName(change)});
                }
            }
            try outstream.print(") ", .{});
            try outstream.print("&rarr; ({})\n", .{if (o.push) |change| @tagName(change) else ""});
        }
        try outstream.print("</td>", .{});

        if (i % 0x10 == 0xF) {
            try outstream.print("</tr>\n", .{});
        }
    }
    try outstream.print("</table>\n</body>\n</html>\n", .{});
}
