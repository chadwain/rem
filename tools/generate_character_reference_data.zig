// Copyright (C) 2021 Chadwain Holness
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//! Expects as program arguments the path to JSON data, and the path to
//! output the resulting zig file. Must be built with runtime safety enabled.

const std = @import("std");
const ArrayList = std.ArrayList;
const Allocator = std.mem.Allocator;

const Node = struct {
    children: ArrayList(Entry),
    input: ArrayList(Item),

    const Entry = struct {
        key: u8,
        node: ?*Node,
        is_match: bool,
        characters: []const u8,

        fn getOrCreateChildNode(entry: *Entry, al: Allocator) !*Node {
            if (entry.node == null) {
                entry.node = try al.create(Node);
                entry.node.?.* = .{ .children = ArrayList(Entry).init(al), .input = ArrayList(Item).init(al) };
            }
            return entry.node.?;
        }
    };

    fn getOrCreateEntry(node: *Node, key: u8) !*Entry {
        for (node.children.items) |*c| {
            if (c.key == key) return c;
        }

        const insert_pos = searchForInsertPosition(key, node.children.items);
        try node.children.insert(insert_pos, .{ .key = key, .node = null, .is_match = false, .characters = undefined });
        return &node.children.items[insert_pos];
    }

    fn searchForInsertPosition(key: u8, entries: []Entry) usize {
        var left: usize = 0;
        var right: usize = entries.len;

        while (left < right) {
            // Avoid overflowing in the midpoint calculation
            const mid = left + (right - left) / 2;
            // Compare the key with the midpoint element
            switch (std.math.order(key, entries[mid].key)) {
                .eq => unreachable,
                .gt => left = mid + 1,
                .lt => right = mid,
            }
        }

        return left;
    }

    fn print(node: *Node, indent: u16) void {
        for (node.children.items) |c| {
            var j: u16 = 0;
            while (j < indent) : (j += 1) {
                std.debug.print(" ", .{});
            }
            std.debug.print("{c}\n", .{c.key});
            if (c.node) |n| {
                n.print(indent + 2);
            }
        }
    }
};

const Item = struct {
    name: []const u8,
    characters: []const u8,
};

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const al = arena.allocator();

    const args = try std.process.argsAlloc(al);
    defer std.process.argsFree(al, args);

    const out_file_path = args[2];
    const cwd = std.fs.cwd();
    if (cwd.access(out_file_path, .{})) return else |_| {}

    const data = blk: {
        const input_file = args[1];
        const file = try std.fs.cwd().openFile(input_file, .{});
        defer file.close();
        break :blk try file.readToEndAlloc(al, std.math.maxInt(c_int));
    };
    defer al.free(data);

    var p = std.json.Parser.init(al, false);
    defer p.deinit();
    var tree = try p.parse(data);
    defer tree.deinit();

    var list = std.ArrayList(Item).init(al);
    defer list.deinit();
    var it = tree.root.Object.iterator();
    while (it.next()) |o| {
        try list.append(.{ .name = o.key_ptr.*[1..], .characters = o.value_ptr.Object.get("characters").?.String });
    }

    var node = Node{ .children = ArrayList(Node.Entry).init(al), .input = list };
    try createTree(al, &node);
    const output = try render(&node, al);
    defer al.free(output);

    var out_file = try cwd.createFile(out_file_path, .{});
    defer out_file.close();
    var writer = out_file.writer();
    try writer.writeAll(output);

    std.debug.print("Generated character reference data at {s}\n", .{out_file_path});
}

fn createTree(al: Allocator, node: *Node) error{OutOfMemory}!void {
    for (node.input.items) |i| {
        const key = i.name[0];
        const entry = try node.getOrCreateEntry(key);
        if (i.name.len > 1) {
            const child_node = try entry.getOrCreateChildNode(al);
            try child_node.input.append(Item{ .name = i.name[1..], .characters = i.characters });
        } else {
            entry.is_match = true;
            entry.characters = i.characters;
        }
    }
    for (node.children.items) |c| {
        if (c.node) |n| {
            try createTree(al, n);
        }
    }
}

fn render(node: *Node, al: Allocator) ![]u8 {
    var output = ArrayList(u8).init(al);
    errdefer output.deinit();
    var writer = output.writer();
    try writer.writeAll(
        \\const std = @import("std");
        \\
        \\/// If the 1st field is null, then the current string does not match any named character references.
        \\/// Otherwise, there is a match, and the 2nd field may or may not be null.
        \\pub const Value = @Type(std.builtin.TypeInfo{ .Struct = .{
        \\    .layout = .Auto,
        \\    .fields = &.{
        \\        .{
        \\            .name = "0",
        \\            .field_type = ?u21,
        \\            .default_value = null,
        \\            .is_comptime = false,
        \\            .alignment = @alignOf(?u21),
        \\        },
        \\        .{
        \\            .name = "1",
        \\            .field_type = ?u21,
        \\            .default_value = null,
        \\            .is_comptime = false,
        \\            .alignment = @alignOf(?u21),
        \\        },
        \\    },
        \\    .decls = &.{},
        \\    .is_tuple = true,
        \\} });
        \\
        \\pub const Node = struct {
        \\    keys: []const u8,
        \\    values: []const Value,
        \\    children: []const ?*const Node,
        \\
        \\    pub fn find(node: *const Node, key: u21) ?usize {
        \\        const truncated = std.math.cast(u8, key) orelse return null;
        \\        return std.sort.binarySearch(u8, truncated, node.keys, {}, keyCmp);
        \\    }
        \\
        \\    pub fn value(node: *const Node, index: usize) Value {
        \\        return node.values[index];
        \\    }
        \\
        \\    pub fn child(node: *const Node, index: usize) ?*const Node {
        \\        return node.children[index];
        \\    }
        \\
        \\    fn keyCmp(ctx: void, lhs: u8, rhs: u8) std.math.Order {
        \\        _ = ctx;
        \\        return std.math.order(lhs, rhs);
        \\    }
        \\};
        \\
        \\pub const root = &Node{
        \\
    );
    try writeKeys(writer, node, 1);
    try writeValues(writer, node, 1);
    try writeChildren(writer, node, 1);
    try writer.writeAll("};\n");

    return output.toOwnedSlice();
}

fn writeKeys(writer: anytype, node: *Node, indent: usize) ArrayList(u8).Writer.Error!void {
    try writeIndentation(writer, indent);
    try writer.writeAll(".keys = &[_]u8{");
    const len = node.children.items.len;
    if (len > 1) try writer.writeByte(' ');
    for (node.children.items) |c, index| {
        try writer.writeAll("\'");
        try writer.writeAll(&.{c.key});
        try writer.writeAll("\'");
        if (index != len - 1) {
            try writer.writeAll(", ");
        } else if (len > 1) {
            try writer.writeByte(' ');
        }
    }
    try writer.writeAll("},\n");
}

fn writeValues(writer: anytype, node: *Node, indent: usize) ArrayList(u8).Writer.Error!void {
    try writeIndentation(writer, indent);
    try writer.writeAll(".values = &[_]Value{");
    if (node.children.items.len > 1) try writer.writeByte(' ');
    for (node.children.items) |c, index| {
        try writer.writeAll(".{");
        if (c.is_match) {
            const len1 = std.unicode.utf8ByteSequenceLength(c.characters[0]) catch unreachable;
            if (c.characters.len > len1) {
                const len2 = std.unicode.utf8ByteSequenceLength(c.characters[len1]) catch unreachable;
                try writer.writeAll(" '\\u{");
                try std.fmt.format(writer, "{X}", .{std.unicode.utf8Decode(c.characters[0..len1]) catch unreachable});
                try writer.writeAll("}', '\\u{");
                try std.fmt.format(writer, "{X}", .{std.unicode.utf8Decode(c.characters[len1 .. len1 + len2]) catch unreachable});
                try writer.writeAll("}' ");
            } else if (c.characters.len == len1) {
                try writer.writeAll("'\\u{");
                try std.fmt.format(writer, "{X}", .{std.unicode.utf8Decode(c.characters[0..len1]) catch unreachable});
                try writer.writeAll("}', null");
            } else {
                try writer.writeAll("null, null");
            }
        } else {
            try writer.writeAll("null, null");
        }
        try writer.writeAll("}");
        if (index != node.children.items.len - 1) {
            try writer.writeAll(", ");
        } else if (node.children.items.len > 1) {
            try writer.writeByte(' ');
        }
    }
    try writer.writeAll("},\n");
}

fn writeChildren(writer: anytype, node: *Node, indent: usize) ArrayList(u8).Writer.Error!void {
    try writeIndentation(writer, indent);
    try writer.writeAll(".children = &[_]?*const Node{\n");
    for (node.children.items) |c| {
        if (c.node) |n| {
            try writeIndentation(writer, indent + 1);
            try writer.writeAll("&.{\n");
            try writeKeys(writer, n, indent + 2);
            try writeValues(writer, n, indent + 2);
            try writeChildren(writer, n, indent + 2);
            try writeIndentation(writer, indent + 1);
            try writer.writeAll("},\n");
        } else {
            try writeIndentation(writer, indent + 1);
            try writer.writeAll("null,\n");
        }
    }
    try writeIndentation(writer, indent);
    try writer.writeAll("},\n");
}

fn writeIndentation(writer: anytype, indent: usize) !void {
    var i = indent;
    while (i > 0) : (i -= 1) {
        try writer.writeAll("    ");
    }
}
