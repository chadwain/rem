// Copyright (C) 2021-2023 Chadwain Holness
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//! Expects as program arguments the path to JSON data, and the path to
//! output the resulting zig file. Must be built with runtime safety enabled.

const std = @import("std");
const assert = std.debug.assert;
const ArrayList = std.ArrayList;
const Allocator = std.mem.Allocator;

comptime {
    assert(@import("builtin").mode == .Debug);
}

pub fn main() !void {
    var arena_allocator = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    const args = try std.process.argsAlloc(arena);
    const out_file_path = args[2];
    const cwd = std.fs.cwd();

    const input_data = blk: {
        const input_file = args[1];
        const file = try cwd.openFile(input_file, .{});
        defer file.close();
        break :blk try file.readToEndAlloc(arena, std.math.maxInt(c_int));
    };

    const tree = try createTree(arena, input_data);
    const output = try render(&tree, arena);

    var out_file = try cwd.createFile(out_file_path, .{});
    defer out_file.close();
    var writer = out_file.writer();
    try writer.writeAll(output);

    std.debug.print("Generated named character reference data at {s}\n", .{out_file_path});
}

const Node = struct {
    children: ArrayList(Entry),
    input: ArrayList(Item),

    const Entry = struct {
        key: u8,
        node: ?*Node,
        is_match: bool,
        characters: []const u8,

        fn getOrCreateChildNode(entry: *Entry, arena: Allocator) !*Node {
            if (entry.node == null) {
                entry.node = try arena.create(Node);
                entry.node.?.* = .{ .children = ArrayList(Entry).init(arena), .input = ArrayList(Item).init(arena) };
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
};

const Item = struct {
    name: []const u8,
    characters: []const u8,
};

fn createTree(arena: Allocator, input_data: []const u8) !Node {
    var parsed_json = try std.json.parseFromSlice(std.json.Value, arena, input_data, .{});

    var node = Node{ .children = ArrayList(Node.Entry).init(arena), .input = std.ArrayList(Item).init(arena) };
    var it = parsed_json.value.object.iterator();
    while (it.next()) |o| {
        const name = o.key_ptr.*[1..];
        try node.input.append(.{ .name = name, .characters = o.value_ptr.object.get("characters").?.string });
    }

    try createChildren(arena, &node);
    return node;
}

fn createChildren(arena: Allocator, node: *Node) error{OutOfMemory}!void {
    for (node.input.items) |i| {
        const key = i.name[0];
        const entry = try node.getOrCreateEntry(key);
        if (i.name.len > 1) {
            const child_node = try entry.getOrCreateChildNode(arena);
            try child_node.input.append(Item{ .name = i.name[1..], .characters = i.characters });
        } else {
            entry.is_match = true;
            entry.characters = i.characters;
        }
    }
    for (node.children.items) |c| {
        if (c.node) |n| {
            try createChildren(arena, n);
        }
    }
}

fn render(root: *const Node, arena: Allocator) ![]u8 {
    const Entry = packed struct { has_value: bool, has_children: bool, index_of_children: u14 };
    var entries = std.ArrayList(Entry).init(arena);

    const Child = packed struct { final: bool, char: u7 };
    var children = std.ArrayList(Child).init(arena);

    const Value = struct {
        first: ?u21,
        second: ?u21,

        fn fromCharacters(characters: []const u8) @This() {
            const len1 = std.unicode.utf8ByteSequenceLength(characters[0]) catch unreachable;
            const first = std.unicode.utf8Decode(characters[0..len1]) catch unreachable;
            if (characters.len <= len1) return @This(){ .first = first, .second = null };
            const len2 = std.unicode.utf8ByteSequenceLength(characters[len1]) catch unreachable;
            const second = std.unicode.utf8Decode(characters[len1 .. len1 + len2]) catch unreachable;
            return @This(){ .first = first, .second = second };
        }
    };
    var values = std.ArrayList(Value).init(arena);

    var stack = std.ArrayList(struct { node: ?*const Node, main_index: u16 }).init(arena);

    try stack.append(.{ .node = root, .main_index = 0 });
    try values.append(.{ .first = null, .second = null });
    try entries.append(.{ .has_value = false, .has_children = false, .index_of_children = undefined });

    while (stack.items.len > 0) {
        const stack_item = stack.pop();
        const stack_len = stack.items.len;

        const main_index = stack_item.main_index;
        const entry = &entries.items[main_index];
        const node = stack_item.node orelse {
            entry.has_children = false;
            entry.index_of_children = undefined;
            continue;
        };

        entry.has_children = true;
        entry.index_of_children = @intCast(children.items.len);
        for (node.children.items, 0..) |c, i| {
            const child_main_index: u16 = @intCast(entries.items.len);
            try children.append(.{ .char = @intCast(c.key), .final = (i == node.children.items.len - 1) });
            try stack.insert(stack_len, .{ .node = c.node, .main_index = child_main_index });
            const child_entry = try entries.addOne();

            child_entry.has_value = c.is_match;
            const value = if (c.is_match) Value.fromCharacters(c.characters) else Value{ .first = null, .second = null };
            try values.append(value);
        }
    }

    var output = ArrayList(u8).init(arena);
    var writer = output.writer();

    try writer.writeAll(
        \\//! This is an auto-generated file.
        \\
        \\const std = @import("std");
        \\
        \\pub const Index = packed struct {
        \\    array_index: u14,
        \\
        \\    pub fn entry(index: Index) Entry {
        \\        return @bitCast(entries[index.array_index]);
        \\    }
        \\
        \\    pub fn value(index: Index) Value {
        \\        return values[index.array_index];
        \\    }
        \\};
        \\
        \\pub const root_index = Index{ .array_index = 0 };
        \\
        \\pub const Entry = packed struct {
        \\    has_value: bool,
        \\    has_children: bool,
        \\    index_of_children: Index,
        \\
        \\    pub fn findChild(entry: Entry, char: u21) ?Index {
        \\        std.debug.assert(entry.has_children);
        \\        const char_u7 = std.math.cast(u7, char) orelse return null;
        \\
        \\        var i = entry.index_of_children.array_index;
        \\        while (true) : (i += 1) {
        \\            const child: Child = @bitCast(children[i]);
        \\            if (child.char == char_u7) {
        \\                return Index{ .array_index = i + 1 };
        \\            } else if (child.final) {
        \\                break;
        \\            }
        \\        }
        \\
        \\        return null;
        \\    }
        \\};
        \\
        \\const Child = packed struct {
        \\    final: bool,
        \\    char: u7,
        \\};
        \\
        \\comptime {
        \\    std.debug.assert(@bitSizeOf(Entry) == 16);
        \\    std.debug.assert(@bitSizeOf(Child) == 8);
        \\}
        \\
        \\/// If the 1st field is null, then the current string does not match any named character references.
        \\/// Otherwise, there is a match, and the 2nd field may or may not be null.
        \\pub const Value = @Type(std.builtin.Type{ .Struct = .{
        \\    .layout = .Auto,
        \\    .fields = &.{
        \\        .{
        \\            .name = "0",
        \\            .type = ?u21,
        \\            .default_value = @as(*const anyopaque, &@as(?u21, null)),
        \\            .is_comptime = false,
        \\            .alignment = @alignOf(?u21),
        \\        },
        \\        .{
        \\            .name = "1",
        \\            .type = ?u21,
        \\            .default_value = @as(*const anyopaque, &@as(?u21, null)),
        \\            .is_comptime = false,
        \\            .alignment = @alignOf(?u21),
        \\        },
        \\    },
        \\    .decls = &.{},
        \\    .is_tuple = true,
        \\} });
        \\
    );

    try writer.print("\nconst entries = [{}]u16{{", .{entries.items.len});
    for (entries.items, 0..) |entry, i| {
        if (i % 20 == 0) try writeNewline(writer);
        try writer.print("{}, ", .{@as(u16, @bitCast(entry))});
    }
    try writer.writeAll("};\n");

    try writer.print("\nconst children = [{}]u8{{", .{children.items.len});
    for (children.items, 0..) |child, i| {
        if (i % 20 == 0) try writeNewline(writer);
        try writer.print("{}, ", .{@as(u8, @bitCast(child))});
    }
    try writer.writeAll("};\n");

    try writer.print("\nconst values = [{}]Value{{", .{values.items.len});
    for (values.items, 0..) |value, i| {
        if (i % 5 == 0) try writeNewline(writer);
        try writer.writeAll("Value{");
        if (value.first) |first| {
            try writer.print("@as(?u21, '\\u{{{X}}}')", .{first});
            if (value.second) |second| {
                try writer.print(", @as(?u21, '\\u{{{X}}}')}}, ", .{second});
            } else {
                try writer.writeAll(", @as(?u21, null)}, ");
            }
        } else {
            try writer.writeAll("null, null}, ");
        }
    }
    try writer.writeAll("};\n");
    try writer.writeByte(0);

    var ast = try std.zig.Ast.parse(arena, output.items[0 .. output.items.len - 1 :0], .zig);
    return try ast.render(arena);
}

fn writeNewline(writer: anytype) !void {
    try writer.writeAll("\n    ");
}
