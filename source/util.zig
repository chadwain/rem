// Copyright (C) 2021-2023 Chadwain Holness
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const ArrayListUnmanaged = std.ArrayListUnmanaged;
const StringHashMapUnmanaged = std.StringHashMapUnmanaged;

const rem = @import("../rem.zig");
const Dom = rem.Dom;
const Document = Dom.Document;
const Element = Dom.Element;
const CharacterData = Dom.CharacterData;

pub fn freeStringHashMap(map: *StringHashMapUnmanaged([]u8), allocator: Allocator) void {
    var iterator = map.iterator();
    while (iterator.next()) |attr| {
        allocator.free(attr.key_ptr.*);
        allocator.free(attr.value_ptr.*);
    }
    map.deinit(allocator);
}

pub fn freeStringHashMapConst(map: *StringHashMapUnmanaged([]const u8), allocator: Allocator) void {
    var iterator = map.iterator();
    while (iterator.next()) |attr| {
        allocator.free(attr.key_ptr.*);
        allocator.free(attr.value_ptr.*);
    }
    map.deinit(allocator);
}

// `map1` and `map2` are of type std.[String]HashMap[Unmanaged]
pub fn eqlStringHashMaps(map1: anytype, map2: @TypeOf(map1)) bool {
    if (map1.count() != map2.count()) return false;
    var iterator = map1.iterator();
    while (iterator.next()) |attr| {
        const map2_value = map2.get(attr.key_ptr.*) orelse return false;
        if (!std.mem.eql(u8, attr.value_ptr.*, map2_value)) return false;
    }
    return true;
}

pub fn eqlNullSlices(comptime T: type, slice1: ?[]const T, slice2: ?[]const T) bool {
    if (slice1) |a| {
        const b = slice2 orelse return false;
        return std.mem.eql(T, a, b);
    } else {
        return slice2 == null;
    }
}

pub fn eqlNullSlices2(comptime T: type, slice1: []const T, slice2: ?[]const T) bool {
    const b = slice2 orelse return false;
    return std.mem.eql(T, slice1, b);
}

pub const eqlIgnoreCase = std.ascii.eqlIgnoreCase;

/// Assumes the second string is already lowercase.
pub fn eqlIgnoreCase2(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (b) |c2, i| {
        assert(c2 == std.ascii.toLower(c2));
        if (c2 != std.ascii.toLower(a[i])) return false;
    }
    return true;
}

pub fn toLowercaseComptime(comptime string: []const u8) [string.len]u8 {
    var result: [string.len]u8 = undefined;
    for (string) |c, i| {
        result[i] = std.ascii.toLower(c);
    }
    return result;
}

pub fn mapToLowercaseComptime(comptime strings: []const []const u8) [strings.len][]const u8 {
    comptime {
        var result: [strings.len][]const u8 = undefined;
        for (strings) |s, i| {
            result[i] = &toLowercaseComptime(s);
        }
        return result;
    }
}

/// Assumes `needle` is already lowercase.
pub fn startsWithIgnoreCase2(haystack: []const u8, needle: []const u8) bool {
    return if (needle.len > haystack.len) false else eqlIgnoreCase2(haystack[0..needle.len], needle);
}

pub fn utf8DecodeStringComptimeLen(comptime string: []const u8) usize {
    var i: usize = 0;
    var decoded_len: usize = 0;
    while (i < string.len) {
        i += std.unicode.utf8ByteSequenceLength(string[i]) catch unreachable;
        decoded_len += 1;
    }
    return decoded_len;
}

pub fn utf8DecodeStringComptime(comptime string: []const u8) [utf8DecodeStringComptimeLen(string)]u21 {
    var result: [utf8DecodeStringComptimeLen(string)]u21 = undefined;
    if (result.len == 0) return result;
    var decoded_it = std.unicode.Utf8View.initComptime(string).iterator();
    var i: usize = 0;
    while (decoded_it.nextCodepoint()) |codepoint| {
        result[i] = codepoint;
        i += 1;
    }
    return result;
}

pub fn printDocument(writer: anytype, document: *const Document, dom: *const Dom, allocator: Allocator) !void {
    try std.fmt.format(writer, "Document: {s}\n", .{@tagName(document.quirks_mode)});

    try printDocumentCdatas(writer, document, 0);

    if (document.doctype) |doctype| {
        try std.fmt.format(writer, "  DocumentType: name={s} publicId={s} systemId={s}\n", .{ doctype.name, doctype.publicId, doctype.systemId });
    }

    try printDocumentCdatas(writer, document, 1);

    const ConstElementOrCharacterData = union(enum) {
        element: *const Element,
        cdata: *const CharacterData,
    };
    var node_stack = ArrayListUnmanaged(struct { node: ConstElementOrCharacterData, depth: usize }){};
    defer node_stack.deinit(allocator);

    if (document.element) |document_element| {
        try node_stack.append(allocator, .{ .node = .{ .element = document_element }, .depth = 1 });
    }

    while (node_stack.items.len > 0) {
        const item = node_stack.pop();
        var len = item.depth;
        while (len > 0) : (len -= 1) {
            try std.fmt.format(writer, "  ", .{});
        }
        switch (item.node) {
            .element => |element| {
                try std.fmt.format(writer, "Element: type={s} local_name={s} namespace={s} attributes=[", .{
                    @tagName(element.element_type),
                    element.localName(dom),
                    @tagName(element.namespace()),
                });
                const num_attributes = element.numAttributes();
                if (num_attributes > 0) {
                    try writer.writeAll(" ");
                    const attribute_slice = element.attributes.slice();
                    var i: u32 = 0;
                    while (i < num_attributes) : (i += 1) {
                        const key = attribute_slice.items(.key)[i];
                        const value = attribute_slice.items(.value)[i];
                        if (key.prefix == .none) {
                            try std.fmt.format(writer, "\"{s}\"=\"{s}\" ", .{ key.local_name, value });
                        } else {
                            try std.fmt.format(writer, "\"{s}:{s}\"=\"{s}\" ", .{ @tagName(key.prefix), key.local_name, value });
                        }
                    }
                }
                try std.fmt.format(writer, "]\n", .{});

                // Add children to stack
                var num_children = element.children.items.len;
                while (num_children > 0) : (num_children -= 1) {
                    const node = switch (element.children.items[num_children - 1]) {
                        .element => |e| ConstElementOrCharacterData{ .element = e },
                        .cdata => |c| ConstElementOrCharacterData{ .cdata = c },
                    };
                    try node_stack.append(allocator, .{ .node = node, .depth = item.depth + 1 });
                }
            },
            .cdata => |cdata| try printCdata(writer, cdata),
        }
    }

    try printDocumentCdatas(writer, document, 2);
}

fn printDocumentCdatas(writer: anytype, document: *const Document, endpoint_index: u2) !void {
    const endpoint = document.cdata_endpoints[endpoint_index];
    for (endpoint.sliceOf(document.cdata.items)) |cdata| {
        try printCdata(writer, cdata);
    }
}

fn printCdata(writer: anytype, cdata: *const CharacterData) !void {
    const interface = switch (cdata.interface) {
        .text => "Text",
        .comment => "Comment",
    };
    try std.fmt.format(writer, "{s}: \"{}\"\n", .{ interface, std.zig.fmtEscapes(cdata.data.items) });
}
