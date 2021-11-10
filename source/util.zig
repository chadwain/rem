// Copyright (C) 2021 Chadwain Holness
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

const std = @import("std");
const Allocator = std.mem.Allocator;
const ArrayListUnmanaged = std.ArrayListUnmanaged;
const StringHashMapUnmanaged = std.StringHashMapUnmanaged;

const html5 = @import("../html5.zig");
const DomTree = html5.dom.DomTree;
const Document = html5.dom.Document;
const Element = html5.dom.Element;
const CharacterData = html5.dom.CharacterData;

pub fn freeStringHashMap(map: *StringHashMapUnmanaged([]u8), allocator: *Allocator) void {
    var iterator = map.iterator();
    while (iterator.next()) |attr| {
        allocator.free(attr.key_ptr.*);
        allocator.free(attr.value_ptr.*);
    }
    map.deinit(allocator);
}

pub fn freeStringHashMapConst(map: *StringHashMapUnmanaged([]const u8), allocator: *Allocator) void {
    var iterator = map.iterator();
    while (iterator.next()) |attr| {
        allocator.free(attr.key_ptr.*);
        allocator.free(attr.value_ptr.*);
    }
    map.deinit(allocator);
}

pub fn eqlStringHashMaps(map1: StringHashMapUnmanaged([]u8), map2: StringHashMapUnmanaged([]u8)) bool {
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

pub fn printDocument(dom: *const DomTree, document: *const Document, writer: anytype, allocator: *Allocator) !void {
    try std.fmt.format(writer, "Document: {s}\n", .{@tagName(document.quirks_mode)});

    try printDocumentCdatas(document, writer, 0);

    if (document.doctype) |doctype| {
        try std.fmt.format(writer, "  DocumentType: name={s} publicId={s} systemId={s}\n", .{ doctype.name, doctype.publicId, doctype.systemId });
    }

    try printDocumentCdatas(document, writer, 1);

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
                try std.fmt.format(writer, "Element: type={s} local_name={s} namespace={s}", .{
                    @tagName(element.element_type),
                    element.localName(dom),
                    @tagName(element.namespace()),
                });
                var attr_it = element.attributes.iterator();
                try std.fmt.format(writer, " [ ", .{});
                while (attr_it.next()) |attr| {
                    try std.fmt.format(writer, "\"{s}\"=\"{s}\" ", .{ attr.key_ptr.*, attr.value_ptr.* });
                }
                try std.fmt.format(writer, "]\n", .{});
                var num_children = element.children.items.len;
                while (num_children > 0) : (num_children -= 1) {
                    const node = switch (element.children.items[num_children - 1]) {
                        .element => |e| ConstElementOrCharacterData{ .element = e },
                        .cdata => |c| ConstElementOrCharacterData{ .cdata = c },
                    };
                    try node_stack.append(allocator, .{ .node = node, .depth = item.depth + 1 });
                }
            },
            .cdata => |cdata| try printCdata(cdata, writer),
        }
    }

    try printDocumentCdatas(document, writer, 2);
}

fn printDocumentCdatas(document: *const Document, writer: anytype, slice_index: u2) !void {
    const slice = document.cdata_slices[slice_index];
    for (slice.sliceOf(document.cdata.items)) |cdata| {
        try printCdata(cdata, writer);
    }
}

fn printCdata(cdata: *const CharacterData, writer: anytype) !void {
    const interface = switch (cdata.interface) {
        .text => "Text",
        .comment => "Comment",
    };
    try std.fmt.format(writer, "  {s}: {s}\n", .{ interface, cdata.data.items });
}
