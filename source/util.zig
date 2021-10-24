// Copyright (C) 2021 Chadwain Holness
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

const std = @import("std");
const Allocator = std.mem.Allocator;
const ArrayListUnmanaged = std.ArrayListUnmanaged;
const StringHashMapUnmanaged = std.StringHashMapUnmanaged;

const html5 = @import("../html5.zig");
const Dom = html5.dom;

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

pub fn utf8DecodeComptimeLen(comptime string: []const u8) usize {
    var i: usize = 0;
    var decoded_len: usize = 0;
    while (i < string.len) {
        i += std.unicode.utf8ByteSequenceLength(string[i]) catch unreachable;
        decoded_len += 1;
    }
    return decoded_len;
}

pub fn utf8DecodeComptime(comptime string: []const u8) [utf8DecodeComptimeLen(string)]u21 {
    var result: [utf8DecodeComptimeLen(string)]u21 = undefined;
    if (result.len == 0) return result;
    var decoded_it = std.unicode.Utf8View.initComptime(string).iterator();
    var i: usize = 0;
    while (decoded_it.nextCodepoint()) |codepoint| {
        result[i] = codepoint;
        i += 1;
    }
    return result;
}

pub fn printDom(dom: Dom.Dom, writer: anytype, allocator: *Allocator) !void {
    try std.fmt.format(writer, "Document: {s}\n", .{@tagName(dom.document.quirks_mode)});

    try printDocumentCdatas(dom, writer, 0);

    if (dom.document.doctype) |doctype| {
        try std.fmt.format(writer, "  DocumentType: name={s} publicId={s} systemId={s}\n", .{ doctype.name, doctype.publicId, doctype.systemId });
    }

    try printDocumentCdatas(dom, writer, 1);

    const ConstElementOrCharacterData = union(enum) {
        element: *const Dom.Element,
        cdata: *const Dom.CharacterData,
    };
    var node_stack = ArrayListUnmanaged(struct { node: ConstElementOrCharacterData, depth: usize }){};
    defer node_stack.deinit(allocator);
    if (dom.document.element) |*document_element| {
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
                const namespace_prefix = element.namespace_prefix orelse "";
                const is = element.is orelse "";
                try std.fmt.format(writer, "Element: type={s} local_name={s} namespace={s} prefix={s} is={s}", .{
                    @tagName(element.element_type),
                    element.local_name,
                    @tagName(element.namespace),
                    namespace_prefix,
                    is,
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
            .cdata => |cdata| try std.fmt.format(writer, "{s}: {s}\n", .{ @tagName(cdata.interface), cdata.data.items }),
        }
    }

    try printDocumentCdatas(dom, writer, 2);
}

fn printDocumentCdatas(dom: Dom.Dom, writer: anytype, slice_index: u2) !void {
    const slice = dom.document.cdata_slices[slice_index];
    for (slice.sliceOf(dom.document.cdata.items)) |cdata| {
        try std.fmt.format(writer, "  {s}: {s}\n", .{ @tagName(cdata.interface), cdata.data.items });
    }
}
