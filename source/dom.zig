const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const ArrayListUnmanaged = std.ArrayListUnmanaged;
const StringHashMapUnmanaged = std.StringHashMapUnmanaged;

pub const Dom = struct {
    document: Document = .{},
};

pub const Document = struct {
    doctype: ?DocumentType = null,
    element: ?Element = null,
    cdata_nodes: ArrayListUnmanaged(CharacterData) = .{},
    cdata_nodes_splits: [3][2]usize = .{.{ 0, 0 }} ** 3,
    cdata_nodes_splits_current: u2 = 0,
    quirks_mode: QuirksMode = .no_quirks,

    const QuirksMode = enum {
        no_quirks,
        quirks,
        limited_quirks,
    };

    pub fn insertDocumentType(
        self: *Document,
        allocator: *Allocator,
        doctype_name: ?[]const u8,
        public_identifier: ?[]const u8,
        system_identifier: ?[]const u8,
    ) !*DocumentType {
        {
            assert(self.doctype == null);
            assert(self.cdata_nodes_splits_current == 0);
            const num_cdatas = self.cdata_nodes_splits[0][1];
            self.cdata_nodes_splits[1] = .{ num_cdatas, num_cdatas };
            self.cdata_nodes_splits_current = 1;
        }

        const name = doctype_name orelse "";
        const publicId = public_identifier orelse "";
        const systemId = system_identifier orelse "";
        const strings = try allocator.alloc(u8, name.len + publicId.len + systemId.len);
        self.doctype = DocumentType{
            .name = strings[0..name.len],
            .publicId = strings[name.len .. name.len + publicId.len],
            .systemId = strings[name.len + publicId.len ..],
        };
        std.mem.copy(u8, self.doctype.?.name, name);
        std.mem.copy(u8, self.doctype.?.publicId, publicId);
        std.mem.copy(u8, self.doctype.?.systemId, systemId);
        return &self.doctype.?;
    }

    pub fn insertElement(self: *Document, element: Element) *Element {
        {
            assert(self.element == null);
            assert(self.cdata_nodes_splits_current < 2);
            if (self.cdata_nodes_splits_current == 0) {
                assert(self.doctype == null);
                const num_cdatas = self.cdata_nodes_splits[0][1];
                self.cdata_nodes_splits[1] = .{ num_cdatas, num_cdatas };
            }
            const num_cdatas = self.cdata_nodes_splits[1][1];
            self.cdata_nodes_splits[2] = .{ num_cdatas, num_cdatas };
            self.cdata_nodes_splits_current = 2;
        }

        self.element = element;
        return &self.element.?;
    }

    pub fn insertCharacterData(self: *Document, allocator: *Allocator, data: []const u8, interface: CharacterDataInterface) !void {
        // Document nodes don't contain Text nodes.
        assert(interface != .text);
        const location = try self.cdata_nodes.addOne(allocator);
        errdefer self.cdata_nodes.shrinkRetainingCapacity(self.cdata_nodes.items.len - 1);
        const copy = try allocator.dupe(u8, data);
        location.* = .{
            .data = .{ .items = copy, .capacity = copy.len },
            .interface = interface,
        };
        self.cdata_nodes_splits[self.cdata_nodes_splits_current][1] += 1;
    }
};

pub const DocumentType = struct {
    name: []u8,
    publicId: []u8,
    systemId: []u8,
};

pub const ElementAttributes = StringHashMapUnmanaged([]u8);

pub const WhatWgNamespace = enum {
    html,
};

pub const ElementInterface = enum {
    element,
    html_html,
    html_head,
    html_body,
    html_script,
};

pub const Element = struct {
    attributes: ElementAttributes,
    namespace: WhatWgNamespace,
    namespace_prefix: ?[]u8,
    local_name: []u8,
    is: ?[]u8,
    interface: ElementInterface,
    children: ArrayListUnmanaged(ElementOrCharacterData),

    pub fn deinit(self: *Element, allocator: *Allocator) void {
        var attr_it = self.attributes.iterator();
        while (attr_it.next()) |attr| {
            allocator.free(attr.key_ptr.*);
            allocator.free(attr.value_ptr.*);
        }
        self.attributes.deinit(allocator);
        if (self.namespace_prefix) |ns| allocator.free(ns);
        allocator.free(self.local_name);
        if (self.is) |is| allocator.free(is);
    }

    pub fn appendAttribute(self: *Element, allocator: *Allocator, key: []u8, value: []u8) !void {
        // TODO: Appending an attribute has more steps.
        try self.attributes.put(allocator, key, value);
    }

    pub fn insertElement(self: *Element, allocator: *Allocator, child: Element) !*Element {
        const child_location = try self.children.addOne(allocator);
        errdefer self.children.shrinkRetainingCapacity(self.children.items.len - 1);
        const element = try allocator.create(Element);
        errdefer allocator.destroy(element);
        element.* = child;
        child_location.* = .{ .element = element };
        return element;
    }

    pub fn insertCharacterData(self: *Element, allocator: *Allocator, data: []const u8, interface: CharacterDataInterface) !void {
        const child_location = try self.children.addOne(allocator);
        errdefer self.children.shrinkRetainingCapacity(self.children.items.len - 1);
        const cdata = try allocator.create(CharacterData);
        errdefer allocator.destroy(cdata);
        const data_copy = try allocator.dupe(u8, data);
        errdefer allocator.free(data_copy);
        cdata.* = .{
            // Ideally, this should be ArrayListUnmanaged(u8).fromOwnedSlice().
            .data = std.ArrayList(u8).fromOwnedSlice(allocator, data_copy).toUnmanaged(),
            .interface = interface,
        };
        child_location.* = .{ .cdata = cdata };
    }
};

pub const CharacterData = struct {
    // TODO Maybe just store a slice
    data: ArrayListUnmanaged(u8),
    interface: CharacterDataInterface,

    pub fn append(self: *CharacterData, allocator: *Allocator, data: []const u8) !void {
        // TODO: Appending data has more steps.
        try self.data.appendSlice(allocator, data);
    }
};

pub const CharacterDataInterface = enum {
    // NOTE: CharacterData is an anstract interface.
    text,
    comment,
};

pub const ElementOrCharacterData = union(enum) {
    element: *Element,
    cdata: *CharacterData,
};

pub fn createAnElement(
    allocator: *Allocator,
    local_name: []const u8,
    namespace: WhatWgNamespace,
    prefix: ?[]const u8,
    is: ?[]const u8,
    interface: ElementInterface,
    // TODO: Figure out what synchronous_custom_elements does.
    synchronous_custom_elements: bool,
) !Element {
    _ = synchronous_custom_elements;
    // TODO: Do custom element definition lookup.
    // TODO: Handle all 3 different cases for this procedure.
    const element_local_name = try allocator.dupe(u8, local_name);
    errdefer allocator.free(element_local_name);
    const element_prefix = if (prefix) |p| try allocator.dupe(u8, p) else null;
    errdefer if (element_prefix) |p| allocator.free(p);
    const element_is = if (is) |s| try allocator.dupe(u8, s) else null;
    errdefer if (element_is) |s| allocator.free(s);
    // TODO: The caller of this function must set the element interface (aka html_element_type).
    var result = Element{
        .attributes = .{},
        .namespace = namespace,
        .namespace_prefix = element_prefix,
        .local_name = element_local_name,
        // TODO: Set the custom element state and custom element defintion.
        .is = element_is,
        .interface = interface,
        .children = .{},
    };
    // TODO: Check for a valid custom element name.
    return result;
}
