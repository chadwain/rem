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

pub const ElementType = enum {
    html_address,
    html_applet,
    html_area,
    html_article,
    html_aside,
    html_base,
    html_basefont,
    html_bgsound,
    html_blockquote,
    html_body,
    html_br,
    html_button,
    html_caption,
    html_center,
    html_col,
    html_colgroup,
    html_dd,
    html_details,
    html_dir,
    html_div,
    html_dl,
    html_dt,
    html_embed,
    html_fieldset,
    html_figcaption,
    html_figure,
    html_footer,
    html_form,
    html_frame,
    html_frameset,
    html_h1,
    html_h2,
    html_h3,
    html_h4,
    html_h5,
    html_h6,
    html_head,
    html_header,
    html_hgroup,
    html_hr,
    html_html,
    html_iframe,
    html_img,
    html_input,
    html_keygen,
    html_li,
    html_link,
    html_listing,
    html_main,
    html_marquee,
    html_menu,
    html_meta,
    html_nav,
    html_noembed,
    html_noframes,
    html_noscript,
    html_object,
    html_ol,
    html_optgroup,
    html_option,
    html_p,
    html_param,
    html_plaintext,
    html_pre,
    html_rb,
    html_rp,
    html_rt,
    html_rtc,
    html_script,
    html_section,
    html_select,
    html_source,
    html_style,
    html_summary,
    html_table,
    html_tbody,
    html_td,
    html_template,
    html_textarea,
    html_tfoot,
    html_th,
    html_thead,
    html_title,
    html_tr,
    html_track,
    html_ul,
    html_wbr,
    html_xmp,

    mathml_mi,
    mathml_mo,
    mathml_mn,
    mathml_ms,
    mathml_mtext,
    mathml_annotation_xml,

    svg_foreign_object,
    svg_desc,
    svg_title,
};

pub const Element = struct {
    attributes: ElementAttributes,
    namespace: WhatWgNamespace,
    namespace_prefix: ?[]u8,
    local_name: []u8,
    is: ?[]u8,
    element_type: ElementType,
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

    pub fn addAttribute(self: *Element, allocator: *Allocator, key: []const u8, value: []const u8) !void {
        const key_copy = try allocator.dupe(u8, key);
        errdefer allocator.free(key_copy);
        const value_copy = try allocator.dupe(u8, value);
        errdefer allocator.free(value_copy);
        try self.attributes.putNoClobber(allocator, key_copy, value_copy);
    }

    pub fn addAttributeNoReplace(self: *Element, allocator: *Allocator, key: []const u8, value: []const u8) !void {
        if (!self.attributes.contains(key)) {
            return self.addAttribute(allocator, key, value);
        }
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
        try self.data.appendSlice(allocator, data);
    }
};

pub const CharacterDataInterface = enum {
    // NOTE: CharacterData is an abstract interface.
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
    element_type: ElementType,
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
    var result = Element{
        .attributes = .{},
        .namespace = namespace,
        .namespace_prefix = element_prefix,
        .local_name = element_local_name,
        // TODO: Set the custom element state and custom element defintion.
        .is = element_is,
        .element_type = element_type,
        .children = .{},
    };
    // TODO: Check for a valid custom element name.
    return result;
}
