// Copyright (C) 2021 Chadwain Holness
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const ArrayListUnmanaged = std.ArrayListUnmanaged;
const ComptimeStringMap = std.ComptimeStringMap;
const StringHashMapUnmanaged = std.StringHashMapUnmanaged;

pub const Dom = struct {
    document: Document = .{},
};

pub const Document = struct {
    doctype: ?DocumentType = null,
    element: ?Element = null,
    cdata: ArrayListUnmanaged(CharacterData) = .{},
    cdata_slices: [3]ArraySlice = .{.{ .begin = 0, .end = 0 }} ** 3,
    cdata_current_slice: u2 = 0,
    quirks_mode: QuirksMode = .no_quirks,

    pub const ArraySlice = struct {
        begin: usize,
        end: usize,

        pub fn sliceOf(self: ArraySlice, array: anytype) @TypeOf(array) {
            return array[self.begin..self.end];
        }
    };

    pub const QuirksMode = enum {
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
            assert(self.cdata_current_slice == 0);
            const num_cdatas = self.cdata_slices[0].end;
            self.cdata_slices[1] = .{ .begin = num_cdatas, .end = num_cdatas };
            self.cdata_current_slice = 1;
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
            assert(self.cdata_current_slice < 2);
            if (self.cdata_current_slice == 0) {
                assert(self.doctype == null);
                const num_cdatas = self.cdata_slices[0].end;
                self.cdata_slices[1] = .{ .begin = num_cdatas, .end = num_cdatas };
            }
            const num_cdatas = self.cdata_slices[1].end;
            self.cdata_slices[2] = .{ .begin = num_cdatas, .end = num_cdatas };
            self.cdata_current_slice = 2;
        }

        self.element = element;
        self.element.?.parent = .document;
        return &self.element.?;
    }

    pub fn insertCharacterData(self: *Document, allocator: *Allocator, data: []const u8, interface: CharacterDataInterface) !void {
        // Document nodes don't contain Text nodes. (DOM§4.2)
        assert(interface != .text);
        const location = try self.cdata.addOne(allocator);
        errdefer self.cdata.shrinkRetainingCapacity(self.cdata.items.len - 1);
        const copy = try allocator.dupe(u8, data);
        location.* = .{
            .data = .{ .items = copy, .capacity = copy.len },
            .interface = interface,
        };
        self.cdata_slices[self.cdata_current_slice].end += 1;
    }
};

pub const DocumentType = struct {
    name: []u8,
    publicId: []u8,
    systemId: []u8,
};

pub const ElementAttributes = StringHashMapUnmanaged([]u8);

pub const Namespace = enum {
    html,
    svg,
    mathml,
    unknown,
};

// TODO There are some Html elements missing from this list.
// Also, keep note of which elements are obsolete.
// (https://html.spec.whatwg.org/multipage/obsolete.html#non-conforming-features)
pub const ElementType = enum {
    html_a,
    html_address,
    html_applet,
    html_area,
    html_article,
    html_aside,
    html_b,
    html_base,
    html_basefont,
    html_bgsound,
    html_big,
    html_blockquote,
    html_body,
    html_br,
    html_button,
    html_caption,
    html_center,
    html_cite,
    html_code,
    html_col,
    html_colgroup,
    html_dd,
    html_details,
    html_dialog,
    html_dir,
    html_div,
    html_dl,
    html_dt,
    html_em,
    html_embed,
    html_fieldset,
    html_figcaption,
    html_figure,
    html_font,
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
    html_i,
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
    html_nobr,
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
    html_ruby,
    html_s,
    html_script,
    html_section,
    html_select,
    html_small,
    html_source,
    html_spacer,
    html_span,
    html_strike,
    html_strong,
    html_style,
    html_summary,
    html_table,
    html_tbody,
    html_td,
    html_template,
    html_test,
    html_textarea,
    html_tfoot,
    html_th,
    html_thead,
    html_title,
    html_tr,
    html_track,
    html_tt,
    html_u,
    html_ul,
    html_wbr,
    html_xmp,

    mathml_math,
    mathml_mi,
    mathml_mo,
    mathml_mn,
    mathml_ms,
    mathml_mtext,
    mathml_annotation_xml,

    svg_svg,
    svg_foreign_object,
    svg_desc,
    svg_title,

    custom_html,
    unknown,

    pub fn namespace(self: ElementType) Namespace {
        // TODO: Some metaprogramming to make this less fragile.
        const html_lowest = std.meta.fieldInfo(ElementType, .html_a).value;
        const html_highest = std.meta.fieldInfo(ElementType, .html_xmp).value;

        const mathml_lowest = std.meta.fieldInfo(ElementType, .mathml_math).value;
        const mathml_highest = std.meta.fieldInfo(ElementType, .mathml_annotation_xml).value;

        const svg_lowest = std.meta.fieldInfo(ElementType, .svg_svg).value;
        const svg_highest = std.meta.fieldInfo(ElementType, .svg_title).value;

        const value = @enumToInt(self);
        if ((value >= html_lowest and value <= html_highest) or self == .custom_html) {
            return .html;
        } else if (value >= mathml_lowest and value <= mathml_highest) {
            return .mathml;
        } else if (value >= svg_lowest and value <= svg_highest) {
            return .svg;
        } else {
            return .unknown;
        }
    }

    const html_map = html_map: {
        @setEvalBranchQuota(5000);
        break :html_map ComptimeStringMap(ElementType, .{
            .{ "a", .html_a },
            .{ "address", .html_address },
            .{ "applet", .html_applet },
            .{ "area", .html_area },
            .{ "article", .html_article },
            .{ "aside", .html_aside },
            .{ "b", .html_b },
            .{ "base", .html_base },
            .{ "basefont", .html_basefont },
            .{ "bgsound", .html_bgsound },
            .{ "big", .html_big },
            .{ "blockquote", .html_blockquote },
            .{ "body", .html_body },
            .{ "br", .html_br },
            .{ "button", .html_button },
            .{ "caption", .html_caption },
            .{ "center", .html_center },
            .{ "cite", .html_cite },
            .{ "code", .html_code },
            .{ "col", .html_col },
            .{ "colgroup", .html_colgroup },
            .{ "dd", .html_dd },
            .{ "details", .html_details },
            .{ "dialog", .html_dialog },
            .{ "dir", .html_dir },
            .{ "div", .html_div },
            .{ "dl", .html_dl },
            .{ "dt", .html_dt },
            .{ "em", .html_em },
            .{ "embed", .html_embed },
            .{ "fieldset", .html_fieldset },
            .{ "figcaption", .html_figcaption },
            .{ "figure", .html_figure },
            .{ "font", .html_font },
            .{ "footer", .html_footer },
            .{ "form", .html_form },
            .{ "frame", .html_frame },
            .{ "frameset", .html_frameset },
            .{ "h1", .html_h1 },
            .{ "h2", .html_h2 },
            .{ "h3", .html_h3 },
            .{ "h4", .html_h4 },
            .{ "h5", .html_h5 },
            .{ "h6", .html_h6 },
            .{ "head", .html_head },
            .{ "header", .html_header },
            .{ "hgroup", .html_hgroup },
            .{ "hr", .html_hr },
            .{ "html", .html_html },
            .{ "i", .html_i },
            .{ "iframe", .html_iframe },
            .{ "img", .html_img },
            .{ "input", .html_input },
            .{ "keygen", .html_keygen },
            .{ "li", .html_li },
            .{ "link", .html_link },
            .{ "listing", .html_listing },
            .{ "main", .html_main },
            .{ "marquee", .html_marquee },
            .{ "menu", .html_menu },
            .{ "meta", .html_meta },
            .{ "nav", .html_nav },
            .{ "nobr", .html_nobr },
            .{ "noembed", .html_noembed },
            .{ "noframes", .html_noframes },
            .{ "noscript", .html_noscript },
            .{ "object", .html_object },
            .{ "ol", .html_ol },
            .{ "optgroup", .html_optgroup },
            .{ "option", .html_option },
            .{ "p", .html_p },
            .{ "param", .html_param },
            .{ "plaintext", .html_plaintext },
            .{ "pre", .html_pre },
            .{ "rb", .html_rb },
            .{ "rp", .html_rp },
            .{ "rt", .html_rt },
            .{ "rtc", .html_rtc },
            .{ "ruby", .html_ruby },
            .{ "s", .html_s },
            .{ "script", .html_script },
            .{ "section", .html_section },
            .{ "select", .html_select },
            .{ "small", .html_small },
            .{ "source", .html_source },
            .{ "spacer", .html_spacer },
            .{ "span", .html_span },
            .{ "strike", .html_strike },
            .{ "strong", .html_strong },
            .{ "style", .html_style },
            .{ "summary", .html_summary },
            .{ "table", .html_table },
            .{ "tbody", .html_tbody },
            .{ "td", .html_td },
            .{ "template", .html_template },
            .{ "test", .html_test },
            .{ "textarea", .html_textarea },
            .{ "tfoot", .html_tfoot },
            .{ "th", .html_th },
            .{ "thead", .html_thead },
            .{ "title", .html_title },
            .{ "tr", .html_tr },
            .{ "track", .html_track },
            .{ "tt", .html_tt },
            .{ "u", .html_u },
            .{ "ul", .html_ul },
            .{ "wbr", .html_wbr },
            .{ "xmp", .html_xmp },
        });
    };

    pub fn fromStringHtml(string: []const u8) ?ElementType {
        return html_map.get(string);
    }
};

pub const ParentNode = union(enum) {
    element: *Element,
    document,
};

pub const Element = struct {
    element_type: ElementType,
    parent: ?ParentNode,
    attributes: ElementAttributes,
    children: ArrayListUnmanaged(ElementOrCharacterData),

    pub fn deinit(self: *Element, allocator: *Allocator) void {
        var attr_it = self.attributes.iterator();
        while (attr_it.next()) |attr| {
            allocator.free(attr.key_ptr.*);
            allocator.free(attr.value_ptr.*);
        }
        self.attributes.deinit(allocator);
        self.children.deinit(allocator);
    }

    pub fn namespace(self: Element) Namespace {
        return self.element_type.namespace();
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
        element.parent = .{ .element = self };
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
    element_type: ElementType,
    is: ?[]const u8,
    // TODO: Figure out what synchronous_custom_elements does.
    synchronous_custom_elements: bool,
) Element {
    _ = is;
    _ = synchronous_custom_elements;
    // TODO: Do custom element definition lookup.
    // TODO: Handle all 3 different cases for this procedure.
    var result = Element{
        .element_type = element_type,
        .parent = null,
        .attributes = .{},
        // TODO: Set the custom element state and custom element defintion.
        .children = .{},
    };
    // TODO: Check for a valid custom element name.
    return result;
}

pub fn printDom(dom: Dom, writer: anytype, allocator: *Allocator) !void {
    try std.fmt.format(writer, "Document: {s}\n", .{@tagName(dom.document.quirks_mode)});

    try printDocumentCdatas(dom, writer, 0);

    if (dom.document.doctype) |doctype| {
        try std.fmt.format(writer, "  DocumentType: name={s} publicId={s} systemId={s}\n", .{ doctype.name, doctype.publicId, doctype.systemId });
    }

    try printDocumentCdatas(dom, writer, 1);

    const ConstElementOrCharacterData = union(enum) {
        element: *const Element,
        cdata: *const CharacterData,
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

fn printDocumentCdatas(dom: Dom, writer: anytype, slice_index: u2) !void {
    const slice = dom.document.cdata_slices[slice_index];
    for (slice.sliceOf(dom.document.cdata.items)) |cdata| {
        try std.fmt.format(writer, "  {s}: {s}\n", .{ @tagName(cdata.interface), cdata.data.items });
    }
}
