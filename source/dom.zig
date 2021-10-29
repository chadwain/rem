// Copyright (C) 2021 Chadwain Holness
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const ArrayListUnmanaged = std.ArrayListUnmanaged;
const ComptimeStringMap = std.ComptimeStringMap;
const AutoHashMapUnmanaged = std.AutoHashMapUnmanaged;
const StringHashMapUnmanaged = std.StringHashMapUnmanaged;

pub const mutation = @import("dom/mutation.zig");

pub const DomException = enum {
    NotFound,
    HierarchyRequest,
};

pub const Dom = struct {
    document: Document = .{},
    allocator: *Allocator,

    /// For elements whose local name cannot be determined by looking at its element_type.
    local_names: AutoHashMapUnmanaged(*const Element, []const u8) = .{},

    all_elements: ArrayListUnmanaged(*Element) = .{},
    all_cdatas: ArrayListUnmanaged(*CharacterData) = .{},
    all_doctypes: ArrayListUnmanaged(*DocumentType) = .{},

    pub fn deinit(self: *Dom) void {
        for (self.all_elements.items) |item| {
            item.deinit(self.allocator);
            self.allocator.destroy(item);
        }
        self.all_elements.deinit(self.allocator);
        for (self.all_cdatas.items) |item| {
            item.deinit(self.allocator);
            self.allocator.destroy(item);
        }
        self.all_cdatas.deinit(self.allocator);
        for (self.all_doctypes.items) |item| {
            item.deinit(self.allocator);
            self.allocator.destroy(item);
        }
        self.all_doctypes.deinit(self.allocator);

        self.document.deinit(self.allocator);

        var iterator = self.local_names.valueIterator();
        while (iterator.next()) |local_name| self.allocator.free(local_name.*);
        self.local_names.deinit(self.allocator);
    }

    pub fn exception(self: *Dom, ex: DomException) error{DomException} {
        _ = self;
        std.debug.print("DOM Exception raised: {s}\n", .{@tagName(ex)});
        return error.DomException;
    }

    pub fn makeCdata(self: *Dom, data: []const u8, interface: CharacterDataInterface) !*CharacterData {
        const cdata = try self.allocator.create(CharacterData);
        errdefer self.allocator.destroy(cdata);
        try self.all_cdatas.append(self.allocator, cdata);
        cdata.* = try CharacterData.init(self.allocator, data, interface);
        return cdata;
    }

    pub fn makeDoctype(self: *Dom, doctype_name: ?[]const u8, public_identifier: ?[]const u8, system_identifier: ?[]const u8) !*DocumentType {
        const doctype = try self.allocator.create(DocumentType);
        errdefer self.allocator.destroy(doctype);
        try self.all_doctypes.append(self.allocator, doctype);
        doctype.* = try DocumentType.init(self.allocator, doctype_name, public_identifier, system_identifier);
        return doctype;
    }

    pub fn makeElement(self: *Dom, element_type: ElementType) !*Element {
        // TODO: This function should implement the "create an element" algorithm.
        // https://dom.spec.whatwg.org/#concept-create-element
        const element = try self.allocator.create(Element);
        errdefer self.allocator.destroy(element);
        try self.all_elements.append(self.allocator, element);
        element.* = Element{ .element_type = element_type, .attributes = .{}, .parent = null, .children = .{} };
        return element;
    }

    pub fn registerLocalName(self: *Dom, element: *const Element, name: []const u8) !void {
        const copy = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(copy);
        try self.local_names.putNoClobber(self.allocator, element, copy);
    }
};

pub const Document = struct {
    doctype: ?*DocumentType = null,
    element: ?*Element = null,
    cdata: ArrayListUnmanaged(*CharacterData) = .{},
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

    fn deinit(self: *Document, allocator: *Allocator) void {
        self.cdata.deinit(allocator);
    }
};

pub const DocumentType = struct {
    name: []u8,
    publicId: []u8,
    systemId: []u8,

    fn init(allocator: *Allocator, doctype_name: ?[]const u8, public_identifier: ?[]const u8, system_identifier: ?[]const u8) !DocumentType {
        const name = doctype_name orelse "";
        const publicId = public_identifier orelse "";
        const systemId = system_identifier orelse "";
        const strings = try allocator.alloc(u8, name.len + publicId.len + systemId.len);

        var result = @as(DocumentType, undefined);
        var index: usize = 0;
        result.name = strings[index .. index + name.len];
        index += name.len;
        result.publicId = strings[index .. index + publicId.len];
        index += publicId.len;
        result.systemId = strings[index .. index + systemId.len];

        std.mem.copy(u8, result.name, name);
        std.mem.copy(u8, result.publicId, publicId);
        std.mem.copy(u8, result.systemId, systemId);

        return result;
    }

    fn deinit(self: *DocumentType, allocator: *Allocator) void {
        const memory = self.name.ptr[0 .. self.name.len + self.publicId.len + self.systemId.len];
        allocator.free(memory);
    }
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
    html_sub,
    html_summary,
    html_sup,
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
    html_var,
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
    custom_mathml,
    custom_svg,
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
        } else if ((value >= mathml_lowest and value <= mathml_highest) or self == .custom_mathml) {
            return .mathml;
        } else if ((value >= svg_lowest and value <= svg_highest) or self == .custom_svg) {
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
            .{ "sub", .html_sub },
            .{ "summary", .html_summary },
            .{ "sup", .html_sup },
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
            .{ "var", .html_var },
            .{ "wbr", .html_wbr },
            .{ "xmp", .html_xmp },
        });
    };

    pub fn fromStringHtml(string: []const u8) ?ElementType {
        return html_map.get(string);
    }

    pub fn toLocalName(self: ElementType) ?[]const u8 {
        return switch (self) {
            .html_a => "a",
            .html_address => "address",
            .html_applet => "applet",
            .html_area => "area",
            .html_article => "article",
            .html_aside => "aside",
            .html_b => "b",
            .html_base => "base",
            .html_basefont => "basefont",
            .html_bgsound => "bgsound",
            .html_big => "big",
            .html_blockquote => "blockquote",
            .html_body => "body",
            .html_br => "br",
            .html_button => "button",
            .html_caption => "caption",
            .html_center => "center",
            .html_cite => "cite",
            .html_code => "code",
            .html_col => "col",
            .html_colgroup => "colgroup",
            .html_dd => "dd",
            .html_details => "details",
            .html_dialog => "dialog",
            .html_dir => "dir",
            .html_div => "div",
            .html_dl => "dl",
            .html_dt => "dt",
            .html_em => "em",
            .html_embed => "embed",
            .html_fieldset => "fieldset",
            .html_figcaption => "figcaption",
            .html_figure => "figure",
            .html_font => "font",
            .html_footer => "footer",
            .html_form => "form",
            .html_frame => "frame",
            .html_frameset => "frameset",
            .html_h1 => "h1",
            .html_h2 => "h2",
            .html_h3 => "h3",
            .html_h4 => "h4",
            .html_h5 => "h5",
            .html_h6 => "h6",
            .html_head => "head",
            .html_header => "header",
            .html_hgroup => "hgroup",
            .html_hr => "hr",
            .html_html => "html",
            .html_i => "i",
            .html_iframe => "iframe",
            .html_img => "img",
            .html_input => "input",
            .html_keygen => "keygen",
            .html_li => "li",
            .html_link => "link",
            .html_listing => "listing",
            .html_main => "main",
            .html_marquee => "marquee",
            .html_menu => "menu",
            .html_meta => "meta",
            .html_nav => "nav",
            .html_nobr => "nobr",
            .html_noembed => "noembed",
            .html_noframes => "noframes",
            .html_noscript => "noscript",
            .html_object => "object",
            .html_ol => "ol",
            .html_optgroup => "optgroup",
            .html_option => "option",
            .html_p => "p",
            .html_param => "param",
            .html_plaintext => "plaintext",
            .html_pre => "pre",
            .html_rb => "rb",
            .html_rp => "rp",
            .html_rt => "rt",
            .html_rtc => "rtc",
            .html_ruby => "ruby",
            .html_s => "s",
            .html_script => "script",
            .html_section => "section",
            .html_select => "select",
            .html_small => "small",
            .html_source => "source",
            .html_spacer => "spacer",
            .html_span => "span",
            .html_strike => "strike",
            .html_strong => "strong",
            .html_style => "style",
            .html_sub => "sub",
            .html_summary => "summary",
            .html_sup => "sup",
            .html_table => "table",
            .html_tbody => "tbody",
            .html_td => "td",
            .html_template => "template",
            .html_test => "test",
            .html_textarea => "textarea",
            .html_tfoot => "tfoot",
            .html_th => "th",
            .html_thead => "thead",
            .html_title => "title",
            .html_tr => "tr",
            .html_track => "track",
            .html_tt => "tt",
            .html_u => "u",
            .html_ul => "ul",
            .html_var => "var",
            .html_wbr => "wbr",
            .html_xmp => "xmp",

            .mathml_math => "math",
            .mathml_mi => @panic("TODO: ElementType.toLocalName for mathml_mi elements"),
            .mathml_mo => @panic("TODO: ElementType.toLocalName for mathml_mo elements"),
            .mathml_mn => @panic("TODO: ElementType.toLocalName for mathml_mn elements"),
            .mathml_ms => @panic("TODO: ElementType.toLocalName for mathml_ms elements"),
            .mathml_mtext => @panic("TODO: ElementType.toLocalName for mathml_mtext elements"),
            .mathml_annotation_xml => @panic("TODO: ElementType.toLocalName for mathml_annotation_xml elements"),

            .svg_svg => "svg",
            .svg_foreign_object => "foreignObject",
            .svg_desc => "desc",
            .svg_title => "title",

            .custom_html,
            .custom_mathml,
            .custom_svg,
            .unknown,
            => null,
        };
    }
};

/// The type for the children of an Element node.
pub const ElementOrCharacterData = union(enum) {
    element: *Element,
    cdata: *CharacterData,
};

/// The type for the parent of an Element node.
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

    pub fn localName(self: *const Element, dom: *const Dom) []const u8 {
        return self.element_type.toLocalName() orelse dom.local_names.get(self) orelse unreachable;
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

    pub fn lastChild(self: *Element) ?ElementOrCharacterData {
        if (self.children.items.len != 0) {
            return self.children.items[self.children.items.len - 1];
        } else {
            return null;
        }
    }

    pub fn indexOfChild(self: *Element, child: ElementOrCharacterData) ?usize {
        for (self.children.items) |c, i| {
            if (std.meta.eql(child, c)) return i;
        } else return null;
    }

    pub fn childBefore(self: *Element, child: ElementOrCharacterData) ?ElementOrCharacterData {
        if (self.children.items.len == 0) return null;
        if (std.meta.eql(self.children.items[0], child)) return null;
        const index = self.indexOfChild(child).?;
        return self.children.items[index - 1];
    }
};

pub const CharacterDataInterface = enum {
    // NOTE: CharacterData is an abstract interface.
    text,
    comment,
};

pub const CharacterData = struct {
    // TODO Maybe just store a slice
    data: ArrayListUnmanaged(u8) = .{},
    interface: CharacterDataInterface,

    fn init(allocator: *Allocator, data: []const u8, interface: CharacterDataInterface) !CharacterData {
        var result = CharacterData{ .interface = interface };
        try result.data.appendSlice(allocator, data);
        return result;
    }

    fn deinit(self: *CharacterData, allocator: *Allocator) void {
        self.data.deinit(allocator);
    }

    // TODO: Move this function to mutation.
    pub fn append(self: *CharacterData, allocator: *Allocator, data: []const u8) !void {
        try self.data.appendSlice(allocator, data);
    }
};
