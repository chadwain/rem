// Copyright (C) 2021-2024 Chadwain Holness
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

const Dom = @This();

const node = @import("dom/node.zig");
pub const Document = node.Document;
pub const DocumentType = node.DocumentType;
pub const DocumentFormatter = node.DocumentFormatter;
pub const Namespace = node.Namespace;
pub const ElementType = node.ElementType;
pub const Element = node.Element;
pub const ParentNode = node.ParentNode;
pub const AttributePrefix = node.AttributePrefix;
pub const AttributeNamespace = node.AttributeNamespace;
pub const ElementAttributesKey = node.ElementAttributesKey;
pub const Attribute = node.Attribute;
pub const CharacterDataInterface = node.CharacterDataInterface;
pub const CharacterData = node.CharacterData;
pub const ElementOrCharacterData = node.ElementOrCharacterData;

pub const mutation = @import("dom/mutation.zig");

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const ArrayListUnmanaged = std.ArrayListUnmanaged;
const StaticStringMap = std.StaticStringMap;
const MultiArrayList = std.MultiArrayList;
const AutoHashMapUnmanaged = std.AutoHashMapUnmanaged;
const StringHashMapUnmanaged = std.StringHashMapUnmanaged;

allocator: Allocator,
/// For elements whose local name cannot be determined by looking at its element_type.
/// This does not take precedence over looking at element_type.
local_names: AutoHashMapUnmanaged(*const Element, []const u8) = .{},
/// Specifically holds MathML annotation-xml elements that are HTML integration points.
/// This does not take precedence if finding if an element is an HTML integration point could be done by other means.
html_integration_points: AutoHashMapUnmanaged(*const Element, void) = .{},

all_documents: ArrayListUnmanaged(*Document) = .{},
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
    for (self.all_documents.items) |item| {
        item.deinit(self.allocator);
        self.allocator.destroy(item);
    }
    self.all_documents.deinit(self.allocator);

    var iterator = self.local_names.valueIterator();
    while (iterator.next()) |local_name| self.allocator.free(local_name.*);
    self.local_names.deinit(self.allocator);

    self.html_integration_points.deinit(self.allocator);
}

pub const Exception = enum {
    NotFound,
    HierarchyRequest,
};

pub fn exception(self: *Dom, ex: Exception) error{DomException} {
    _ = self;
    std.debug.print("DOM Exception raised: {s}\n", .{@tagName(ex)});
    return error.DomException;
}

/// Creates a new Document node. The returned node is owned by the Dom.
pub fn makeDocument(self: *Dom) !*Document {
    const document = try self.allocator.create(Document);
    errdefer self.allocator.destroy(document);
    try self.all_documents.append(self.allocator, document);
    document.* = Document{};
    return document;
}

/// Creates a new CharacterData node. The returned node is owned by the Dom.
pub fn makeCdata(self: *Dom, data: []const u8, interface: CharacterDataInterface) !*CharacterData {
    const cdata = try self.allocator.create(CharacterData);
    errdefer self.allocator.destroy(cdata);
    try self.all_cdatas.append(self.allocator, cdata);
    cdata.* = try CharacterData.init(self.allocator, data, interface);
    return cdata;
}

/// Creates a new DocumentType node. The returned node is owned by the Dom.
pub fn makeDoctype(self: *Dom, doctype_name: ?[]const u8, public_identifier: ?[]const u8, system_identifier: ?[]const u8) !*DocumentType {
    const doctype = try self.allocator.create(DocumentType);
    errdefer self.allocator.destroy(doctype);
    try self.all_doctypes.append(self.allocator, doctype);
    doctype.* = try DocumentType.init(self.allocator, doctype_name, public_identifier, system_identifier);
    return doctype;
}

/// Creates a new Element node. The returned node is owned by the Dom.
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

pub fn registerHtmlIntegrationPoint(self: *Dom, element: *const Element) !void {
    assert(element.element_type == .mathml_annotation_xml);
    try self.html_integration_points.putNoClobber(self.allocator, element, {});
}

pub fn documentFormatter(self: *const Dom, document: *const Document, allocator: Allocator) DocumentFormatter {
    return .{
        .dom = self,
        .document = document,
        .allocator = allocator,
    };
}
