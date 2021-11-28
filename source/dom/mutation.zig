// Copyright (C) 2021 Chadwain Holness
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//! This file implements the mutation algorithms of the DOM.
//! https://dom.spec.whatwg.org/#mutation-algorithms

const std = @import("std");
const assert = std.debug.assert;

const rem = @import("../../rem.zig");
const Dom = rem.dom.Dom;
const Document = rem.dom.Document;
const DocumentType = rem.dom.DocumentType;
const Element = rem.dom.Element;
const CharacterData = rem.dom.CharacterData;
const ElementOrCharacterData = rem.dom.ElementOrCharacterData;

pub const SuppressObservers = enum { Suppress, NoSuppress };

/// This is the DOM's append mutation algorithm, specialized for a Document parent and a DocumentType node.
pub fn documentAppendDocumentType(dom: *Dom, document: *Document, doctype: *DocumentType, suppress: SuppressObservers) !void {
    // Ensure pre-insertion validity. Only step 6 of this algorithm applies.
    if (document.doctype != null or document.element != null) {
        return dom.exception(.HierarchyRequest);
    }

    // The pre-insert steps are essentially a no-op.

    // Insert doctype into document.
    // TODO: Most of the steps in this algorithm have been skipped.
    _ = suppress;
    {
        assert(document.cdata_current_endpoint == 0);
        const num_cdatas = document.cdata_endpoints[0].end;
        document.cdata_endpoints[1] = .{ .begin = num_cdatas, .end = num_cdatas };
        document.cdata_current_endpoint = 1;
    }
    document.doctype = doctype;
}

/// This is the DOM's append mutation algorithm, specialized for a Document parent and an Element node.
pub fn documentAppendElement(dom: *Dom, document: *Document, element: *Element, suppress: SuppressObservers) !void {
    // Ensure pre-insertion validity. Only step 6 of this algorithm applies.
    if (document.element != null) {
        return dom.exception(.HierarchyRequest);
    }

    // The pre-insert steps are essentially a no-op.

    // Insert element into document.
    // TODO: Most of the steps in this algorithm have been skipped.
    _ = suppress;
    {
        assert(document.cdata_current_endpoint < 2);
        if (document.cdata_current_endpoint == 0) {
            assert(document.doctype == null);
            const num_cdatas = document.cdata_endpoints[0].end;
            document.cdata_endpoints[1] = .{ .begin = num_cdatas, .end = num_cdatas };
        }
        const num_cdatas = document.cdata_endpoints[1].end;
        document.cdata_endpoints[2] = .{ .begin = num_cdatas, .end = num_cdatas };
        document.cdata_current_endpoint = 2;
    }
    document.element = element;
}

/// This is the DOM's append mutation algorithm, specialized for a Document parent and a CharacterData node.
pub fn documentAppendCdata(dom: *Dom, document: *Document, cdata: *CharacterData, suppress: SuppressObservers) !void {
    // Ensure pre-insertion validity. Only step 5 of this algorithm applies.
    if (cdata.interface == .text) {
        return dom.exception(.HierarchyRequest);
    }

    // The pre-insert steps are essentially a no-op.

    // Insert cdata into document.
    // TODO: Most of the steps in this algorithm have been skipped.
    _ = suppress;
    try document.cdata.append(dom.allocator, cdata);
    document.cdata_endpoints[document.cdata_current_endpoint].end += 1;
}

/// This is the DOM's insert mutation algorithm, specialized for an Element node parent.
pub fn elementInsert(
    dom: *Dom,
    parent: *Element,
    child: ElementOrCharacterData,
    node: ElementOrCharacterData,
    suppress: SuppressObservers,
) !void {
    // Insert node into parent before child.
    // TODO: Most of the steps in this algorithm have been skipped.
    _ = suppress;
    const index = parent.indexOfChild(child) orelse unreachable;
    try parent.children.insert(dom.allocator, index, node);
    switch (node) {
        .element => |e| e.parent = .{ .element = parent },
        // TODO: Set the parent element of a cdata node.
        .cdata => {},
    }
}

/// This is the DOM's append mutation algorithm, specialized for an Element node parent.
pub fn elementAppend(dom: *Dom, parent: *Element, node: ElementOrCharacterData, suppress: SuppressObservers) !void {
    // TODO: Ensure pre-insertion validity. Only step 2 of that algorithm applies.
    // TODO: Check if node is a host-including inclusive ancestor of parent.

    // The pre-insert steps are essentially a no-op.

    // Insert node into parent.
    // TODO: Most of the steps in this algorithm have been skipped.
    _ = suppress;
    try parent.children.append(dom.allocator, node);
    switch (node) {
        .element => |e| e.parent = .{ .element = parent },
        // TODO: Set the parent element of a cdata node.
        .cdata => {},
    }
}

pub fn elementRemove(dom: *Dom, node: *Element, suppress: SuppressObservers) void {
    // Remove node.
    // TODO: Most of the steps in this algorithm have been skipped.
    _ = dom;
    _ = suppress;
    switch (node.parent.?) {
        .element => |e| {
            const index = e.indexOfChild(.{ .element = node }).?;
            _ = e.children.orderedRemove(index);
        },
        .document => @panic("TODO elementRemove: parent is a document"),
    }
    node.parent = null;
}
