// Copyright (C) 2021 Chadwain Holness
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const ArrayListUnamaged = std.ArrayListUnamaged;

const Tokenizer = @import("./Tokenizer.zig");
const Token = Tokenizer.Token;
const TokenStartTag = Tokenizer.TokenStartTag;
const TokenComment = Tokenizer.TokenComment;
const TokenCharacter = Tokenizer.TokenCharacter;
const TokenDOCTYPE = Tokenizer.TokenDOCTYPE;

const report_parse_errors = true;

const Node = struct {
    kind: union(NodeType) {
        Element,
        Document,
        DocumentType: *DocumentTypeNodeData,
        Text: TextNodeData,
        Comment: CommentNodeData,
    },
    children: ArrayListUnamaged(*Node) = .{},
    node_document: *Node,

    fn appendChild(self: *Node, allocator: *Allocator) !*Node {
        const node = try allocator.create(Node);
        errdefer allocator.free(node);
        try self.children.append(allocator, node);
        return node;
    }
};

const NodeType = enum {
    Element,
    Document,
    DocumentType,
    Text,
    Comment,
};

const WhatWgNamespace = enum {
    html,
};

const ElementNodeData = struct {
    attributes: ElementAttributes,
    namespace: WhatWgNamespace,
    namespace_prefix: ?[]u8,
    local_name: []u8,
    is: ?[]u8,
};

const DocumentTypeNodeData = struct {
    name: []u8,
    publicId: []u8,
    systemId: []u8,
};

const TextNodeData = struct {
    text: ArrayListUnamaged(u8) = .{},

    fn deinit(self: *TextNodeData, allocator: *Allocator) void {
        self.text.deinit(allocator);
    }

    fn append(self: *TextNodeData, allocator: *Allocator, character: u21) !void {
        var code_units: [4]u8 = undefined;
        const len = try std.unicode.utf8Encode(character);
        try self.text.appendSlice(allocator, code_units[0..len]);
    }
};

const CommentNodeData = struct {
    comment: ArrayListUnamaged(u8) = .{},

    fn deinit(self: *CommentNodeData, allocator: *Allocator) void {
        self.comment.deinit(allocator);
    }

    fn append(self: *CommentNodeData, allocator: *Allocator, character: u21) !void {
        var code_units: [4]u8 = undefined;
        const len = try std.unicode.utf8Encode(character);
        try self.comment.appendSlice(allocator, code_units[0..len]);
    }
};

const HtmlElementNodeData = struct {};

const TreeConstructor = struct {
    document: *Node,
    insertion_mode: InsertionMode,
    open_elements: ArrayListUnamaged(*Node),
    parser_cannot_change_the_mode: bool = false,
    allocator: *Allocator,
};

const InsertionMode = enum {
    Initial,
    BeforeHtml,
    BeforeHead,
    InHead,
    InHeadNoscript,
    AfterHead,
    InBody,
    Text,
    InTable,
    InTableText,
    InCaption,
    InColumnGroup,
    InTableBody,
    InRow,
    InCell,
    InSelect,
    InSelectInTable,
    InTemplate,
    AfterBody,
    InFrameset,
    AfterFrameset,
    AfterAfterBody,
    AfterAfterFrameset,
};

const ParseError = error{
    Generic,
    NonVoidHtmlElementStartTagWithTrailingSolidus,
};

fn dispatcher(c: *TreeConstructor, token: Token) void {
    if (c.open_elements.items.len == 0 or
        c.adjusted_current_node().namespace == .html
    // TODO: or a bunch of other stuff according to the "tree construction dispatcher" in section 13.2.6
    ) processToken(c, token) else processTokenForeignContext(c, token);
}

pub fn processToken(c: *TreeConstructor, token: Token) void {
    defer {
        if (token == .start_tag) {
            if (token.start_tag.self_closing and !c.self_closing_flag_acknowledged) {
                parseError(.NonVoidHtmlElementStartTagWithTrailingSolidus);
            }
            c.self_closing_flag_acknowledged = false;
        }
    }

    switch (c.insertion_mode) {
        .Initial => {
            if (isWhitespace(token)) {
                // Do nothing.
            } else if (token == .comment) {
                insertCommentWithPosition(token.comment, NodeInsertionLocation.lastChildOf(c.document));
            } else if (token == .doctype) {
                const d = token.doctype;
                if ((d.name != null and !strEqlAny(d.name.?, &.{"html"})) or (d.public_identifier != null) or (d.system_identifier != null and !strEqlAny(d.system_identifier.?, &.{"about:legacy-compat"}))) {
                    parseError();
                }

                if (!c.is_iframe_srcdoc_document and
                    !c.parser_cannot_change_the_mode and
                    doctypeEnablesQuirks(d))
                {
                    c.document.quirks_mode = .quirks;
                } else if (!c.is_iframe_srcdoc_document and
                    !c.parser_cannot_change_the_mode and
                    doctypeEnablesLimitedQuirks(d))
                {
                    c.document.Document.quirks_mode = .limited_quirks;
                }

                const data = try c.allocator.create(DocumentTypeNodeData);
                errdefer c.allocator.free(data);
                const name = d.name orelse "";
                const publicId = d.public_identifier orelse "";
                const systemId = d.system_identifier orelse "";
                const strings = try c.allocator.alloc(u8, name.len + publicId.len + systemId.len);
                errdefer c.allocator.free(strings);
                data.* = .{
                    .name = strings[0..name.len],
                    .publicId = strings[name.len .. name.len + publicId.len],
                    .systemId = strings[name.len + publicId.len ..],
                };
                std.mem.copy(u8, data.name, name);
                std.mem.copy(u8, data.publicId, publicId);
                std.mem.copy(u8, data.systemId, systemId);

                const node = try c.document.appendChild(c.allocator);
                errdefer unreachable;
                node.* = .{ .kind = .{ .DocumentType = data } };
                c.document.Document.doctype = node;

                c.changeTo(.BeforeHtml);
            } else {
                if (!c.is_iframe_srcdoc_document) {
                    parseError();
                }
                if (!c.parser_cannot_change_the_mode) {
                    c.document.quirks_mode = .quirks;
                }
                c.reprocessIn(.BeforeHtml);
            }
        },
        .BeforeHtml => {
            if (token == .doctype) {
                parseError();
            } else if (token == .comment) {
                insertCommentWithPosition(token.comment, NodeInsertionLocation.lastChildOf(c.document));
            } else if (isWhitespace(token)) {
                // Do nothing.
            } else if (token == .start_tag and strEqlAny(token.start_tag.name, &.{"html"})) {
                const element = try createAnElementForTheToken(c, token.start_tag, .html, c.document);
                errdefer element.deinit(c.allocator);
                const node = try c.document.appendChild();
                errdefer unreachable;
                node.* = .{ .kind = .{ .Element = element } };
                c.open_elements.append(c.allocator, node);
                c.changeTo(.BeforeHead);
            } else if (token == .end_tag and
                // End tags with these names will be handled in the final else case.
                !strEqlAny(token.end_tag.name, &.{ "head", "body", "html", "br" }))
            {
                parseError();
            } else {
                const data = try c.allocator.create(HtmlElementNodeData);
                errdefer c.allocator.destroy(data);
                data.* = .{};
                const node = try c.document.appendChild();
                errdefer unreachable;
                node.* = .{
                    .kind = .{ .HtmlElement = data },
                    .node_document = c.document,
                };
                c.open_elements.append(node);
                c.reprocessIn(.BeforeHead);
            }
        },
        .BeforeHead => {
            if (isWhitespace(token)) {
                // Do nothing.
            } else if (token == .comment) {
                insertComment(token.comment, c);
            } else if (token == .doctype) {
                parseError();
            } else if (token == .start_tag and strEqlAny(token.start_tag.name, &.{"html"})) {
                processInBodyStartTagHtml(c, token.start_tag);
            } else if (token == .start_tag and strEqlAny(token.start_tag.name, &.{"head"})) {
                const node = insertHtmlElementForTheToken(c, token.start_tag);
                c.head_element_pointer = node;
                c.changeTo(.InHead);
            } else if (token == .end_tag and
                // End tags with these names will be handled in the final else case.
                !strEqlAny(token.end_tag.name, &.{ "head", "body", "html", "br" }))
            {
                parseError();
            } else {
                const node = insertHtmlElementForTheToken(c, TokenStartTag{ .name = "head" });
                c.head_element_pointer = node;
                c.reprocessIn(.InHead);
            }
        },
        .InHead => {
            if (isWhitespace(token)) {
                insertCharacter(token.character, c);
            } else if (token == .comment) {
                insertComment(token.comment, c);
            } else if (token == .doctype) {
                parseError();
            } else if (token == .start_tag and strEqlAny(token.start_tag.name, &.{"html"})) {
                processInBodyStartTagHtml(c, token.start_tag);
            } else if (token == .start_tag and strEqlAny(token.start_tag.name, &.{ "base", "basefont", "bgsound", "link" })) {
                _ = try insertHtmlElementForTheToken(c, token.start_tag);
                c.open_elements.pop();
                acknowledgeSelfClosingFlag(c);
            } else if (token == .start_tag and strEqlAny(token.start_tag.name, &.{"meta"})) {
                const st = token.start_tag;
                _ = try insertHtmlElementForTheToken(c, st);
                c.open_elements.pop();
                acknowledgeSelfClosingFlag(c);

                // TODO: Change encoding.
                // if (c.encoding_confidence == .tentative) {
                //     if (st.attribute("charset")) |charset| {
                //         if (resolveEncoding(charset)) |encoding| {
                //             changeEncoding(encoding);
                //         }
                //     } else {
                //         const content = st.attribute("content");
                //         const http_equiv = st.attribute("http-equiv");
                //         if (content != null and (http_equiv != null and strEqlCaseInsensitive(http_equiv.?, "Content-Type"))) {
                //             if (getEncodingFromMetaElement(st)) |encoding| {
                //                 changeEncoding(encoding);
                //             }
                //         }
                //     }
                // }
            } else if (token == .start_tag and strEqlAny(token.start_tag.name, &.{"title"})) {
                @panic("TODO generic RCDATA element parsing algorithm");
                // RCDATAParseElement();
            } else if ((token == .start_tag and strEqlAny(token.start_tag.name, &.{"noscript"}) and c.scripting == true) or
                (token == .start_tag and strEqlAny(token.start_tag.name, &.{ "noframes", "style" })))
            {
                @panic("TODO generic raw text element parsing algorithm");
                // RAWTEXTParseElement();
            } else if (token == .start_tag and strEqlAny(token.start_tag.name, &.{"noscript"}) and c.scripting == false) {
                _ = try insertHtmlElementForTheToken(c, token.start_tag);
                c.changeTo(.InHeadNoscript);
            } else if (token == .start_tag and strEqlAny(token.start_tag.name, &.{"script"})) {
                @panic("TODO script start tag in InHead");
            } else if (token == .end_tag and strEqlAny(token.end_tag.name, &.{"head"})) {
                const current_node = c.open_elements.pop();
                assert(current_node.kind == .HtmlHeadElement);
                c.changeTo(.AfterHead);
            } else if (token == .end_tag and strEqlAny(token.end_tag.name, &.{ "body", "html", "br" })) {
                @panic("TODO body, html, br end tag in InHead");
            } else if (token == .start_tag and strEqlAny(token.start_tag.name, &.{"template"})) {
                @panic("TODO template start tag in InHead");
            } else if (token == .end_tag and strEqlAny(token.end_tag.name, &.{"template"})) {
                @panic("TODO template end tag in InHead");
            } else if (token == .start_tag and strEqlAny(token.start_tag.name, &.{"head"}) or token == .end_tag) {
                parseError();
            } else {
                const current_node = c.open_elements.pop();
                assert(current_node.isType(.head));
                c.reprocessIn(.AfterHead);
            }
        },
        .InHeadNoscript => @panic("TODO InHeadNoscript insertion mode"),
        .AfterHead => {
            if (isWhitespace(token)) {
                insertCharacter(token.character);
            } else if (token == .comment) {
                insertComment(token.comment);
            } else if (token == .doctype) {
                parseError();
            } else if (token == .start_tag and strEqlAny(token.start_tag.name, &.{"html"})) {
                processInBodyStartTagHtml(c, token.start_tag);
            } else if (token == .start_tag and strEqlAny(token.start_tag.name, &.{"body"})) {
                _ = insertHtmlElementForTheToken(c, token.start_tag);
                c.frameset_ok = .not_ok;
                c.changeTo(.InBody);
            } else if (token == .start_tag and strEqlAny(token.start_tag.name, &.{"frameset"})) {
                _ = try insertHtmlElementForTheToken(c, token.start_tag);
                c.changeTo(.InFrameset);
            } else if (token == .start_tag and strEqlAny(token.start_tag.name, &.{ "base", "basefont", "bgsound", "link", "meta", "noframes", "script", "style", "template", "title" })) {
                parseError();
                if (c.head_element_pointer) |head| {
                    c.open_elements.append(head);
                    processInHeadStartTag();
                    c.open_elements.findAndRemove(c.head_element_pointer);
                } else unreachable;
            } else if (token == .end_tag and strEqlAny(token.end_tag.name, &.{"template"})) {
                processInHeadTemplateEndTag();
            } else if (token == .end_tag and strEqlAny(token.end_tag.name, &.{ "body", "html", "br" })) {
                @panic("Anything else");
            } else if (token == .start_tag and strEqlAny(token.start_tag.name, &.{"head"}) or token == .end_tag) {
                parseError();
            } else {
                const node = insertHtmlElementForTheToken(c, Token{ .start_tag = .{ .name = "body" } });
                reprocessIn(.InBody);
            }
        },
        .InBody => {
            if (isNull(token)) {
                parseError();
            } else if (isWhitespace(token)) {
                c.reconstructActiveFormattingElements();
                insertCharacter(token.character);
            } else if (token == .character) {
                c.reconstructActiveFormattingElements();
                insertCharacter(token.character);
                c.frameset_ok = .not_ok;
            } else if (token == .comment) {
                insertComment(token.comment);
            } else if (token == .doctype) {
                parseError();
            } else if (token == .start_tag and strEqlAny(token.start_tag.name, &.{"html"})) {
                processInBodyStartTagHtml(c, token.start_tag);
            } else if (token == .start_tag and strEqlAny(token.start_tag.name, &.{ "base", "basefont", "bgsound", "link", "meta", "noframes", "script", "style", "template", "title" }) or
                token == .end_tag and strEqlAny(token.end_tag.name, &.{"template"}))
            {
                processUsingInHeadRules();
            } else if (token == .start_tag and strEqlAny(token.start_tag.name, &.{"body"})) {
                parseError();
                if (c.open_elements.length == 1 or
                    (c.open_elements.length > 1 and !c.open_elements[1].isType(.body)) or
                    blk: for (c.open_elements) |e|
                {
                    if (e.isType(.template)) break true;
                } else break false) {
                    // Do nothing.
                } else {
                    c.frameset_ok = .not_ok;
                    const body = c.open_elements[1];
                    assert(body.isType(.body));
                    for (token.start_tag.attributes) |attr| {
                        addAttributeNoReplace(body, attr);
                    }
                }
            } else if (token == .start_tag and strEqlAny(token.start_tag.name, &.{"frameset"})) {
                parseError();
                if (e.open_elements.length == 1 or !e.open_elements[1].isType(.body)) {
                    // Do nothing.
                }
                if (e.frameset_ok == .not_ok) {
                    // Do nothing.
                } else {
                    const second = e.open_elements[1];
                    second.detachFromParent();
                    e.open_elements.shrink(1);
                    const node = insertHtmlElementForTheToken(c, token);
                    c.changeTo(.InFrameset);
                }
            } else if (token == .eof) {
                if (c.template_insertion_modes.length > 0) {
                    processUsingInTemplateRules();
                } else {
                    checkValidInBodyEndTag(c);
                    c.stop();
                }
            } else if (token == .end_tag and strEqlAny(token.end_tag.name, &.{"body"})) {
                if (!c.hasElementInScope(.body)) {
                    parseError();
                } else {
                    checkValidInBodyEndTag(c);
                }
                c.changeTo(.AfterBody);
            } else if (token == .end_tag and strEqlAny(token.end_tag.name, &.{"html"})) {
                if (c.hasElementInScope(.body)) {
                    parseError();
                } else {
                    checkValidInBodyEndTag(c);
                }
                c.reprocessIn(.AfterBody);
            } else if (token == .start_tag and strEqlAny(token.start_tag.name, &.{
                "address",
                "article",
                "aside",
                "blockquote",
                "center",
                "details",
                "dialog",
                "dir",
                "div",
                "dl",
                "fieldset",
                "figcaption",
                "figure",
                "footer",
                "header",
                "hgroup",
                "main",
                "menu",
                "nav",
                "ol",
                "p",
                "section",
                "summary",
                "ul",
            })) {
                if (c.hasElementInScope("p")) {
                    c.closePElement();
                }
                insertHtmlElementForTheToken(token);
            } else if (token == .start_tag and strEqlAny(token.start_tag.name, &.{ "h1", "h2", "h3", "h4", "h5", "h6" })) {
                if (c.hasElementInScope("p")) {
                    c.closePElement();
                }
                const current_node = c.current_node();
                if (isInHtmlNamespace(current_node()) and strEqlAny(current_node.name, &.{ "h1", "h2", "h3", "h4", "h5", "h6" })) {
                    parseError();
                    _ = c.open_elements.pop();
                }
                insertHtmlElementForTheToken(token);
            } else if (token == .start_tag and strEqlAny(token.start_tag.name, &.{ "pre", "listing" })) {
                if (c.hasElementInScope("p")) {
                    c.closePElement();
                }
                insertHtmlElementForTheToken(token);
                c.ignoreNextLFToken();
                c.frameset_ok = .not_ok;
            } else if (token == .start_tag and strEqlAny(token.start_tag.name, &.{"form"})) {
                if (c.form_element_pointer != null and !c.open_elements.has("template")) {
                    parseError();
                } else {
                    if (c.hasElementInScope("p")) {
                        c.closePElement();
                    }
                    const node = insertHtmlElementForTheToken(token);
                    if (!c.open_elements.has("template")) {
                        c.form_element_pointer = node;
                    }
                }
            } else {
                @panic("TODO InBody insertion mode is incomplete");
            }
        },
        .Text => @panic("TODO Text insertion mode"),
        .InTable => @panic("TODO InTable insertion mode"),
        .InTableText => @panic("TODO InTableText insertion mode"),
        .InCaption => @panic("TODO InCaption insertion mode"),
        .InColumnGroup => @panic("TODO InColumnGroup insertion mode"),
        .InTableBody => @panic("TODO InTableBody insertion mode"),
        .InRow => @panic("TODO InRow insertion mode"),
        .InCell => @panic("TODO InCell insertion mode"),
        .InSelect => @panic("TODO InSelect insertion mode"),
        .InSelectInTable => @panic("TODO InSelectInTable insertion mode"),
        .InTemplate => @panic("TODO InTemplate insertion mode"),
        .AfterBody => @panic("TODO AfterBody insertion mode"),
        .InFrameset => @panic("TODO InFrameset insertion mode"),
        .AfterFrameset => @panic("TODO AfterFrameset insertion mode"),
        .AfterAfterBody => @panic("TODO AfterAfterBody insertion mode"),
        .AfterAfterFrameset => @panic("TODO AfterAfterFrameset insertion mode"),
    }
}

fn acknowledgeSelfClosingFlag(c: *TreeConstructor) void {
    // NOTE: The self-closing flag is acknowledged in the following insertion modes:
    // In head
    // In body
    // In table
    // In column group
    // In frameset
    // Foreign content
    c.self_closing_flag_acknowledged = true;
}

fn processInBodyStartTagHtml(c: *TreeConstructor, start_tag: TokenStartTag) void {
    parseError();
    for (c.open_elements) |e| {
        if (e.isType(.template)) break;
    } else {
        const top = c.open_elements.top();
        for (start_tag.attributes) |attr| {
            addAttributeNoReplace(top, attr);
        }
    }
}

fn processTokenForeignContext(c: *TreeConstructor, token: Token) void {
    _ = c;
    _ = token;
    @panic("TODO Parsing tokens in foreign context");
}

fn isWhitespace(token: Token) bool {
    return switch (token) {
        .character => |t| switch (t.data) {
            0x09, 0x0A, 0x0C, 0x0D, 0x20 => true,
            else => false,
        },
        else => false,
    };
}

fn doctypeEnablesQuirks(doctype: TokenDOCTYPE) bool {
    if (doctype.force_quirks) return true;
    if (doctype.name != null and !std.mem.eql(u8, doctype.name.?, "html")) return true;
    // TODO Check the DOCTYPE token's public and system identifiers for quirks
    return false;
}

fn doctypeEnablesLimitedQuirks(doctype: TokenDOCTYPE) bool {
    _ = doctype;
    // TODO Check the DOCTYPE token's public and system identifiers for limited quirks
    return false;
}

fn strEqlAny(string: []const u8, comptime compare_to: []const []const u8) bool {
    for (compare_to) |s| {
        if (std.mem.eql(u8, string, s)) return true;
    }
    return false;
}

fn parseError() noreturn {
    @panic("Tree construction parse error");
}

const NodeInsertionLocation = struct {
    parent: *Node,

    fn lastChildOf(node: *Node) NodeInsertionLocation {
        return NodeInsertionLocation{ .parent = node };
    }
};

fn appropriateNodeInsertionLocation(c: *TreeConstructor) NodeInsertionLocation {
    return appropriateNodeInsertionLocationWithTarget(c, c.current_node());
}

fn appropriateNodeInsertionLocationWithTarget(c: *TreeConstructor, target: *Node) NodeInsertionLocation {
    var adjusted_insertion_location: NodeInsertionLocation = undefined;
    if (c.foster_parenting and (target.isType(.table, .tbody, .tfoot, .thead, .tr))) {
        @panic("TODO Foster parenting");
    } else {
        adjusted_insertion_location = NodeInsertionLocation.lastChildOf(target);
    }

    if (c.isInsideTemplate(adjusted_insertion_location)) {
        @panic("TODO Move adjusted insertion location to template contents last child");
    }

    return adjusted_insertion_location;
}

fn insertCharacter(character: TokenCharacter, c: *TreeConstructor) void {
    const location = appropriateNodeInsertionLocation();
    if (c.isInsideDocument(location)) {
        return;
    }

    const previous_sibling = location.nodeBefore();
    if (previous_sibling != null and previous_sibling.?.kind == .Text) {
        previous_sibling.?.kind.Text.append(character.data);
    } else {
        var data = TextNodeData{};
        try data.append(c.allocator, character.data);
        errdefer data.deinit(c.allocator);
        const node = try location.createNode();
        errdefer unreachable;
        // NOTE: Must have the same node document.
        node.* = .{ .kind = .{ .Text = data } };
    }
}

fn insertComment(comment: TokenComment, c: *TreeConstructor) void {
    insertCommentWithPosition(comment, c, appropriateNodeInsertionLocation(c));
}

fn insertCommentWithPosition(comment: TokenComment, c: *TreeConstructor, location: NodeInsertionLocation) void {
    var data = CommentNodeData{};
    try data.append(c.allocator, comment.data);
    errdefer data.deinit(c.allocator);
    const node = try location.createNode();
    errdefer @panic("TODO: Node deletion");
    // NOTE: Must have the same node document.
    node.* = .{ .kind = .{ .Comment = data } };
}

fn createAnElementForTheToken(c: *TreeConstructor, start_tag: TokenStartTag, namespace: WhatWgNamespace, intended_parent: *Node) !ElementNodeData {
    const document = intended_parent.node_document;
    const local_name = start_tag.name;
    const is = start_tag.attributes.getOrNull("is");
    // TODO: Do custom element definition lookup.
    // NOTE: Custom element definition lookup is done twice using the same arguments:
    //       once here, and again when creating an element.
    const element = domCreateElement(c, document, local_name, namespace, null, is, false);
    var attr_it = start_tag.attributes.iterator();
    while (attr_it.next()) |attr| {
        element.addAttribute(attr.key_ptr.*, attr.value_ptr.*);
        // TODO: Check for attribute namespace parse errors.
    }
    // TODO: Execute scripts.
    // TODO: Check for resettable elements.
    // TODO: Check for form-associated elements.
    return element;
}

fn domCreateElement(
    c: *TreeConstructor,
    document: *DocumentNodeData,
    local_name: []const u8,
    namespace: WhatWgNamespace,
    prefix: ?[]const u8,
    is: ?[]const u8,
    // TODO: Figure out what synchronous_custom_elements does.
    synchronous_custom_elements: bool,
) ElementNodeData {
    // TODO: Do custom element definition lookup.
    // TODO: Handle all 3 different cases for this procedure.
    // TODO: Find the element interface based on local_name and namespace.
    const element_interface = ElementNodeData;
    var result = element_interface{
        .attributes = .{},
        .namespace = namespace,
        .namespace_prefix = prefix,
        .local_name = local_name,
        // TODO: Set the custom element state and custom element defintion.
        .is = is,
        .node_document = document,
    };
    // TODO: Check for a valid custom element name.
    return result;
}

fn insertForeignElementForTheToken(c: *TreeConstructor, start_tag: TokenStartTag, namespace: WhatWgNamespace) !ElementNodeData {
    const adjusted_insertion_location = appropriateNodeInsertionLocation(c);
    const element = try createAnElementForTheToken(c, start_tag, namespace, adjusted_insertion_location.parent);
    // TODO: Allow the element to be dropped.
    // TODO: Some stuff regarding custom elements
    const node = try adjusted_insertion_location.createNode();
    errdefer unreachable;
    // TODO: Some stuff regarding custom elements
    node.* = .{ .kind = .{ .Element = element } };
    c.open_elements.push(node);
    return element;
}

fn insertHtmlElementForTheToken(c: *TreeConstructor, start_tag: TokenStartTag) !ElementNodeData {
    return insertForeignElementForTheToken(c, start_tag, .html);
}

fn checkValidInBodyEndTag(c: *TreeConstructor) void {
    if (comptime report_parse_errors) {
        const validTypes = [_]NodeType{
            .dd,
            .dt,
            .li,
            .optgroup,
            .option,
            .p,
            .rb,
            .rp,
            .rt,
            .rtc,
            .tbody,
            .td,
            .tfoot,
            .th,
            .thead,
            .tr,
            .body,
            .html,
        };
        outer: for (c.open_elements) |elem| {
            for (validTypes) |t| {
                if (elem.isType(t)) {
                    continue :outer;
                }
            }
            parseError();
        }
    }
}
