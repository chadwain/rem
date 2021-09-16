// Copyright (C) 2021 Chadwain Holness
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const ArrayListUnmanaged = std.ArrayListUnmanaged;
const StringHashMapUnmanaged = std.StringHashMapUnmanaged;

const Tokenizer = @import("./Tokenizer.zig");
const Token = Tokenizer.Token;
const TokenStartTag = Tokenizer.TokenStartTag;
const TokenEndTag = Tokenizer.TokenEndTag;
const TokenComment = Tokenizer.TokenComment;
const TokenCharacter = Tokenizer.TokenCharacter;
const TokenDOCTYPE = Tokenizer.TokenDOCTYPE;

const report_parse_errors = true;

test {
    const al = std.heap.page_allocator;
    const input = "<!doctype html><html><body>hello</body></html>";
    var it = (try std.unicode.Utf8View.init(input)).iterator();
    var list = std.ArrayList(u21).init(al);
    defer list.deinit();
    while (it.nextCodepoint()) |cp| {
        try list.append(cp);
    }

    var tokenizer = Tokenizer.init(list.items, al, .Data);
    defer tokenizer.deinit();
    while (!tokenizer.reached_eof) {
        try tokenizer.run();
    }

    std.debug.print("\nTokens:\n", .{});
    for (tokenizer.tokens.items) |token| {
        std.debug.print("{any}\n", .{token});
    }
    std.debug.print("\n", .{});

    var c = try TreeConstructor.init(al);

    for (tokenizer.tokens.items) |token| {
        try c.run(token);
        if (c.stopped) break;
    }

    std.debug.print("\nDOM Tree:\n\n", .{});
    var node_stack = ArrayListUnmanaged(struct { node: *Node, depth: usize }){};
    defer node_stack.deinit(al);
    try node_stack.append(al, .{ .node = c.document, .depth = 0 });
    while (node_stack.items.len > 0) {
        const item = node_stack.pop();
        var len = item.depth;
        while (len > 0) : (len -= 1) {
            std.debug.print("  ", .{});
        }
        const node = item.node;
        std.debug.print("{any}\n", .{node.*});
        var num_children = node.children.items.len;
        while (num_children > 0) : (num_children -= 1) {
            try node_stack.append(al, .{ .node = node.children.items[num_children - 1], .depth = item.depth + 1 });
        }
    }
}

const Node = struct {
    kind: union(NodeType) {
        Element: *ElementNodeData,
        Document: *DocumentNodeData,
        DocumentType: *DocumentTypeNodeData,
        Text: *TextNodeData,
        Comment: *CommentNodeData,
    },
    children: ArrayListUnmanaged(*Node) = .{},
    node_document: *Node,

    fn deinit(self: *Node, allocator: *Allocator) void {
        self.children.deinit(allocator);
        switch (self.kind) {
            .Element => |d| d.deinit(allocator),
            .Document => {},
            .DocumentType => |d| d.deinit(allocator),
            .Text => |d| d.deinit(allocator),
            .Comment => |d| d.deinit(allocator),
        }
    }

    fn appendChild(self: *Node, allocator: *Allocator) !*Node {
        const node = try allocator.create(Node);
        errdefer allocator.destroy(node);
        try self.children.append(allocator, node);
        return node;
    }

    pub fn format(value: Node, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = fmt;
        _ = options;
        switch (value.kind) {
            .Element => |e| {
                try writer.writeAll("Element type=");
                if (e.html_element_type) |t| {
                    try writer.writeAll(@tagName(t));
                } else {
                    try writer.writeAll("(non-html)");
                }
                try writer.writeAll(" name=");
                try writer.writeAll(e.local_name);
                try writer.writeAll(" namespace=");
                if (e.namespace_prefix) |namespace_prefix| {
                    try writer.writeAll(namespace_prefix);
                    try writer.writeAll(":");
                }
                try writer.writeAll(@tagName(e.namespace));
                try writer.writeAll(" [");
                var attr_it = e.attributes.iterator();
                while (attr_it.next()) |attr| {
                    try writer.writeAll("\"");
                    try writer.writeAll(attr.key_ptr.*);
                    try writer.writeAll("\": \"");
                    try writer.writeAll(attr.value_ptr.*);
                    try writer.writeAll("\"");
                }
                try writer.writeAll("]");
            },
            .Document => |d| {
                try writer.writeAll("Document ");
                try writer.writeAll(@tagName(d.quirks_mode));
            },
            .DocumentType => |dt| {
                try writer.writeAll("DocumentType name=");
                try writer.writeAll(dt.name);
                try writer.writeAll(" publicId=");
                try writer.writeAll(dt.publicId);
                try writer.writeAll(" systemId=");
                try writer.writeAll(dt.systemId);
            },
            .Text => |t| {
                try writer.writeAll("Text \"");
                try writer.writeAll(t.text.items);
                try writer.writeAll("\"");
            },
            .Comment => |c| {
                try writer.writeAll("Comment \"");
                try writer.writeAll(c.comment.items);
                try writer.writeAll("\"");
            },
        }
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

const ElementAttributes = StringHashMapUnmanaged([]u8);

const ElementNodeData = struct {
    attributes: ElementAttributes,
    namespace: WhatWgNamespace,
    namespace_prefix: ?[]u8,
    local_name: []u8,
    is: ?[]u8,
    // TODO: Are html_element_type and local_name always the same?
    html_element_type: ?HtmlElementType,

    fn deinit(self: *ElementNodeData, allocator: *Allocator) void {
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

    fn appendAttribute(self: *ElementNodeData, allocator: *Allocator, key: []u8, value: []u8) !void {
        // TODO: Appending an attribute has more steps.
        try self.attributes.put(allocator, key, value);
    }
};

const HtmlElementType = enum {
    html,
    head,
    body,
    script,
};

const DocumentNodeData = struct {
    doctype: ?*Node = null,
    quirks_mode: QuirksMode = .no_quirks,

    const QuirksMode = enum {
        no_quirks,
        quirks,
        limited_quirks,
    };
};

const DocumentTypeNodeData = struct {
    name: []u8,
    publicId: []u8,
    systemId: []u8,

    fn deinit(self: *DocumentTypeNodeData, allocator: *Allocator) void {
        allocator.free(self.name);
        allocator.free(self.publicId);
        allocator.free(self.systemId);
    }
};

const TextNodeData = struct {
    text: ArrayListUnmanaged(u8) = .{},

    fn deinit(self: *TextNodeData, allocator: *Allocator) void {
        self.text.deinit(allocator);
    }

    fn append(self: *TextNodeData, allocator: *Allocator, character: u21) !void {
        var code_units: [4]u8 = undefined;
        const len = try std.unicode.utf8Encode(character, &code_units);
        try self.text.appendSlice(allocator, code_units[0..len]);
    }
};

const CommentNodeData = struct {
    comment: ArrayListUnmanaged(u8) = .{},

    fn deinit(self: *CommentNodeData, allocator: *Allocator) void {
        self.comment.deinit(allocator);
    }

    fn append(self: *CommentNodeData, allocator: *Allocator, string: []const u8) !void {
        try self.comment.appendSlice(allocator, string);
    }
};

const TreeConstructor = struct {
    document: *Node,
    head_element_pointer: ?*Node = null,

    insertion_mode: InsertionMode = .Initial,
    original_insertion_mode: InsertionMode = undefined,
    open_elements: ArrayListUnmanaged(*Node) = .{},
    active_formatting_elements: ArrayListUnmanaged(*Node) = .{},
    template_insertion_modes: ArrayListUnmanaged(InsertionMode) = .{},
    reprocess: bool = false,
    stopped: bool = false,
    parser_cannot_change_the_mode: bool = false,
    is_iframe_srcdoc_document: bool = false,
    is_fragment_parser: bool = false,
    self_closing_flag_acknowledged: bool = false,
    frameset_ok: FramesetOk = .ok,
    scripting: bool = false,
    foster_parenting: bool = false,

    allocator: *Allocator,

    const FramesetOk = enum {
        ok,
        not_ok,
    };

    fn init(allocator: *Allocator) !TreeConstructor {
        const document = try allocator.create(DocumentNodeData);
        errdefer allocator.destroy(document);
        document.* = .{};

        const node = try allocator.create(Node);
        errdefer allocator.destroy(node);
        node.* = .{ .kind = .{ .Document = document }, .node_document = node };

        return TreeConstructor{
            .allocator = allocator,
            .document = node,
        };
    }

    fn run(self: *TreeConstructor, token: Token) !void {
        var should_process = true;
        while (should_process) {
            self.reprocess = false;
            // TODO: Must call dispatcher instead.
            try processToken(self, token);
            should_process = self.reprocess;
        }
    }

    fn changeTo(self: *TreeConstructor, insertion_mode: InsertionMode) void {
        self.insertion_mode = insertion_mode;
        std.debug.print("Change to: {s}\n", .{@tagName(insertion_mode)});
    }

    fn changeToOriginalInsertionMode(self: *TreeConstructor) void {
        self.changeTo(self.original_insertion_mode);
        self.original_insertion_mode = undefined;
    }

    fn reprocessIn(self: *TreeConstructor, insertion_mode: InsertionMode) void {
        self.reprocess = true;
        self.insertion_mode = insertion_mode;
        std.debug.print("Reprocess in: {s}\n", .{@tagName(insertion_mode)});
    }

    fn reprocessInOriginalInsertionMode(self: *TreeConstructor) void {
        self.reprocessIn(self.original_insertion_mode);
        self.original_insertion_mode = undefined;
    }

    fn stop(self: *TreeConstructor) void {
        // TODO: Stopping parsing has more steps.
        self.stopped = true;
        std.debug.print("Stopped parsing.", .{});
    }

    fn currentNode(self: *TreeConstructor) *Node {
        return self.open_elements.items[self.open_elements.items.len - 1];
    }
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

const ParseError = enum {
    Generic,
    NonVoidHtmlElementStartTagWithTrailingSolidus,
};

fn dispatcher(c: *TreeConstructor, token: Token) void {
    if (c.open_elements.items.len == 0 or
        c.adjusted_current_node().namespace == .html
    // TODO: or a bunch of other stuff according to the "tree construction dispatcher" in section 13.2.6
    ) processToken(c, token) else processTokenForeignContent(c, token);
}

pub fn processToken(c: *TreeConstructor, token: Token) !void {
    std.debug.print("{any}\n", .{token});

    defer {
        if (token == .start_tag) {
            if (token.start_tag.self_closing and !c.self_closing_flag_acknowledged) {
                parseError(.NonVoidHtmlElementStartTagWithTrailingSolidus);
            }
            c.self_closing_flag_acknowledged = false;
        }
    }

    switch (c.insertion_mode) {
        .Initial => try initial(c, token),
        .BeforeHtml => try beforeHtml(c, token),
        .BeforeHead => {
            if (isWhitespace(token)) {
                // Ignore the token.
            } else if (token == .comment) {
                try insertComment(c, token.comment);
            } else if (token == .doctype) {
                parseError(.Generic);
                // Ignore the token.
            } else if (token == .start_tag and strEqlAny(token.start_tag.name, &.{"html"})) {
                inBodyStartTagHtml(c, token.start_tag);
            } else if (token == .start_tag and strEqlAny(token.start_tag.name, &.{"head"})) {
                const node = try insertHtmlElementForTheToken(c, token.start_tag);
                c.head_element_pointer = node;
                c.changeTo(.InHead);
            } else if (token == .end_tag and
                // End tags with these names will be handled in the final else case.
                !strEqlAny(token.end_tag.name, &.{ "head", "body", "html", "br" }))
            {
                parseError(.Generic);
                // Ignore the token.
            } else {
                const node = try insertHtmlElementForTheToken(c, TokenStartTag{
                    .name = "head",
                    .attributes = .{},
                    .self_closing = false,
                });
                c.head_element_pointer = node;
                c.reprocessIn(.InHead);
            }
        },
        .InHead => try inHead(c, token),
        .InHeadNoscript => @panic("TODO InHeadNoscript insertion mode"),
        .AfterHead => {
            if (isWhitespace(token)) {
                try insertCharacter(c, token.character);
            } else if (token == .comment) {
                try insertComment(c, token.comment);
            } else if (token == .doctype) {
                parseError(.Generic);
                // Ignore the token.
            } else if (token == .start_tag and strEqlAny(token.start_tag.name, &.{"html"})) {
                inBodyStartTagHtml(c, token.start_tag);
            } else if (token == .start_tag and strEqlAny(token.start_tag.name, &.{"body"})) {
                _ = try insertHtmlElementForTheToken(c, token.start_tag);
                c.frameset_ok = .not_ok;
                c.changeTo(.InBody);
            } else if (token == .start_tag and strEqlAny(token.start_tag.name, &.{"frameset"})) {
                _ = try insertHtmlElementForTheToken(c, token.start_tag);
                c.changeTo(.InFrameset);
            } else if (token == .start_tag and strEqlAny(token.start_tag.name, &.{ "base", "basefont", "bgsound", "link", "meta", "noframes", "script", "style", "template", "title" })) {
                parseError(.Generic);
                if (c.head_element_pointer) |head| {
                    try c.open_elements.append(c.allocator, head);
                    try inHead(c, token);
                    // Remove the node pointed to by the head element pointer from the stack of open elements.
                    for (c.open_elements.items) |e, i| {
                        if (e == c.head_element_pointer.?) {
                            _ = c.open_elements.orderedRemove(i);
                        }
                    }
                } else unreachable;
            } else if (token == .end_tag and strEqlAny(token.end_tag.name, &.{"template"})) {
                processInHeadTemplateEndTag(c, token.end_tag);
            } else if (token == .end_tag and strEqlAny(token.end_tag.name, &.{ "body", "html", "br" })) {
                // NOTE: Same as "anything else".
                _ = try insertHtmlElementForTheToken(c, TokenStartTag{
                    .name = "body",
                    .attributes = .{},
                    .self_closing = false,
                });
                c.reprocessIn(.InBody);
            } else if (token == .start_tag and strEqlAny(token.start_tag.name, &.{"head"}) or token == .end_tag) {
                parseError(.Generic);
                // Ignore the token.
            } else {
                _ = try insertHtmlElementForTheToken(c, TokenStartTag{
                    .name = "body",
                    .attributes = .{},
                    .self_closing = false,
                });
                c.reprocessIn(.InBody);
            }
        },
        .InBody => try inBody(c, token),
        .Text => try text(c, token),
        .InTable => @panic("TODO InTable insertion mode"),
        .InTableText => @panic("TODO InTableText insertion mode"),
        .InCaption => @panic("TODO InCaption insertion mode"),
        .InColumnGroup => @panic("TODO InColumnGroup insertion mode"),
        .InTableBody => @panic("TODO InTableBody insertion mode"),
        .InRow => @panic("TODO InRow insertion mode"),
        .InCell => @panic("TODO InCell insertion mode"),
        .InSelect => @panic("TODO InSelect insertion mode"),
        .InSelectInTable => @panic("TODO InSelectInTable insertion mode"),
        .InTemplate => inTemplate(c, token),
        .AfterBody => afterBody(c, token),
        .InFrameset => @panic("TODO InFrameset insertion mode"),
        .AfterFrameset => @panic("TODO AfterFrameset insertion mode"),
        .AfterAfterBody => try afterAfterBody(c, token),
        .AfterAfterFrameset => @panic("TODO AfterAfterFrameset insertion mode"),
    }
}

fn initial(c: *TreeConstructor, token: Token) !void {
    switch (token) {
        .character => |character| {
            if (isWhitespaceCharacter(character.data)) {
                // Ignore the token.
            } else {
                initialAnythingElse(c);
            }
        },
        .comment => |comment| try insertCommentWithPosition(c, comment, NodeInsertionLocation.lastChildOf(c.document)),
        .doctype => {
            const d = token.doctype;
            if ((d.name != null and !strEqlAny(d.name.?, &.{"html"})) or (d.public_identifier != null) or (d.system_identifier != null and !strEqlAny(d.system_identifier.?, &.{"about:legacy-compat"}))) {
                parseError(.Generic);
            }

            if (!c.is_iframe_srcdoc_document and
                !c.parser_cannot_change_the_mode and
                doctypeEnablesQuirks(d))
            {
                c.document.kind.Document.quirks_mode = .quirks;
            } else if (!c.is_iframe_srcdoc_document and
                !c.parser_cannot_change_the_mode and
                doctypeEnablesLimitedQuirks(d))
            {
                c.document.kind.Document.quirks_mode = .limited_quirks;
            }

            const data = try c.allocator.create(DocumentTypeNodeData);
            errdefer c.allocator.destroy(data);
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
            errdefer @panic("TODO: Node deletion");
            node.* = .{
                .kind = .{ .DocumentType = data },
                .node_document = c.document,
            };
            c.document.kind.Document.doctype = node;

            c.changeTo(.BeforeHtml);
        },
        else => initialAnythingElse(c),
    }
}

fn initialAnythingElse(c: *TreeConstructor) void {
    if (!c.is_iframe_srcdoc_document) {
        parseError(.Generic);
    }
    if (!c.parser_cannot_change_the_mode) {
        c.document.kind.Document.quirks_mode = .quirks;
    }
    c.reprocessIn(.BeforeHtml);
}

fn beforeHtml(c: *TreeConstructor, token: Token) !void {
    switch (token) {
        .doctype => {
            parseError(.Generic);
            // Ignore the token.
        },
        .comment => |comment| try insertCommentWithPosition(c, comment, NodeInsertionLocation.lastChildOf(c.document)),
        .character => |character| {
            if (isWhitespaceCharacter(character.data)) {
                // Ignore the token.
            } else {
                try beforeHtmlAnythingElse(c);
            }
        },
        .start_tag => |start_tag| {
            if (strEqlAny(start_tag.name, &.{"html"})) {
                const node = try createAnElementForTheToken(c, start_tag, .html, c.document);
                errdefer node.kind.Element.deinit(c.allocator);
                const node_ptr = try c.document.appendChild(c.allocator);
                errdefer @panic("TODO: Node deletion");
                node_ptr.* = node;
                try c.open_elements.append(c.allocator, node_ptr);
                c.changeTo(.BeforeHead);
            } else {
                try beforeHtmlAnythingElse(c);
            }
        },
        .end_tag => |end_tag| {
            if (strEqlAny(end_tag.name, &.{ "head", "body", "html", "br" })) {
                try beforeHtmlAnythingElse(c);
            } else {
                parseError(.Generic);
                // Ignore the token.
            }
        },
        else => try beforeHtmlAnythingElse(c),
    }
}

fn beforeHtmlAnythingElse(c: *TreeConstructor) !void {
    const local_name = try c.allocator.dupe(u8, "html");
    errdefer c.allocator.free(local_name);
    const html = try c.allocator.create(ElementNodeData);
    errdefer c.allocator.destroy(html);
    html.* = .{
        .attributes = .{},
        .namespace = .html,
        .namespace_prefix = null,
        .local_name = local_name,
        .is = null,
        .html_element_type = .html,
    };

    const node = try c.document.appendChild(c.allocator);
    errdefer @panic("TODO: Node deletion");
    node.* = .{
        .kind = .{ .Element = html },
        .node_document = c.document,
    };
    try c.open_elements.append(c.allocator, node);
    c.reprocessIn(.BeforeHead);
}

fn inHead(c: *TreeConstructor, token: Token) !void {
    if (isWhitespace(token)) {
        try insertCharacter(c, token.character);
    } else if (token == .comment) {
        try insertComment(c, token.comment);
    } else if (token == .doctype) {
        parseError(.Generic);
        // Ignore the token.
    } else if (token == .start_tag and strEqlAny(token.start_tag.name, &.{"html"})) {
        inBodyStartTagHtml(c, token.start_tag);
    } else if (token == .start_tag and strEqlAny(token.start_tag.name, &.{ "base", "basefont", "bgsound", "link" })) {
        _ = try insertHtmlElementForTheToken(c, token.start_tag);
        _ = c.open_elements.pop();
        acknowledgeSelfClosingFlag(c);
    } else if (token == .start_tag and strEqlAny(token.start_tag.name, &.{"meta"})) {
        const st = token.start_tag;
        _ = try insertHtmlElementForTheToken(c, st);
        _ = c.open_elements.pop();
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
        // NOTE: NOT the same as "anything else".
        const current_node = c.open_elements.pop();
        assert(current_node.kind.Element.html_element_type.? == .head);
        c.changeTo(.AfterHead);
    } else if (token == .end_tag and strEqlAny(token.end_tag.name, &.{ "body", "html", "br" })) {
        // NOTE: Same as "anything else".
        const current_node = c.open_elements.pop();
        assert(current_node.kind.Element.html_element_type.? == .head);
        c.reprocessIn(.AfterHead);
    } else if (token == .start_tag and strEqlAny(token.start_tag.name, &.{"template"})) {
        @panic("TODO template start tag in InHead");
    } else if (token == .end_tag and strEqlAny(token.end_tag.name, &.{"template"})) {
        processInHeadTemplateEndTag(c, token.end_tag);
    } else if (token == .start_tag and strEqlAny(token.start_tag.name, &.{"head"}) or token == .end_tag) {
        parseError(.Generic);
        // Ignore the token.
    } else {
        const current_node = c.open_elements.pop();
        assert(current_node.kind.Element.html_element_type.? == .head);
        c.reprocessIn(.AfterHead);
    }
}

fn processInHeadTemplateEndTag(c: *TreeConstructor, end_tag: TokenEndTag) void {
    _ = c;
    _ = end_tag;
    @panic("TODO template end tag in InHead");
}

fn inTemplate(c: *TreeConstructor, token: Token) void {
    _ = c;
    _ = token;
    @panic("TODO InTemplate insertion mode");
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

fn inBody(c: *TreeConstructor, token: Token) !void {
    switch (token) {
        .doctype => inBodyDoctype(c),
        .character => |character| {
            if (isNullCharacter(character.data)) {
                parseError(.Generic);
                // Ignore the token.
            } else {
                reconstructActiveFormattingElements(c);
                try insertCharacter(c, character);
                if (!isWhitespaceCharacter(character.data)) {
                    c.frameset_ok = .not_ok;
                }
            }
        },
        .comment => |comment| try insertComment(c, comment),
        .eof => {
            if (c.template_insertion_modes.items.len > 0) {
                // TODO: Jump straight to the EOF token handler.
                inTemplate(c, token);
            } else {
                checkValidInBodyEndTag(c);
                c.stop();
            }
        },
        .start_tag => |start_tag| {
            if (strEqlAny(start_tag.name, &.{"html"})) {
                inBodyStartTagHtml(c, start_tag);
            } else if (strEqlAny(start_tag.name, &.{ "base", "basefont", "bgsound", "link", "meta", "noframes", "script", "style", "template", "title" })) {
                // TODO: Jump straight to the appropriate handler.
                try inHead(c, token);
            } else if (strEqlAny(start_tag.name, &.{"body"})) {
                parseError(.Generic);
                @panic("TODO: InBody start tag body");
                //if (c.open_elements.items.len == 1 or
                //    (c.open_elements.items.len > 1 and c.open_elements.items[1].kind != .HtmlBodyElement) or
                //    for (c.open_elements.items) |e|
                //{
                //    if (e.kind == .HtmlTemplateElement) break true;
                //} else false) {
                //    // Ignore the token.
                //} else {
                //    c.frameset_ok = .not_ok;
                //    const body = c.open_elements[1];
                //    assert(body.kind == .HtmlBodyElement);
                //    for (token.start_tag.attributes) |attr| {
                //        try body.appendAttributeNoReplace(attr);
                //    }
                //}
            } else if (strEqlAny(start_tag.name, &.{"frameset"})) {
                parseError(.Generic);
                @panic("TODO: InBody start tag frameset");
                //if (c.open_elements.items.len == 1 or c.open_elements.items[1].kind != .HtmlBodyElement) {
                //    // Do nothing.
                //}
                //if (c.frameset_ok == .not_ok) {
                //    // Do nothing.
                //} else {
                //    const second = c.open_elements.items[1];
                //    second.detachFromParent();
                //    c.open_elements.shrink(1);
                //    _ = insertHtmlElementForTheToken(c, token);
                //    c.changeTo(.InFrameset);
                //}
            } else if (strEqlAny(start_tag.name, &.{
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
                if (hasElementInScope(c, .p)) {
                    closePElement(c);
                }
                _ = try insertHtmlElementForTheToken(c, start_tag);
            } else if (strEqlAny(start_tag.name, &.{ "h1", "h2", "h3", "h4", "h5", "h6" })) {
                @panic("TODO InBody start tag h1-h6");
                //if (c.hasElementInScope("p")) {
                //    c.closePElement();
                //}
                //const current_node = c.current_node();
                //if (isInHtmlNamespace(current_node()) and strEqlAny(current_node.name, &.{ "h1", "h2", "h3", "h4", "h5", "h6" })) {
                //    parseError(.Generic);
                //    _ = c.open_elements.pop();
                //}
                //insertHtmlElementForTheToken(token);
            } else if (strEqlAny(start_tag.name, &.{ "pre", "listing" })) {
                @panic("TODO InBody start tag pre, listing");
                //if (c.hasElementInScope("p")) {
                //    c.closePElement();
                //}
                //insertHtmlElementForTheToken(token);
                //c.ignoreNextLFToken();
                //c.frameset_ok = .not_ok;
            } else if (strEqlAny(start_tag.name, &.{"form"})) {
                @panic("TODO InBody start tag form");
                //if (c.form_element_pointer != null and !c.open_elements.has("template")) {
                //    parseError(.Generic);
                //} else {
                //    if (c.hasElementInScope("p")) {
                //        c.closePElement();
                //    }
                //    const node = insertHtmlElementForTheToken(token);
                //    if (!c.open_elements.has("template")) {
                //        c.form_element_pointer = node;
                //    }
                //}
            } else {
                @panic("TODO InBody insertion mode is incomplete");
            }
        },
        .end_tag => |end_tag| {
            if (token == .end_tag and strEqlAny(token.end_tag.name, &.{"template"})) {
                // TODO: Jump straight to the appropriate handler.
                try inHead(c, token);
            } else if (strEqlAny(end_tag.name, &.{"body"})) {
                if (!hasElementInScope(c, .body)) {
                    parseError(.Generic);
                    // Ignore the token.
                } else {
                    checkValidInBodyEndTag(c);
                    c.changeTo(.AfterBody);
                }
            } else if (strEqlAny(end_tag.name, &.{"html"})) {
                if (!hasElementInScope(c, .body)) {
                    parseError(.Generic);
                    // Ignore the token.
                } else {
                    checkValidInBodyEndTag(c);
                    c.reprocessIn(.AfterBody);
                }
            } else {
                @panic("TODO InBody insertion mode is incomplete");
            }
        },
    }
}

fn inBodyDoctype(c: *TreeConstructor) void {
    _ = c;
    parseError(.Generic);
    // Ignore the token.
}

fn inBodyWhitespaceCharacter(c: *TreeConstructor, character: TokenCharacter) !void {
    reconstructActiveFormattingElements(c);
    try insertCharacter(c, character);
}

fn inBodyStartTagHtml(c: *TreeConstructor, start_tag: TokenStartTag) void {
    _ = c;
    _ = start_tag;
    parseError(.Generic);
    @panic("TODO: InBody start tag html");
    //for (c.open_elements.items) |e| {
    //    if (e.isType(.template)) break;
    //} else {
    //    const top = c.open_elements.top();
    //    for (start_tag.attributes) |attr| {
    //        top.appendAttributeNoReplace(attr);
    //    }
    //}
}

fn text(c: *TreeConstructor, token: Token) !void {
    switch (token) {
        .character => |character| {
            assert(!isNullCharacter(character.data));
            try insertCharacter(c, character);
        },
        .eof => {
            parseError(.Generic);
            const current_node = c.open_elements.pop();
            if (current_node.kind.Element.html_element_type.? == .script) {
                // Mark the script element as "already started".
                @panic("TODO Text eof");
            }
            c.reprocessInOriginalInsertionMode();
        },
        .end_tag => |end_tag| {
            if (strEqlAny(end_tag.name, &.{"script"})) {
                @panic("TODO Text end tag script");
            } else {
                _ = c.open_elements.pop();
                c.changeToOriginalInsertionMode();
            }
        },
        else => unreachable,
    }
}

fn afterBody(c: *TreeConstructor, token: Token) void {
    if (isWhitespace(token)) {
        @panic("TODO Process using InBody whitespace rules.");
    } else if (token == .comment) {
        @panic("TODO: AfterBody comment");
    } else if (token == .doctype) {
        parseError(.Generic);
        // Ignore the token.
    } else if (token == .start_tag and strEqlAny(token.start_tag.name, &.{"html"})) {
        inBodyStartTagHtml(c, token.start_tag);
    } else if (token == .end_tag and strEqlAny(token.end_tag.name, &.{"html"})) {
        if (c.is_fragment_parser) {
            parseError(.Generic);
            // Ignore the token.
        } else {
            c.changeTo(.AfterAfterBody);
        }
    } else if (token == .eof) {
        c.stop();
    } else {
        parseError(.Generic);
        c.reprocessIn(.InBody);
    }
}

fn afterAfterBody(c: *TreeConstructor, token: Token) !void {
    switch (token) {
        .comment => |comment| try insertCommentWithPosition(c, comment, NodeInsertionLocation.lastChildOf(c.document)),
        .doctype => {
            inBodyDoctype(c);
        },
        .character => |character| {
            if (isWhitespaceCharacter(character.data)) {
                try inBodyWhitespaceCharacter(c, character);
            } else {
                afterAfterBodyAnythingElse(c);
            }
        },
        .start_tag => |start_tag| {
            if (strEqlAny(start_tag.name, &.{"html"})) {
                @panic("TODO: AfterAfterBody start tag html: use InBody rules");
            } else {
                afterAfterBodyAnythingElse(c);
            }
        },
        .eof => c.stop(),
        else => afterAfterBodyAnythingElse(c),
    }
}

fn afterAfterBodyAnythingElse(c: *TreeConstructor) void {
    parseError(.Generic);
    c.reprocessIn(.InBody);
}

fn processTokenForeignContent(c: *TreeConstructor, token: Token) void {
    _ = c;
    _ = token;
    @panic("TODO Parsing tokens in foreign content");
}

fn isNullToken(token: Token) bool {
    return switch (token) {
        .character => |t| isNullCharacter(t.data),
        else => false,
    };
}

fn isNullCharacter(character: u21) bool {
    return character == 0x00;
}

fn isWhitespace(token: Token) bool {
    return switch (token) {
        .character => |t| isWhitespaceCharacter(t.data),
        else => false,
    };
}

fn isWhitespaceCharacter(character: u21) bool {
    return switch (character) {
        0x09, 0x0A, 0x0C, 0x0D, 0x20 => true,
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

fn parseError(err: ParseError) void {
    // TODO: Handle parse errors.
    std.debug.print("Tree construction parse error: {s}\n", .{@tagName(err)});
}

const NodeInsertionLocation = struct {
    parent: *Node,

    fn createNode(self: NodeInsertionLocation, allocator: *Allocator) !*Node {
        return self.parent.appendChild(allocator);
    }

    fn lastChildOf(node: *Node) NodeInsertionLocation {
        return NodeInsertionLocation{ .parent = node };
    }

    fn nodeBefore(self: NodeInsertionLocation) ?*Node {
        if (self.parent.children.items.len == 0) return null;
        return self.parent.children.items[self.parent.children.items.len - 1];
    }
};

fn appropriateNodeInsertionLocation(c: *TreeConstructor) NodeInsertionLocation {
    return appropriateNodeInsertionLocationWithTarget(c, c.currentNode());
}

fn appropriateNodeInsertionLocationWithTarget(c: *TreeConstructor, target: *Node) NodeInsertionLocation {
    _ = c;
    var adjusted_insertion_location: NodeInsertionLocation = undefined;
    // TODO: Apply foster parenting.
    adjusted_insertion_location = NodeInsertionLocation.lastChildOf(target);

    // TODO: Check if adjusted_insertion_location is a template.
    return adjusted_insertion_location;
}

fn insertCharacter(c: *TreeConstructor, character: TokenCharacter) !void {
    const location = appropriateNodeInsertionLocation(c);
    if (location.parent.kind == .Document) {
        return;
    }

    // TODO Optimization.
    const previous_sibling = location.nodeBefore();
    if (previous_sibling != null and previous_sibling.?.kind == .Text) {
        try previous_sibling.?.kind.Text.append(c.allocator, character.data);
    } else {
        const data = try c.allocator.create(TextNodeData);
        errdefer c.allocator.destroy(data);
        data.* = .{};
        errdefer data.deinit(c.allocator);
        try data.append(c.allocator, character.data);

        const node = try location.createNode(c.allocator);
        errdefer @panic("TODO: Node deletion");
        node.* = .{
            .kind = .{ .Text = data },
            .node_document = location.parent.node_document,
        };
    }
}

fn insertComment(c: *TreeConstructor, comment: TokenComment) !void {
    return insertCommentWithPosition(c, comment, appropriateNodeInsertionLocation(c));
}

fn insertCommentWithPosition(c: *TreeConstructor, comment: TokenComment, location: NodeInsertionLocation) !void {
    const data = try c.allocator.create(CommentNodeData);
    errdefer c.allocator.destroy(data);
    data.* = .{};
    errdefer data.deinit(c.allocator);
    try data.append(c.allocator, comment.data);

    const node = try location.createNode(c.allocator);
    errdefer @panic("TODO: Node deletion");
    node.* = .{
        .kind = .{ .Comment = data },
        .node_document = location.parent.node_document,
    };
}

fn createAnElementForTheToken(
    c: *TreeConstructor,
    start_tag: TokenStartTag,
    namespace: WhatWgNamespace,
    intended_parent: *Node,
) !Node {
    // TODO: Speculative HTML parser.
    const document = intended_parent.node_document;
    const local_name = start_tag.name;
    const is = start_tag.attributes.get("is");
    // TODO: Do custom element definition lookup.
    // NOTE: Custom element definition lookup is done twice using the same arguments:
    //       once here, and again when creating an element.
    const element = try c.allocator.create(ElementNodeData);
    errdefer c.allocator.destroy(element);
    element.* = try domCreateElement(c, local_name, namespace, null, is, false);
    errdefer element.deinit(c.allocator);
    var attr_it = start_tag.attributes.iterator();
    while (attr_it.next()) |attr| {
        const key = try c.allocator.dupe(u8, attr.key_ptr.*);
        errdefer c.allocator.free(key);
        const value = try c.allocator.dupe(u8, attr.value_ptr.*);
        errdefer c.allocator.free(value);
        try element.appendAttribute(c.allocator, key, value);
        // TODO: Check for attribute namespace parse errors.
    }
    // TODO: Execute scripts.
    // TODO: Check for resettable elements.
    // TODO: Check for form-associated elements.
    return Node{
        .kind = .{ .Element = element },
        .node_document = document,
    };
}

fn domCreateElement(
    c: *TreeConstructor,
    local_name: []const u8,
    namespace: WhatWgNamespace,
    prefix: ?[]const u8,
    is: ?[]const u8,
    // TODO: Figure out what synchronous_custom_elements does.
    synchronous_custom_elements: bool,
) !ElementNodeData {
    _ = synchronous_custom_elements;
    // TODO: Do custom element definition lookup.
    // TODO: Handle all 3 different cases for this procedure.
    const element_local_name = try c.allocator.dupe(u8, local_name);
    errdefer c.allocator.free(element_local_name);
    const element_prefix = if (prefix) |p| try c.allocator.dupe(u8, p) else null;
    errdefer if (element_prefix) |p| c.allocator.free(p);
    const element_is = if (is) |s| try c.allocator.dupe(u8, s) else null;
    errdefer if (element_is) |s| c.allocator.free(s);
    // TODO: The caller of this function must set the element interface (aka html_element_type).
    var result = ElementNodeData{
        .attributes = .{},
        .namespace = namespace,
        .namespace_prefix = element_prefix,
        .local_name = element_local_name,
        // TODO: Set the custom element state and custom element defintion.
        .is = element_is,
        // NOTE: If the element is an HTML element, this field must be set later.
        .html_element_type = undefined,
    };
    // TODO: Check for a valid custom element name.
    return result;
}

fn insertForeignElementForTheToken(c: *TreeConstructor, start_tag: TokenStartTag, namespace: WhatWgNamespace) !*Node {
    const adjusted_insertion_location = appropriateNodeInsertionLocation(c);
    var element = try createAnElementForTheToken(c, start_tag, namespace, adjusted_insertion_location.parent);
    errdefer element.deinit(c.allocator);
    // TODO: Set html_element_type in createAnElementForTheToken.
    if (std.mem.eql(u8, start_tag.name, "html")) {
        element.kind.Element.html_element_type = .html;
    } else if (std.mem.eql(u8, start_tag.name, "head")) {
        element.kind.Element.html_element_type = .head;
    } else if (std.mem.eql(u8, start_tag.name, "body")) {
        element.kind.Element.html_element_type = .body;
    } else {
        @panic("TODO: Set the HTML element type.");
    }
    // TODO: Allow the element to be dropped.
    // TODO: Some stuff regarding custom elements
    const node_ptr = try adjusted_insertion_location.createNode(c.allocator);
    errdefer @panic("TODO: Node deletion");
    // TODO: Some stuff regarding custom elements
    node_ptr.* = element;
    try c.open_elements.append(c.allocator, node_ptr);
    return node_ptr;
}

fn insertHtmlElementForTheToken(c: *TreeConstructor, start_tag: TokenStartTag) !*Node {
    return insertForeignElementForTheToken(c, start_tag, .html);
}

fn reconstructActiveFormattingElements(c: *TreeConstructor) void {
    if (c.active_formatting_elements.items.len == 0) return;
    @panic("TODO Reconstruct the active formatting elements");
}

fn hasElementInScope(c: *TreeConstructor, element_type: enum { body, html, p }) bool {
    _ = c;
    _ = element_type;
    // TODO Check for elements in scope.
    return true;
}

fn closePElement(c: *TreeConstructor) void {
    _ = c;
    @panic("TODO Close a P element.");
}

fn checkValidInBodyEndTag(c: *TreeConstructor) void {
    if (comptime report_parse_errors) {
        // TODO: Check the stack of open elements for parse errors
        _ = c;
        //const validTypes = [_]NodeType{
        //    .dd,
        //    .dt,
        //    .li,
        //    .optgroup,
        //    .option,
        //    .p,
        //    .rb,
        //    .rp,
        //    .rt,
        //    .rtc,
        //    .tbody,
        //    .td,
        //    .tfoot,
        //    .th,
        //    .thead,
        //    .tr,
        //    .body,
        //    .html,
        //};
        //outer: for (c.open_elements) |elem| {
        //    for (validTypes) |t| {
        //        if (elem.isType(t)) {
        //            continue :outer;
        //        }
        //    }
        //    parseError(.Generic);
        //}
    }
}
