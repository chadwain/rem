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

const Dom = @import("./dom.zig");
const Document = Dom.Document;
const Element = Dom.Element;
const ElementType = Dom.ElementType;
const CharacterData = Dom.CharacterData;
const CharacterDataInterface = Dom.CharacterDataInterface;

const report_parse_errors = true;

test {
    const al = std.heap.page_allocator;
    const input = "<!doctype html><!--Side note 1--><html><body>hello<!--Side note 2--></body></html><!--Side note 3-->";
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

    var dom = Dom.Dom{};
    var c = TreeConstructor.init(&dom, al);

    for (tokenizer.tokens.items) |token| {
        try c.run(token);
        if (c.stopped) break;
    }

    std.debug.print("\nDOM Tree:\n\n", .{});
    std.debug.print("Document: {s}\n", .{@tagName(c.dom.document.quirks_mode)});

    {
        const split = c.dom.document.cdata_nodes_splits[0];
        const cdatas = c.dom.document.cdata_nodes.items[split[0]..split[1]];
        for (cdatas) |cdata| std.debug.print("  {s}: {s}\n", .{ @tagName(cdata.interface), cdata.data.items });
    }

    if (c.dom.document.doctype) |doctype| {
        std.debug.print("  DocumentType: name={s} publicId={s} systemId={s}\n", .{ doctype.name, doctype.publicId, doctype.systemId });
    }

    {
        const split = c.dom.document.cdata_nodes_splits[1];
        const cdatas = c.dom.document.cdata_nodes.items[split[0]..split[1]];
        for (cdatas) |cdata| std.debug.print("  {s}: {s}\n", .{ @tagName(cdata.interface), cdata.data.items });
    }

    var node_stack = ArrayListUnmanaged(struct { node: Dom.ElementOrCharacterData, depth: usize }){};
    defer node_stack.deinit(al);
    if (c.dom.document.element) |*document_element| {
        try node_stack.append(al, .{ .node = .{ .element = document_element }, .depth = 1 });
    }
    while (node_stack.items.len > 0) {
        const item = node_stack.pop();
        var len = item.depth;
        while (len > 0) : (len -= 1) {
            std.debug.print("  ", .{});
        }
        switch (item.node) {
            .element => |element| {
                const namespace_prefix = element.namespace_prefix orelse "";
                const is = element.is orelse "";
                std.debug.print("Element: type={s} local_name={s} namespace={s} prefix={s} is={s}", .{
                    @tagName(element.element_type),
                    element.local_name,
                    @tagName(element.namespace),
                    namespace_prefix,
                    is,
                });
                var attr_it = element.attributes.iterator();
                std.debug.print(" [ ", .{});
                while (attr_it.next()) |attr| {
                    std.debug.print("\"{s}\"=\"{s}\" ", .{ attr.key_ptr.*, attr.value_ptr.* });
                }
                std.debug.print("]\n", .{});
                var num_children = element.children.items.len;
                while (num_children > 0) : (num_children -= 1) {
                    try node_stack.append(al, .{ .node = element.children.items[num_children - 1], .depth = item.depth + 1 });
                }
            },
            .cdata => |cdata| std.debug.print("{s}: {s}\n", .{ @tagName(cdata.interface), cdata.data.items }),
        }
    }

    {
        const split = c.dom.document.cdata_nodes_splits[2];
        const cdatas = c.dom.document.cdata_nodes.items[split[0]..split[1]];
        for (cdatas) |cdata| std.debug.print("  {s}: {s}\n", .{ @tagName(cdata.interface), cdata.data.items });
    }
}

const ParentNode = union(enum) {
    document: *Document,
    element: *Element,
};

const TreeConstructor = struct {
    dom: *Dom.Dom,
    allocator: *Allocator,

    insertion_mode: InsertionMode = .Initial,
    original_insertion_mode: InsertionMode = undefined,
    open_elements: ArrayListUnmanaged(*Dom.Element) = .{},
    active_formatting_elements: ArrayListUnmanaged(*Dom.Element) = .{},
    template_insertion_modes: ArrayListUnmanaged(InsertionMode) = .{},
    head_element_pointer: ?*Dom.Element = null,
    form_element_pointer: ?*Dom.Element = null,
    reprocess: bool = false,
    stopped: bool = false,
    ignore_next_lf_token: bool = false,
    parser_cannot_change_the_mode: bool = false,
    is_iframe_srcdoc_document: bool = false,
    is_fragment_parser: bool = false,
    self_closing_flag_acknowledged: bool = false,
    frameset_ok: FramesetOk = .ok,
    scripting: bool = false,
    foster_parenting: bool = false,

    const FramesetOk = enum {
        ok,
        not_ok,
    };

    fn init(dom: *Dom.Dom, allocator: *Allocator) TreeConstructor {
        return TreeConstructor{
            .dom = dom,
            .allocator = allocator,
        };
    }

    fn run(self: *TreeConstructor, token: Token) !void {
        if (self.ignore_next_lf_token) {
            self.ignore_next_lf_token = false;
            if (token == .character and token.character.data == '\n') return;
        }

        var should_process = true;
        while (should_process) {
            self.reprocess = false;
            // TODO: Must call dispatcher instead.
            try dispatcher(self, token);
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

    fn currentNode(self: *TreeConstructor) *Element {
        return self.open_elements.items[self.open_elements.items.len - 1];
    }

    fn adjustedCurrentNode(self: *TreeConstructor) *Element {
        if (self.is_fragment_parser and self.open_elements.items.len == 1) {
            @panic("TODO: Adjusted current node, fragment case");
        } else {
            return self.currentNode();
        }
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

fn dispatcher(c: *TreeConstructor, token: Token) !void {
    if (c.open_elements.items.len == 0) return processToken(c, token);

    const adjusted_current_node = c.adjustedCurrentNode();
    if (adjusted_current_node.namespace == .html or
        token == .eof
    // TODO: or a bunch of other stuff according to the "tree construction dispatcher" in section 13.2.6
    ) try processToken(c, token) else processTokenForeignContent(c, token);
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
        .comment => |comment| try insertCommentToDocument(c, comment),
        .doctype => |d| {
            if ((d.name != null and !strEqlAny(d.name.?, &.{"html"})) or (d.public_identifier != null) or (d.system_identifier != null and !strEqlAny(d.system_identifier.?, &.{"about:legacy-compat"}))) {
                parseError(.Generic);
            }

            if (!c.is_iframe_srcdoc_document and
                !c.parser_cannot_change_the_mode and
                doctypeEnablesQuirks(d))
            {
                c.dom.document.quirks_mode = .quirks;
            } else if (!c.is_iframe_srcdoc_document and
                !c.parser_cannot_change_the_mode and
                doctypeEnablesLimitedQuirks(d))
            {
                c.dom.document.quirks_mode = .limited_quirks;
            }

            _ = try c.dom.document.insertDocumentType(c.allocator, d.name, d.public_identifier, d.system_identifier);
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
        c.dom.document.quirks_mode = .quirks;
    }
    c.reprocessIn(.BeforeHtml);
}

fn beforeHtml(c: *TreeConstructor, token: Token) !void {
    switch (token) {
        .doctype => {
            parseError(.Generic);
            // Ignore the token.
        },
        .comment => |comment| try insertCommentToDocument(c, comment),
        .character => |character| {
            if (isWhitespaceCharacter(character.data)) {
                // Ignore the token.
            } else {
                try beforeHtmlAnythingElse(c);
            }
        },
        .start_tag => |start_tag| {
            if (strEqlAny(start_tag.name, &.{"html"})) {
                const element = try createAnElementForTheToken(c, start_tag, .html, .{ .document = &c.dom.document });
                const element_ptr = c.dom.document.insertElement(element);
                try c.open_elements.append(c.allocator, element_ptr);
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
    const element = c.dom.document.insertElement(Dom.Element{
        .attributes = .{},
        .namespace = .html,
        .namespace_prefix = null,
        .local_name = local_name,
        .is = null,
        .element_type = .html_html,
        .children = .{},
    });
    try c.open_elements.append(c.allocator, element);
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
        assert(current_node.element_type == .html_head);
        c.changeTo(.AfterHead);
    } else if (token == .end_tag and strEqlAny(token.end_tag.name, &.{ "body", "html", "br" })) {
        // NOTE: Same as "anything else".
        const current_node = c.open_elements.pop();
        assert(current_node.element_type == .html_head);
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
        assert(current_node.element_type == .html_head);
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
        .doctype => inBodyDoctype(),
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
                if (c.open_elements.items.len == 1 or
                    (c.open_elements.items.len > 1 and c.open_elements.items[1].element_type != .html_body) or
                    for (c.open_elements.items) |e|
                {
                    if (e.element_type == .html_template) break true;
                } else false) {
                    assert(c.is_fragment_parser);
                    // Ignore the token.
                } else {
                    c.frameset_ok = .not_ok;
                    const body = c.open_elements.items[1];
                    assert(body.element_type == .html_body);
                    var attr_it = start_tag.attributes.iterator();
                    while (attr_it.next()) |attr| {
                        try body.addAttributeNoReplace(c.allocator, attr.key_ptr.*, attr.value_ptr.*);
                    }
                }
            } else if (strEqlAny(start_tag.name, &.{"frameset"})) {
                parseError(.Generic);
                if (c.open_elements.items.len == 1 or c.open_elements.items[1].element_type != .html_body) {
                    assert(c.is_fragment_parser);
                    // Ignore the token.
                } else if (c.frameset_ok == .not_ok) {
                    // Ignore the token.
                } else {
                    @panic("TODO: InBody start tag frameset, removing an element");
                    // The stack of open elements has at least 2 elements because of previous checks.
                    // const second = c.open_elements.items[1];
                    // second.detachFromParent();
                    // c.open_elements.shrinkRetainingCapacity(1);
                    // _ = try insertHtmlElementForTheToken(c, token);
                    // c.changeTo(.InFrameset);
                }
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
                if (hasElementInButtonScope(c, .html_p)) {
                    closePElement(c);
                }
                _ = try insertHtmlElementForTheToken(c, start_tag);
            } else if (strEqlAny(start_tag.name, &.{ "h1", "h2", "h3", "h4", "h5", "h6" })) {
                if (hasElementInButtonScope(c, .html_p)) {
                    closePElement(c);
                }
                const current_node = c.currentNode();
                if (current_node.namespace == .html and strEqlAny(current_node.local_name, &.{ "h1", "h2", "h3", "h4", "h5", "h6" })) {
                    parseError(.Generic);
                    _ = c.open_elements.pop();
                }
                _ = try insertHtmlElementForTheToken(c, start_tag);
            } else if (strEqlAny(start_tag.name, &.{ "pre", "listing" })) {
                if (hasElementInButtonScope(c, .html_p)) {
                    closePElement(c);
                }
                _ = try insertHtmlElementForTheToken(c, start_tag);
                c.ignore_next_lf_token = true;
                c.frameset_ok = .not_ok;
            } else if (strEqlAny(start_tag.name, &.{"form"})) {
                const stack_has_template_element = stackOfOpenElementsHas(c, .html_template);
                if (c.form_element_pointer != null and !stack_has_template_element) {
                    parseError(.Generic);
                    // Ignore the token.
                } else {
                    if (hasElementInButtonScope(c, .html_p)) {
                        closePElement(c);
                    }
                    const element = try insertHtmlElementForTheToken(c, start_tag);
                    if (!stack_has_template_element) {
                        c.form_element_pointer = element;
                    }
                }
            } else if (strEqlAny(start_tag.name, &.{"li"})) {
                c.frameset_ok = .not_ok;
                var index = c.open_elements.items.len;
                var node = c.open_elements.items[index - 1];
                // TODO: Rewrite this.
                while (true) {
                    if (node.element_type == .html_li) {
                        generateImpliedEndTags(c, .html_li);
                        if (c.currentNode().element_type != .html_li) {
                            parseError(.Generic);
                        }
                        while (c.open_elements.pop().element_type != .html_li) {}
                        break;
                    } else if (isSpecialElement(node.element_type) and node.element_type != .html_address and node.element_type != .html_div and node.element_type != .html_p) {
                        break;
                    } else {
                        index -= 1;
                        node = c.open_elements.items[index - 1];
                    }
                }
                if (hasElementInButtonScope(c, .html_p)) {
                    closePElement(c);
                }
                _ = try insertHtmlElementForTheToken(c, start_tag);
            } else {
                @panic("TODO InBody insertion mode is incomplete");
            }
        },
        .end_tag => |end_tag| {
            if (strEqlAny(end_tag.name, &.{"template"})) {
                // TODO: Jump straight to the appropriate handler.
                try inHead(c, token);
            } else if (strEqlAny(end_tag.name, &.{"body"})) {
                if (!hasElementInScope(c, .html_body)) {
                    parseError(.Generic);
                    // Ignore the token.
                } else {
                    checkValidInBodyEndTag(c);
                    c.changeTo(.AfterBody);
                }
            } else if (strEqlAny(end_tag.name, &.{"html"})) {
                if (!hasElementInScope(c, .html_body)) {
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

fn inBodyDoctype() void {
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
    //        top.addAttributeNoReplace(attr);
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
            if (current_node.element_type == .html_script) {
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
        .comment => |comment| try insertCommentToDocument(c, comment),
        .doctype => {
            inBodyDoctype();
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

fn elemTypeEqlAny(element_type: ElementType, comptime compare_to: []const ElementType) bool {
    for (compare_to) |t| {
        if (element_type == t) return true;
    }
    return false;
}

fn parseError(err: ParseError) void {
    // TODO: Handle parse errors.
    std.debug.print("Tree construction parse error: {s}\n", .{@tagName(err)});
}

const NodeInsertionLocation = struct {
    parent: ParentNode,

    fn asLastChildOfDocument(document: *Document) NodeInsertionLocation {
        return NodeInsertionLocation{ .parent = .{ .document = document } };
    }

    fn asLastChildOfElement(element: *Element) NodeInsertionLocation {
        return NodeInsertionLocation{ .parent = .{ .element = element } };
    }

    fn makeElement(self: NodeInsertionLocation, allocator: *Allocator, element: Element) !*Element {
        // TODO: Assuming that the insertion location is last child of parent.
        return switch (self.parent) {
            .document => |doc| doc.insertElement(element),
            .element => |e| try e.insertElement(allocator, element),
        };
    }

    fn makeCharacterData(self: NodeInsertionLocation, allocator: *Allocator, data: []const u8, interface: CharacterDataInterface) !void {
        // TODO: Assuming that the insertion location is last child of parent.
        switch (self.parent) {
            .document => |doc| try doc.insertCharacterData(allocator, data, interface),
            .element => |e| try e.insertCharacterData(allocator, data, interface),
        }
    }

    // Only meant to be called when inserting a character, after checking that the parent is not a Document.
    fn previousSiblingIsText(self: NodeInsertionLocation) ?*Dom.CharacterData {
        // TODO: Assuming that the insertion location is last child of parent.
        switch (self.parent) {
            .document => unreachable,
            .element => |e| {
                if (e.children.items.len == 0) return null;
                return switch (e.children.items[e.children.items.len - 1]) {
                    .element => null,
                    .cdata => |cdata| if (cdata.interface == .text) cdata else null,
                };
            },
        }
    }
};

fn appropriateNodeInsertionLocation(c: *TreeConstructor) NodeInsertionLocation {
    return appropriateNodeInsertionLocationWithTarget(c, c.currentNode());
}

fn appropriateNodeInsertionLocationWithTarget(c: *TreeConstructor, target: *Element) NodeInsertionLocation {
    var adjusted_insertion_location: *Element = undefined;
    var position: enum { last_child } = undefined;
    if (c.foster_parenting and elemTypeEqlAny(target.element_type, &.{ .html_table, .html_tbody, .html_tfoot, .html_thead, .html_tr })) substeps: {
        @setCold(true);
        var last_template: ?*Dom.Element = null;
        var last_table: ?*Dom.Element = null;
        var index = c.open_elements.items.len;
        while (index > 0) : (index -= 1) {
            var node = c.open_elements.items[index - 1];
            if (node.element_type == .html_template) {
                last_template = node;
                if (last_table != null) break;
            } else if (node.element_type == .html_table) {
                if (last_template != null) {
                    // last_template is lower in the stack than last_table.
                    @panic("TODO Appropriate place for inserting a node is inside a template");
                } else {
                    last_table = node;
                }
            }
        }
        if (last_template != null and last_table == null) {
            @panic("TODO Appropriate place for inserting a node is inside a template");
        }
        if (last_table == null) {
            assert(c.is_fragment_parser);
            adjusted_insertion_location = c.open_elements.items[0];
            position = .last_child;
            break :substeps;
        }
        @panic("TODO Foster parenting implementation is incomplete");
    } else {
        adjusted_insertion_location = target;
        position = .last_child;
    }

    if (adjusted_insertion_location.element_type == .html_template) {
        @setCold(true);
        @panic("TODO Appropriate place for inserting a node is inside a template");
    }

    return switch (position) {
        .last_child => NodeInsertionLocation.asLastChildOfElement(adjusted_insertion_location),
    };
}

fn insertCharacter(c: *TreeConstructor, character: TokenCharacter) !void {
    const location = appropriateNodeInsertionLocation(c);
    if (location.parent == .document) {
        return;
    }

    var code_units: [4]u8 = undefined;
    const len = try std.unicode.utf8Encode(character.data, &code_units);
    if (location.previousSiblingIsText()) |text_node| {
        try text_node.append(c.allocator, code_units[0..len]);
    } else {
        try location.makeCharacterData(c.allocator, code_units[0..len], .text);
    }
}

fn insertComment(c: *TreeConstructor, comment: TokenComment) !void {
    return insertCommentWithPosition(c, comment, appropriateNodeInsertionLocation(c));
}

fn insertCommentWithPosition(c: *TreeConstructor, comment: TokenComment, location: NodeInsertionLocation) !void {
    return location.makeCharacterData(c.allocator, comment.data, .comment);
}

fn insertCommentToDocument(c: *TreeConstructor, comment: TokenComment) !void {
    return c.dom.document.insertCharacterData(c.allocator, comment.data, .comment);
}

fn createAnElementForTheToken(
    c: *TreeConstructor,
    start_tag: TokenStartTag,
    namespace: Dom.WhatWgNamespace,
    intended_parent: ParentNode,
) !Element {
    // TODO: Speculative HTML parser.
    // TODO: Get the element's node element.
    _ = intended_parent;
    const local_name = start_tag.name;
    const is = start_tag.attributes.get("is");
    // TODO: Do custom element definition lookup.
    // NOTE: Custom element definition lookup is done twice using the same arguments:
    //       once here, and again when creating an element.
    // TODO: Find a better way to set element_type.
    var element_type: ElementType = undefined;
    if (std.mem.eql(u8, start_tag.name, "html")) {
        element_type = .html_html;
    } else if (std.mem.eql(u8, start_tag.name, "head")) {
        element_type = .html_head;
    } else if (std.mem.eql(u8, start_tag.name, "body")) {
        element_type = .html_body;
    } else {
        @panic("TODO: Set the HTML element type.");
    }
    var element = try Dom.createAnElement(c.allocator, local_name, namespace, null, is, element_type, false);
    errdefer element.deinit(c.allocator);
    var attr_it = start_tag.attributes.iterator();
    while (attr_it.next()) |attr| {
        try element.addAttribute(c.allocator, attr.key_ptr.*, attr.value_ptr.*);
        // TODO: Check for attribute namespace parse errors.
    }
    // TODO: Execute scripts.
    // TODO: Check for resettable elements.
    // TODO: Check for form-associated elements.
    return element;
}

fn insertForeignElementForTheToken(c: *TreeConstructor, start_tag: TokenStartTag, namespace: Dom.WhatWgNamespace) !*Element {
    const adjusted_insertion_location = appropriateNodeInsertionLocation(c);
    var element = try createAnElementForTheToken(c, start_tag, namespace, adjusted_insertion_location.parent);
    errdefer element.deinit(c.allocator);
    // TODO: Allow the element to be dropped.
    // TODO: Some stuff regarding custom elements
    const element_ptr = try adjusted_insertion_location.makeElement(c.allocator, element);
    // TODO: Some stuff regarding custom elements
    try c.open_elements.append(c.allocator, element_ptr);
    return element_ptr;
}

fn insertHtmlElementForTheToken(c: *TreeConstructor, start_tag: TokenStartTag) !*Element {
    return insertForeignElementForTheToken(c, start_tag, .html);
}

fn stackOfOpenElementsHas(c: *TreeConstructor, element_type: ElementType) bool {
    var index = c.open_elements.items.len;
    while (index > 0) : (index -= 1) {
        if (c.open_elements.items[index - 1].element_type == element_type) return true;
    }
    return false;
}

fn reconstructActiveFormattingElements(c: *TreeConstructor) void {
    if (c.active_formatting_elements.items.len == 0) return;
    @panic("TODO Reconstruct the active formatting elements");
}

fn isSpecialElement(element_type: ElementType) bool {
    return switch (element_type) {
        .html_address,
        .html_applet,
        .html_area,
        .html_article,
        .html_aside,
        .html_base,
        .html_basefont,
        .html_bgsound,
        .html_blockquote,
        .html_body,
        .html_br,
        .html_button,
        .html_caption,
        .html_center,
        .html_col,
        .html_colgroup,
        .html_dd,
        .html_details,
        .html_dir,
        .html_div,
        .html_dl,
        .html_dt,
        .html_embed,
        .html_fieldset,
        .html_figcaption,
        .html_figure,
        .html_footer,
        .html_form,
        .html_frame,
        .html_frameset,
        .html_h1,
        .html_h2,
        .html_h3,
        .html_h4,
        .html_h5,
        .html_h6,
        .html_head,
        .html_header,
        .html_hgroup,
        .html_hr,
        .html_html,
        .html_iframe,
        .html_img,
        .html_input,
        .html_keygen,
        .html_li,
        .html_link,
        .html_listing,
        .html_main,
        .html_marquee,
        .html_menu,
        .html_meta,
        .html_nav,
        .html_noembed,
        .html_noframes,
        .html_noscript,
        .html_object,
        .html_ol,
        .html_p,
        .html_param,
        .html_plaintext,
        .html_pre,
        .html_script,
        .html_section,
        .html_select,
        .html_source,
        .html_style,
        .html_summary,
        .html_table,
        .html_tbody,
        .html_td,
        .html_template,
        .html_textarea,
        .html_tfoot,
        .html_th,
        .html_thead,
        .html_title,
        .html_tr,
        .html_track,
        .html_ul,
        .html_wbr,
        .html_xmp,
        .mathml_mi,
        .mathml_mo,
        .mathml_mn,
        .mathml_ms,
        .mathml_mtext,
        .mathml_annotation_xml,
        .svg_foreign_object,
        .svg_desc,
        .svg_title,
        => true,
        else => false,
    };
}

fn hasElementInSpecificScope(c: *TreeConstructor, target: ElementType, comptime list: []const ElementType) bool {
    var index = c.open_elements.items.len;
    var node = c.open_elements.items[index - 1];
    while (node.element_type != target) {
        if (std.mem.indexOfScalar(ElementType, list, node.element_type) != null) return false;
        index -= 1;
        node = c.open_elements.items[index - 1];
    }
    return true;
}

fn hasElementInScope(c: *TreeConstructor, target: ElementType) bool {
    const list = &[_]ElementType{
        .html_applet,
        .html_caption,
        .html_html,
        .html_table,
        .html_td,
        .html_th,
        .html_marquee,
        .html_object,
        .html_template,
        .mathml_mi,
        .mathml_mo,
        .mathml_mn,
        .mathml_ms,
        .mathml_mtext,
        .mathml_annotation_xml,
        .svg_foreign_object,
        .svg_desc,
        .svg_title,
    };
    return hasElementInSpecificScope(c, target, list);
}

fn hasElementInButtonScope(c: *TreeConstructor, target: ElementType) bool {
    const list = &[_]ElementType{
        .html_applet,
        .html_button,
        .html_caption,
        .html_html,
        .html_table,
        .html_td,
        .html_th,
        .html_marquee,
        .html_object,
        .html_template,
        .mathml_mi,
        .mathml_mo,
        .mathml_mn,
        .mathml_ms,
        .mathml_mtext,
        .mathml_annotation_xml,
        .svg_foreign_object,
        .svg_desc,
        .svg_title,
    };
    return hasElementInSpecificScope(c, target, list);
}

fn generateImpliedEndTags(c: *TreeConstructor, exception: ?ElementType) void {
    const list = &[_]ElementType{
        .html_dd,
        .html_dt,
        .html_li,
        .html_optgroup,
        .html_option,
        .html_p,
        .html_rb,
        .html_rp,
        .html_rt,
        .html_rtc,
    };

    var element_type = c.currentNode().element_type;
    while (std.mem.indexOfScalar(ElementType, list, element_type)) |_| {
        if (exception == null or element_type != exception.?) {
            _ = c.open_elements.pop();
            element_type = c.currentNode().element_type;
        } else {
            break;
        }
    }
}

fn closePElement(c: *TreeConstructor) void {
    generateImpliedEndTags(c, .html_p);
    if (c.currentNode().element_type != .html_p) {
        parseError(.Generic);
    }
    while (c.open_elements.pop().element_type != .html_p) {}
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
