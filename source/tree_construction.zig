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
const ElementInterface = Dom.ElementInterface;
const CharacterData = Dom.CharacterData;
const CharacterDataInterface = Dom.CharacterDataInterface;

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

    var dom = Dom.Dom{};
    var c = TreeConstructor.init(&dom, al);

    for (tokenizer.tokens.items) |token| {
        try c.run(token);
        if (c.stopped) break;
    }

    std.debug.print("\nDOM Tree:\n\n", .{});
    std.debug.print("Document: {s}\n", .{@tagName(c.dom.document.quirks_mode)});
    if (c.dom.document.doctype) |doctype| {
        std.debug.print("DocumentType: name={s} publicId={s} systemId={s}\n", .{ doctype.name, doctype.publicId, doctype.systemId });
    }

    var node_stack = ArrayListUnmanaged(struct { node: Dom.ElementOrCharacterData, depth: usize }){};
    defer node_stack.deinit(al);
    if (c.dom.document.element) |*document_element| {
        try node_stack.append(al, .{ .node = .{ .element = document_element }, .depth = 0 });
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
                std.debug.print("Element: interface={s} local_name={s} namespace={s} prefix={s} is={s}", .{
                    @tagName(element.interface),
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
            .cdata => |cdata| std.debug.print("{s}\n", .{cdata.data.items}),
        }
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
    reprocess: bool = false,
    stopped: bool = false,
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
        .interface = .html_html,
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
        assert(current_node.interface == .html_head);
        c.changeTo(.AfterHead);
    } else if (token == .end_tag and strEqlAny(token.end_tag.name, &.{ "body", "html", "br" })) {
        // NOTE: Same as "anything else".
        const current_node = c.open_elements.pop();
        assert(current_node.interface == .html_head);
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
        assert(current_node.interface == .html_head);
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
                //    for (tart_tag.attributes) |attr| {
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
            if (strEqlAny(end_tag.name, &.{"template"})) {
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
            if (current_node.interface == .html_script) {
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
    _ = c;
    var adjusted_insertion_location: NodeInsertionLocation = undefined;
    // TODO: Apply foster parenting.
    adjusted_insertion_location = NodeInsertionLocation.asLastChildOfElement(target);

    // TODO: Check if adjusted_insertion_location is a template.
    return adjusted_insertion_location;
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
    // TODO: Find a better way to set html_element_type.
    var interface: ElementInterface = undefined;
    if (std.mem.eql(u8, start_tag.name, "html")) {
        interface = .html_html;
    } else if (std.mem.eql(u8, start_tag.name, "head")) {
        interface = .html_head;
    } else if (std.mem.eql(u8, start_tag.name, "body")) {
        interface = .html_body;
    } else {
        @panic("TODO: Set the HTML element type.");
    }
    var element = try Dom.createAnElement(c.allocator, local_name, namespace, null, is, interface, false);
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
