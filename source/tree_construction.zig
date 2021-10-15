// Copyright (C) 2021 Chadwain Holness
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const ArrayListUnmanaged = std.ArrayListUnmanaged;
const StringHashMapUnmanaged = std.StringHashMapUnmanaged;

const html5 = @import("../html5.zig");

const Tokenizer = html5.Tokenizer;
const Token = Tokenizer.Token;
const TokenStartTag = Tokenizer.TokenStartTag;
const TokenEndTag = Tokenizer.TokenEndTag;
const TokenComment = Tokenizer.TokenComment;
const TokenCharacter = Tokenizer.TokenCharacter;
const TokenDOCTYPE = Tokenizer.TokenDOCTYPE;

const Dom = html5.dom;
const Document = Dom.Document;
const Element = Dom.Element;
const ElementType = Dom.ElementType;
const CharacterData = Dom.CharacterData;
const CharacterDataInterface = Dom.CharacterDataInterface;

test {
    const allocator = std.heap.page_allocator;

    const string = "<!doctype><html>asdf</body hello=world>";
    const input = &decodeComptimeString(string);

    var all_tokens = std.ArrayList(Token).init(allocator);
    defer {
        for (all_tokens.items) |*t| t.deinit(allocator);
        all_tokens.deinit();
    }

    var all_parse_errors = std.ArrayList(Tokenizer.ParseError).init(allocator);
    defer all_parse_errors.deinit();

    var tokenizer = Tokenizer.init(input, allocator, &all_tokens, &all_parse_errors);
    defer tokenizer.deinit();

    while (try tokenizer.run()) {}

    var dom = Dom.Dom{};
    var constructor = TreeConstructor.init(&dom, allocator);
    for (all_tokens.items) |token| {
        const run_result = try constructor.run(token);
        if (run_result.new_tokenizer_state != null) @panic("TODO: Changing the tokenizer state.");
    }
}

fn decodeComptimeStringLen(comptime string: []const u8) usize {
    var i: usize = 0;
    var decoded_len: usize = 0;
    while (i < string.len) {
        i += std.unicode.utf8ByteSequenceLength(string[i]) catch unreachable;
        decoded_len += 1;
    }
    return decoded_len;
}

fn decodeComptimeString(comptime string: []const u8) [decodeComptimeStringLen(string)]u21 {
    var result: [decodeComptimeStringLen(string)]u21 = undefined;
    if (result.len == 0) return result;
    var decoded_it = std.unicode.Utf8View.initComptime(string).iterator();
    var i: usize = 0;
    while (decoded_it.nextCodepoint()) |codepoint| {
        result[i] = codepoint;
        i += 1;
    }
    return result;
}

const report_parse_errors = true;

pub const RunResult = struct {
    new_tokenizer_state: ?Tokenizer.State = null,
    adjusted_current_node_is_not_in_html_namespace: bool = undefined,
};

pub const TreeConstructor = struct {
    dom: *Dom.Dom,
    allocator: *Allocator,

    insertion_mode: InsertionMode = .Initial,
    original_insertion_mode: InsertionMode = undefined,
    open_elements: ArrayListUnmanaged(*Dom.Element) = .{},
    active_formatting_elements: ArrayListUnmanaged(FormattingElement) = .{},
    active_formatting_element_original_attributes: ArrayListUnmanaged(Dom.ElementAttributes) = .{},
    index_of_last_marker: ?usize = null,
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
    new_tokenizer_state: ?Tokenizer.State = null,

    const FramesetOk = enum {
        ok,
        not_ok,
    };

    pub fn init(dom: *Dom.Dom, allocator: *Allocator) TreeConstructor {
        return TreeConstructor{
            .dom = dom,
            .allocator = allocator,
        };
    }

    pub fn run(self: *TreeConstructor, token: Token) !RunResult {
        var result = RunResult{};
        defer result.adjusted_current_node_is_not_in_html_namespace = self.open_elements.items.len > 0 and adjustedCurrentNode(self).namespace() != .html;

        if (self.ignore_next_lf_token) {
            self.ignore_next_lf_token = false;
            if (token == .character and token.character.data == '\n') return result;
        }

        var should_process = true;
        while (should_process) {
            self.reprocess = false;
            try dispatcher(self, token);
            should_process = self.reprocess;
        }

        result.new_tokenizer_state = self.new_tokenizer_state;
        self.new_tokenizer_state = null;

        return result;
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

fn changeTo(c: *TreeConstructor, insertion_mode: InsertionMode) void {
    c.insertion_mode = insertion_mode;
    std.debug.print("Change to: {s}\n", .{@tagName(insertion_mode)});
}

fn changeToOriginalInsertionMode(c: *TreeConstructor) void {
    changeTo(c, c.original_insertion_mode);
    c.original_insertion_mode = undefined;
}

fn changeToAndSetOriginalInsertionMode(c: *TreeConstructor, insertion_mode: InsertionMode, original_insertion_mode: InsertionMode) void {
    c.original_insertion_mode = original_insertion_mode;
    changeTo(c, insertion_mode);
}

fn reprocessIn(c: *TreeConstructor, insertion_mode: InsertionMode) void {
    c.reprocess = true;
    c.insertion_mode = insertion_mode;
    std.debug.print("Reprocess in: {s}\n", .{@tagName(insertion_mode)});
}

fn reprocessInOriginalInsertionMode(c: *TreeConstructor) void {
    reprocessIn(c, c.original_insertion_mode);
    c.original_insertion_mode = undefined;
}

fn stop(c: *TreeConstructor) void {
    // TODO: Stopping parsing has more steps.
    c.stopped = true;
    std.debug.print("Stopped parsing.", .{});
}

fn setTokenizerState(c: *TreeConstructor, state: Tokenizer.State) void {
    c.new_tokenizer_state = state;
}

fn dispatcher(c: *TreeConstructor, token: Token) !void {
    if (c.open_elements.items.len == 0) return processToken(c, token);

    const adjusted_current_node = adjustedCurrentNode(c);
    if (adjusted_current_node.namespace() == .html or
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
                try inBodyStartTagHtml(c, token.start_tag);
            } else if (token == .start_tag and strEqlAny(token.start_tag.name, &.{"head"})) {
                const node = try insertHtmlElementForTheToken(c, token.start_tag);
                c.head_element_pointer = node;
                changeTo(c, .InHead);
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
                reprocessIn(c, .InHead);
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
                try inBodyStartTagHtml(c, token.start_tag);
            } else if (token == .start_tag and strEqlAny(token.start_tag.name, &.{"body"})) {
                _ = try insertHtmlElementForTheToken(c, token.start_tag);
                c.frameset_ok = .not_ok;
                changeTo(c, .InBody);
            } else if (token == .start_tag and strEqlAny(token.start_tag.name, &.{"frameset"})) {
                _ = try insertHtmlElementForTheToken(c, token.start_tag);
                changeTo(c, .InFrameset);
            } else if (token == .start_tag and strEqlAny(token.start_tag.name, &.{ "base", "basefont", "bgsound", "link", "meta", "noframes", "script", "style", "template", "title" })) {
                parseError(.Generic);
                if (c.head_element_pointer) |head| {
                    try c.open_elements.append(c.allocator, head);
                    try inHead(c, token);
                    removeFromStackOfOpenElements(c, c.head_element_pointer.?);
                } else unreachable;
            } else if (token == .end_tag and strEqlAny(token.end_tag.name, &.{"template"})) {
                inHeadEndTagTemplate(c, token.end_tag);
            } else if (token == .end_tag and strEqlAny(token.end_tag.name, &.{ "body", "html", "br" })) {
                // NOTE: Same as "anything else".
                _ = try insertHtmlElementForTheToken(c, TokenStartTag{
                    .name = "body",
                    .attributes = .{},
                    .self_closing = false,
                });
                reprocessIn(c, .InBody);
            } else if (token == .start_tag and strEqlAny(token.start_tag.name, &.{"head"}) or token == .end_tag) {
                parseError(.Generic);
                // Ignore the token.
            } else {
                _ = try insertHtmlElementForTheToken(c, TokenStartTag{
                    .name = "body",
                    .attributes = .{},
                    .self_closing = false,
                });
                reprocessIn(c, .InBody);
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
        .AfterBody => try afterBody(c, token),
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
            if (!eqlNullStrings(d.name, "html") or (d.public_identifier != null) or (d.system_identifier != null and !strEql(d.system_identifier.?, "about:legacy-compat"))) {
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
            changeTo(c, .BeforeHtml);
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
    reprocessIn(c, .BeforeHtml);
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
            if (strEql(start_tag.name, "html")) {
                const element = try createAnElementForTheToken(c, start_tag, .html, .{ .document = &c.dom.document });
                const element_ptr = c.dom.document.insertElement(element);
                try c.open_elements.append(c.allocator, element_ptr);
                changeTo(c, .BeforeHead);
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
    const element = c.dom.document.insertElement(Dom.Element{
        .element_type = .html_html,
        .attributes = .{},
        .is = null,
        .children = .{},
    });
    try c.open_elements.append(c.allocator, element);
    reprocessIn(c, .BeforeHead);
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
        try inBodyStartTagHtml(c, token.start_tag);
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
        try textParsingAlgorithm(.RCDATA, c, token.start_tag);
    } else if ((token == .start_tag and strEqlAny(token.start_tag.name, &.{"noscript"}) and c.scripting == true) or
        (token == .start_tag and strEqlAny(token.start_tag.name, &.{ "noframes", "style" })))
    {
        try textParsingAlgorithm(.RAWTEXT, c, token.start_tag);
    } else if (token == .start_tag and strEqlAny(token.start_tag.name, &.{"noscript"}) and c.scripting == false) {
        _ = try insertHtmlElementForTheToken(c, token.start_tag);
        changeTo(c, .InHeadNoscript);
    } else if (token == .start_tag and strEqlAny(token.start_tag.name, &.{"script"})) {
        @panic("TODO script start tag in InHead");
    } else if (token == .end_tag and strEqlAny(token.end_tag.name, &.{"head"})) {
        // NOTE: NOT the same as "anything else".
        const current_node = c.open_elements.pop();
        assert(current_node.element_type == .html_head);
        changeTo(c, .AfterHead);
    } else if (token == .end_tag and strEqlAny(token.end_tag.name, &.{ "body", "html", "br" })) {
        // NOTE: Same as "anything else".
        const current_node = c.open_elements.pop();
        assert(current_node.element_type == .html_head);
        reprocessIn(c, .AfterHead);
    } else if (token == .start_tag and strEqlAny(token.start_tag.name, &.{"template"})) {
        @panic("TODO template start tag in InHead");
    } else if (token == .end_tag and strEqlAny(token.end_tag.name, &.{"template"})) {
        inHeadEndTagTemplate(c, token.end_tag);
    } else if (token == .start_tag and strEqlAny(token.start_tag.name, &.{"head"}) or token == .end_tag) {
        parseError(.Generic);
        // Ignore the token.
    } else {
        const current_node = c.open_elements.pop();
        assert(current_node.element_type == .html_head);
        reprocessIn(c, .AfterHead);
    }
}

fn inHeadEndTagTemplate(c: *TreeConstructor, end_tag: TokenEndTag) void {
    _ = c;
    _ = end_tag;
    @panic("TODO template end tag in InHead");
}

fn inTemplate(c: *TreeConstructor, token: Token) void {
    _ = c;
    _ = token;
    @panic("TODO InTemplate insertion mode");
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
                stop(c);
            }
        },
        .start_tag => |start_tag| {
            if (ElementType.fromStringHtml(start_tag.name)) |token_element_type| switch (token_element_type) {
                .html_html => {
                    try inBodyStartTagHtml(c, start_tag);
                },
                .html_base, .html_basefont, .html_bgsound, .html_link, .html_meta, .html_noframes, .html_script, .html_style, .html_template, .html_title => {
                    // TODO: Jump straight to the appropriate handler.
                    try inHead(c, token);
                },
                .html_body => {
                    parseError(.Generic);
                    if (c.open_elements.items.len == 1 or
                        (c.open_elements.items.len > 1 and c.open_elements.items[1].element_type != .html_body) or
                        stackOfOpenElementsHas(c, .html_template))
                    {
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
                },
                .html_frameset => {
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
                        // changeTo(c, .InFrameset);
                    }
                },
                .html_address,
                .html_article,
                .html_aside,
                .html_blockquote,
                .html_center,
                .html_details,
                .html_dialog,
                .html_dir,
                .html_div,
                .html_dl,
                .html_fieldset,
                .html_figcaption,
                .html_figure,
                .html_footer,
                .html_header,
                .html_hgroup,
                .html_main,
                .html_menu,
                .html_nav,
                .html_ol,
                .html_p,
                .html_section,
                .html_summary,
                .html_ul,
                => {
                    if (hasElementInButtonScope(c, ElementType.html_p)) {
                        closePElement(c);
                    }
                    _ = try insertHtmlElementForTheToken(c, start_tag);
                },
                .html_h1, .html_h2, .html_h3, .html_h4, .html_h5, .html_h6 => {
                    if (hasElementInButtonScope(c, ElementType.html_p)) {
                        closePElement(c);
                    }
                    const current_node = currentNode(c);
                    if (current_node.namespace() == .html and elemTypeEqlAny(current_node.element_type, &.{ .html_h1, .html_h2, .html_h3, .html_h4, .html_h5, .html_h6 })) {
                        parseError(.Generic);
                        _ = c.open_elements.pop();
                    }
                    _ = try insertHtmlElementForTheToken(c, start_tag);
                },
                .html_pre, .html_listing => {
                    if (hasElementInButtonScope(c, ElementType.html_p)) {
                        closePElement(c);
                    }
                    _ = try insertHtmlElementForTheToken(c, start_tag);
                    c.ignore_next_lf_token = true;
                    c.frameset_ok = .not_ok;
                },
                .html_form => {
                    const stack_has_template_element = stackOfOpenElementsHas(c, .html_template);
                    if (c.form_element_pointer != null and !stack_has_template_element) {
                        parseError(.Generic);
                        // Ignore the token.
                    } else {
                        if (hasElementInButtonScope(c, ElementType.html_p)) {
                            closePElement(c);
                        }
                        const element = try insertHtmlElementForTheToken(c, start_tag);
                        if (!stack_has_template_element) {
                            c.form_element_pointer = element;
                        }
                    }
                },
                .html_li => {
                    c.frameset_ok = .not_ok;
                    var index = c.open_elements.items.len;
                    while (true) {
                        const node = c.open_elements.items[index - 1];
                        if (node.element_type == .html_li) {
                            generateImpliedEndTags(c, .html_li);
                            if (currentNode(c).element_type != .html_li) {
                                parseError(.Generic);
                            }
                            while (c.open_elements.pop().element_type != .html_li) {}
                            break;
                        } else if (isSpecialElement(node.element_type) and node.element_type != .html_address and node.element_type != .html_div and node.element_type != .html_p) {
                            break;
                        } else {
                            index -= 1;
                        }
                    }
                    if (hasElementInButtonScope(c, ElementType.html_p)) {
                        closePElement(c);
                    }
                    _ = try insertHtmlElementForTheToken(c, start_tag);
                },
                .html_dd, .html_dt => {
                    c.frameset_ok = .not_ok;
                    var index = c.open_elements.items.len;
                    while (true) {
                        const node = c.open_elements.items[index - 1];
                        if (node.element_type == .html_dd) {
                            generateImpliedEndTags(c, .html_dd);
                            if (currentNode(c).element_type != .html_dd) {
                                parseError(.Generic);
                            }
                            while (c.open_elements.pop().element_type != .html_dd) {}
                            break;
                        } else if (node.element_type == .html_dt) {
                            generateImpliedEndTags(c, .html_dt);
                            if (currentNode(c).element_type != .html_dt) {
                                parseError(.Generic);
                            }
                            while (c.open_elements.pop().element_type != .html_dt) {}
                            break;
                        } else if (isSpecialElement(node.element_type) and node.element_type != .html_address and node.element_type != .html_div and node.element_type != .html_p) {
                            break;
                        } else {
                            index -= 1;
                        }
                    }
                    if (hasElementInButtonScope(c, ElementType.html_p)) {
                        closePElement(c);
                    }
                    _ = try insertHtmlElementForTheToken(c, start_tag);
                },
                .html_plaintext => {
                    if (hasElementInButtonScope(c, ElementType.html_p)) {
                        closePElement(c);
                    }
                    _ = try insertHtmlElementForTheToken(c, start_tag);
                    // TODO: Special case this?
                    setTokenizerState(c, .PLAINTEXT);
                },
                .html_button => {
                    if (hasElementInScope(c, ElementType.html_button)) {
                        parseError(.Generic);
                        generateImpliedEndTags(c, null);
                        while (c.open_elements.pop().element_type != .html_button) {}
                    }
                    reconstructActiveFormattingElements(c);
                    _ = try insertHtmlElementForTheToken(c, start_tag);
                    c.frameset_ok = .not_ok;
                },
                .html_a => {
                    const begin = if (c.index_of_last_marker) |lm| lm + 1 else 0;
                    for (c.active_formatting_elements.items[begin..]) |fe, i| {
                        if (fe.element.element_type == .html_a) {
                            parseError(.Generic);
                            const removed = adoptionAgencyAlgorithm(c, start_tag.name);
                            if (!removed) removeFromStackOfOpenElements(c, fe.element);
                            removeFromListOfActiveFormattingElements(c, begin + i);
                            break;
                        }
                    }
                    reconstructActiveFormattingElements(c);
                    const element = try insertHtmlElementForTheToken(c, start_tag);
                    try pushOntoListOfActiveFormattingElements(c, element);
                },
                .html_b, .html_big, .html_code, .html_em, .html_font, .html_i, .html_s, .html_small, .html_strike, .html_strong, .html_tt, .html_u => {
                    reconstructActiveFormattingElements(c);
                    const element = try insertHtmlElementForTheToken(c, start_tag);
                    try pushOntoListOfActiveFormattingElements(c, element);
                },
                .html_nobr => {
                    reconstructActiveFormattingElements(c);
                    if (hasElementInScope(c, ElementType.html_nobr)) {
                        parseError(.Generic);
                        _ = adoptionAgencyAlgorithm(c, start_tag.name);
                        reconstructActiveFormattingElements(c);
                    }
                    const element = try insertHtmlElementForTheToken(c, start_tag);
                    try pushOntoListOfActiveFormattingElements(c, element);
                },
                .html_applet, .html_marquee, .html_object => {
                    reconstructActiveFormattingElements(c);
                    _ = try insertHtmlElementForTheToken(c, start_tag);
                    try insertAMarker(c);
                    c.frameset_ok = .not_ok;
                },
                .html_table => {
                    if (c.dom.document.quirks_mode != .quirks and !hasElementInButtonScope(c, .html_p)) {
                        closePElement(c);
                    }
                    _ = try insertHtmlElementForTheToken(c, start_tag);
                    c.frameset_ok = .not_ok;
                    changeTo(c, .InTable);
                },
                .html_area, .html_br, .html_embed, .html_img, .html_keygen, .html_wbr => {
                    reconstructActiveFormattingElements(c);
                    _ = try insertHtmlElementForTheToken(c, start_tag);
                    _ = c.open_elements.pop();
                    acknowledgeSelfClosingFlag(c);
                    c.frameset_ok = .not_ok;
                },
                .html_input => {
                    reconstructActiveFormattingElements(c);
                    _ = try insertHtmlElementForTheToken(c, start_tag);
                    _ = c.open_elements.pop();
                    acknowledgeSelfClosingFlag(c);
                    const @"type" = start_tag.attributes.get("type");
                    if (@"type" == null or strEql(@"type".?, "hidden")) {
                        c.frameset_ok = .not_ok;
                    }
                },
                .html_param, .html_source, .html_track => {
                    _ = try insertHtmlElementForTheToken(c, start_tag);
                    _ = c.open_elements.pop();
                    acknowledgeSelfClosingFlag(c);
                },
                .html_hr => {
                    if (hasElementInButtonScope(c, .html_p)) {
                        closePElement(c);
                    }
                    _ = try insertHtmlElementForTheToken(c, start_tag);
                    _ = c.open_elements.pop();
                    acknowledgeSelfClosingFlag(c);
                    c.frameset_ok = .not_ok;
                },

                .html_textarea => {
                    _ = try insertHtmlElementForTheToken(c, start_tag);
                    c.ignore_next_lf_token = true;
                    setTokenizerState(c, .RCDATA);
                    c.frameset_ok = .not_ok;
                    changeToAndSetOriginalInsertionMode(c, .Text, c.insertion_mode);
                },
                .html_xmp => {
                    if (hasElementInButtonScope(c, .html_p)) {
                        closePElement(c);
                    }
                    reconstructActiveFormattingElements(c);
                    c.frameset_ok = .not_ok;
                    try textParsingAlgorithm(.RAWTEXT, c, start_tag);
                },
                .html_iframe => {
                    c.frameset_ok = .not_ok;
                    try textParsingAlgorithm(.RAWTEXT, c, start_tag);
                },
                .html_noembed => try textParsingAlgorithm(.RAWTEXT, c, start_tag),
                .html_noscript => try inBodyStartTagNoscript(c, start_tag),
                .html_select => {
                    reconstructActiveFormattingElements(c);
                    _ = try insertHtmlElementForTheToken(c, start_tag);
                    c.frameset_ok = .not_ok;
                    switch (c.insertion_mode) {
                        .InTable, .InCaption, .InTableBody, .InRow, .InCell => changeTo(c, .InSelectInTable),
                        else => changeTo(c, .InSelect),
                    }
                },
                .html_optgroup, .html_option => {
                    if (currentNode(c).element_type == .html_option) {
                        _ = c.open_elements.pop();
                    }
                    reconstructActiveFormattingElements(c);
                    _ = try insertHtmlElementForTheToken(c, start_tag);
                },
                .html_rb, .html_rtc => {
                    if (hasElementInScope(c, ElementType.html_ruby)) {
                        generateImpliedEndTags(c, null);
                        if (currentNode(c).element_type != .html_ruby) {
                            parseError(.Generic);
                        }
                    }
                    _ = try insertHtmlElementForTheToken(c, start_tag);
                },
                .html_rp, .html_rt => {
                    if (hasElementInScope(c, ElementType.html_ruby)) {
                        generateImpliedEndTags(c, .html_rtc);
                        const current_node_elem_type = currentNode(c).element_type;
                        if (current_node_elem_type != .html_rtc and current_node_elem_type != .html_ruby) {
                            parseError(.Generic);
                        }
                    }
                    _ = try insertHtmlElementForTheToken(c, start_tag);
                },
                .html_caption, .html_col, .html_colgroup, .html_frame, .html_head, .html_tbody, .html_td, .html_tfoot, .html_th, .html_thead, .html_tr => {
                    parseError(.Generic);
                    // Ignore the token.
                },
                else => try inBodyStartTagAnythingElse(c, start_tag),
            } else {
                if (strEql(start_tag.name, "image")) {
                    parseError(.Generic);
                    reconstructActiveFormattingElements(c);
                    _ = try insertHtmlElementForTheToken(c, TokenStartTag{
                        .name = "img",
                        .attributes = start_tag.attributes,
                        .self_closing = start_tag.self_closing,
                    });
                    _ = c.open_elements.pop();
                    acknowledgeSelfClosingFlag(c);
                    c.frameset_ok = .not_ok;
                } else if (strEql(start_tag.name, "math")) {
                    reconstructActiveFormattingElements(c);
                    // TODO adjustMathMlAttributes
                    // TODO adjustForeignAttributes
                    _ = try insertForeignElementForTheToken(c, start_tag, .mathml);
                    if (start_tag.self_closing) {
                        _ = c.open_elements.pop();
                        acknowledgeSelfClosingFlag(c);
                    }
                } else if (strEql(start_tag.name, "svg")) {
                    reconstructActiveFormattingElements(c);
                    // TODO adjustSvgAttributes
                    // TODO adjustForeignAttributes
                    _ = try insertForeignElementForTheToken(c, start_tag, .svg);
                    if (start_tag.self_closing) {
                        _ = c.open_elements.pop();
                        acknowledgeSelfClosingFlag(c);
                    }
                } else {
                    try inBodyStartTagAnythingElse(c, start_tag);
                }
            }
        },
        .end_tag => |end_tag| {
            if (ElementType.fromStringHtml(end_tag.name)) |token_element_type| switch (token_element_type) {
                .html_template => {
                    // TODO: Jump straight to the appropriate handler.
                    try inHead(c, token);
                },
                .html_body => {
                    if (!hasElementInScope(c, ElementType.html_body)) {
                        parseError(.Generic);
                        // Ignore the token.
                    } else {
                        checkValidInBodyEndTag(c);
                        changeTo(c, .AfterBody);
                    }
                },
                .html_html => {
                    if (!hasElementInScope(c, ElementType.html_body)) {
                        parseError(.Generic);
                        // Ignore the token.
                    } else {
                        checkValidInBodyEndTag(c);
                        reprocessIn(c, .AfterBody);
                    }
                },
                .html_address,
                .html_article,
                .html_aside,
                .html_blockquote,
                .html_button,
                .html_center,
                .html_details,
                .html_dialog,
                .html_dir,
                .html_div,
                .html_dl,
                .html_fieldset,
                .html_figcaption,
                .html_figure,
                .html_footer,
                .html_header,
                .html_hgroup,
                .html_listing,
                .html_main,
                .html_menu,
                .html_nav,
                .html_ol,
                .html_pre,
                .html_section,
                .html_summary,
                .html_ul,
                => {
                    if (!hasElementInScope(c, token_element_type)) {
                        parseError(.Generic);
                        // Ignore the token.
                    } else {
                        generateImpliedEndTags(c, null);
                        if (currentNode(c).element_type != token_element_type) {
                            parseError(.Generic);
                        }
                        while (c.open_elements.pop().element_type != token_element_type) {}
                    }
                },
                .html_form => {
                    if (stackOfOpenElementsHas(c, .html_template)) {
                        const form = c.form_element_pointer;
                        c.form_element_pointer = null;

                        if (form == null or !hasElementInScope(c, form.?)) {
                            parseError(.Generic);
                            // Ignore the token;
                            return;
                        }
                        // form is not null at this point.

                        generateImpliedEndTags(c, null);
                        if (currentNode(c) != form.?) {
                            parseError(.Generic);
                        }
                        removeFromStackOfOpenElements(c, form.?);
                    } else {
                        if (!hasElementInScope(c, ElementType.html_form)) {
                            parseError(.Generic);
                            // Ignore the token.
                            return;
                        }
                        generateImpliedEndTags(c, null);
                        if (currentNode(c).element_type != .html_form) {
                            parseError(.Generic);
                        }
                        while (c.open_elements.pop().element_type != .html_form) {}
                    }
                },
                .html_p => {
                    if (!hasElementInButtonScope(c, ElementType.html_p)) {
                        parseError(.Generic);
                        _ = try insertHtmlElementForTheToken(c, TokenStartTag{
                            .name = "p",
                            .attributes = .{},
                            .self_closing = false,
                        });
                        closePElement(c);
                    }
                },
                .html_li => {
                    if (!hasElementInListItemScope(c, ElementType.html_li)) {
                        parseError(.Generic);
                        // Ignore the token.
                    } else {
                        generateImpliedEndTags(c, .html_li);
                        if (currentNode(c).element_type != .html_li) {
                            parseError(.Generic);
                        }
                        while (c.open_elements.pop().element_type != .html_li) {}
                    }
                },
                .html_dd, .html_dt => {
                    if (!hasElementInScope(c, token_element_type)) {
                        parseError(.Generic);
                        // Ignore the token.
                    } else {
                        generateImpliedEndTags(c, token_element_type);
                        if (currentNode(c).element_type != token_element_type) {
                            parseError(.Generic);
                        }
                        while (c.open_elements.pop().element_type != token_element_type) {}
                    }
                },
                .html_h1, .html_h2, .html_h3, .html_h4, .html_h5, .html_h6 => {
                    if (!hasElementInScope(c, @as([]const ElementType, &[_]ElementType{ .html_h1, .html_h2, .html_h3, .html_h4, .html_h5, .html_h6 }))) {
                        parseError(.Generic);
                        // Ignore the token.
                    } else {
                        generateImpliedEndTags(c, null);
                        if (currentNode(c).element_type != token_element_type) {
                            parseError(.Generic);
                        }
                        var bottom_of_stack = c.open_elements.pop();
                        while (elemTypeEqlAny(bottom_of_stack.element_type, &.{ .html_h1, .html_h2, .html_h3, .html_h4, .html_h5, .html_h6 })) {
                            bottom_of_stack = c.open_elements.pop();
                        }
                    }
                },
                .html_a, .html_b, .html_big, .html_code, .html_em, .html_font, .html_i, .html_nobr, .html_s, .html_small, .html_strike, .html_strong, .html_tt, .html_u => {
                    _ = adoptionAgencyAlgorithm(c, end_tag.name);
                },
                .html_applet, .html_marquee, .html_object => {
                    if (!hasElementInScope(c, token_element_type)) {
                        parseError(.Generic);
                        // Ignore the token.
                    } else {
                        generateImpliedEndTags(c, null);
                        if (currentNode(c).element_type != token_element_type) {
                            parseError(.Generic);
                        }
                        while (c.open_elements.pop().element_type != token_element_type) {}
                        clearListOfActiveFormattingElementsUpToLastMarker(c);
                    }
                },
                .html_br => {
                    reconstructActiveFormattingElements(c);
                    _ = try insertHtmlElementForTheToken(c, TokenStartTag{
                        .name = "br",
                        .attributes = .{},
                        .self_closing = false,
                    });
                    _ = c.open_elements.pop();
                    c.frameset_ok = .not_ok;
                },
                else => {
                    @panic("TODO InBody insertion mode is incomplete");
                },
            } else @panic("TODO: InBody any other end tag");
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

fn inBodyStartTagHtml(c: *TreeConstructor, start_tag: TokenStartTag) !void {
    parseError(.Generic);
    if (stackOfOpenElementsHas(c, .html_template)) {
        // Ignore the token.
    } else {
        const top_element = c.open_elements.items[0];
        var iterator = start_tag.attributes.iterator();
        while (iterator.next()) |attr| {
            try top_element.addAttributeNoReplace(c.allocator, attr.key_ptr.*, attr.value_ptr.*);
        }
    }
}

fn inBodyStartTagNoscript(c: *TreeConstructor, start_tag: TokenStartTag) !void {
    if (c.scripting) {
        try textParsingAlgorithm(.RAWTEXT, c, start_tag);
    } else {
        try inBodyStartTagAnythingElse(c, start_tag);
    }
}

fn inBodyStartTagAnythingElse(c: *TreeConstructor, start_tag: TokenStartTag) !void {
    reconstructActiveFormattingElements(c);
    _ = try insertHtmlElementForTheToken(c, start_tag);
}

fn text(c: *TreeConstructor, token: Token) !void {
    switch (token) {
        .character => |character| {
            try insertCharacter(c, character);
        },
        .eof => {
            parseError(.Generic);
            const current_node = c.open_elements.pop();
            if (current_node.element_type == .html_script) {
                // Mark the script element as "already started".
                @panic("TODO Text eof, current node is a script");
            }
            reprocessInOriginalInsertionMode(c);
        },
        .end_tag => |end_tag| {
            if (strEql(end_tag.name, "script")) {
                @panic("TODO Text end tag script");
            } else {
                _ = c.open_elements.pop();
                changeToOriginalInsertionMode(c);
            }
        },
        else => unreachable,
    }
}

fn afterBody(c: *TreeConstructor, token: Token) !void {
    if (isWhitespace(token)) {
        @panic("TODO Process using InBody whitespace rules.");
    } else if (token == .comment) {
        @panic("TODO: AfterBody comment");
    } else if (token == .doctype) {
        parseError(.Generic);
        // Ignore the token.
    } else if (token == .start_tag and strEqlAny(token.start_tag.name, &.{"html"})) {
        try inBodyStartTagHtml(c, token.start_tag);
    } else if (token == .end_tag and strEqlAny(token.end_tag.name, &.{"html"})) {
        if (c.is_fragment_parser) {
            parseError(.Generic);
            // Ignore the token.
        } else {
            changeTo(c, .AfterAfterBody);
        }
    } else if (token == .eof) {
        stop(c);
    } else {
        parseError(.Generic);
        reprocessIn(c, .InBody);
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
        .eof => stop(c),
        else => afterAfterBodyAnythingElse(c),
    }
}

fn afterAfterBodyAnythingElse(c: *TreeConstructor) void {
    parseError(.Generic);
    reprocessIn(c, .InBody);
}

fn processTokenForeignContent(c: *TreeConstructor, token: Token) void {
    _ = c;
    _ = token;
    @panic("TODO Parsing tokens in foreign content");
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

fn textParsingAlgorithm(variant: enum { RAWTEXT, RCDATA }, c: *TreeConstructor, start_tag: TokenStartTag) !void {
    _ = try insertHtmlElementForTheToken(c, start_tag);
    switch (variant) {
        .RAWTEXT => setTokenizerState(c, .RAWTEXT),
        .RCDATA => setTokenizerState(c, .RCDATA),
    }
    changeToAndSetOriginalInsertionMode(c, .Text, c.insertion_mode);
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

fn strEql(string: []const u8, other: []const u8) bool {
    return std.mem.eql(u8, string, other);
}

fn strEqlAny(string: []const u8, compare_to: []const []const u8) bool {
    for (compare_to) |s| {
        if (std.mem.eql(u8, string, s)) return true;
    }
    return false;
}

fn eqlNullStrings(s1: ?[]const u8, s2: ?[]const u8) bool {
    if (s1) |a| {
        if (s2) |b| return std.mem.eql(u8, a, b) else return false;
    } else {
        return s2 == null;
    }
}

fn elemTypeEqlAny(element_type: ElementType, compare_to: []const ElementType) bool {
    for (compare_to) |t| {
        if (element_type == t) return true;
    }
    return false;
}

fn parseError(err: ParseError) void {
    // TODO: Handle parse errors.
    std.debug.print("Tree construction parse error: {s}\n", .{@tagName(err)});
}

const ParentNode = union(enum) {
    document: *Document,
    element: *Element,
};

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

fn currentNode(c: *TreeConstructor) *Element {
    return c.open_elements.items[c.open_elements.items.len - 1];
}

fn adjustedCurrentNode(c: *TreeConstructor) *Element {
    if (c.is_fragment_parser and c.open_elements.items.len == 1) {
        @panic("TODO: Adjusted current node, fragment case");
    } else {
        return currentNode(c);
    }
}

fn appropriateNodeInsertionLocation(c: *TreeConstructor) NodeInsertionLocation {
    return appropriateNodeInsertionLocationWithTarget(c, currentNode(c));
}

fn appropriateNodeInsertionLocationWithTarget(c: *TreeConstructor, target: *Element) NodeInsertionLocation {
    var adjusted_insertion_location: *Element = undefined;
    var position: enum { last_child } = undefined;
    if (c.foster_parenting and elemTypeEqlAny(target.element_type, &.{ .html_table, .html_tbody, .html_tfoot, .html_thead, .html_tr })) substeps: {
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
    namespace: Dom.Namespace,
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
    var element_type: ElementType = if (namespace == .html) Dom.ElementType.fromStringHtml(local_name) orelse @panic("TODO: Unknown HTML element type") else @panic("TODO: Create an element in non-HTML namespace");
    var element = try Dom.createAnElement(c.allocator, element_type, is, false);
    errdefer element.deinit(c.allocator);
    // TODO This should follow https://dom.spec.whatwg.org/#concept-element-attributes-append
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

fn insertForeignElementForTheToken(c: *TreeConstructor, start_tag: TokenStartTag, namespace: Dom.Namespace) !*Element {
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

const FormattingElement = struct {
    element: *Element,
    original_attributes_index: usize,

    fn eql(self: FormattingElement, c: *TreeConstructor, element: *Element) bool {
        if (self.element.element_type != element.element_type) return false;
        const original_attributes = c.active_formatting_element_original_attributes.items[self.original_attributes_index];
        if (original_attributes.count() != element.attributes.count()) return false;
        var attr_it = element.attributes.iterator();
        while (attr_it.next()) |attr| {
            const original_entry = original_attributes.get(attr.key_ptr.*) orelse return false;
            if (!strEql(attr.value_ptr.*, original_entry)) return false;
        }
        return true;
    }
};

fn addFormattingElementOriginalAttributes(c: *TreeConstructor, element: *Element) !usize {
    const attributes_copy = try c.active_formatting_element_original_attributes.addOne(c.allocator);
    errdefer _ = c.active_formatting_element_original_attributes.pop();

    attributes_copy.* = Dom.ElementAttributes{};
    errdefer html5.util.freeStringHashMap(attributes_copy, c.allocator);
    try attributes_copy.ensureTotalCapacity(c.allocator, element.attributes.count());

    var iterator = element.attributes.iterator();
    while (iterator.next()) |attr| {
        const key = try c.allocator.dupe(u8, attr.key_ptr.*);
        errdefer c.allocator.free(key);
        const value = try c.allocator.dupe(u8, attr.value_ptr.*);
        errdefer c.allocator.free(value);
        attributes_copy.putAssumeCapacity(key, value);
    }
    return c.active_formatting_element_original_attributes.items.len - 1;
}

fn deleteFormattingElementOriginalAttributes(c: *TreeConstructor, index: usize) void {
    for (c.active_formatting_elements.items) |*fe| {
        if (fe.original_attributes_index == index) {
            // There should be no active formatting elements referring to this
            // if it is being deleted.
            unreachable;
        } else if (fe.original_attributes_index > index) {
            fe.original_attributes_index -= 1;
        }
    }
    const original_attributes = &c.active_formatting_element_original_attributes.items[index];
    html5.util.freeStringHashMap(original_attributes, c.allocator);
    _ = c.active_formatting_element_original_attributes.orderedRemove(index);
}

fn addToListOfActiveFormattingElementsWithoutMatch(c: *TreeConstructor, element: *Element) !void {
    const result = try c.active_formatting_elements.addOne(c.allocator);
    errdefer _ = c.active_formatting_elements.pop();
    const original_attributes_index = try addFormattingElementOriginalAttributes(c, element);
    result.* = .{ .element = element, .original_attributes_index = original_attributes_index };
}

fn addToListOfActiveFormattingElementsWithMatch(c: *TreeConstructor, element: *Element, formatting_element: FormattingElement) !void {
    try c.active_formatting_elements.append(c.allocator, .{
        .element = element,
        .original_attributes_index = formatting_element.original_attributes_index,
    });
}

fn removeFromListOfActiveFormattingElements(c: *TreeConstructor, index: usize) void {
    const original_attributes_index = c.active_formatting_elements.items[index].original_attributes_index;
    _ = c.active_formatting_elements.orderedRemove(index);
    for (c.active_formatting_elements.items) |fe| {
        if (fe.original_attributes_index == original_attributes_index) return;
    }
    // NOTE: Alternatively, we could just never free the original attributes.
    deleteFormattingElementOriginalAttributes(c, original_attributes_index);
}

fn insertAMarker(c: *TreeConstructor) !void {
    _ = c;
    @panic("TODO Insert a marker onto the list of active formatting elements");
}

fn pushOntoListOfActiveFormattingElements(c: *TreeConstructor, element: *Element) !void {
    var matching_element_count: u2 = 0;
    var first_matching_element_index: usize = undefined;

    var i = if (c.index_of_last_marker) |lm| lm + 1 else 0;
    while (i < c.active_formatting_elements.items.len) : (i += 1) {
        const formatting_element = c.active_formatting_elements.items[i];
        if (!formatting_element.eql(c, element)) continue;

        matching_element_count += 1;
        if (matching_element_count == 1) {
            first_matching_element_index = i;
        } else if (matching_element_count == 3) {
            removeFromListOfActiveFormattingElements(c, first_matching_element_index);
            break;
        }
    }

    if (matching_element_count > 0)
        try addToListOfActiveFormattingElementsWithMatch(c, element, c.active_formatting_elements.items[first_matching_element_index])
    else
        try addToListOfActiveFormattingElementsWithoutMatch(c, element);
}

fn reconstructActiveFormattingElements(c: *TreeConstructor) void {
    if (c.active_formatting_elements.items.len == 0) return;
    @panic("TODO Reconstruct the active formatting elements");
}

fn clearListOfActiveFormattingElementsUpToLastMarker(c: *TreeConstructor) void {
    _ = c;
    @panic("TODO Clear the list of active formatting elements up to the last marker");
}

fn adoptionAgencyAlgorithm(c: *TreeConstructor, tag_name: []const u8) bool {
    _ = c;
    _ = tag_name;
    @panic("TODO adoption agency algorithm");
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

fn hasElementInSpecificScope(c: *TreeConstructor, target: anytype, comptime list: []const ElementType) bool {
    var index = c.open_elements.items.len;
    var node = c.open_elements.items[index - 1];

    switch (@TypeOf(target)) {
        *Element => while (node != target) {
            if (std.mem.indexOfScalar(ElementType, list, node.element_type) != null) return false;
            index -= 1;
            node = c.open_elements.items[index - 1];
        },
        ElementType => while (node.element_type != target) {
            if (std.mem.indexOfScalar(ElementType, list, node.element_type) != null) return false;
            index -= 1;
            node = c.open_elements.items[index - 1];
        },
        []const ElementType => while (!elemTypeEqlAny(node.element_type, target)) {
            if (std.mem.indexOfScalar(ElementType, list, node.element_type) != null) return false;
            index -= 1;
            node = c.open_elements.items[index - 1];
        },
        else => |T| @compileError("target must be either '" ++ @typeName(*Element) ++ "', '" ++ @typeName(ElementType) ++ "', or '" ++ @typeName([]const ElementType) ++ "', instead found '" ++ @typeName(T) ++ "'"),
    }
    return true;
}

fn hasElementInScope(c: *TreeConstructor, target: anytype) bool {
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

fn hasElementInListItemScope(c: *TreeConstructor, target: ElementType) bool {
    const list = &[_]ElementType{
        .html_applet,
        .html_caption,
        .html_html,
        .html_table,
        .html_td,
        .html_th,
        .html_marquee,
        .html_object,
        .html_ol,
        .html_template,
        .html_ul,
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

    var element_type = currentNode(c).element_type;
    while (std.mem.indexOfScalar(ElementType, list, element_type)) |_| {
        if (exception == null or element_type != exception.?) {
            _ = c.open_elements.pop();
            element_type = currentNode(c).element_type;
        } else {
            break;
        }
    }
}

fn closePElement(c: *TreeConstructor) void {
    generateImpliedEndTags(c, .html_p);
    if (currentNode(c).element_type != .html_p) {
        parseError(.Generic);
    }
    while (c.open_elements.pop().element_type != .html_p) {}
}

fn removeFromStackOfOpenElements(c: *TreeConstructor, element: *Element) void {
    for (c.open_elements.items) |e, i| {
        if (e == element) {
            _ = c.open_elements.orderedRemove(i);
            return;
        }
    }
    unreachable;
}

fn checkValidInBodyEndTag(c: *TreeConstructor) void {
    if (comptime report_parse_errors) {
        const valid_types = &[_]ElementType{
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
            .html_tbody,
            .html_td,
            .html_tfoot,
            .html_th,
            .html_thead,
            .html_tr,
            .html_body,
            .html_html,
        };
        for (c.open_elements.items) |e| {
            if (!elemTypeEqlAny(e.element_type, valid_types)) {
                parseError(.Generic);
            }
        }
    }
}
