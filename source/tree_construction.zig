// Copyright (C) 2021-2023 Chadwain Holness
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const ArrayListUnmanaged = std.ArrayListUnmanaged;
const ComptimeStringMap = std.ComptimeStringMap;
const StringHashMapUnmanaged = std.StringHashMapUnmanaged;

const rem = @import("../rem.zig");
const Token = @import("./token.zig").Token;
const Tokenizer = @import("./Tokenizer.zig");
const Parser = @import("./Parser.zig");
const ParseError = Parser.ParseError;

const Dom = @import("./Dom.zig");
const Document = Dom.Document;
const Element = Dom.Element;
const ElementType = Dom.ElementType;
const ElementAttributesKey = Dom.ElementAttributesKey;
const CharacterData = Dom.CharacterData;
const CharacterDataInterface = Dom.CharacterDataInterface;
const ElementOrCharacterData = Dom.ElementOrCharacterData;

// TODO: Use decoded Unicode codepoints ([]u21) for everything

pub const TreeConstructor = struct {
    dom: *Dom,
    document: *Document,
    allocator: Allocator,

    fragment_context: ?*Element,
    scripting: bool,

    insertion_mode: InsertionMode = .Initial,
    original_insertion_mode: InsertionMode = undefined,

    open_elements: ArrayListUnmanaged(*Element) = .{},
    template_insertion_modes: ArrayListUnmanaged(InsertionMode) = .{},

    active_formatting_elements: ArrayListUnmanaged(FormattingElement) = .{},
    // TODO: Somehow make it so that tag attributes do not need to be copied
    formatting_element_tag_attributes: ArrayListUnmanaged(Token.StartTag.Attributes) = .{},
    index_of_last_marker: ?usize = null,

    head_element_pointer: ?*Element = null,
    form_element_pointer: ?*Element = null,

    pending_table_character_tokens: ArrayListUnmanaged(Token.Character) = .{},
    pending_table_chars_contains_non_whitespace: bool = false,

    parser_cannot_change_the_mode: bool = false,
    is_iframe_srcdoc_document: bool = false,

    reprocess: bool = false,
    stopped: bool = false,
    ignore_next_lf_token: bool = false,
    self_closing_flag_acknowledged: bool = false,
    frameset_ok: FramesetOk = .ok,
    foster_parenting: bool = false,
    new_tokenizer_state: ?Tokenizer.State = null,
    new_tokenizer_last_start_tag: Tokenizer.LastStartTag = undefined,

    const FramesetOk = enum {
        ok,
        not_ok,
    };

    pub const Arguments = struct {
        fragment_context: ?*Element = null,
        scripting: bool = false,
    };

    pub const RunResult = struct {
        new_tokenizer_state: ?Tokenizer.State = null,
        new_tokenizer_last_start_tag: Tokenizer.LastStartTag = undefined,
        adjusted_current_node_is_not_in_html_namespace: bool = undefined,
    };

    /// Create a new HTML5 tree constructor.
    pub fn init(dom: *Dom, document: *Document, allocator: Allocator, args: Arguments) TreeConstructor {
        return TreeConstructor{
            .dom = dom,
            .document = document,
            .allocator = allocator,
            .fragment_context = args.fragment_context,
            .scripting = args.scripting,
        };
    }

    /// Free the memory associated with the tree constructor.
    pub fn deinit(self: *TreeConstructor) void {
        self.open_elements.deinit(self.allocator);
        self.template_insertion_modes.deinit(self.allocator);
        self.active_formatting_elements.deinit(self.allocator);
        for (self.formatting_element_tag_attributes.items) |*attributes| {
            freeStringHashMap(attributes, self.allocator);
        }
        self.formatting_element_tag_attributes.deinit(self.allocator);
        self.pending_table_character_tokens.deinit(self.allocator);
    }

    /// Process the token using the rules for tree construction.
    pub fn run(self: *TreeConstructor, token: Token) !RunResult {
        var result = RunResult{};

        if (self.ignore_next_lf_token) {
            self.ignore_next_lf_token = false;
            if (token == .character and token.character.data == '\n') {
                result.adjusted_current_node_is_not_in_html_namespace = self.open_elements.items.len > 0 and
                    adjustedCurrentNode(self).namespace() != .html;
                return result;
            }
        }

        // std.debug.print("{any}\n", .{token});
        var should_process = true;
        while (should_process) {
            self.reprocess = false;
            try dispatcher(self, token);
            should_process = self.reprocess;
        }

        result.new_tokenizer_state = self.new_tokenizer_state;
        result.new_tokenizer_last_start_tag = self.new_tokenizer_last_start_tag;
        self.new_tokenizer_state = null;
        self.new_tokenizer_last_start_tag = undefined;

        result.adjusted_current_node_is_not_in_html_namespace = self.open_elements.items.len > 0 and
            adjustedCurrentNode(self).namespace() != .html;
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

fn changeTo(c: *TreeConstructor, insertion_mode: InsertionMode) void {
    c.insertion_mode = insertion_mode;
    // std.debug.print("Change to: {s}\n", .{@tagName(insertion_mode)});
}

fn changeToOriginalInsertionMode(c: *TreeConstructor) void {
    changeTo(c, c.original_insertion_mode);
    c.original_insertion_mode = undefined;
}

fn changeToAndSetOriginalInsertionMode(c: *TreeConstructor, insertion_mode: InsertionMode, original_insertion_mode: InsertionMode) void {
    c.original_insertion_mode = original_insertion_mode;
    changeTo(c, insertion_mode);
}

fn reprocess(c: *TreeConstructor) void {
    c.reprocess = true;
    // std.debug.print("Reprocess in: {s}\n", .{@tagName(c.insertion_mode)});
}

fn reprocessIn(c: *TreeConstructor, insertion_mode: InsertionMode) void {
    c.reprocess = true;
    c.insertion_mode = insertion_mode;
    // std.debug.print("Reprocess in: {s}\n", .{@tagName(insertion_mode)});
}

fn reprocessInOriginalInsertionMode(c: *TreeConstructor) void {
    reprocessIn(c, c.original_insertion_mode);
    c.original_insertion_mode = undefined;
}

fn reprocessAndSetOriginalInsertionMode(c: *TreeConstructor, insertion_mode: InsertionMode, original_insertion_mode: InsertionMode) void {
    c.original_insertion_mode = original_insertion_mode;
    reprocessIn(c, insertion_mode);
}

// This is public because it is called from FragmentParser.
pub fn resetInsertionModeAppropriately(c: *TreeConstructor) void {
    var i = c.open_elements.items.len;
    while (i > 0) : (i -= 1) {
        const last = i == 1;
        const node = if (last and c.fragment_context != null) c.fragment_context.? else c.open_elements.items[i - 1];
        switch (node.element_type) {
            .html_select => {
                if (!last) {
                    var j = i - 1;
                    while (j > 0) : (j -= 1) {
                        const ancestor = c.open_elements.items[j - 1];
                        switch (ancestor.element_type) {
                            .html_template => break,
                            .html_table => {
                                changeTo(c, .InSelectInTable);
                                return;
                            },
                            else => {},
                        }
                    }
                }
                changeTo(c, .InSelect);
                return;
            },
            .html_td, .html_th => {
                if (!last) {
                    changeTo(c, .InCell);
                } else {
                    changeTo(c, .InBody);
                }
                return;
            },
            .html_tr => {
                changeTo(c, .InRow);
                return;
            },
            .html_tbody, .html_thead, .html_tfoot => {
                changeTo(c, .InTableBody);
                return;
            },
            .html_caption => {
                changeTo(c, .InCaption);
                return;
            },
            .html_colgroup => {
                changeTo(c, .InColumnGroup);
                return;
            },
            .html_table => {
                changeTo(c, .InTable);
                return;
            },
            .html_template => {
                changeTo(c, currentTemplateInsertionMode(c));
                return;
            },
            .html_head => {
                if (!last) {
                    changeTo(c, .InHead);
                } else {
                    changeTo(c, .InBody);
                }
                return;
            },
            .html_body => {
                changeTo(c, .InBody);
                return;
            },
            .html_frameset => {
                changeTo(c, .InFrameset);
                return;
            },
            .html_html => {
                if (c.head_element_pointer == null) {
                    changeTo(c, .BeforeHead);
                } else {
                    changeTo(c, .AfterHead);
                }
                return;
            },
            else => if (last) {
                changeTo(c, .InBody);
                return;
            },
        }
    }
    unreachable;
}

fn stop(c: *TreeConstructor) void {
    // TODO: Stopping parsing has more steps.
    c.open_elements.clearAndFree(c.allocator);
    c.stopped = true;
    // std.debug.print("Stopped parsing.", .{});
}

fn setTokenizerState(c: *TreeConstructor, state: Tokenizer.State, comptime element_type: ElementType) void {
    c.new_tokenizer_state = state;
    c.new_tokenizer_last_start_tag = comptime Tokenizer.LastStartTag.fromString(element_type.toLocalName().?).?;
}

fn dispatcher(c: *TreeConstructor, token: Token) !void {
    if (c.open_elements.items.len == 0 or token == .eof) return processToken(c, token);

    const adjusted_current_node = adjustedCurrentNode(c);
    if (adjusted_current_node.namespace() == .html or
        (adjusted_current_node.element_type == .mathml_annotation_xml and token == .start_tag and strEql(token.start_tag.name, "svg")))
        return processToken(c, token);

    const is_mathml_integration = isMathMlTextIntegrationPoint(adjusted_current_node);
    if ((is_mathml_integration and (token == .character or (token == .start_tag and !strEqlAny(token.start_tag.name, &.{ "mglyph", "malignmark" })))))
        return processToken(c, token);

    const is_html_integration_point = isHtmlIntegrationPoint(c.dom, adjusted_current_node);
    if (is_html_integration_point and (token == .start_tag or token == .character))
        return processToken(c, token);

    return processTokenForeignContent(c, token);
}

fn processToken(c: *TreeConstructor, token: Token) !void {
    switch (c.insertion_mode) {
        .Initial => try initial(c, token), // Done.
        .BeforeHtml => try beforeHtml(c, token),
        .BeforeHead => try beforeHead(c, token), // Done.
        .InHead => try inHead(c, token),
        .InHeadNoscript => try inHeadNoscript(c, token), // Done.
        .AfterHead => try afterHead(c, token), // Done.
        .InBody => try inBody(c, token),
        .Text => try text(c, token),
        .InTable => try inTable(c, token), // Done.
        .InTableText => try inTableText(c, token), // Done.
        .InCaption => try inCaption(c, token), // Done.
        .InColumnGroup => try inColumnGroup(c, token), // Done.
        .InTableBody => try inTableBody(c, token), // Done.
        .InRow => try inRow(c, token), // Done.
        .InCell => try inCell(c, token), // Done.
        .InSelect => try inSelect(c, token),
        .InSelectInTable => try inSelectInTable(c, token), // Done.
        .InTemplate => try inTemplate(c, token), // Done.
        .AfterBody => try afterBody(c, token), // Done.
        .InFrameset => try inFrameset(c, token), // Done.
        .AfterFrameset => try afterFrameset(c, token), // Done.
        .AfterAfterBody => try afterAfterBody(c, token), // Done.
        .AfterAfterFrameset => try afterAfterFrameset(c, token), // Done.
    }

    if (token == .start_tag) {
        if (token.start_tag.self_closing and !c.self_closing_flag_acknowledged) {
            try parseError(c, .NonVoidHtmlElementStartTagWithTrailingSolidus);
        }
        c.self_closing_flag_acknowledged = false;
    }
}

fn initial(c: *TreeConstructor, token: Token) !void {
    switch (token) {
        .character => |character| {
            if (isWhitespace(character)) {
                // Ignore the token.
            } else {
                try initialAnythingElse(c);
            }
        },
        .comment => |comment| try insertCommentToDocument(c, comment),
        .doctype => |d| {
            if ((d.name == null or !strEql("html", d.name.?)) or
                (d.public_identifier != null) or
                (d.system_identifier != null and !strEql("about:legacy-compat", d.system_identifier.?)))
            {
                try parseError(c, .TreeConstructionError);
            }

            const doctype = try c.dom.makeDoctype(d.name, d.public_identifier, d.system_identifier);
            try Dom.mutation.documentAppendDocumentType(c.dom, c.document, doctype, .Suppress);

            if (!c.is_iframe_srcdoc_document and !c.parser_cannot_change_the_mode) {
                if (doctypeEnablesQuirks(d)) {
                    c.document.quirks_mode = .quirks;
                } else if (doctypeEnablesLimitedQuirks(d)) {
                    c.document.quirks_mode = .limited_quirks;
                }
            }

            changeTo(c, .BeforeHtml);
        },
        else => try initialAnythingElse(c),
    }
}

fn initialAnythingElse(c: *TreeConstructor) !void {
    if (!c.is_iframe_srcdoc_document) {
        try parseError(c, .TreeConstructionError);
    }
    if (!c.parser_cannot_change_the_mode) {
        c.document.quirks_mode = .quirks;
    }
    reprocessIn(c, .BeforeHtml);
}

fn beforeHtml(c: *TreeConstructor, token: Token) !void {
    switch (token) {
        .character => |character| {
            if (isWhitespace(character)) {
                // Ignore the token.
            } else {
                try beforeHtmlAnythingElse(c);
            }
        },
        .comment => |comment| try insertCommentToDocument(c, comment),
        .doctype => {
            try parseError(c, .TreeConstructionError);
            // Ignore the token.
        },
        .start_tag => |start_tag| {
            if (ElementType.fromStringHtml(start_tag.name)) |token_element_type| switch (token_element_type) {
                .html_html => {
                    const element = try createAnElementForTheToken(c, start_tag, .html_html, .{ .document = c.document }, .dont_adjust);
                    try Dom.mutation.documentAppendElement(c.dom, c.document, element, .Suppress);
                    try c.open_elements.append(c.allocator, element);
                    changeTo(c, .BeforeHead);
                },
                else => try beforeHtmlAnythingElse(c),
            } else {
                try beforeHtmlAnythingElse(c);
            }
        },
        .end_tag => |end_tag| {
            if (ElementType.fromStringHtml(end_tag.name)) |token_element_type| switch (token_element_type) {
                .html_head, .html_body, .html_html, .html_br => try beforeHtmlAnythingElse(c),
                else => {
                    try parseError(c, .TreeConstructionError);
                    // Ignore the token.
                },
            } else {
                try parseError(c, .TreeConstructionError);
                // Ignore the token.
            }
        },
        .eof => try beforeHtmlAnythingElse(c),
    }
}

fn beforeHtmlAnythingElse(c: *TreeConstructor) !void {
    // TODO: Set the element's "node document"
    const element = try c.dom.makeElement(.html_html);
    element.parent = .document;
    try Dom.mutation.documentAppendElement(c.dom, c.document, element, .Suppress);
    try c.open_elements.append(c.allocator, element);
    reprocessIn(c, .BeforeHead);
}

fn beforeHead(c: *TreeConstructor, token: Token) !void {
    switch (token) {
        .character => |character| if (isWhitespace(character)) {
            // Ignore the token.
        } else {
            try beforeHeadAnythingElse(c);
        },
        .comment => |comment| try insertComment(c, comment),
        .doctype => {
            try parseError(c, .TreeConstructionError);
            // Ignore the token.
        },
        .start_tag => |start_tag| {
            if (ElementType.fromStringHtml(start_tag.name)) |token_element_type| switch (token_element_type) {
                .html_html => try inBodyStartTagHtml(c, start_tag),
                .html_head => {
                    const node = try insertHtmlElementForTheToken(c, token.start_tag, .html_head);
                    c.head_element_pointer = node;
                    changeTo(c, .InHead);
                },
                else => try beforeHeadAnythingElse(c),
            } else {
                try beforeHeadAnythingElse(c);
            }
        },
        .end_tag => |end_tag| {
            if (ElementType.fromStringHtml(end_tag.name)) |token_element_type| switch (token_element_type) {
                .html_head, .html_body, .html_html, .html_br => try beforeHeadAnythingElse(c),
                else => {
                    try parseError(c, .TreeConstructionError);
                    // Ignore the token.
                },
            } else {
                try parseError(c, .TreeConstructionError);
                // Ignore the token.
            }
        },
        .eof => try beforeHeadAnythingElse(c),
    }
}

fn beforeHeadAnythingElse(c: *TreeConstructor) !void {
    const node = try insertHtmlElementForTheToken(c, Token.StartTag{
        .name = "head",
        .attributes = .{},
        .self_closing = false,
    }, .html_head);
    c.head_element_pointer = node;
    reprocessIn(c, .InHead);
}

fn inHead(c: *TreeConstructor, token: Token) !void {
    switch (token) {
        .character => |character| if (isWhitespace(character)) {
            try inHeadWhitespace(c, character);
        } else {
            inHeadAnythingElse(c);
        },
        .comment => |comment| try inHeadComment(c, comment),
        .doctype => {
            try parseError(c, .TreeConstructionError);
            // Ignore the token.
        },
        .start_tag => |start_tag| {
            if (ElementType.fromStringHtml(start_tag.name)) |token_element_type| switch (token_element_type) {
                .html_html => try inBodyStartTagHtml(c, start_tag),
                .html_base, .html_basefont, .html_bgsound, .html_link => try inHeadStartTagBaseBasefontBgsoundLink(c, start_tag, token_element_type),
                .html_meta => try inHeadStartTagMeta(c, start_tag),
                .html_title => try inHeadStartTagTitle(c, start_tag),
                .html_noscript => try inHeadStartTagNoscript(c, start_tag),
                .html_noframes => try inHeadStartTagNoframesStyle(c, start_tag, .html_noframes),
                .html_style => try inHeadStartTagNoframesStyle(c, start_tag, .html_style),
                .html_script => try inHeadStartTagScript(c, start_tag),
                .html_template => try inHeadStartTagTemplate(c, start_tag),
                .html_head => {
                    try parseError(c, .TreeConstructionError);
                    // Ignore the token.
                },
                else => inHeadAnythingElse(c),
            } else {
                inHeadAnythingElse(c);
            }
        },
        .end_tag => |end_tag| {
            if (strEql(end_tag.name, "head")) {
                const current_node = c.open_elements.pop();
                assert(current_node.element_type == .html_head);
                changeTo(c, .AfterHead);
            } else if (strEqlAny(end_tag.name, &.{ "body", "html", "br" })) {
                inHeadAnythingElse(c);
            } else if (strEql(end_tag.name, "template")) {
                _ = try inHeadEndTagTemplate(c);
            } else {
                try parseError(c, .TreeConstructionError);
                // Ignore the token.
            }
        },
        .eof => inHeadAnythingElse(c),
    }
}

fn inHeadWhitespace(c: *TreeConstructor, character: Token.Character) !void {
    try insertCharacter(c, character);
}

fn inHeadComment(c: *TreeConstructor, comment: Token.Comment) !void {
    try insertComment(c, comment);
}

fn inHeadStartTagBaseBasefontBgsoundLink(c: *TreeConstructor, start_tag: Token.StartTag, element_type: ElementType) !void {
    _ = try insertHtmlElementForTheToken(c, start_tag, element_type);
    _ = c.open_elements.pop();
    acknowledgeSelfClosingFlag(c);
}

fn inHeadStartTagMeta(c: *TreeConstructor, start_tag: Token.StartTag) !void {
    _ = try insertHtmlElementForTheToken(c, start_tag, .html_meta);
    _ = c.open_elements.pop();
    acknowledgeSelfClosingFlag(c);

    // TODO: Only do this if the active speculative HTML parser is null.
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
}

fn inHeadStartTagTitle(c: *TreeConstructor, start_tag: Token.StartTag) !void {
    try textParsingAlgorithm(.RCDATA, c, start_tag, .html_title);
}

fn inHeadStartTagNoframesStyle(c: *TreeConstructor, start_tag: Token.StartTag, comptime element_type: ElementType) !void {
    try textParsingAlgorithm(.RAWTEXT, c, start_tag, element_type);
}

fn inHeadStartTagScript(c: *TreeConstructor, start_tag: Token.StartTag) !void {
    // Step 1
    const adjusted_insertion_location = appropriateNodeInsertionLocation(c);

    // Step 2
    const intended_parent: ParentNode = switch (adjusted_insertion_location) {
        .element_last_child => |e| .{ .element = e },
        .parent_before_child => |s| .{ .element = s.parent },
    };
    const element = try createAnElementForTheToken(c, start_tag, .html_script, intended_parent, .dont_adjust);

    if (c.scripting) {
        @panic("TODO: In head start tag script, scripting is enabled");
    }

    // Step 6
    switch (adjusted_insertion_location) {
        // TODO: Check pre-insertion validity
        .element_last_child => |e| try Dom.mutation.elementAppend(c.dom, e, .{ .element = element }, .Suppress),
        .parent_before_child => |s| try Dom.mutation.elementInsert(c.dom, s.parent, .{ .element = s.child }, .{ .element = element }, .Suppress),
    }

    // Step 7
    try c.open_elements.append(c.allocator, element);

    // Step 8
    setTokenizerState(c, .ScriptData, .html_script);

    // Step 9
    // Step 10
    changeToAndSetOriginalInsertionMode(c, .Text, c.insertion_mode);
}

fn inHeadStartTagTemplate(c: *TreeConstructor, start_tag: Token.StartTag) !void {
    _ = try insertHtmlElementForTheToken(c, start_tag, .html_template);
    try insertAMarker(c);
    c.frameset_ok = .not_ok;
    changeTo(c, .InTemplate);
    try c.template_insertion_modes.append(c.allocator, .InTemplate);
}

fn inHeadStartTagNoscript(c: *TreeConstructor, start_tag: Token.StartTag) !void {
    if (c.scripting) {
        try textParsingAlgorithm(.RAWTEXT, c, start_tag, .html_noscript);
    } else {
        _ = try insertHtmlElementForTheToken(c, start_tag, .html_noscript);
        changeTo(c, .InHeadNoscript);
    }
}

// Returns false if the token should be ignored.
fn inHeadEndTagTemplate(c: *TreeConstructor) !bool {
    if (!stackOfOpenElementsHas(c, .html_template)) {
        try parseError(c, .TreeConstructionError);
        // Ignore the token.
        return false;
    } else {
        generateImpliedEndTagsThoroughly(c);
        if (currentNode(c).element_type != .html_template) {
            try parseError(c, .TreeConstructionError);
        }
        while (c.open_elements.pop().element_type != .html_template) {}
        clearListOfActiveFormattingElementsUpToLastMarker(c);
        _ = c.template_insertion_modes.pop();
        resetInsertionModeAppropriately(c);
        return true;
    }
}

fn inHeadAnythingElse(c: *TreeConstructor) void {
    const current_node = c.open_elements.pop();
    assert(current_node.element_type == .html_head);
    reprocessIn(c, .AfterHead);
}

fn inHeadNoscript(c: *TreeConstructor, token: Token) !void {
    switch (token) {
        .doctype => {
            try parseError(c, .TreeConstructionError);
            // Ignore the token.
        },
        .start_tag => |start_tag| {
            if (ElementType.fromStringHtml(start_tag.name)) |token_element_type| switch (token_element_type) {
                .html_html => try inBodyStartTagHtml(c, start_tag),
                .html_basefont, .html_bgsound, .html_link => try inHeadStartTagBaseBasefontBgsoundLink(c, start_tag, token_element_type),
                .html_meta => try inHeadStartTagMeta(c, start_tag),
                .html_noframes => try inHeadStartTagNoframesStyle(c, start_tag, .html_noframes),
                .html_style => try inHeadStartTagNoframesStyle(c, start_tag, .html_style),
                .html_head, .html_noscript => {
                    try parseError(c, .TreeConstructionError);
                    // Ignore the token.
                },
                else => try inHeadNoscriptAnythingElse(c),
            } else {
                try inHeadNoscriptAnythingElse(c);
            }
        },
        .end_tag => |end_tag| {
            if (ElementType.fromStringHtml(end_tag.name)) |token_element_type| switch (token_element_type) {
                .html_noscript => {
                    _ = c.open_elements.pop();
                    assert(currentNode(c).element_type == .html_head);
                    changeTo(c, .InHead);
                },
                .html_br => try inHeadNoscriptAnythingElse(c),
                else => {
                    try parseError(c, .TreeConstructionError);
                    // Ignore the token.
                },
            } else {
                try parseError(c, .TreeConstructionError);
                // Ignore the token.
            }
        },
        .comment => |comment| try inHeadComment(c, comment),
        .character => |character| {
            if (isWhitespace(character)) {
                try inHeadWhitespace(c, character);
            } else {
                try inHeadNoscriptAnythingElse(c);
            }
        },
        .eof => try inHeadNoscriptAnythingElse(c),
    }
}

fn inHeadNoscriptAnythingElse(c: *TreeConstructor) !void {
    try parseError(c, .TreeConstructionError);
    assert(c.open_elements.pop().element_type == .html_noscript);
    assert(currentNode(c).element_type == .html_head);
    reprocessIn(c, .InHead);
}

fn afterHead(c: *TreeConstructor, token: Token) !void {
    switch (token) {
        .character => |character| if (isWhitespace(character)) {
            try insertCharacter(c, character);
        } else {
            try afterHeadAnythingElse(c);
        },
        .comment => |comment| try insertComment(c, comment),
        .doctype => {
            try parseError(c, .TreeConstructionError);
            // Ignore the token.
        },
        .eof => try afterHeadAnythingElse(c),
        .start_tag => |start_tag| {
            if (ElementType.fromStringHtml(start_tag.name)) |token_element_type| switch (token_element_type) {
                .html_html => try inBodyStartTagHtml(c, start_tag),
                .html_body => {
                    _ = try insertHtmlElementForTheToken(c, start_tag, token_element_type);
                    c.frameset_ok = .not_ok;
                    changeTo(c, .InBody);
                },
                .html_frameset => {
                    _ = try insertHtmlElementForTheToken(c, start_tag, token_element_type);
                    changeTo(c, .InFrameset);
                },
                .html_base,
                .html_basefont,
                .html_bgsound,
                .html_link,
                .html_meta,
                .html_noframes,
                .html_script,
                .html_style,
                .html_template,
                .html_title,
                => {
                    try parseError(c, .TreeConstructionError);
                    try c.open_elements.append(c.allocator, c.head_element_pointer.?);
                    switch (token_element_type) {
                        .html_base, .html_basefont, .html_bgsound, .html_link => try inHeadStartTagBaseBasefontBgsoundLink(c, start_tag, token_element_type),
                        .html_meta => try inHeadStartTagMeta(c, start_tag),
                        .html_noframes => try inHeadStartTagNoframesStyle(c, start_tag, .html_noframes),
                        .html_style => try inHeadStartTagNoframesStyle(c, start_tag, .html_style),
                        .html_script => try inHeadStartTagScript(c, start_tag),
                        .html_template => try inHeadStartTagTemplate(c, start_tag),
                        .html_title => try inHeadStartTagTitle(c, start_tag),
                        else => unreachable,
                    }
                    removeFromStackOfOpenElements(c, c.head_element_pointer.?);
                },
                .html_head => {
                    try parseError(c, .TreeConstructionError);
                    // Ignore the token.
                },
                else => try afterHeadAnythingElse(c),
            } else {
                try afterHeadAnythingElse(c);
            }
        },
        .end_tag => |end_tag| {
            if (ElementType.fromStringHtml(end_tag.name)) |token_element_type| switch (token_element_type) {
                .html_template => _ = try inHeadEndTagTemplate(c),
                .html_body, .html_html, .html_br => try afterHeadAnythingElse(c),
                else => {
                    try parseError(c, .TreeConstructionError);
                    // Ignore the token.
                },
            } else {
                try parseError(c, .TreeConstructionError);
                // Ignore the token.
            }
        },
    }
}

fn afterHeadAnythingElse(c: *TreeConstructor) !void {
    _ = try insertHtmlElementForTheToken(c, Token.StartTag{
        .name = "body",
        .attributes = .{},
        .self_closing = false,
    }, .html_body);
    reprocessIn(c, .InBody);
}

fn inBody(c: *TreeConstructor, token: Token) !void {
    switch (token) {
        .doctype => try inBodyDoctype(c),
        .character => |character| try inBodyCharacter(c, character),
        .comment => |comment| try inBodyComment(c, comment),
        .eof => try inBodyEof(c),
        .start_tag => |start_tag| {
            if (ElementType.fromStringHtml(start_tag.name)) |token_element_type| switch (token_element_type) {
                .html_html => try inBodyStartTagHtml(c, start_tag),
                .html_base, .html_basefont, .html_bgsound, .html_link => try inHeadStartTagBaseBasefontBgsoundLink(c, start_tag, token_element_type),
                .html_meta => try inHeadStartTagMeta(c, start_tag),
                .html_noframes => try inHeadStartTagNoframesStyle(c, start_tag, .html_noframes),
                .html_style => try inHeadStartTagNoframesStyle(c, start_tag, .html_style),
                .html_script => try inHeadStartTagScript(c, start_tag),
                .html_template => try inHeadStartTagTemplate(c, start_tag),
                .html_title => try inHeadStartTagTitle(c, start_tag),
                .html_body => {
                    try parseError(c, .TreeConstructionError);
                    if (c.open_elements.items.len == 1 or
                        c.open_elements.items[1].element_type != .html_body or
                        stackOfOpenElementsHas(c, .html_template))
                    {
                        assert(c.fragment_context != null);
                        // Ignore the token.
                    } else {
                        c.frameset_ok = .not_ok;
                        const body = c.open_elements.items[1];
                        assert(body.element_type == .html_body);
                        var attr_it = start_tag.attributes.iterator();
                        while (attr_it.next()) |attr| {
                            try body.appendAttributeIfNotExists(c.dom.allocator, .{ .prefix = .none, .namespace = .none, .local_name = attr.key_ptr.* }, attr.value_ptr.*);
                        }
                    }
                },
                .html_frameset => {
                    try parseError(c, .TreeConstructionError);
                    if (c.open_elements.items.len == 1 or c.open_elements.items[1].element_type != .html_body) {
                        assert(c.fragment_context != null);
                        // Ignore the token.
                    } else if (c.frameset_ok == .not_ok) {
                        // Ignore the token.
                    } else {
                        // The stack of open elements has at least 2 elements because of previous checks.
                        Dom.mutation.elementRemove(c.dom, c.open_elements.items[1], .Suppress);
                        c.open_elements.shrinkRetainingCapacity(1);
                        _ = try insertHtmlElementForTheToken(c, start_tag, .html_frameset);
                        changeTo(c, .InFrameset);
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
                        // NOTE: The index of the p element, which is found in hasElementInButtonScope, can be used in closePElement
                        try closePElement(c);
                    }
                    _ = try insertHtmlElementForTheToken(c, start_tag, token_element_type);
                },
                .html_h1, .html_h2, .html_h3, .html_h4, .html_h5, .html_h6 => {
                    if (hasElementInButtonScope(c, ElementType.html_p)) {
                        // NOTE: The index of the p element, which is found in hasElementInButtonScope, can be used in closePElement
                        try closePElement(c);
                    }
                    const current_node = currentNode(c);
                    if (elemTypeEqlAny(current_node.element_type, &.{ .html_h1, .html_h2, .html_h3, .html_h4, .html_h5, .html_h6 })) {
                        try parseError(c, .TreeConstructionError);
                        _ = c.open_elements.pop();
                    }
                    _ = try insertHtmlElementForTheToken(c, start_tag, token_element_type);
                },
                .html_pre, .html_listing => {
                    if (hasElementInButtonScope(c, ElementType.html_p)) {
                        // NOTE: The index of the p element, which is found in hasElementInButtonScope, can be used in closePElement
                        try closePElement(c);
                    }
                    _ = try insertHtmlElementForTheToken(c, start_tag, token_element_type);
                    c.ignore_next_lf_token = true;
                    c.frameset_ok = .not_ok;
                },
                .html_form => {
                    const stack_has_template_element = stackOfOpenElementsHas(c, .html_template);
                    if (c.form_element_pointer != null and !stack_has_template_element) {
                        try parseError(c, .TreeConstructionError);
                        // Ignore the token.
                    } else {
                        if (hasElementInButtonScope(c, ElementType.html_p)) {
                            // NOTE: The index of the p element, which is found in hasElementInButtonScope, can be used in closePElement
                            try closePElement(c);
                        }
                        const element = try insertHtmlElementForTheToken(c, start_tag, token_element_type);
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
                            generateImpliedEndTags(c, ElementType.html_li);
                            if (currentNode(c).element_type != .html_li) {
                                try parseError(c, .TreeConstructionError);
                            }
                            while (c.open_elements.pop().element_type != .html_li) {}
                            break;
                        } else if (isSpecialElementButNotAddressDivP(node.element_type)) {
                            break;
                        } else {
                            index -= 1;
                        }
                    }
                    if (hasElementInButtonScope(c, ElementType.html_p)) {
                        // NOTE: The index of the p element, which is found in hasElementInButtonScope, can be used in closePElement
                        try closePElement(c);
                    }
                    _ = try insertHtmlElementForTheToken(c, start_tag, token_element_type);
                },
                .html_dd, .html_dt => {
                    c.frameset_ok = .not_ok;
                    var index = c.open_elements.items.len;
                    while (true) {
                        const node = c.open_elements.items[index - 1];
                        const is_dd_or_dt = switch (node.element_type) {
                            .html_dd, .html_dt => true,
                            else => false,
                        };
                        if (is_dd_or_dt) {
                            const dd_or_dt = node.element_type;
                            generateImpliedEndTags(c, dd_or_dt);
                            if (currentNode(c).element_type != dd_or_dt) {
                                try parseError(c, .TreeConstructionError);
                            }
                            while (c.open_elements.pop().element_type != dd_or_dt) {}
                            break;
                        } else if (isSpecialElementButNotAddressDivP(node.element_type)) {
                            break;
                        } else {
                            index -= 1;
                        }
                    }
                    if (hasElementInButtonScope(c, ElementType.html_p)) {
                        // NOTE: The index of the p element, which is found in hasElementInButtonScope, can be used in closePElement
                        try closePElement(c);
                    }
                    _ = try insertHtmlElementForTheToken(c, start_tag, token_element_type);
                },
                .html_plaintext => {
                    if (hasElementInButtonScope(c, ElementType.html_p)) {
                        // NOTE: The index of the p element, which is found in hasElementInButtonScope, can be used in closePElement
                        try closePElement(c);
                    }
                    _ = try insertHtmlElementForTheToken(c, start_tag, token_element_type);
                    // TODO: Once a start tag with the tag name "plaintext" has been seen, that will be
                    // the last token ever seen other than character tokens (and the end-of-file token),
                    // because there is no way to switch out of the PLAINTEXT state.
                    setTokenizerState(c, .PLAINTEXT, .html_plaintext);
                },
                .html_button => {
                    if (hasElementInScope(c, ElementType.html_button)) {
                        try parseError(c, .TreeConstructionError);
                        generateImpliedEndTags(c, null);
                        // NOTE: The index of the button element, which is found in hasElementInScope, can be used here
                        while (c.open_elements.pop().element_type != .html_button) {}
                    }
                    try reconstructActiveFormattingElements(c);
                    _ = try insertHtmlElementForTheToken(c, start_tag, token_element_type);
                    c.frameset_ok = .not_ok;
                },
                .html_a => {
                    const begin = if (c.index_of_last_marker) |lm| lm + 1 else 0;
                    for (c.active_formatting_elements.items[begin..]) |fe| {
                        if (fe.element.?.element_type == .html_a) {
                            try parseError(c, .TreeConstructionError);
                            try adoptionAgencyAlgorithm(c, .html_a);
                            for (c.active_formatting_elements.items) |fe2, j| {
                                if (fe2.element == fe.element.?) removeFromListOfActiveFormattingElements(c, j);
                            }
                            // TODO: The adoption agency algorithm may have already removed the element from the stack of open elements
                            // if the element was in table scope.
                            for (c.open_elements.items) |e, j| {
                                if (e == fe.element.?) _ = c.open_elements.orderedRemove(j);
                            }
                            break;
                        }
                    }
                    try reconstructActiveFormattingElements(c);
                    const element = try insertHtmlElementForTheToken(c, start_tag, token_element_type);
                    try pushOntoListOfActiveFormattingElements(c, element);
                },
                .html_b,
                .html_big,
                .html_code,
                .html_em,
                .html_font,
                .html_i,
                .html_s,
                .html_small,
                .html_strike,
                .html_strong,
                .html_tt,
                .html_u,
                => {
                    try reconstructActiveFormattingElements(c);
                    const element = try insertHtmlElementForTheToken(c, start_tag, token_element_type);
                    try pushOntoListOfActiveFormattingElements(c, element);
                },
                .html_nobr => {
                    try reconstructActiveFormattingElements(c);
                    if (hasElementInScope(c, ElementType.html_nobr)) {
                        try parseError(c, .TreeConstructionError);
                        try adoptionAgencyAlgorithm(c, .html_nobr);
                        try reconstructActiveFormattingElements(c);
                    }
                    const element = try insertHtmlElementForTheToken(c, start_tag, token_element_type);
                    try pushOntoListOfActiveFormattingElements(c, element);
                },
                .html_applet, .html_marquee, .html_object => {
                    try reconstructActiveFormattingElements(c);
                    _ = try insertHtmlElementForTheToken(c, start_tag, token_element_type);
                    try insertAMarker(c);
                    c.frameset_ok = .not_ok;
                },
                .html_table => {
                    if (c.document.quirks_mode != .quirks and hasElementInButtonScope(c, .html_p)) {
                        // NOTE: The index of the p element, which is found in hasElementInButtonScope, can be used in closePElement
                        try closePElement(c);
                    }
                    _ = try insertHtmlElementForTheToken(c, start_tag, token_element_type);
                    c.frameset_ok = .not_ok;
                    changeTo(c, .InTable);
                },
                .html_area, .html_br, .html_embed, .html_img, .html_keygen, .html_wbr => {
                    try reconstructActiveFormattingElements(c);
                    _ = try insertHtmlElementForTheToken(c, start_tag, token_element_type);
                    _ = c.open_elements.pop();
                    acknowledgeSelfClosingFlag(c);
                    c.frameset_ok = .not_ok;
                },
                .html_input => {
                    try reconstructActiveFormattingElements(c);
                    _ = try insertHtmlElementForTheToken(c, start_tag, token_element_type);
                    _ = c.open_elements.pop();
                    acknowledgeSelfClosingFlag(c);
                    const @"type" = start_tag.attributes.get("type");
                    if (@"type" == null or !rem.util.eqlIgnoreCase2(@"type".?, "hidden")) {
                        c.frameset_ok = .not_ok;
                    }
                },
                .html_param, .html_source, .html_track => {
                    _ = try insertHtmlElementForTheToken(c, start_tag, token_element_type);
                    _ = c.open_elements.pop();
                    acknowledgeSelfClosingFlag(c);
                },
                .html_hr => {
                    if (hasElementInButtonScope(c, .html_p)) {
                        // NOTE: The index of the p element, which is found in hasElementInButtonScope, can be used in closePElement
                        try closePElement(c);
                    }
                    _ = try insertHtmlElementForTheToken(c, start_tag, token_element_type);
                    _ = c.open_elements.pop();
                    acknowledgeSelfClosingFlag(c);
                    c.frameset_ok = .not_ok;
                },
                .html_textarea => {
                    _ = try insertHtmlElementForTheToken(c, start_tag, token_element_type);
                    c.ignore_next_lf_token = true;
                    setTokenizerState(c, .RCDATA, .html_textarea);
                    c.frameset_ok = .not_ok;
                    changeToAndSetOriginalInsertionMode(c, .Text, c.insertion_mode);
                },
                .html_xmp => {
                    if (hasElementInButtonScope(c, .html_p)) {
                        // NOTE: The index of the p element, which is found in hasElementInButtonScope, can be used in closePElement
                        try closePElement(c);
                    }
                    try reconstructActiveFormattingElements(c);
                    c.frameset_ok = .not_ok;
                    try textParsingAlgorithm(.RAWTEXT, c, start_tag, .html_xmp);
                },
                .html_iframe => {
                    c.frameset_ok = .not_ok;
                    try textParsingAlgorithm(.RAWTEXT, c, start_tag, .html_iframe);
                },
                .html_noembed => try textParsingAlgorithm(.RAWTEXT, c, start_tag, .html_noembed),
                .html_noscript => try inBodyStartTagNoscript(c, start_tag),
                .html_select => {
                    try reconstructActiveFormattingElements(c);
                    _ = try insertHtmlElementForTheToken(c, start_tag, token_element_type);
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
                    try reconstructActiveFormattingElements(c);
                    _ = try insertHtmlElementForTheToken(c, start_tag, token_element_type);
                },
                .html_rb, .html_rtc => {
                    if (hasElementInScope(c, ElementType.html_ruby)) {
                        generateImpliedEndTags(c, null);
                        if (currentNode(c).element_type != .html_ruby) {
                            try parseError(c, .TreeConstructionError);
                        }
                    }
                    _ = try insertHtmlElementForTheToken(c, start_tag, token_element_type);
                },
                .html_rp, .html_rt => {
                    if (hasElementInScope(c, ElementType.html_ruby)) {
                        generateImpliedEndTags(c, ElementType.html_rtc);
                        const current_node_is_rtc_or_ruby = switch (currentNode(c).element_type) {
                            .html_rtc, .html_ruby => true,
                            else => false,
                        };
                        if (!current_node_is_rtc_or_ruby) {
                            try parseError(c, .TreeConstructionError);
                        }
                    }
                    _ = try insertHtmlElementForTheToken(c, start_tag, token_element_type);
                },
                .html_caption,
                .html_col,
                .html_colgroup,
                .html_frame,
                .html_head,
                .html_tbody,
                .html_td,
                .html_tfoot,
                .html_th,
                .html_thead,
                .html_tr,
                => {
                    try parseError(c, .TreeConstructionError);
                    // Ignore the token.
                },
                else => try inBodyStartTagAnythingElse(c, start_tag, token_element_type),
            } else {
                if (strEql(start_tag.name, "image")) {
                    try parseError(c, .TreeConstructionError);
                    try reconstructActiveFormattingElements(c);
                    _ = try insertHtmlElementForTheToken(c, Token.StartTag{
                        .name = "img",
                        .attributes = start_tag.attributes,
                        .self_closing = start_tag.self_closing,
                    }, .html_img);
                    _ = c.open_elements.pop();
                    acknowledgeSelfClosingFlag(c);
                    c.frameset_ok = .not_ok;
                } else if (strEql(start_tag.name, "math")) {
                    try reconstructActiveFormattingElements(c);
                    _ = try insertForeignElementForTheToken(c, start_tag, .mathml_math, .adjust_mathml_attributes);
                    if (start_tag.self_closing) {
                        _ = c.open_elements.pop();
                        acknowledgeSelfClosingFlag(c);
                    }
                } else if (strEql(start_tag.name, "svg")) {
                    try reconstructActiveFormattingElements(c);
                    _ = try insertForeignElementForTheToken(c, start_tag, .svg_svg, .adjust_svg_attributes);
                    if (start_tag.self_closing) {
                        _ = c.open_elements.pop();
                        acknowledgeSelfClosingFlag(c);
                    }
                } else {
                    try inBodyStartTagAnythingElse(c, start_tag, .custom_html);
                }
            }
        },
        .end_tag => |end_tag| {
            if (ElementType.fromStringHtml(end_tag.name)) |token_element_type| switch (token_element_type) {
                .html_template => _ = try inHeadEndTagTemplate(c),
                .html_body => {
                    if (!hasElementInScope(c, ElementType.html_body)) {
                        try parseError(c, .TreeConstructionError);
                        // Ignore the token.
                    } else {
                        try inBodyEofCheckForParseErrors(c);
                        changeTo(c, .AfterBody);
                    }
                },
                .html_html => {
                    if (!hasElementInScope(c, ElementType.html_body)) {
                        try parseError(c, .TreeConstructionError);
                        // Ignore the token.
                    } else {
                        try inBodyEofCheckForParseErrors(c);
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
                        try parseError(c, .TreeConstructionError);
                        // Ignore the token.
                    } else {
                        generateImpliedEndTags(c, null);
                        if (currentNode(c).element_type != token_element_type) {
                            try parseError(c, .TreeConstructionError);
                        }
                        popUntilElementTypeHasBeenPopped(c, token_element_type);
                    }
                },
                .html_form => {
                    if (!stackOfOpenElementsHas(c, .html_template)) {
                        const form = c.form_element_pointer;
                        c.form_element_pointer = null;

                        if (form == null or !hasElementInScope(c, form.?)) {
                            try parseError(c, .TreeConstructionError);
                            // Ignore the token;
                            return;
                        }
                        // form is not null at this point.

                        generateImpliedEndTags(c, null);
                        if (currentNode(c) != form.?) {
                            try parseError(c, .TreeConstructionError);
                        }
                        // TODO: The index of the form element may have been found in hasElementInScope
                        removeFromStackOfOpenElements(c, form.?);
                    } else {
                        if (!hasElementInScope(c, ElementType.html_form)) {
                            try parseError(c, .TreeConstructionError);
                            // Ignore the token.
                            return;
                        }
                        generateImpliedEndTags(c, null);
                        if (currentNode(c).element_type != .html_form) {
                            try parseError(c, .TreeConstructionError);
                        }
                        popUntilElementTypeHasBeenPopped(c, ElementType.html_form);
                    }
                },
                .html_p => {
                    if (!hasElementInButtonScope(c, ElementType.html_p)) {
                        try parseError(c, .TreeConstructionError);
                        _ = try insertHtmlElementForTheToken(c, Token.StartTag{
                            .name = "p",
                            .attributes = .{},
                            .self_closing = false,
                        }, .html_p);
                    }
                    try closePElement(c);
                },
                .html_li => {
                    if (!hasElementInListItemScope(c, ElementType.html_li)) {
                        try parseError(c, .TreeConstructionError);
                        // Ignore the token.
                    } else {
                        generateImpliedEndTags(c, ElementType.html_li);
                        if (currentNode(c).element_type != .html_li) {
                            try parseError(c, .TreeConstructionError);
                        }
                        popUntilElementTypeHasBeenPopped(c, ElementType.html_li);
                    }
                },
                .html_dd, .html_dt => {
                    if (!hasElementInScope(c, token_element_type)) {
                        try parseError(c, .TreeConstructionError);
                        // Ignore the token.
                    } else {
                        generateImpliedEndTags(c, token_element_type);
                        if (currentNode(c).element_type != token_element_type) {
                            try parseError(c, .TreeConstructionError);
                        }
                        popUntilElementTypeHasBeenPopped(c, token_element_type);
                    }
                },
                .html_h1, .html_h2, .html_h3, .html_h4, .html_h5, .html_h6 => {
                    if (!hasElementInScope(
                        c,
                        @as([]const ElementType, &[_]ElementType{ .html_h1, .html_h2, .html_h3, .html_h4, .html_h5, .html_h6 }),
                    )) {
                        try parseError(c, .TreeConstructionError);
                        // Ignore the token.
                    } else {
                        generateImpliedEndTags(c, null);
                        if (currentNode(c).element_type != token_element_type) {
                            try parseError(c, .TreeConstructionError);
                        }
                        popUntilElementTypeHasBeenPopped(
                            c,
                            @as([]const ElementType, &[6]ElementType{ .html_h1, .html_h2, .html_h3, .html_h4, .html_h5, .html_h6 }),
                        );
                    }
                },
                .html_a,
                .html_b,
                .html_big,
                .html_code,
                .html_em,
                .html_font,
                .html_i,
                .html_nobr,
                .html_s,
                .html_small,
                .html_strike,
                .html_strong,
                .html_tt,
                .html_u,
                => try adoptionAgencyAlgorithm(c, token_element_type),
                .html_applet, .html_marquee, .html_object => {
                    if (!hasElementInScope(c, token_element_type)) {
                        try parseError(c, .TreeConstructionError);
                        // Ignore the token.
                    } else {
                        generateImpliedEndTags(c, null);
                        if (currentNode(c).element_type != token_element_type) {
                            try parseError(c, .TreeConstructionError);
                        }
                        popUntilElementTypeHasBeenPopped(c, token_element_type);
                        clearListOfActiveFormattingElementsUpToLastMarker(c);
                    }
                },
                .html_br => {
                    try reconstructActiveFormattingElements(c);
                    _ = try insertHtmlElementForTheToken(c, Token.StartTag{
                        .name = "br",
                        .attributes = .{},
                        .self_closing = false,
                    }, .html_br);
                    _ = c.open_elements.pop();
                    c.frameset_ok = .not_ok;
                },
                else => try inBodyEndTagAnythingElse(c, token_element_type),
            } else try inBodyEndTagAnythingElse(c, end_tag.name);
        },
    }
}

fn inBodyDoctype(c: *TreeConstructor) !void {
    try parseError(c, .TreeConstructionError);
    // Ignore the token.
}

fn inBodyComment(c: *TreeConstructor, comment: Token.Comment) !void {
    try insertComment(c, comment);
}

fn inBodyEof(c: *TreeConstructor) !void {
    if (c.template_insertion_modes.items.len > 0) {
        try inTemplateEof(c);
    } else {
        try inBodyEofCheckForParseErrors(c);
        stop(c);
    }
}

fn inBodyEofCheckForParseErrors(c: *TreeConstructor) !void {
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
            return parseError(c, .TreeConstructionError);
        }
    }
}

fn inBodyCharacter(c: *TreeConstructor, character: Token.Character) !void {
    if (isNull(character)) {
        try parseError(c, .TreeConstructionError);
        // Ignore the token.
    } else {
        try reconstructActiveFormattingElements(c);
        try insertCharacter(c, character);
        if (!isWhitespace(character)) {
            c.frameset_ok = .not_ok;
        }
    }
}

fn inBodyWhitespaceCharacter(c: *TreeConstructor, character: Token.Character) !void {
    try reconstructActiveFormattingElements(c);
    try insertCharacter(c, character);
}

fn inBodyStartTagHtml(c: *TreeConstructor, start_tag: Token.StartTag) !void {
    try parseError(c, .TreeConstructionError);
    if (stackOfOpenElementsHas(c, .html_template)) {
        // Ignore the token.
    } else {
        const top_element = stackOfOpenElementsTop(c);
        var iterator = start_tag.attributes.iterator();
        while (iterator.next()) |attr| {
            try top_element.appendAttributeIfNotExists(c.dom.allocator, .{ .prefix = .none, .namespace = .none, .local_name = attr.key_ptr.* }, attr.value_ptr.*);
        }
    }
}

fn inBodyStartTagNoscript(c: *TreeConstructor, start_tag: Token.StartTag) !void {
    if (c.scripting) {
        try textParsingAlgorithm(.RAWTEXT, c, start_tag, .html_noscript);
    } else {
        try inBodyStartTagAnythingElse(c, start_tag, .html_noscript);
    }
}

fn inBodyStartTagAnythingElse(c: *TreeConstructor, start_tag: Token.StartTag, element_type: ElementType) !void {
    try reconstructActiveFormattingElements(c);
    _ = try insertHtmlElementForTheToken(c, start_tag, element_type);
}

fn inBodyEndTagAnythingElse(c: *TreeConstructor, element_type_or_tag_name: anytype) !void {
    switch (@TypeOf(element_type_or_tag_name)) {
        ElementType => assert(element_type_or_tag_name.namespace() == .html),
        []const u8 => {},
        else => |T| @compileError("expected " ++ @typeName(ElementType) ++ " or " ++ @typeName([]const u8) ++ ", found '" ++ @typeName(T) ++ "'"),
    }

    var i = c.open_elements.items.len;
    while (i > 0) : (i -= 1) {
        const node = c.open_elements.items[i - 1];
        const node_matches_tag: bool = switch (@TypeOf(element_type_or_tag_name)) {
            ElementType => node.element_type == element_type_or_tag_name,
            []const u8 => node.namespace() == .html and strEql(element_type_or_tag_name, node.localName(c.dom)),
            else => unreachable,
        };

        if (node_matches_tag) {
            generateImpliedEndTags(c, element_type_or_tag_name);
            if (i != c.open_elements.items.len) try parseError(c, .TreeConstructionError);
            c.open_elements.shrinkRetainingCapacity(i - 1);
            break;
        } else {
            if (isSpecialElement(node.element_type)) {
                try parseError(c, .TreeConstructionError);
                // Ignore the token.
                return;
            }
        }
    }
}

fn text(c: *TreeConstructor, token: Token) !void {
    switch (token) {
        .character => |character| {
            assert(!isNull(character));
            try insertCharacter(c, character);
        },
        .eof => {
            try parseError(c, .TreeConstructionError);
            const current_node = c.open_elements.pop();
            if (current_node.element_type == .html_script and c.scripting) {
                @panic("TODO Text eof, current node is a script, scripting is enabled");
            }
            reprocessInOriginalInsertionMode(c);
        },
        .end_tag => |end_tag| {
            if (strEql(end_tag.name, "script")) {
                if (c.scripting) {
                    @panic("TODO Text end tag script, scripting is enabled");
                }
                assert(c.open_elements.pop().element_type == .html_script);
                changeToOriginalInsertionMode(c);
            } else {
                _ = c.open_elements.pop();
                changeToOriginalInsertionMode(c);
            }
        },
        else => unreachable,
    }
}

fn inTable(c: *TreeConstructor, token: Token) !void {
    switch (token) {
        .doctype => {
            try parseError(c, .TreeConstructionError);
            // Ignore the token.
        },
        .comment => |comment| try insertComment(c, comment),
        .eof => try inBodyEof(c),
        .character => {
            switch (currentNode(c).element_type) {
                .html_table, .html_tbody, .html_tfoot, .html_thead, .html_tr => {
                    reprocessAndSetOriginalInsertionMode(c, .InTableText, c.insertion_mode);
                },
                else => try inTableAnythingElse(c, token),
            }
        },
        .start_tag => |start_tag| {
            if (ElementType.fromStringHtml(start_tag.name)) |token_element_type| switch (token_element_type) {
                .html_caption => {
                    clearTheStackBackToATableContext(c);
                    try insertAMarker(c);
                    _ = try insertHtmlElementForTheToken(c, start_tag, .html_caption);
                    changeTo(c, .InCaption);
                },
                .html_colgroup => {
                    clearTheStackBackToATableContext(c);
                    _ = try insertHtmlElementForTheToken(c, start_tag, .html_colgroup);
                    changeTo(c, .InColumnGroup);
                },
                .html_col => {
                    clearTheStackBackToATableContext(c);
                    _ = try insertHtmlElementForTheToken(c, Token.StartTag{
                        .name = "colgroup",
                        .attributes = .{},
                        .self_closing = false,
                    }, .html_colgroup);
                    reprocessIn(c, .InColumnGroup);
                },
                .html_tbody, .html_tfoot, .html_thead => {
                    clearTheStackBackToATableContext(c);
                    _ = try insertHtmlElementForTheToken(c, start_tag, token_element_type);
                    changeTo(c, .InTableBody);
                },
                .html_td, .html_th, .html_tr => {
                    clearTheStackBackToATableContext(c);
                    _ = try insertHtmlElementForTheToken(c, Token.StartTag{
                        .name = "tbody",
                        .attributes = .{},
                        .self_closing = false,
                    }, .html_tbody);
                    reprocessIn(c, .InTableBody);
                },
                .html_table => {
                    try parseError(c, .TreeConstructionError);
                    if (!hasElementInTableScope(c, ElementType.html_table)) {
                        // Ignore the token.
                    } else {
                        popUntilElementTypeHasBeenPopped(c, ElementType.html_table);
                        resetInsertionModeAppropriately(c);
                        reprocess(c);
                    }
                },
                .html_style => try inHeadStartTagNoframesStyle(c, start_tag, .html_style),
                .html_script => try inHeadStartTagScript(c, start_tag),
                .html_template => try inHeadStartTagTemplate(c, start_tag),
                .html_input => {
                    const @"type" = start_tag.attributes.get("type");
                    if (@"type" == null or !rem.util.eqlIgnoreCase2(@"type".?, "hidden")) {
                        try inTableAnythingElse(c, token);
                    } else {
                        try parseError(c, .TreeConstructionError);
                        _ = try insertHtmlElementForTheToken(c, start_tag, .html_input);
                        _ = c.open_elements.pop();
                        acknowledgeSelfClosingFlag(c);
                    }
                },
                .html_form => {
                    try parseError(c, .TreeConstructionError);
                    if (c.form_element_pointer != null or stackOfOpenElementsHas(c, .html_template)) {
                        // Ignore the token.
                    } else {
                        const form = try insertHtmlElementForTheToken(c, start_tag, .html_form);
                        c.form_element_pointer = form;
                        _ = c.open_elements.pop();
                    }
                },
                else => try inTableAnythingElse(c, token),
            } else {
                try inTableAnythingElse(c, token);
            }
        },
        .end_tag => |end_tag| {
            if (ElementType.fromStringHtml(end_tag.name)) |token_element_type| switch (token_element_type) {
                .html_table => {
                    if (!hasElementInTableScope(c, ElementType.html_table)) {
                        try parseError(c, .TreeConstructionError);
                        // Ignore the token.
                    } else {
                        popUntilElementTypeHasBeenPopped(c, ElementType.html_table);
                        resetInsertionModeAppropriately(c);
                    }
                },
                .html_body,
                .html_caption,
                .html_col,
                .html_colgroup,
                .html_html,
                .html_tbody,
                .html_td,
                .html_tfoot,
                .html_th,
                .html_thead,
                .html_tr,
                => {
                    try parseError(c, .TreeConstructionError);
                    // Ignore the token.
                },
                .html_template => _ = try inHeadEndTagTemplate(c),
                else => try inTableAnythingElse(c, token),
            } else {
                try inTableAnythingElse(c, token);
            }
        },
    }
}

fn inTableAnythingElse(c: *TreeConstructor, token: Token) !void {
    try parseError(c, .TreeConstructionError);
    c.foster_parenting = true;
    try inBody(c, token);
    c.foster_parenting = false;
}

fn clearTheStackBackToATableContext(c: *TreeConstructor) void {
    var current_node = currentNode(c);
    while (!elemTypeEqlAny(current_node.element_type, &.{ .html_table, .html_template, .html_html })) {
        _ = c.open_elements.pop();
        current_node = currentNode(c);
    }
}

fn inTableText(c: *TreeConstructor, token: Token) !void {
    switch (token) {
        .character => |character| {
            if (isNull(character)) {
                try parseError(c, .TreeConstructionError);
                // Ignore the token.
            } else {
                if (!isWhitespace(character)) c.pending_table_chars_contains_non_whitespace = true;
                try c.pending_table_character_tokens.append(c.allocator, character);
            }
        },
        else => {
            if (c.pending_table_chars_contains_non_whitespace) {
                try parseError(c, .TreeConstructionError);
                c.foster_parenting = true;
                for (c.pending_table_character_tokens.items) |character| {
                    try inBodyCharacter(c, character);
                }
                c.foster_parenting = false;
            } else {
                for (c.pending_table_character_tokens.items) |character| {
                    try insertCharacter(c, character);
                }
            }
            c.pending_table_chars_contains_non_whitespace = false;
            c.pending_table_character_tokens.clearRetainingCapacity();
            reprocessInOriginalInsertionMode(c);
        },
    }
}

fn inCaption(c: *TreeConstructor, token: Token) !void {
    switch (token) {
        .start_tag => |start_tag| {
            if (ElementType.fromStringHtml(start_tag.name)) |token_element_type| switch (token_element_type) {
                .html_caption,
                .html_col,
                .html_colgroup,
                .html_tbody,
                .html_td,
                .html_tfoot,
                .html_th,
                .html_thead,
                .html_tr,
                => if (try inCaptionEndTagCaption(c)) {
                    reprocess(c);
                },
                else => try inCaptionAnythingElse(c, token),
            } else {
                try inCaptionAnythingElse(c, token);
            }
        },
        .end_tag => |end_tag| {
            if (ElementType.fromStringHtml(end_tag.name)) |token_element_type| switch (token_element_type) {
                .html_caption => _ = try inCaptionEndTagCaption(c),
                .html_table => if (try inCaptionEndTagCaption(c)) {
                    reprocess(c);
                },
                .html_body,
                .html_col,
                .html_colgroup,
                .html_html,
                .html_tbody,
                .html_td,
                .html_tfoot,
                .html_th,
                .html_thead,
                .html_tr,
                => {
                    try parseError(c, .TreeConstructionError);
                    // Ignore the token.
                },
                else => try inCaptionAnythingElse(c, token),
            } else {
                try inCaptionAnythingElse(c, token);
            }
        },
        else => try inCaptionAnythingElse(c, token),
    }
}

// Returns false if the token should be ignored.
fn inCaptionEndTagCaption(c: *TreeConstructor) !bool {
    if (!hasElementInTableScope(c, ElementType.html_caption)) {
        try parseError(c, .TreeConstructionError);
        // Ignore the token.
        return false;
    } else {
        generateImpliedEndTags(c, null);
        if (currentNode(c).element_type != .html_caption) {
            try parseError(c, .TreeConstructionError);
        }
        popUntilElementTypeHasBeenPopped(c, ElementType.html_caption);
        clearListOfActiveFormattingElementsUpToLastMarker(c);
        changeTo(c, .InTable);
        return true;
    }
}

fn inCaptionAnythingElse(c: *TreeConstructor, token: Token) !void {
    try inBody(c, token);
}

fn inColumnGroup(c: *TreeConstructor, token: Token) !void {
    switch (token) {
        .character => |character| {
            if (isWhitespace(character)) {
                try insertCharacter(c, character);
            } else {
                try inColumnGroupAnythingElse(c);
            }
        },
        .comment => |comment| try insertComment(c, comment),
        .doctype => {
            try parseError(c, .TreeConstructionError);
            // Ignore the token.
        },
        .eof => try inBodyEof(c),
        .start_tag => |start_tag| {
            if (ElementType.fromStringHtml(start_tag.name)) |token_element_type| switch (token_element_type) {
                .html_html => try inBodyStartTagHtml(c, start_tag),
                .html_col => {
                    _ = try insertHtmlElementForTheToken(c, start_tag, .html_col);
                    _ = c.open_elements.pop();
                    acknowledgeSelfClosingFlag(c);
                },
                .html_template => try inHeadStartTagTemplate(c, start_tag),
                else => try inColumnGroupAnythingElse(c),
            } else {
                try inColumnGroupAnythingElse(c);
            }
        },
        .end_tag => |end_tag| {
            if (ElementType.fromStringHtml(end_tag.name)) |token_element_type| switch (token_element_type) {
                .html_colgroup => _ = try inColumnGroupEndTagColgroup(c),
                .html_col => {
                    try parseError(c, .TreeConstructionError);
                    // Ignore the token.
                },
                .html_template => _ = try inHeadEndTagTemplate(c),
                else => try inColumnGroupAnythingElse(c),
            } else {
                try inColumnGroupAnythingElse(c);
            }
        },
    }
}

// Returns false if the token should be ignored.
fn inColumnGroupEndTagColgroup(c: *TreeConstructor) !bool {
    if (currentNode(c).element_type != .html_colgroup) {
        try parseError(c, .TreeConstructionError);
        // Ignore the token.
        return false;
    } else {
        _ = c.open_elements.pop();
        changeTo(c, .InTable);
        return true;
    }
}

fn inColumnGroupAnythingElse(c: *TreeConstructor) !void {
    if (try inColumnGroupEndTagColgroup(c)) {
        reprocess(c);
    }
}

fn inTableBody(c: *TreeConstructor, token: Token) !void {
    switch (token) {
        .start_tag => |start_tag| {
            if (ElementType.fromStringHtml(start_tag.name)) |token_element_type| switch (token_element_type) {
                .html_tr => {
                    clearTheStackBackToATableBodyContext(c);
                    _ = try insertHtmlElementForTheToken(c, start_tag, token_element_type);
                    changeTo(c, .InRow);
                },
                .html_th, .html_td => {
                    try parseError(c, .TreeConstructionError);
                    clearTheStackBackToATableBodyContext(c);
                    _ = try insertHtmlElementForTheToken(c, Token.StartTag{
                        .name = "tr",
                        .attributes = .{},
                        .self_closing = false,
                    }, .html_tr);
                    reprocessIn(c, .InRow);
                },
                .html_caption, .html_col, .html_colgroup, .html_tbody, .html_tfoot, .html_thead => try inTableBodyEndTagTable(c),
                else => try inTableBodyAnythingElse(c, token),
            } else {
                try inTableBodyAnythingElse(c, token);
            }
        },
        .end_tag => |end_tag| {
            if (ElementType.fromStringHtml(end_tag.name)) |token_element_type| switch (token_element_type) {
                .html_tbody, .html_tfoot, .html_thead => {
                    if (!hasElementInTableScope(c, token_element_type)) {
                        try parseError(c, .TreeConstructionError);
                        // Ignore the token.
                    } else {
                        clearTheStackBackToATableBodyContext(c);
                        _ = c.open_elements.pop();
                        changeTo(c, .InTable);
                    }
                },
                .html_table => try inTableBodyEndTagTable(c),
                .html_body, .html_caption, .html_col, .html_colgroup, .html_html, .html_td, .html_th, .html_tr => {
                    try parseError(c, .TreeConstructionError);
                    // Ignore the token.
                },
                else => try inTableBodyAnythingElse(c, token),
            } else {
                try inTableBodyAnythingElse(c, token);
            }
        },
        else => try inTableBodyAnythingElse(c, token),
    }
}

fn inTableBodyEndTagTable(c: *TreeConstructor) !void {
    if (!hasElementInTableScope(c, @as([]const ElementType, &[_]ElementType{ .html_tbody, .html_thead, .html_tfoot }))) {
        try parseError(c, .TreeConstructionError);
        // Ignore the token.
    } else {
        clearTheStackBackToATableBodyContext(c);
        _ = c.open_elements.pop();
        reprocessIn(c, .InTable);
    }
}

// TODO: This essentially causes the token to be completely reprocessed.
// Maybe worth deleting this, and handling this in inTableBody?
fn inTableBodyAnythingElse(c: *TreeConstructor, token: Token) !void {
    try inTable(c, token);
}

fn clearTheStackBackToATableBodyContext(c: *TreeConstructor) void {
    var current_node = currentNode(c);
    while (!elemTypeEqlAny(current_node.element_type, &.{ .html_tbody, .html_tfoot, .html_thead, .html_template, .html_html })) {
        _ = c.open_elements.pop();
        current_node = currentNode(c);
    }
}

fn inRow(c: *TreeConstructor, token: Token) !void {
    switch (token) {
        .start_tag => |start_tag| {
            if (ElementType.fromStringHtml(start_tag.name)) |token_element_type| switch (token_element_type) {
                .html_th, .html_td => {
                    clearTheStackBackToATableRowContext(c);
                    _ = try insertHtmlElementForTheToken(c, start_tag, token_element_type);
                    changeTo(c, .InCell);
                    try insertAMarker(c);
                },
                .html_caption, .html_col, .html_colgroup, .html_tbody, .html_tfoot, .html_thead, .html_tr => {
                    if (try inRowEndTagTr(c)) {
                        reprocess(c);
                    }
                },
                else => try inRowAnythingElse(c, token),
            } else {
                try inRowAnythingElse(c, token);
            }
        },
        .end_tag => |end_tag| {
            if (ElementType.fromStringHtml(end_tag.name)) |token_element_type| switch (token_element_type) {
                .html_tr => _ = try inRowEndTagTr(c),
                .html_table => {
                    if (try inRowEndTagTr(c)) {
                        reprocess(c);
                    }
                },
                .html_tbody, .html_tfoot, .html_thead => {
                    if (!hasElementInTableScope(c, token_element_type)) {
                        try parseError(c, .TreeConstructionError);
                        // Ignore the token.
                    } else if (try inRowEndTagTr(c)) {
                        reprocess(c);
                    }
                },
                .html_body, .html_caption, .html_col, .html_colgroup, .html_html, .html_td, .html_th => {
                    try parseError(c, .TreeConstructionError);
                    // Ignore the token.
                },
                else => try inRowAnythingElse(c, token),
            } else {
                try inRowAnythingElse(c, token);
            }
        },
        else => try inRowAnythingElse(c, token),
    }
}

// Returns false if the token should be ignored.
fn inRowEndTagTr(c: *TreeConstructor) !bool {
    if (!hasElementInTableScope(c, ElementType.html_tr)) {
        try parseError(c, .TreeConstructionError);
        // Ignore the token.
        return false;
    } else {
        clearTheStackBackToATableRowContext(c);
        assert(c.open_elements.pop().element_type == .html_tr);
        changeTo(c, .InTableBody);
        return true;
    }
}

// TODO: This essentially causes the token to be completely reprocessed.
// Maybe worth deleting this, and handling this in inRow?
fn inRowAnythingElse(c: *TreeConstructor, token: Token) !void {
    try inTable(c, token);
}

fn clearTheStackBackToATableRowContext(c: *TreeConstructor) void {
    var current_node = currentNode(c);
    while (!elemTypeEqlAny(current_node.element_type, &.{ .html_tr, .html_template, .html_html })) {
        _ = c.open_elements.pop();
        current_node = currentNode(c);
    }
}

fn inCell(c: *TreeConstructor, token: Token) !void {
    switch (token) {
        .start_tag => |start_tag| {
            if (ElementType.fromStringHtml(start_tag.name)) |token_element_type| switch (token_element_type) {
                .html_caption, .html_col, .html_colgroup, .html_tbody, .html_td, .html_tfoot, .html_th, .html_thead, .html_tr => {
                    if (!hasElementInTableScope(c, @as([]const ElementType, &[_]ElementType{ .html_td, .html_th }))) {
                        try parseError(c, .TreeConstructionError);
                        // Ignore the token.
                    } else {
                        try closeTheCell(c);
                        reprocess(c);
                    }
                },
                else => try inCellAnythingElse(c, token),
            } else {
                try inCellAnythingElse(c, token);
            }
        },
        .end_tag => |end_tag| {
            if (ElementType.fromStringHtml(end_tag.name)) |token_element_type| switch (token_element_type) {
                .html_td, .html_th => {
                    if (!hasElementInTableScope(c, token_element_type)) {
                        try parseError(c, .TreeConstructionError);
                        // Ignore the token.
                    } else {
                        generateImpliedEndTags(c, null);
                        if (currentNode(c).element_type != token_element_type) {
                            try parseError(c, .TreeConstructionError);
                        }
                        popUntilElementTypeHasBeenPopped(c, token_element_type);
                        clearListOfActiveFormattingElementsUpToLastMarker(c);
                        changeTo(c, .InRow);
                    }
                },
                .html_body, .html_caption, .html_col, .html_colgroup, .html_html => {
                    try parseError(c, .TreeConstructionError);
                    // Ignore the token.
                },
                .html_table, .html_tbody, .html_tfoot, .html_thead, .html_tr => {
                    if (!hasElementInTableScope(c, token_element_type)) {
                        try parseError(c, .TreeConstructionError);
                        // Ignore the token.
                    } else {
                        try closeTheCell(c);
                        reprocess(c);
                    }
                },
                else => try inCellAnythingElse(c, token),
            } else {
                try inCellAnythingElse(c, token);
            }
        },
        else => try inCellAnythingElse(c, token),
    }
}

// TODO: This essentially causes the token to be completely reprocessed.
// Maybe worth deleting this, and handling this in inCell?
fn inCellAnythingElse(c: *TreeConstructor, token: Token) !void {
    try inBody(c, token);
}

fn closeTheCell(c: *TreeConstructor) !void {
    generateImpliedEndTags(c, null);
    const current_node_elem_type = currentNode(c).element_type;
    if (!elemTypeEqlAny(current_node_elem_type, &.{ .html_td, .html_th })) {
        try parseError(c, .TreeConstructionError);
    }
    popUntilElementTypeHasBeenPopped(c, @as([]const ElementType, &[2]ElementType{ .html_td, .html_th }));
    clearListOfActiveFormattingElementsUpToLastMarker(c);
    changeTo(c, .InRow);
}

fn inSelect(c: *TreeConstructor, token: Token) !void {
    switch (token) {
        .character => |character| {
            if (isNull(character)) {
                try parseError(c, .TreeConstructionError);
                // Ignore the token.
            } else {
                try insertCharacter(c, character);
            }
        },
        .comment => |comment| try insertComment(c, comment),
        .doctype => {
            try parseError(c, .TreeConstructionError);
            // Ignore the token.
        },
        .eof => try inBodyEof(c),
        .start_tag => |start_tag| {
            if (ElementType.fromStringHtml(start_tag.name)) |token_element_type| switch (token_element_type) {
                .html_html => try inBodyStartTagHtml(c, start_tag),
                .html_option => {
                    if (currentNode(c).element_type == .html_option) {
                        _ = c.open_elements.pop();
                    }
                    _ = try insertHtmlElementForTheToken(c, start_tag, token_element_type);
                },
                .html_optgroup => {
                    if (currentNode(c).element_type == .html_option) {
                        _ = c.open_elements.pop();
                    }
                    if (currentNode(c).element_type == .html_optgroup) {
                        _ = c.open_elements.pop();
                    }
                    _ = try insertHtmlElementForTheToken(c, start_tag, token_element_type);
                },
                .html_select => {
                    try parseError(c, .TreeConstructionError);
                    _ = try inSelectEndTagSelect(c);
                },
                .html_input, .html_keygen, .html_textarea => {
                    try parseError(c, .TreeConstructionError);
                    if (try inSelectEndTagSelect(c)) {
                        reprocess(c);
                    }
                },
                .html_script => try inHeadStartTagScript(c, start_tag),
                .html_template => try inHeadStartTagTemplate(c, start_tag),
                else => try inSelectAnythingElse(c),
            } else {
                try inSelectAnythingElse(c);
            }
        },
        .end_tag => |end_tag| {
            if (ElementType.fromStringHtml(end_tag.name)) |token_element_type| switch (token_element_type) {
                .html_optgroup => {
                    if (currentNode(c).element_type == .html_option) {
                        if (c.open_elements.items[c.open_elements.items.len - 2].element_type == .html_optgroup) {
                            _ = c.open_elements.pop();
                        }
                    }
                    if (currentNode(c).element_type == .html_optgroup) {
                        _ = c.open_elements.pop();
                    } else {
                        try parseError(c, .TreeConstructionError);
                        // Ignore the token.
                    }
                },
                .html_option => {
                    if (currentNode(c).element_type == .html_option) {
                        _ = c.open_elements.pop();
                    } else {
                        try parseError(c, .TreeConstructionError);
                        // Ignore the token.
                    }
                },
                .html_select => _ = try inSelectEndTagSelect(c),
                .html_template => _ = try inHeadEndTagTemplate(c),
                else => try inSelectAnythingElse(c),
            } else {
                try inSelectAnythingElse(c);
            }
        },
    }
}

// Returns false if the token should be ignored.
fn inSelectEndTagSelect(c: *TreeConstructor) !bool {
    if (!hasElementInSelectScope(c, .html_select)) {
        try parseError(c, .TreeConstructionError);
        // Ignore the token.
        return false;
    } else {
        popUntilElementTypeHasBeenPopped(c, ElementType.html_select);
        resetInsertionModeAppropriately(c);
        return true;
    }
}

fn inSelectAnythingElse(c: *TreeConstructor) !void {
    try parseError(c, .TreeConstructionError);
    // Ignore the token.
}

fn inSelectInTable(c: *TreeConstructor, token: Token) !void {
    switch (token) {
        .start_tag => |start_tag| {
            if (ElementType.fromStringHtml(start_tag.name)) |token_element_type| switch (token_element_type) {
                .html_caption, .html_table, .html_tbody, .html_tfoot, .html_thead, .html_tr, .html_td, .html_th => {
                    try parseError(c, .TreeConstructionError);
                    inSelectInTableCommon(c);
                },
                else => try inSelectInTableAnythingElse(c, token),
            } else {
                try inSelectInTableAnythingElse(c, token);
            }
        },
        .end_tag => |end_tag| {
            if (ElementType.fromStringHtml(end_tag.name)) |token_element_type| switch (token_element_type) {
                .html_caption, .html_table, .html_tbody, .html_tfoot, .html_thead, .html_tr, .html_td, .html_th => {
                    try parseError(c, .TreeConstructionError);
                    if (!hasElementInSelectScope(c, token_element_type)) {
                        // Ignore the token.
                    } else {
                        inSelectInTableCommon(c);
                    }
                },
                else => try inSelectInTableAnythingElse(c, token),
            } else {
                try inSelectInTableAnythingElse(c, token);
            }
        },
        else => try inSelectInTableAnythingElse(c, token),
    }
}

fn inSelectInTableCommon(c: *TreeConstructor) void {
    popUntilElementTypeHasBeenPopped(c, ElementType.html_select);
    resetInsertionModeAppropriately(c);
    reprocess(c);
}

// TODO: This essentially causes the token to be completely reprocessed.
// Maybe worth deleting this, and handling this in inSelectInTable?
fn inSelectInTableAnythingElse(c: *TreeConstructor, token: Token) !void {
    try inSelect(c, token);
}

fn inTemplate(c: *TreeConstructor, token: Token) !void {
    switch (token) {
        .character => |character| try inBodyCharacter(c, character),
        .comment => |comment| try inBodyComment(c, comment),
        .doctype => try inBodyDoctype(c),
        .eof => try inTemplateEof(c),
        .start_tag => |start_tag| {
            if (ElementType.fromStringHtml(start_tag.name)) |token_element_type| switch (token_element_type) {
                .html_base, .html_basefont, .html_bgsound, .html_link => try inHeadStartTagBaseBasefontBgsoundLink(c, start_tag, token_element_type),
                .html_meta => try inHeadStartTagMeta(c, start_tag),
                .html_noframes => try inHeadStartTagNoframesStyle(c, start_tag, .html_noframes),
                .html_style => try inHeadStartTagNoframesStyle(c, start_tag, .html_style),
                .html_script => try inHeadStartTagScript(c, start_tag),
                .html_template => try inHeadStartTagTemplate(c, start_tag),
                .html_title => try inHeadStartTagTitle(c, start_tag),
                .html_caption, .html_colgroup, .html_tbody, .html_tfoot, .html_thead => inTemplatePushTemplate(c, .InTable),
                .html_col => inTemplatePushTemplate(c, .InColumnGroup),
                .html_tr => inTemplatePushTemplate(c, .InTableBody),
                .html_td, .html_th => inTemplatePushTemplate(c, .InRow),
                else => inTemplateAnyOtherStartTag(c),
            } else {
                inTemplateAnyOtherStartTag(c);
            }
        },
        .end_tag => |end_tag| {
            if (ElementType.fromStringHtml(end_tag.name)) |token_element_type| switch (token_element_type) {
                .html_template => _ = try inHeadEndTagTemplate(c),
                else => try inTemplateAnyOtherEndTag(c),
            } else {
                try inTemplateAnyOtherEndTag(c);
            }
        },
    }
}

fn inTemplateEof(c: *TreeConstructor) !void {
    if (!stackOfOpenElementsHas(c, .html_template)) {
        stop(c);
        return;
    } else {
        try parseError(c, .TreeConstructionError);
    }
    popUntilElementTypeHasBeenPopped(c, ElementType.html_template);
    clearListOfActiveFormattingElementsUpToLastMarker(c);
    _ = c.template_insertion_modes.pop();
    resetInsertionModeAppropriately(c);
    reprocess(c);
}

fn inTemplatePushTemplate(c: *TreeConstructor, insertion_mode: InsertionMode) void {
    c.template_insertion_modes.items[c.template_insertion_modes.items.len - 1] = insertion_mode;
    reprocessIn(c, insertion_mode);
}

fn inTemplateAnyOtherStartTag(c: *TreeConstructor) void {
    inTemplatePushTemplate(c, .InBody);
}

fn inTemplateAnyOtherEndTag(c: *TreeConstructor) !void {
    try parseError(c, .TreeConstructionError);
    // Ignore the token.
}

fn afterBody(c: *TreeConstructor, token: Token) !void {
    switch (token) {
        .character => |character| if (isWhitespace(character))
            try inBodyWhitespaceCharacter(c, character)
        else
            try afterBodyAnythingElse(c),
        .comment => |comment| try insertCommentToElement(c, comment, stackOfOpenElementsTop(c)),
        .doctype => {
            try parseError(c, .TreeConstructionError);
            // Ignore the token.
        },
        .start_tag => |start_tag| if (strEql(start_tag.name, "html"))
            try inBodyStartTagHtml(c, token.start_tag)
        else
            try afterBodyAnythingElse(c),
        .end_tag => |end_tag| if (strEql(end_tag.name, "html")) {
            if (c.fragment_context != null) {
                try parseError(c, .TreeConstructionError);
                // Ignore the token.
            } else {
                changeTo(c, .AfterAfterBody);
            }
        },
        .eof => stop(c),
    }
}

fn afterBodyAnythingElse(c: *TreeConstructor) !void {
    try parseError(c, .TreeConstructionError);
    reprocessIn(c, .InBody);
}

fn inFrameset(c: *TreeConstructor, token: Token) !void {
    switch (token) {
        .character => |character| if (isWhitespace(character)) {
            try insertCharacter(c, character);
        } else {
            try inFramesetAnythingElse(c);
        },
        .comment => |comment| try insertComment(c, comment),
        .doctype => {
            try parseError(c, .TreeConstructionError);
            // Ignore the token.
        },
        .eof => {
            if (currentNode(c).element_type != .html_html) {
                try parseError(c, .TreeConstructionError);
            }
            stop(c);
        },
        .start_tag => |start_tag| {
            if (ElementType.fromStringHtml(start_tag.name)) |token_element_type| switch (token_element_type) {
                .html_html => try inBodyStartTagHtml(c, start_tag),
                .html_frameset => _ = try insertHtmlElementForTheToken(c, start_tag, token_element_type),
                .html_frame => {
                    _ = try insertHtmlElementForTheToken(c, start_tag, token_element_type);
                    _ = c.open_elements.pop();
                    acknowledgeSelfClosingFlag(c);
                },
                .html_noframes => try inHeadStartTagNoframesStyle(c, start_tag, .html_noframes),
                else => try inFramesetAnythingElse(c),
            } else {
                try inFramesetAnythingElse(c);
            }
        },
        .end_tag => |end_tag| {
            if (strEql(end_tag.name, "frameset")) {
                if (c.open_elements.items.len == 1) {
                    try parseError(c, .TreeConstructionError);
                    // Ignore the token.
                } else {
                    _ = c.open_elements.pop();
                    if (c.fragment_context == null and currentNode(c).element_type != .html_frameset) {
                        changeTo(c, .AfterFrameset);
                    }
                }
            } else {
                try inFramesetAnythingElse(c);
            }
        },
    }
}

fn inFramesetAnythingElse(c: *TreeConstructor) !void {
    try parseError(c, .TreeConstructionError);
    // Ignore the token.
}

fn afterFrameset(c: *TreeConstructor, token: Token) !void {
    switch (token) {
        .character => |character| if (isWhitespace(character)) {
            try insertCharacter(c, character);
        } else {
            try afterFramesetAnythingElse(c);
        },
        .comment => |comment| try insertComment(c, comment),
        .doctype => try afterFramesetAnythingElse(c),
        .eof => stop(c),
        .start_tag => |start_tag| {
            if (strEql(start_tag.name, "html")) {
                try inBodyStartTagHtml(c, start_tag);
            } else if (strEql(start_tag.name, "noframes")) {
                try inHeadStartTagNoframesStyle(c, start_tag, .html_noframes);
            } else {
                try afterFramesetAnythingElse(c);
            }
        },
        .end_tag => |end_tag| {
            if (strEql(end_tag.name, "html")) {
                changeTo(c, .AfterAfterFrameset);
            } else {
                try afterFramesetAnythingElse(c);
            }
        },
    }
}

fn afterFramesetAnythingElse(c: *TreeConstructor) !void {
    try parseError(c, .TreeConstructionError);
    // Ignore the token.
}

fn afterAfterBody(c: *TreeConstructor, token: Token) !void {
    switch (token) {
        .comment => |comment| try insertCommentToDocument(c, comment),
        .doctype => {
            try inBodyDoctype(c);
        },
        .character => |character| {
            if (isWhitespace(character)) {
                try inBodyWhitespaceCharacter(c, character);
            } else {
                try afterAfterBodyAnythingElse(c);
            }
        },
        .start_tag => |start_tag| {
            if (strEql(start_tag.name, "html")) {
                try inBodyStartTagHtml(c, start_tag);
            } else {
                try afterAfterBodyAnythingElse(c);
            }
        },
        .eof => stop(c),
        else => try afterAfterBodyAnythingElse(c),
    }
}

fn afterAfterBodyAnythingElse(c: *TreeConstructor) !void {
    try parseError(c, .TreeConstructionError);
    reprocessIn(c, .InBody);
}

fn afterAfterFrameset(c: *TreeConstructor, token: Token) !void {
    switch (token) {
        .character => |character| if (isWhitespace(character)) {
            try inBodyWhitespaceCharacter(c, character);
        } else {
            try afterAfterFramesetAnythingElse(c);
        },
        .comment => |comment| try insertCommentToDocument(c, comment),
        .doctype => try inBodyDoctype(c),
        .eof => stop(c),
        .start_tag => |start_tag| {
            if (strEql(start_tag.name, "html")) {
                try inBodyStartTagHtml(c, start_tag);
            } else if (strEql(start_tag.name, "noframes")) {
                try inHeadStartTagNoframesStyle(c, start_tag, .html_noframes);
            } else {
                try afterAfterFramesetAnythingElse(c);
            }
        },
        .end_tag => try afterAfterFramesetAnythingElse(c),
    }
}

fn afterAfterFramesetAnythingElse(c: *TreeConstructor) !void {
    try parseError(c, .TreeConstructionError);
    // Ignore the token.
}

fn processTokenForeignContent(c: *TreeConstructor, token: Token) !void {
    switch (token) {
        .character => |character| {
            if (isNull(character)) {
                try parseError(c, .TreeConstructionError);
                try insertCharacter(c, Token.Character{ .data = '\u{FFFD}' });
            } else {
                try insertCharacter(c, character);
                if (!isWhitespace(character)) {
                    c.frameset_ok = .not_ok;
                }
            }
        },
        .comment => |comment| try insertComment(c, comment),
        .doctype => {
            try parseError(c, .TreeConstructionError);
            // Ignore the token.
        },
        .eof => unreachable,
        .start_tag => |start_tag| {
            if (ElementType.fromStringHtml(start_tag.name)) |token_element_type| switch (token_element_type) {
                .html_b,
                .html_big,
                .html_blockquote,
                .html_body,
                .html_br,
                .html_center,
                .html_code,
                .html_dd,
                .html_div,
                .html_dl,
                .html_dt,
                .html_em,
                .html_embed,
                .html_h1,
                .html_h2,
                .html_h3,
                .html_h4,
                .html_h5,
                .html_h6,
                .html_head,
                .html_hr,
                .html_i,
                .html_img,
                .html_li,
                .html_listing,
                .html_menu,
                .html_meta,
                .html_nobr,
                .html_ol,
                .html_p,
                .html_pre,
                .html_ruby,
                .html_s,
                .html_small,
                .html_span,
                .html_strong,
                .html_strike,
                .html_sub,
                .html_sup,
                .html_table,
                .html_tt,
                .html_u,
                .html_ul,
                .html_var,
                => try foreignContentEndTagBrP(c, token),
                .html_font => {
                    if (start_tag.attributes.contains("color") or
                        start_tag.attributes.contains("face") or
                        start_tag.attributes.contains("size"))
                    {
                        try foreignContentEndTagBrP(c, token);
                    } else {
                        try foreignContentStartTagAnythingElse(c, start_tag, .html_font);
                    }
                },
                else => try foreignContentStartTagAnythingElse(c, start_tag, token_element_type),
            } else {
                try foreignContentStartTagAnythingElse(c, start_tag, .custom_html);
            }
        },
        .end_tag => |end_tag| {
            if (ElementType.fromStringHtml(end_tag.name)) |token_element_type| switch (token_element_type) {
                .html_br, .html_p => try foreignContentEndTagBrP(c, token),
                .html_script => {
                    if (currentNode(c).element_type == .svg_script) {
                        foreignContentEndTagScriptWithinSvgScript(c);
                    } else {
                        try foreignContentEndTagAnythingElse(c, end_tag);
                    }
                },
                else => try foreignContentEndTagAnythingElse(c, end_tag),
            } else {
                try foreignContentEndTagAnythingElse(c, end_tag);
            }
        },
    }
}

fn foreignContentEndTagBrP(c: *TreeConstructor, token: Token) !void {
    try parseError(c, .TreeConstructionError);
    var current_node = currentNode(c);
    while (current_node.namespace() != .html and !isMathMlTextIntegrationPoint(current_node) and !isHtmlIntegrationPoint(c.dom, current_node)) {
        _ = c.open_elements.pop();
        current_node = currentNode(c);
    }
    return processToken(c, token);
}

fn foreignContentStartTagAnythingElse(c: *TreeConstructor, start_tag: Token.StartTag, token_element_type: ElementType) !void {
    const foreign_content_change_svg_tag_name_map = ComptimeStringMap([]const u8, .{
        .{ "altglyph", "altGlyph" },
        .{ "altglyphdef", "altGlyphDef" },
        .{ "altglyphitem", "altGlyphItem" },
        .{ "animatecolor", "animateColor" },
        .{ "animatemotion", "animateMotion" },
        .{ "animatetransform", "animateTransform" },
        .{ "clippath", "clipPath" },
        .{ "feblend", "feBlend" },
        .{ "fecolormatrix", "feColorMatrix" },
        .{ "fecomponenttransfer", "feComponentTransfer" },
        .{ "fecomposite", "feComposite" },
        .{ "feconvolvematrix", "feConvolveMatrix" },
        .{ "fediffuselighting", "feDiffuseLighting" },
        .{ "fedisplacementmap", "feDisplacementMap" },
        .{ "fedistantlight", "feDistantLight" },
        .{ "fedropshadow", "feDropShadow" },
        .{ "feflood", "feFlood" },
        .{ "fefunca", "feFuncA" },
        .{ "fefuncb", "feFuncB" },
        .{ "fefuncg", "feFuncG" },
        .{ "fefuncr", "feFuncR" },
        .{ "fegaussianblur", "feGaussianBlur" },
        .{ "feimage", "feImage" },
        .{ "femerge", "feMerge" },
        .{ "femergenode", "feMergeNode" },
        .{ "femorphology", "feMorphology" },
        .{ "feoffset", "feOffset" },
        .{ "fepointlight", "fePointLight" },
        .{ "fespecularlighting", "feSpecularLighting" },
        .{ "fespotlight", "feSpotLight" },
        .{ "fetile", "feTile" },
        .{ "feturbulence", "feTurbulence" },
        .{ "foreignobject", "foreignObject" },
        .{ "glyphref", "glyphRef" },
        .{ "lineargradient", "linearGradient" },
        .{ "radialgradient", "radialGradient" },
        .{ "textpath", "textPath" },
    });

    const adjusted_current_node = adjustedCurrentNode(c);
    const namespace = adjusted_current_node.namespace();
    var element_type: ElementType = undefined;
    var new_token: Token.StartTag = undefined;
    var adjust_attributes: AdjustAttributes = undefined;
    switch (namespace) {
        .html => {
            new_token = start_tag;
            adjust_attributes = .dont_adjust;
            element_type = token_element_type;
        },
        .mathml => {
            new_token = start_tag;
            adjust_attributes = .adjust_mathml_attributes;
            element_type = ElementType.fromStringMathMl(start_tag.name) orelse .some_other_mathml;
        },
        .svg => {
            const new_tag_name = foreign_content_change_svg_tag_name_map.get(start_tag.name) orelse start_tag.name;
            new_token = Token.StartTag{
                .name = new_tag_name,
                .attributes = start_tag.attributes,
                .self_closing = start_tag.self_closing,
            };
            adjust_attributes = .adjust_svg_attributes;
            element_type = ElementType.fromStringSvg(new_tag_name) orelse .some_other_svg;
        },
    }

    const element = try insertForeignElementForTheToken(c, new_token, element_type, adjust_attributes);
    if (element_type == .mathml_annotation_xml) {
        if (start_tag.attributes.get("encoding")) |encoding| {
            if (rem.util.eqlIgnoreCase2(encoding, "text/html") or rem.util.eqlIgnoreCase2(encoding, "application/xhtml+xml")) {
                try c.dom.registerHtmlIntegrationPoint(element);
            }
        }
    }

    if (start_tag.self_closing) {
        acknowledgeSelfClosingFlag(c);
        if (currentNode(c).namespace() == .svg and strEql(start_tag.name, "script")) {
            foreignContentEndTagScriptWithinSvgScript(c);
        } else {
            _ = c.open_elements.pop();
        }
    }
}

fn foreignContentEndTagScriptWithinSvgScript(c: *TreeConstructor) void {
    _ = c.open_elements.pop();
    if (c.scripting) {
        @panic("TODO Foreign content end tag script, current node is SVG script, scripting is enabled");
    }
}

fn foreignContentEndTagAnythingElse(c: *TreeConstructor, end_tag: Token.EndTag) !void {
    var index = c.open_elements.items.len;
    var node = c.open_elements.items[index - 1];
    if (!rem.util.eqlIgnoreCase(end_tag.name, node.localName(c.dom))) {
        try parseError(c, .TreeConstructionError);
    }
    while (index > 1) {
        if (rem.util.eqlIgnoreCase(end_tag.name, node.localName(c.dom))) {
            c.open_elements.shrinkRetainingCapacity(index - 1);
            return;
        }
        index -= 1;
        node = c.open_elements.items[index - 1];
        if (node.namespace() == .html) {
            return processToken(c, Token{ .end_tag = end_tag });
        }
    }
    assert(c.fragment_context != null);
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

const RawtextOrRcdata = enum { RAWTEXT, RCDATA };

fn textParsingAlgorithm(variant: RawtextOrRcdata, c: *TreeConstructor, start_tag: Token.StartTag, comptime element_type: ElementType) !void {
    _ = try insertHtmlElementForTheToken(c, start_tag, element_type);
    switch (variant) {
        .RAWTEXT => setTokenizerState(c, .RAWTEXT, element_type),
        .RCDATA => setTokenizerState(c, .RCDATA, element_type),
    }
    changeToAndSetOriginalInsertionMode(c, .Text, c.insertion_mode);
}

fn isNull(character: Token.Character) bool {
    return character.data == 0x00;
}

fn isWhitespace(character: Token.Character) bool {
    // TODO: The tokenizer removed all 0x0D characters.
    return switch (character.data) {
        0x09, 0x0A, 0x0C, 0x0D, 0x20 => true,
        else => false,
    };
}

fn doctypeEnablesQuirks(doctype: Token.Doctype) bool {
    const lower = rem.util.toLowercaseComptime;
    const eql = rem.util.eqlIgnoreCase2;
    const startsWith = rem.util.startsWithIgnoreCase2;

    // TODO: Use std.ComptimeStringMap
    if (doctype.force_quirks) return true;
    if (doctype.name != null and !strEql(doctype.name.?, "html")) return true;
    if (doctype.system_identifier) |system_identifier| {
        if (eql("http://www.ibm.com/data/dtd/v11/ibmxhtml1-transitional.dtd", system_identifier)) {
            return true;
        }
    } else {
        if (doctype.public_identifier) |public_identifier| {
            for (&[_][]const u8{
                &lower("-//W3C//DTD HTML 4.01 Frameset//"),
                &lower("-//W3C//DTD HTML 4.01 Transitional//"),
            }) |s| {
                if (startsWith(public_identifier, s)) return true;
            }
        }
    }
    if (doctype.public_identifier) |public_identifier| {
        for (&[_][]const u8{
            &lower("-//W3O//DTD W3 HTML Strict 3.0//EN//"),
            &lower("-/W3C/DTD HTML 4.0 Transitional/EN"),
            &lower("HTML"),
        }) |s| {
            if (eql(s, public_identifier)) return true;
        }

        @setEvalBranchQuota(6000);
        for (&[_][]const u8{
            &lower("+//Silmaril//dtd html Pro v0r11 19970101//"),
            &lower("-//AS//DTD HTML 3.0 asWedit + extensions//"),
            &lower("-//AdvaSoft Ltd//DTD HTML 3.0 asWedit + extensions//"),
            &lower("-//IETF//DTD HTML 2.0 Level 1//"),
            &lower("-//IETF//DTD HTML 2.0 Level 2//"),
            &lower("-//IETF//DTD HTML 2.0 Strict Level 1//"),
            &lower("-//IETF//DTD HTML 2.0 Strict Level 2//"),
            &lower("-//IETF//DTD HTML 2.0 Strict//"),
            &lower("-//IETF//DTD HTML 2.0//"),
            &lower("-//IETF//DTD HTML 2.1E//"),
            &lower("-//IETF//DTD HTML 3.0//"),
            &lower("-//IETF//DTD HTML 3.2 Final//"),
            &lower("-//IETF//DTD HTML 3.2//"),
            &lower("-//IETF//DTD HTML 3//"),
            &lower("-//IETF//DTD HTML Level 0//"),
            &lower("-//IETF//DTD HTML Level 1//"),
            &lower("-//IETF//DTD HTML Level 2//"),
            &lower("-//IETF//DTD HTML Level 3//"),
            &lower("-//IETF//DTD HTML Strict Level 0//"),
            &lower("-//IETF//DTD HTML Strict Level 1//"),
            &lower("-//IETF//DTD HTML Strict Level 2//"),
            &lower("-//IETF//DTD HTML Strict Level 3//"),
            &lower("-//IETF//DTD HTML Strict//"),
            &lower("-//IETF//DTD HTML//"),
            &lower("-//Metrius//DTD Metrius Presentational//"),
            &lower("-//Microsoft//DTD Internet Explorer 2.0 HTML Strict//"),
            &lower("-//Microsoft//DTD Internet Explorer 2.0 HTML//"),
            &lower("-//Microsoft//DTD Internet Explorer 2.0 Tables//"),
            &lower("-//Microsoft//DTD Internet Explorer 3.0 HTML Strict//"),
            &lower("-//Microsoft//DTD Internet Explorer 3.0 HTML//"),
            &lower("-//Microsoft//DTD Internet Explorer 3.0 Tables//"),
            &lower("-//Netscape Comm. Corp.//DTD HTML//"),
            &lower("-//Netscape Comm. Corp.//DTD Strict HTML//"),
            &lower("-//O'Reilly and Associates//DTD HTML 2.0//"),
            &lower("-//O'Reilly and Associates//DTD HTML Extended 1.0//"),
            &lower("-//O'Reilly and Associates//DTD HTML Extended Relaxed 1.0//"),
            &lower("-//SQ//DTD HTML 2.0 HoTMetaL + extensions//"),
            &lower("-//SoftQuad Software//DTD HoTMetaL PRO 6.0::19990601::extensions to HTML 4.0//"),
            &lower("-//SoftQuad//DTD HoTMetaL PRO 4.0::19971010::extensions to HTML 4.0//"),
            &lower("-//Spyglass//DTD HTML 2.0 Extended//"),
            &lower("-//Sun Microsystems Corp.//DTD HotJava HTML//"),
            &lower("-//Sun Microsystems Corp.//DTD HotJava Strict HTML//"),
            &lower("-//W3C//DTD HTML 3 1995-03-24//"),
            &lower("-//W3C//DTD HTML 3.2 Draft//"),
            &lower("-//W3C//DTD HTML 3.2 Final//"),
            &lower("-//W3C//DTD HTML 3.2//"),
            &lower("-//W3C//DTD HTML 3.2S Draft//"),
            &lower("-//W3C//DTD HTML 4.0 Frameset//"),
            &lower("-//W3C//DTD HTML 4.0 Transitional//"),
            &lower("-//W3C//DTD HTML Experimental 19960712//"),
            &lower("-//W3C//DTD HTML Experimental 970421//"),
            &lower("-//W3C//DTD W3 HTML//"),
            &lower("-//W3O//DTD W3 HTML 3.0//"),
            &lower("-//WebTechs//DTD Mozilla HTML 2.0//"),
            &lower("-//WebTechs//DTD Mozilla HTML//"),
        }) |s| {
            if (startsWith(public_identifier, s)) return true;
        }
    }
    return false;
}

fn doctypeEnablesLimitedQuirks(doctype: Token.Doctype) bool {
    const lower = rem.util.toLowercaseComptime;
    const startsWith = rem.util.startsWithIgnoreCase2;

    // TODO: Use std.ComptimeStringMap
    const pi = doctype.public_identifier orelse return false;
    for (&[_][]const u8{
        &lower("-//W3C//DTD XHTML 1.0 Frameset//"),
        &lower("-//W3C//DTD XHTML 1.0 Transitional//"),
    }) |s| {
        if (startsWith(pi, s)) {
            return true;
        }
    }
    if (doctype.system_identifier != null) {
        for (&[_][]const u8{
            &lower("-//W3C//DTD HTML 4.01 Frameset//"),
            &lower("-//W3C//DTD HTML 4.01 Transitional//"),
        }) |s| {
            if (startsWith(pi, s)) {
                return true;
            }
        }
    }
    return false;
}

fn strEql(string: []const u8, other: []const u8) bool {
    return std.mem.eql(u8, string, other);
}

// TODO: Use std.ComptimeStringMap
fn strEqlAny(string: []const u8, compare_to: []const []const u8) bool {
    for (compare_to) |s| {
        if (std.mem.eql(u8, string, s)) return true;
    }
    return false;
}

fn freeStringHashMap(map: anytype, allocator: Allocator) void {
    var iterator = map.iterator();
    while (iterator.next()) |attr| {
        allocator.free(attr.key_ptr.*);
        allocator.free(attr.value_ptr.*);
    }
    map.deinit(allocator);
}

fn elemTypeEqlAny(element_type: ElementType, compare_to: []const ElementType) bool {
    for (compare_to) |t| {
        if (element_type == t) return true;
    }
    return false;
}

fn parseError(c: *TreeConstructor, err: ParseError) !void {
    const parser = @fieldParentPtr(Parser, "constructor", c);
    try parser.parseError(err);
}

const ParentNode = union(enum) {
    document: *Document,
    element: *Element,
};

fn currentNode(c: *TreeConstructor) *Element {
    return c.open_elements.items[c.open_elements.items.len - 1];
}

fn adjustedCurrentNode(c: *TreeConstructor) *Element {
    if (c.fragment_context != null and c.open_elements.items.len == 1) {
        return c.fragment_context.?;
    } else {
        return currentNode(c);
    }
}

fn currentTemplateInsertionMode(c: *TreeConstructor) InsertionMode {
    return c.template_insertion_modes.items[c.template_insertion_modes.items.len - 1];
}

/// Represents the appropriate place for inserting a node.
const NodeInsertionLocation = union(enum) {
    // NOTE: The appropriate place for inserting a node may not be inside an Element.
    // See https://html.spec.whatwg.org/multipage/parsing.html#appropriate-place-for-inserting-a-node

    /// The location is after the last child of the element.
    element_last_child: *Element,

    /// The location is the previous sibling of the child.
    parent_before_child: struct { parent: *Element, child: *Element },
};

fn appropriateNodeInsertionLocation(c: *TreeConstructor) NodeInsertionLocation {
    return appropriateNodeInsertionLocationWithTarget(c, currentNode(c));
}

fn appropriateNodeInsertionLocationWithTarget(c: *TreeConstructor, target: *Element) NodeInsertionLocation {
    var adjusted_insertion_location: NodeInsertionLocation = undefined;
    if (c.foster_parenting and elemTypeEqlAny(target.element_type, &.{ .html_table, .html_tbody, .html_tfoot, .html_thead, .html_tr })) substeps: {
        var last_template: ?*Element = null;
        var last_table: ?*Element = null;
        var index_of_last_table: usize = undefined;
        var index = c.open_elements.items.len;

        // Steps 2.1 and 2.2
        while (index > 0) : (index -= 1) {
            var node = c.open_elements.items[index - 1];
            if (node.element_type == .html_template) {
                last_template = node;
                if (last_table != null) break;
            } else if (node.element_type == .html_table) {
                if (last_template != null) {
                    // Step 2.3: last_template is lower in the stack than last_table.
                    @panic("TODO Appropriate place for inserting a node is inside a template");
                } else {
                    last_table = node;
                    index_of_last_table = index - 1;
                }
            }
        }

        // Step 2.3
        if (last_template != null and last_table == null) {
            @panic("TODO Appropriate place for inserting a node is inside a template");
        }

        // Step 2.4
        if (last_table == null) {
            assert(c.fragment_context != null);
            adjusted_insertion_location = .{ .element_last_child = stackOfOpenElementsTop(c) };
            break :substeps;
        }

        // Step 2.5
        if (last_table.?.parent) |table_parent| {
            switch (table_parent) {
                .element => |parent_element| {
                    // Step 3
                    if (parent_element.element_type == .html_template) {
                        @panic("TODO Appropriate place for inserting a node is inside a template");
                    }

                    adjusted_insertion_location = .{ .parent_before_child = .{ .parent = parent_element, .child = last_table.? } };
                },
                .document => @panic("TODO Appropriate place for inserting a node step 2.5: Parent is a document"),
            }
            break :substeps;
        }

        // Steps 2.6 and 2.7
        const previous_element = c.open_elements.items[index_of_last_table - 1];
        adjusted_insertion_location = .{ .element_last_child = previous_element };

        // Step 3
        if (previous_element.element_type == .html_template) {
            @panic("TODO Appropriate place for inserting a node is inside a template");
        }
    } else {
        adjusted_insertion_location = .{ .element_last_child = target };
        // Step 3
        if (target.element_type == .html_template) {
            @panic("TODO Appropriate place for inserting a node is inside a template");
        }
    }

    return adjusted_insertion_location;
}

fn insertCharacter(c: *TreeConstructor, character: Token.Character) !void {
    const location = appropriateNodeInsertionLocation(c);
    // TODO: If the adjusted insertion location is in a Document node, then return.

    var code_units: [4]u8 = undefined;
    const len = try std.unicode.utf8Encode(character.data, &code_units);
    switch (location) {
        .element_last_child => |element| {
            const last_child = element.lastChild();
            if (last_child != null and last_child.? == .cdata and last_child.?.cdata.interface == .text) {
                try last_child.?.cdata.append(c.dom.allocator, code_units[0..len]);
            } else {
                const cdata = try c.dom.makeCdata(code_units[0..len], .text);
                // TODO: Catch a possible DomException.
                try Dom.mutation.elementAppend(c.dom, element, .{ .cdata = cdata }, .Suppress);
            }
        },
        .parent_before_child => |s| {
            const child_before = s.parent.childBefore(.{ .element = s.child });
            if (child_before != null and child_before.? == .cdata and child_before.?.cdata.interface == .text) {
                try child_before.?.cdata.append(c.dom.allocator, code_units[0..len]);
            } else {
                const cdata = try c.dom.makeCdata(code_units[0..len], .text);
                // TODO: Catch a possible DomException.
                try Dom.mutation.elementInsert(c.dom, s.parent, .{ .element = s.child }, .{ .cdata = cdata }, .Suppress);
            }
        },
    }
}

fn insertComment(c: *TreeConstructor, comment: Token.Comment) !void {
    const location = appropriateNodeInsertionLocation(c);
    switch (location) {
        .element_last_child => |element| return insertCommentToElement(c, comment, element),
        .parent_before_child => |s| return insertCommentToElementBeforeChild(c, comment, s.parent, s.child),
    }
}

fn insertCommentToDocument(c: *TreeConstructor, comment: Token.Comment) !void {
    const cdata = try c.dom.makeCdata(comment.data, .comment);
    // TODO: Catch a possible DomException.
    return Dom.mutation.documentAppendCdata(c.dom, c.document, cdata, .Suppress);
}

fn insertCommentToElement(c: *TreeConstructor, comment: Token.Comment, element: *Element) !void {
    const cdata = try c.dom.makeCdata(comment.data, .comment);
    // TODO: Catch a possible DomException.
    return Dom.mutation.elementAppend(c.dom, element, .{ .cdata = cdata }, .Suppress);
}

fn insertCommentToElementBeforeChild(c: *TreeConstructor, comment: Token.Comment, parent: *Element, child: *Element) !void {
    const cdata = try c.dom.makeCdata(comment.data, .comment);
    // TODO: Catch a possible DomException.
    return Dom.mutation.elementInsert(c.dom, parent, .{ .element = child }, .{ .cdata = cdata }, .Suppress);
}

/// Implements https://html.spec.whatwg.org/multipage/parsing.html#create-an-element-for-the-token
fn createAnElementForTheToken(
    c: *TreeConstructor,
    /// Only the attributes of the start tag is used.
    /// The element type is determined by element_type.
    // TODO: Don't take an entire start tag, only its attributes.
    start_tag: Token.StartTag,
    element_type: ElementType,
    intended_parent: ParentNode,
    adjust_attributes: AdjustAttributes,
) !*Element {
    _ = intended_parent;
    // TODO: Most of the steps of this algorithm have been skipped.

    // Step 9
    const element = try c.dom.makeElement(element_type);
    if (element_type.toLocalName() == null) {
        try c.dom.registerLocalName(element, start_tag.name);
    }

    // Step 10
    // TODO: This should follow https://dom.spec.whatwg.org/#concept-element-attributes-append
    var attr_it = start_tag.attributes.iterator();
    switch (adjust_attributes) {
        .dont_adjust => try elementAppendAttributes(c.dom, element, &attr_it),
        .adjust_mathml_attributes => try appendAttributesAdjustMathMlForeign(c.dom, element, &attr_it),
        .adjust_svg_attributes => try appendAttributesAdjustSvgForeign(c.dom, element, &attr_it),
    }

    return element;
}

const AdjustAttributes = enum { dont_adjust, adjust_mathml_attributes, adjust_svg_attributes };

const adjust_foreign_attributes_map = ComptimeStringMap(ElementAttributesKey, .{
    .{ "xlink:actuate", .{ .prefix = .xlink, .local_name = "actuate", .namespace = .xlink } },
    .{ "xlink:arcrole", .{ .prefix = .xlink, .local_name = "arcrole", .namespace = .xlink } },
    .{ "xlink:href", .{ .prefix = .xlink, .local_name = "href", .namespace = .xlink } },
    .{ "xlink:role", .{ .prefix = .xlink, .local_name = "role", .namespace = .xlink } },
    .{ "xlink:show", .{ .prefix = .xlink, .local_name = "show", .namespace = .xlink } },
    .{ "xlink:title", .{ .prefix = .xlink, .local_name = "title", .namespace = .xlink } },
    .{ "xlink:type", .{ .prefix = .xlink, .local_name = "type", .namespace = .xlink } },
    .{ "xml:lang", .{ .prefix = .xml, .local_name = "lang", .namespace = .xml } },
    .{ "xml:space", .{ .prefix = .xml, .local_name = "space", .namespace = .xml } },
    .{ "xmlns", .{ .prefix = .none, .local_name = "xmlns", .namespace = .xmlns } },
    .{ "xmlns:xlink", .{ .prefix = .xmlns, .local_name = "xlink", .namespace = .xmlns } },
});

/// Appends the attributes from the token to the Element.
fn elementAppendAttributes(dom: *Dom, element: *Element, attributes: *Token.StartTag.Attributes.Iterator) !void {
    while (attributes.next()) |attr| {
        try element.appendAttribute(dom.allocator, .{ .prefix = .none, .namespace = .none, .local_name = attr.key_ptr.* }, attr.value_ptr.*);
    }
}

/// Appends the attributes from the token to the Element, while also doing the
/// "adjust MathML attributes" and "adjust foreign attributes" algorithms.
fn appendAttributesAdjustMathMlForeign(dom: *Dom, element: *Element, attributes: *Token.StartTag.Attributes.Iterator) !void {
    while (attributes.next()) |attr| {
        const name = attr.key_ptr.*;
        const value = attr.value_ptr.*;
        if (strEql(name, "definitionurl")) {
            try element.appendAttribute(dom.allocator, .{ .prefix = .none, .namespace = .none, .local_name = "definitionURL" }, value);
        } else if (adjust_foreign_attributes_map.get(name)) |key| {
            try element.appendAttribute(dom.allocator, key, value);
        } else {
            try element.appendAttribute(dom.allocator, .{ .prefix = .none, .namespace = .none, .local_name = name }, value);
        }
    }
}

/// Appends the attributes from the token to the Element, while also doing the
/// "adjust SVG attributes" and "adjust foreign attributes" algorithms.
fn appendAttributesAdjustSvgForeign(dom: *Dom, element: *Element, attributes: *Token.StartTag.Attributes.Iterator) !void {
    const adjust_svg_attributes_map = ComptimeStringMap([]const u8, .{
        .{ "attributename", "attributeName" },
        .{ "attributetype", "attributeType" },
        .{ "basefrequency", "baseFrequency" },
        .{ "baseprofile", "baseProfile" },
        .{ "calcmode", "calcMode" },
        .{ "clippathunits", "clipPathUnits" },
        .{ "diffuseconstant", "diffuseConstant" },
        .{ "edgemode", "edgeMode" },
        .{ "filterunits", "filterUnits" },
        .{ "glyphref", "glyphRef" },
        .{ "gradienttransform", "gradientTransform" },
        .{ "gradientunits", "gradientUnits" },
        .{ "kernelmatrix", "kernelMatrix" },
        .{ "kernelunitlength", "kernelUnitLength" },
        .{ "keypoints", "keyPoints" },
        .{ "keysplines", "keySplines" },
        .{ "keytimes", "keyTimes" },
        .{ "lengthadjust", "lengthAdjust" },
        .{ "limitingconeangle", "limitingConeAngle" },
        .{ "markerheight", "markerHeight" },
        .{ "markerunits", "markerUnits" },
        .{ "markerwidth", "markerWidth" },
        .{ "maskcontentunits", "maskContentUnits" },
        .{ "maskunits", "maskUnits" },
        .{ "numoctaves", "numOctaves" },
        .{ "pathlength", "pathLength" },
        .{ "patterncontentunits", "patternContentUnits" },
        .{ "patterntransform", "patternTransform" },
        .{ "patternunits", "patternUnits" },
        .{ "pointsatx", "pointsAtX" },
        .{ "pointsaty", "pointsAtY" },
        .{ "pointsatz", "pointsAtZ" },
        .{ "preservealpha", "preserveAlpha" },
        .{ "preserveaspectratio", "preserveAspectRatio" },
        .{ "primitiveunits", "primitiveUnits" },
        .{ "refx", "refX" },
        .{ "refy", "refY" },
        .{ "repeatcount", "repeatCount" },
        .{ "repeatdur", "repeatDur" },
        .{ "requiredextensions", "requiredExtensions" },
        .{ "requiredfeatures", "requiredFeatures" },
        .{ "specularconstant", "specularConstant" },
        .{ "specularexponent", "specularExponent" },
        .{ "spreadmethod", "spreadMethod" },
        .{ "startoffset", "startOffset" },
        .{ "stddeviation", "stdDeviation" },
        .{ "stitchtiles", "stitchTiles" },
        .{ "surfacescale", "surfaceScale" },
        .{ "systemlanguage", "systemLanguage" },
        .{ "tablevalues", "tableValues" },
        .{ "targetx", "targetX" },
        .{ "targety", "targetY" },
        .{ "textlength", "textLength" },
        .{ "viewbox", "viewBox" },
        .{ "viewtarget", "viewTarget" },
        .{ "xchannelselector", "xChannelSelector" },
        .{ "ychannelselector", "yChannelSelector" },
        .{ "zoomandpan", "zoomAndPan" },
    });

    while (attributes.next()) |attr| {
        const name = attr.key_ptr.*;
        const value = attr.value_ptr.*;
        if (adjust_svg_attributes_map.get(name)) |new_key| {
            try element.appendAttribute(dom.allocator, .{ .prefix = .none, .namespace = .none, .local_name = new_key }, value);
        } else if (adjust_foreign_attributes_map.get(name)) |key| {
            try element.appendAttribute(dom.allocator, key, value);
        } else {
            try element.appendAttribute(dom.allocator, .{ .prefix = .none, .namespace = .none, .local_name = name }, value);
        }
    }
}

/// Implements https://html.spec.whatwg.org/multipage/parsing.html#insert-a-foreign-element
// TODO: Add an option to not add the element to the list of open elements (skipping step 4 of this algorithm).
fn insertForeignElementForTheToken(
    c: *TreeConstructor,
    start_tag: Token.StartTag,
    element_type: ElementType,
    adjust_attributes: AdjustAttributes,
) !*Element {
    const adjusted_insertion_location = appropriateNodeInsertionLocation(c);
    const intended_parent: ParentNode = switch (adjusted_insertion_location) {
        .element_last_child => |e| .{ .element = e },
        .parent_before_child => |s| .{ .element = s.parent },
    };

    const element = try createAnElementForTheToken(c, start_tag, element_type, intended_parent, adjust_attributes);

    if (c.fragment_context != null) {
        // TODO: push a new element queue onto element's relevant agent's custom element reactions stack.
    }
    switch (adjusted_insertion_location) {
        // TODO: Check pre-insertion validity
        // TODO: If it is NOT possible to insert element at the adjusted insertion location, then ignore the error.
        .element_last_child => |e| try Dom.mutation.elementAppend(c.dom, e, .{ .element = element }, .Suppress),
        .parent_before_child => |s| try Dom.mutation.elementInsert(c.dom, s.parent, .{ .element = s.child }, .{ .element = element }, .Suppress),
    }
    if (c.fragment_context != null) {
        // TODO: pop the element queue from element's relevant agent's custom element reactions stack,
        // and invoke custom element reactions in that queue.
    }

    try c.open_elements.append(c.allocator, element);
    return element;
}

/// Implements https://html.spec.whatwg.org/multipage/parsing.html#insert-an-html-element
fn insertHtmlElementForTheToken(c: *TreeConstructor, start_tag: Token.StartTag, element_type: ElementType) !*Element {
    assert(element_type.namespace() == .html);
    return insertForeignElementForTheToken(c, start_tag, element_type, .dont_adjust);
}

fn stackOfOpenElementsTop(c: *TreeConstructor) *Element {
    const top = c.open_elements.items[0];
    assert(top.element_type == .html_html);
    return top;
}

// TODO: This function could probably be deleted in favor of flags that keep track of what has been pushed onto the stack.
fn stackOfOpenElementsHas(c: *TreeConstructor, element_type: ElementType) bool {
    var index = c.open_elements.items.len;
    while (index > 0) : (index -= 1) {
        if (c.open_elements.items[index - 1].element_type == element_type) return true;
    }
    return false;
}

// TODO: This function could probably be deleted in favor of flags that keep track of what has been pushed onto the stack.
fn stackOfOpenElementsHasElement(c: *TreeConstructor, element: *Element) bool {
    var index = c.open_elements.items.len;
    while (index > 0) : (index -= 1) {
        if (c.open_elements.items[index - 1] == element) return true;
    }
    return false;
}

// TODO: This function could probably be deleted in favor of flags that keep track of what has been pushed onto the stack.
fn findInStackOfOpenElements(c: *TreeConstructor, element: *Element) ?usize {
    var index = c.open_elements.items.len;
    while (index > 0) : (index -= 1) {
        if (c.open_elements.items[index - 1] == element) return index - 1;
    }
    return null;
}

// TODO: This function could probably be deleted in favor of flags that keep track of what has been pushed onto the stack.
fn removeFromStackOfOpenElements(c: *TreeConstructor, element: *Element) void {
    for (c.open_elements.items) |e, i| {
        if (e == element) {
            _ = c.open_elements.orderedRemove(i);
            return;
        }
    }
    unreachable;
}

fn popUntilElementTypeHasBeenPopped(c: *TreeConstructor, element_type: anytype) void {
    switch (@TypeOf(element_type)) {
        ElementType => while (c.open_elements.pop().element_type != element_type) {},
        []const ElementType => while (!elemTypeEqlAny(c.open_elements.pop().element_type, element_type)) {},
        else => |T| @compileError("Expected " ++ @typeName(ElementType) ++ " or " ++ @typeName([]const ElementType) ++ ", found '" ++ @typeName(T) ++ "'"),
    }
}

const FormattingElement = struct {
    /// If element is null, then this FormattingElement is considered to be a marker.
    element: ?*Element,
    /// If this FormattingElement is a marker, this is undefined.
    /// Otherwise, this is an index into formatting_element_tag_attributes.
    tag_attributes_ref: usize,

    fn eql(self: FormattingElement, c: *TreeConstructor, element: *Element) bool {
        const e = self.element orelse return false;
        if (e.element_type != element.element_type) return false;
        const tag_attributes = c.formatting_element_tag_attributes.items[self.tag_attributes_ref];
        if (tag_attributes.count() != element.attributes.len) return false;

        const element_attributes_slice = element.attributes.slice();
        for (element_attributes_slice.items(.key)) |key, index| {
            // TODO: Need to compare namespaces too
            const tag_entry = tag_attributes.get(key.local_name) orelse return false;
            const value = element_attributes_slice.items(.value)[index];
            if (!strEql(value, tag_entry)) return false;
        }
        return true;
    }
};

fn addFormattingElementTagAttributes(c: *TreeConstructor, element: *Element) !usize {
    const attributes_copy = try c.formatting_element_tag_attributes.addOne(c.allocator);
    errdefer _ = c.formatting_element_tag_attributes.pop();

    attributes_copy.* = Token.StartTag.Attributes{};
    errdefer freeStringHashMap(attributes_copy, c.allocator);
    try attributes_copy.ensureTotalCapacity(c.allocator, element.numAttributes());

    const slice = element.attributes.slice();
    var index: usize = 0;
    while (index < slice.len) : (index += 1) {
        const key = try c.allocator.dupe(u8, slice.items(.key)[index].local_name);
        errdefer c.allocator.free(key);
        const value = try c.allocator.dupe(u8, slice.items(.value)[index]);
        errdefer c.allocator.free(value);
        attributes_copy.putAssumeCapacity(key, value);
    }
    return c.formatting_element_tag_attributes.items.len - 1;
}

fn deleteFormattingElementTagAttributes(c: *TreeConstructor, ref: usize) void {
    for (c.active_formatting_elements.items) |*fe| {
        if (fe.tag_attributes_ref == ref) {
            // There should be no active formatting elements referring to this
            // if it is being deleted.
            unreachable;
        } else if (fe.tag_attributes_ref > ref) {
            fe.tag_attributes_ref -= 1;
        }
    }
    const tag_attributes = &c.formatting_element_tag_attributes.items[ref];
    freeStringHashMap(tag_attributes, c.allocator);
    _ = c.formatting_element_tag_attributes.orderedRemove(ref);
}

fn addToListOfActiveFormattingElementsWithoutMatch(c: *TreeConstructor, element: *Element) !void {
    const result = try c.active_formatting_elements.addOne(c.allocator);
    errdefer _ = c.active_formatting_elements.pop();
    const tag_attributes_ref = try addFormattingElementTagAttributes(c, element);
    result.* = .{ .element = element, .tag_attributes_ref = tag_attributes_ref };
}

fn addToListOfActiveFormattingElementsWithMatch(c: *TreeConstructor, element: *Element, tag_attributes_ref: usize) !void {
    try c.active_formatting_elements.append(c.allocator, .{
        .element = element,
        .tag_attributes_ref = tag_attributes_ref,
    });
}

// TODO: The way this function is used is dubious
fn removeFromListOfActiveFormattingElements(c: *TreeConstructor, index: usize) void {
    const formatting_element = c.active_formatting_elements.orderedRemove(index);
    const tag_attributes_ref = formatting_element.tag_attributes_ref;
    if (formatting_element.element == null) {
        // We just removed a marker. Update index_of_last_marker.
        var i = c.active_formatting_elements.items.len;
        while (i > 0) : (i -= 1) {
            if (c.active_formatting_elements.items[i - 1].element == null) c.index_of_last_marker = i - 1;
        } else c.index_of_last_marker = null;
    } else {
        // Check if there is another element with the same tag attributes as the element we just removed.
        // If there is none, then free the tag attributes.
        for (c.active_formatting_elements.items) |fe| {
            if (fe.tag_attributes_ref == tag_attributes_ref) return;
        }
        // NOTE: Alternatively, we could just never free the tag attributes.
        deleteFormattingElementTagAttributes(c, tag_attributes_ref);
    }
}

fn insertAMarker(c: *TreeConstructor) !void {
    try c.active_formatting_elements.append(c.allocator, FormattingElement{ .element = null, .tag_attributes_ref = undefined });
    c.index_of_last_marker = c.active_formatting_elements.items.len - 1;
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
            break;
        }
    }

    if (matching_element_count > 0) {
        const tag_attributes_ref = c.active_formatting_elements.items[first_matching_element_index].tag_attributes_ref;
        if (matching_element_count == 3) {
            removeFromListOfActiveFormattingElements(c, first_matching_element_index);
        }
        try addToListOfActiveFormattingElementsWithMatch(c, element, tag_attributes_ref);
    } else {
        try addToListOfActiveFormattingElementsWithoutMatch(c, element);
    }
}

fn reconstructActiveFormattingElements(c: *TreeConstructor) !void {
    // Step 1
    // If the list of active formatting elements is empty, both loops will not execute and nothing will happen.

    // Step 2
    // If the list of active formatting elements has one element on it, the first loop will execute for that element and,
    // if it satisfies the criteria of this step, the second loop will not execute and nothing will happen.

    // Steps 3-6
    var index = c.active_formatting_elements.items.len;
    while (index > 0) : (index -= 1) {
        const entry = c.active_formatting_elements.items[index - 1];
        if (entry.element == null or stackOfOpenElementsHasElement(c, entry.element.?)) {
            // Step 7
            // By breaking, we don't decrement index, which has the effect of moving to the next list item in the next while loop.
            break;
        }
    }

    // Steps 8-10
    while (index < c.active_formatting_elements.items.len) : (index += 1) {
        const entry = &c.active_formatting_elements.items[index];
        const new_element = try insertHtmlElementForTheToken(
            c,
            Token.StartTag{
                // We can get away with using a "fake" token because createAnElementForTheToken
                // doesn't use the token's name unless we're creating a custom element (which we aren't).
                .name = undefined,
                .attributes = c.formatting_element_tag_attributes.items[entry.tag_attributes_ref],
                .self_closing = undefined,
            },
            entry.element.?.element_type,
        );
        entry.element = new_element;
    }
}

fn clearListOfActiveFormattingElementsUpToLastMarker(c: *TreeConstructor) void {
    var i = c.active_formatting_elements.items.len;
    while (i > 0) : (i -= 1) {
        const was_marker = c.active_formatting_elements.items[i - 1].element == null;
        removeFromListOfActiveFormattingElements(c, i - 1);
        if (was_marker) break;
    }
}

fn adoptionAgencyAlgorithm(c: *TreeConstructor, element_type: ElementType) !void {
    assert(element_type.namespace() == .html);

    // Step 2
    blk: {
        const current_node = currentNode(c);
        if (current_node.element_type == element_type) {
            for (c.active_formatting_elements.items) |fe| {
                const fe_element = fe.element orelse continue;
                if (current_node == fe_element) break :blk;
            }
            _ = c.open_elements.pop();
            return;
        }
    }

    var outer_loop_counter: usize = 0;
    while (outer_loop_counter < 8) : (outer_loop_counter += 1) {
        // Step 4.3
        const formatting_element_index = blk: {
            const after_last_marker = if (c.index_of_last_marker) |lm| lm + 1 else 0;
            var i = c.active_formatting_elements.items.len;
            while (i > after_last_marker) : (i -= 1) {
                if (c.active_formatting_elements.items[i - 1].element.?.element_type == element_type) break :blk i - 1;
            } else {
                return inBodyEndTagAnythingElse(c, element_type);
            }
        };
        const formatting_element = c.active_formatting_elements.items[formatting_element_index];
        // Step 4.4
        const formatting_element_in_open_elements_index = blk: {
            var i = c.open_elements.items.len;
            while (i > 0) : (i -= 1) {
                if (formatting_element.element.? == c.open_elements.items[i - 1]) break :blk i - 1;
            } else {
                try parseError(c, .TreeConstructionError);
                removeFromListOfActiveFormattingElements(c, formatting_element_index);
                return;
            }
        };
        // Step 4.5
        if (!hasElementInScope(c, formatting_element.element.?)) {
            try parseError(c, .TreeConstructionError);
            return;
        }
        // Step 4.6
        if (currentNode(c) != formatting_element.element.?) {
            try parseError(c, .TreeConstructionError);
        }
        // Step 4.7
        var furthest_block_in_open_elements_index = blk: {
            var i = formatting_element_in_open_elements_index + 1;
            while (i < c.open_elements.items.len) : (i += 1) {
                const node = c.open_elements.items[i];
                if (isSpecialElement(node.element_type)) break :blk i;
            } else {
                // Step 4.8
                c.open_elements.shrinkRetainingCapacity(formatting_element_in_open_elements_index);
                removeFromListOfActiveFormattingElements(c, formatting_element_index);
                return;
            }
        };
        const furthest_block = c.open_elements.items[furthest_block_in_open_elements_index];

        // Step 4.9
        const common_ancestor = c.open_elements.items[formatting_element_in_open_elements_index - 1];

        // Step 4.10
        var bookmark_in_formatting_elements_index = formatting_element_index;

        // Step 4.11
        var node_in_open_elements_index = furthest_block_in_open_elements_index;
        var last_node_in_open_elements_index = furthest_block_in_open_elements_index;
        var next_node_in_open_elements_index = furthest_block_in_open_elements_index - 1;

        // Steps 4.12 and 4.13
        var inner_loop_counter: usize = 0;
        while (true) {
            inner_loop_counter += 1;
            node_in_open_elements_index = next_node_in_open_elements_index;
            const node_in_open_elements = &c.open_elements.items[node_in_open_elements_index];
            if (node_in_open_elements.* == formatting_element.element.?) break;

            var node_in_formatting_elements_index = blk: {
                var i = c.active_formatting_elements.items.len;
                while (i > 0) : (i -= 1) {
                    if (node_in_open_elements.* == c.active_formatting_elements.items[i - 1].element) break :blk i - 1;
                } else break :blk null;
            };

            // Step 4.13.4
            if (inner_loop_counter > 3 and node_in_formatting_elements_index != null) {
                removeFromListOfActiveFormattingElements(c, node_in_formatting_elements_index.?);
                if (node_in_formatting_elements_index.? < bookmark_in_formatting_elements_index) bookmark_in_formatting_elements_index -= 1;
                node_in_formatting_elements_index = null;
            }

            // Step 4.13.5
            if (node_in_formatting_elements_index == null) {
                _ = c.open_elements.orderedRemove(node_in_open_elements_index);
                last_node_in_open_elements_index -= 1;
                next_node_in_open_elements_index = node_in_open_elements_index - 1;
                continue;
            }

            // Step 4.13.6
            const node_in_formatting_elements = &c.active_formatting_elements.items[node_in_formatting_elements_index.?];
            const new_element = try createAnElementForTheToken(
                c,
                Token.StartTag{
                    .name = undefined,
                    .attributes = c.formatting_element_tag_attributes.items[node_in_formatting_elements.tag_attributes_ref],
                    .self_closing = undefined,
                },
                node_in_open_elements.*.element_type,
                .{ .element = common_ancestor },
                .dont_adjust,
            );
            node_in_formatting_elements.*.element = new_element;
            node_in_open_elements.* = new_element;

            // Step 4.13.7
            if (last_node_in_open_elements_index == furthest_block_in_open_elements_index) {
                bookmark_in_formatting_elements_index = node_in_formatting_elements_index.? + 1;
            }

            // Step 4.13.8
            try Dom.mutation.elementAppend(
                c.dom,
                node_in_open_elements.*,
                .{ .element = c.open_elements.items[last_node_in_open_elements_index] },
                .Suppress,
            );

            // Step 4.13.9
            last_node_in_open_elements_index = node_in_open_elements_index;
            next_node_in_open_elements_index = node_in_open_elements_index - 1;
        }

        // Step 4.14
        const location = appropriateNodeInsertionLocationWithTarget(c, common_ancestor);
        switch (location) {
            .element_last_child => |e| try Dom.mutation.elementAppend(
                c.dom,
                e,
                .{ .element = c.open_elements.items[last_node_in_open_elements_index] },
                .Suppress,
            ),
            .parent_before_child => |s| try Dom.mutation.elementInsert(
                c.dom,
                s.parent,
                .{ .element = s.child },
                .{ .element = c.open_elements.items[last_node_in_open_elements_index] },
                .Suppress,
            ),
        }

        // Step 4.15
        const new_element = try createAnElementForTheToken(
            c,
            Token.StartTag{
                .name = undefined,
                .attributes = c.formatting_element_tag_attributes.items[formatting_element.tag_attributes_ref],
                .self_closing = undefined,
            },
            formatting_element.element.?.element_type,
            .{ .element = furthest_block },
            .dont_adjust,
        );
        // Step 4.16
        // TODO: This needs to go through the DOM API
        std.mem.swap(ArrayListUnmanaged(ElementOrCharacterData), &furthest_block.children, &new_element.children);

        // Step 4.17
        try Dom.mutation.elementAppend(c.dom, furthest_block, .{ .element = new_element }, .Suppress);

        // Step 4.18
        // Instead of calling removeFromListOfActiveFormattingElements, which might delete the tag attributes
        // for formatting_element, remove it from the list directly.
        _ = c.active_formatting_elements.orderedRemove(formatting_element_index);
        if (formatting_element_index < bookmark_in_formatting_elements_index) bookmark_in_formatting_elements_index -= 1;
        if (bookmark_in_formatting_elements_index < c.active_formatting_elements.items.len) {
            try c.active_formatting_elements.insert(
                c.allocator,
                bookmark_in_formatting_elements_index,
                .{ .element = new_element, .tag_attributes_ref = formatting_element.tag_attributes_ref },
            );
        } else {
            assert(bookmark_in_formatting_elements_index == c.active_formatting_elements.items.len);
            try c.active_formatting_elements.append(
                c.allocator,
                .{ .element = new_element, .tag_attributes_ref = formatting_element.tag_attributes_ref },
            );
        }

        // Step 4.19
        _ = c.open_elements.orderedRemove(formatting_element_in_open_elements_index);
        furthest_block_in_open_elements_index = findInStackOfOpenElements(c, furthest_block).?;
        if (furthest_block_in_open_elements_index < c.open_elements.items.len - 1) {
            try c.open_elements.insert(c.allocator, furthest_block_in_open_elements_index + 1, new_element);
        } else {
            try c.open_elements.append(c.allocator, new_element);
        }
    }
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

fn isSpecialElementButNotAddressDivP(element_type: ElementType) bool {
    return switch (element_type) {
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
        else => |T| @compileError("target must be either '" ++ @typeName(*Element) ++ "', '" ++ @typeName(ElementType) ++
            "', or '" ++ @typeName([]const ElementType) ++ "', instead found '" ++ @typeName(T) ++ "'"),
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

fn hasElementInTableScope(c: *TreeConstructor, target: anytype) bool {
    const list = &[_]ElementType{
        .html_html,
        .html_table,
        .html_template,
    };
    return hasElementInSpecificScope(c, target, list);
}

fn hasElementInSelectScope(c: *TreeConstructor, target: ElementType) bool {
    // This one's a little bit different from the others.
    const exclude_list = &[_]ElementType{
        .html_optgroup,
        .html_option,
    };
    var index = c.open_elements.items.len;
    var node = c.open_elements.items[index - 1];
    while (node.element_type != target) {
        if (!elemTypeEqlAny(node.element_type, exclude_list)) return false;
        index -= 1;
        node = c.open_elements.items[index - 1];
    }
    return true;
}

fn generateImpliedEndTags(c: *TreeConstructor, exception: anytype) void {
    // TODO: Look closely at where this function is called
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

    var node = currentNode(c);
    while (std.mem.indexOfScalar(ElementType, list, node.element_type)) |_| {
        const Exception = @TypeOf(exception);
        const should_pop: bool = switch (@typeInfo(Exception)) {
            .Null => true,
            else => if (Exception == []const u8)
                !strEql(exception, node.localName(c.dom))
            else if (Exception == ElementType)
                node.element_type != exception
            else
                @compileError("Expected null, ElementType, or []const u8, instead found '" ++ @typeName(Exception) ++ "'."),
        };

        if (should_pop) {
            _ = c.open_elements.pop();
            node = currentNode(c);
        } else {
            break;
        }
    }
}

fn generateImpliedEndTagsThoroughly(c: *TreeConstructor) void {
    const list = &[_]ElementType{
        .html_caption,
        .html_colgroup,
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
    };
    var element_type = currentNode(c).element_type;
    while (!elemTypeEqlAny(element_type, list)) {
        _ = c.open_elements.pop();
        element_type = currentNode(c).element_type;
    }
}

fn closePElement(c: *TreeConstructor) !void {
    generateImpliedEndTags(c, ElementType.html_p);
    if (currentNode(c).element_type != .html_p) {
        try parseError(c, .TreeConstructionError);
    }
    while (c.open_elements.pop().element_type != .html_p) {}
}

fn isMathMlTextIntegrationPoint(element: *Element) bool {
    return switch (element.element_type) {
        .mathml_mi,
        .mathml_mo,
        .mathml_mn,
        .mathml_ms,
        .mathml_mtext,
        => true,
        else => false,
    };
}

fn isHtmlIntegrationPoint(dom: *Dom, element: *const Element) bool {
    return switch (element.element_type) {
        .svg_foreign_object,
        .svg_desc,
        .svg_title,
        => true,
        .mathml_annotation_xml => dom.html_integration_points.get(element) != null,
        else => false,
    };
}
