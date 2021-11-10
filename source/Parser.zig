// Copyright (C) 2021 Chadwain Holness
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//! The Parser wraps the Tokenizer and the TreeConstructor.
//! It handles the execution and the passing of messages between the two objects.

const html5 = @import("../html5.zig");

const Dom = html5.dom;
const DomTree = Dom.DomTree;
const Document = Dom.Document;
const Element = Dom.Element;

const Token = html5.token.Token;
const Tokenizer = html5.Tokenizer;
const tree_construction = html5.tree_construction;
const TreeConstructor = tree_construction.TreeConstructor;

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;

tokenizer: Tokenizer,
constructor: TreeConstructor,
input: []const u21,
allocator: *Allocator,

const Self = @This();

pub const ParseError = enum {
    SurrogateInInputStream,
    NoncharacterInInputStream,
    ControlCharacterInInputStream,
    UnexpectedNullCharacter,
    UnexpectedQuestionMarkInsteadOfTagName,
    EOFBeforeTagName,
    InvalidFirstCharacterOfTagName,
    MissingEndTagName,
    EOFInTag,
    EOFInScriptHtmlCommentLikeText,
    UnexpectedEqualsSignBeforeAttributeName,
    UnexpectedCharacterInAttributeName,
    MissingAttributeValue,
    UnexpectedCharacterInUnquotedAttributeValue,
    MissingWhitespaceBetweenAttributes,
    UnexpectedSolidusInTag,
    EndTagWithAttributes,
    EndTagWithTrailingSolidus,
    CDATAInHtmlContent,
    IncorrectlyOpenedComment,
    AbruptClosingOfEmptyComment,
    EOFInComment,
    NestedComment,
    IncorrectlyClosedComment,
    EOFInDOCTYPE,
    MissingWhitespaceBeforeDOCTYPEName,
    MissingDOCTYPEName,
    InvalidCharacterSequenceAfterDOCTYPEName,
    MissingWhitespaceAfterDOCTYPEPublicKeyword,
    MissingDOCTYPEPublicIdentifier,
    MissingQuoteBeforeDOCTYPEPublicIdentifier,
    AbruptDOCTYPEPublicIdentifier,
    MissingWhitespaceBetweenDOCTYPEPublicAndSystemIdentifiers,
    MissingQuoteBeforeDOCTYPESystemIdentifier,
    MissingWhitespaceAfterDOCTYPESystemKeyword,
    MissingDOCTYPESystemIdentifier,
    AbruptDOCTYPESystemIdentifier,
    UnexpectedCharacterAfterDOCTYPESystemIdentifier,
    EOFInCDATA,
    MissingSemicolonAfterCharacterReference,
    UnknownNamedCharacterReference,
    AbsenceOfDigitsInNumericCharacterReference,
    NullCharacterReference,
    CharacterReferenceOutsideUnicodeRange,
    SurrogateCharacterReference,
    NoncharacterCharacterReference,
    ControlCharacterReference,
    DuplicateAttribute,

    NonVoidHtmlElementStartTagWithTrailingSolidus,
    TreeConstructionError,
};

/// Create a new HTML5 parser.
pub fn init(dom: *DomTree, input: []const u21, allocator: *Allocator, scripting: bool) !Self {
    const document = try dom.makeDocument();

    const token_sink = try allocator.create(ArrayList(Token));
    errdefer allocator.destroy(token_sink);
    token_sink.* = ArrayList(Token).init(allocator);

    const parse_error_sink = try allocator.create(ArrayList(ParseError));
    errdefer allocator.destroy(parse_error_sink);
    parse_error_sink.* = ArrayList(ParseError).init(allocator);

    return Self{
        .tokenizer = Tokenizer.init(allocator, token_sink, parse_error_sink),
        .constructor = TreeConstructor.init(dom, document, allocator, .{ .scripting = scripting }),
        .input = input,
        .allocator = allocator,
    };
}

/// Create a new HTML5 fragment parser.
// Follows https://html.spec.whatwg.org/multipage/parsing.html#parsing-html-fragments
pub fn initFragment(
    dom: *DomTree,
    context: *Element,
    input: []const u21,
    allocator: *Allocator,
    scripting: bool,
    // Must be the same "quirks mode" as the node document of the context.
    quirks_mode: Document.QuirksMode,
) !Self {
    // Step 1
    const document = try dom.makeDocument();

    // Step 2
    document.quirks_mode = quirks_mode;

    // Steps 3 and 4
    const initial_state: Tokenizer.State = switch (context.element_type) {
        .html_title, .html_textarea => .RCDATA,
        .html_style, .html_xmp, .html_iframe, .html_noembed, .html_noframes => .RAWTEXT,
        .html_script => .ScriptData,
        .html_noscript => if (scripting) Tokenizer.State.RAWTEXT else Tokenizer.State.Data,
        .html_plaintext => .PLAINTEXT,
        else => .Data,
    };

    const token_sink = try allocator.create(ArrayList(Token));
    errdefer allocator.destroy(token_sink);
    token_sink.* = ArrayList(Token).init(allocator);

    const parse_error_sink = try allocator.create(ArrayList(ParseError));
    errdefer allocator.destroy(parse_error_sink);
    parse_error_sink.* = ArrayList(ParseError).init(allocator);

    var result = Self{
        .tokenizer = Tokenizer.initState(allocator, initial_state, token_sink, parse_error_sink),
        .constructor = TreeConstructor.init(dom, document, allocator, .{
            .fragment_context = context,
            .scripting = scripting,
        }),
        // Step 12
        .input = input,
        .allocator = allocator,
    };

    // Steps 5-7
    const html = try dom.makeElement(.html_html);
    try Dom.mutation.documentAppendElement(dom, document, html, .Suppress);
    try result.constructor.open_elements.append(result.constructor.allocator, html);

    // Step 8
    if (context.element_type == .html_template) {
        try result.constructor.template_insertion_modes.append(result.constructor.allocator, .InTemplate);
    }

    // Step 9
    const should_be_html_integration_point = switch (context.element_type) {
        .svg_foreign_object, .svg_desc, .svg_title => true,
        .mathml_annotation_xml => blk: {
            const eql = std.ascii.eqlIgnoreCase;
            const encoding = context.attributes.get("encoding") orelse break :blk false;
            break :blk eql(encoding, "text/html") or eql(encoding, "application/xhtml+xml");
        },
        else => false,
    };
    if (should_be_html_integration_point) try dom.registerHtmlIntegrationPoint(context);

    // Step 10
    tree_construction.resetInsertionModeAppropriately(&result.constructor);

    // Step 11
    var form: ?*Element = context;
    while (form) |f| {
        if (f.element_type == .html_form) {
            result.constructor.form_element_pointer = f;
            break;
        } else switch (f.parent orelse break) {
            .document => break,
            .element => |e| form = e,
        }
    }

    // Step 12
    // TODO: Set the encoding confidence.

    return result;
}

/// Frees the memory associated with the parser.
pub fn deinit(self: *Self) void {
    for (self.tokenizer.tokens.items) |*t| t.deinit(self.allocator);
    self.tokenizer.tokens.deinit();
    self.tokenizer.parse_errors.deinit();
    self.allocator.destroy(self.tokenizer.tokens);
    self.allocator.destroy(self.tokenizer.parse_errors);
    self.tokenizer.deinit();
    self.constructor.deinit();
}

/// Runs the tokenization and tree construction steps to completion.
pub fn run(self: *Self) !void {
    const tokens: *ArrayList(Token) = self.tokenizer.tokens;
    while (try self.tokenizer.run(&self.input)) {
        if (tokens.items.len > 0) {
            var constructor_result: TreeConstructor.RunResult = undefined;
            for (tokens.items) |*token, i| {
                constructor_result = try self.constructor.run(token.*);
                token.deinit(self.tokenizer.allocator);
                assert(constructor_result.new_tokenizer_state == null or i == tokens.items.len - 1);
            }
            tokens.clearRetainingCapacity();

            if (constructor_result.new_tokenizer_state) |state| self.tokenizer.setState(state);
            self.tokenizer.setAdjustedCurrentNodeIsNotInHtmlNamespace(constructor_result.adjusted_current_node_is_not_in_html_namespace);
        }
    }
}

/// Returns the Document node associated with this parser.
pub fn getDocument(self: Self) *Document {
    return self.constructor.document;
}

/// Returns all of the parse errors that were encountered.
pub fn errors(self: Self) []const ParseError {
    return self.tokenizer.parse_errors.items;
}

test "Parser usage" {
    const string = "<!doctype html><html>asdf</body hello=world>";
    const input = &html5.util.utf8DecodeStringComptime(string);
    const allocator = std.testing.allocator;

    var dom = DomTree{ .allocator = allocator };
    defer dom.deinit();

    var parser = try init(&dom, input, allocator, false);
    defer parser.deinit();
    try parser.run();
}

test "Parser usage, fragment case" {
    const string = "<span class=pizza>tacos</span>";
    const input = &html5.util.utf8DecodeStringComptime(string);
    const allocator = std.testing.allocator;

    var dom = DomTree{ .allocator = allocator };
    defer dom.deinit();
    const context = try dom.makeElement(.html_div);

    var parser = try initFragment(&dom, context, input, allocator, false, .no_quirks);
    defer parser.deinit();
    try parser.run();
}
