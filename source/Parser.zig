// Copyright (C) 2021 Chadwain Holness
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//! The Parser wraps the Tokenizer and the TreeConstructor.
//! It handles the execution and the passing of messages between the two objects.

const rem = @import("../rem.zig");

const Dom = rem.dom.Dom;
const Document = rem.dom.Document;
const Element = rem.dom.Element;

const Token = rem.token.Token;
const Tokenizer = rem.Tokenizer;
const tree_construction = rem.tree_construction;
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

pub const OnError = enum {
    /// The parser will continue to run when it encounters an error.
    ignore,
    /// The parser will immediately stop when it encounters an error.
    /// The error that caused the parser to stop can be seen by calling errors().
    abort,
    /// The parser will continue to run when it encounters an error.
    /// All errors that are encountered will be saved to a list, which can be accessed by calling errors().
    report,
};

pub const ErrorHandler = union(OnError) {
    ignore,
    abort: ?ParseError,
    report: ArrayList(ParseError),

    pub fn sendError(self: *@This(), err: ParseError) !void {
        switch (self.*) {
            .ignore => {},
            .abort => |*the_error| {
                the_error.* = err;
                return error.AbortParsing;
            },
            .report => |*list| try list.append(err),
        }
    }

    pub fn deinit(self: *@This()) void {
        switch (self.*) {
            .ignore, .abort => {},
            .report => |list| list.deinit(),
        }
    }
};

/// Create a new HTML5 parser.
pub fn init(
    dom: *Dom,
    /// Must not be freed while being used by the parser.
    input: []const u21,
    allocator: *Allocator,
    on_error: OnError,
    scripting: bool,
) !Self {
    const document = try dom.makeDocument();

    const token_sink = try allocator.create(ArrayList(Token));
    errdefer allocator.destroy(token_sink);
    token_sink.* = ArrayList(Token).init(allocator);
    errdefer token_sink.deinit();

    const error_handler = try allocator.create(ErrorHandler);
    errdefer allocator.destroy(error_handler);
    error_handler.* = switch (on_error) {
        .ignore => .ignore,
        .abort => .{ .abort = null },
        .report => .{ .report = ArrayList(ParseError).init(allocator) },
    };
    errdefer error_handler.deinit();

    return Self{
        .tokenizer = Tokenizer.init(allocator, token_sink, error_handler),
        .constructor = TreeConstructor.init(dom, document, allocator, error_handler, .{ .scripting = scripting }),
        .input = input,
        .allocator = allocator,
    };
}

/// Create a new HTML5 fragment parser.
// Follows https://html.spec.whatwg.org/multipage/parsing.html#parsing-html-fragments
pub fn initFragment(
    dom: *Dom,
    context: *Element,
    /// Must not be freed while being used by the parser.
    input: []const u21,
    allocator: *Allocator,
    on_error: OnError,
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
    errdefer token_sink.deinit();

    const error_handler = try allocator.create(ErrorHandler);
    errdefer allocator.destroy(error_handler);
    error_handler.* = switch (on_error) {
        .ignore => .ignore,
        .abort => .{ .abort = null },
        .report => .{ .report = ArrayList(ParseError).init(allocator) },
    };
    errdefer error_handler.deinit();

    var result = Self{
        .tokenizer = Tokenizer.initState(allocator, initial_state, token_sink, error_handler),
        .constructor = TreeConstructor.init(dom, document, allocator, error_handler, .{
            .fragment_context = context,
            .scripting = scripting,
        }),
        // Step 12
        .input = input,
        .allocator = allocator,
    };

    // Steps 5-7
    const html = try dom.makeElement(.html_html);
    try rem.dom.mutation.documentAppendElement(dom, document, html, .Suppress);
    try result.constructor.open_elements.append(result.constructor.allocator, html);

    // Step 8
    if (context.element_type == .html_template) {
        try result.constructor.template_insertion_modes.append(result.constructor.allocator, .InTemplate);
    }

    // Step 9
    const should_be_html_integration_point = if (context.element_type == .mathml_annotation_xml) blk: {
        const eql = rem.util.eqlIgnoreCase2;
        const encoding = context.attributes.get("encoding") orelse break :blk false;
        break :blk eql(encoding, "text/html") or eql(encoding, "application/xhtml+xml");
    } else false;
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

    // TODO: Set the tree constructor's 'parser_cannot_change_the_mode' and 'is_iframe_srcdoc_document' flags.

    return result;
}

/// Frees the memory associated with the parser.
pub fn deinit(self: *Self) void {
    for (self.tokenizer.tokens.items) |*t| t.deinit(self.allocator);
    self.tokenizer.tokens.deinit();
    self.tokenizer.error_handler.deinit();
    self.allocator.destroy(self.tokenizer.tokens);
    self.allocator.destroy(self.tokenizer.error_handler);
    self.tokenizer.deinit();
    self.constructor.deinit();
}

/// Runs the tokenization and tree construction steps to completion.
pub fn run(self: *Self) !void {
    const tokens: *ArrayList(Token) = self.tokenizer.tokens;
    while (self.tokenizer.run(&self.input) catch |err| switch (err) {
        error.AbortParsing => blk: {
            self.abort();
            break :blk false;
        },
        error.OutOfMemory,
        error.Utf8CannotEncodeSurrogateHalf,
        error.CodepointTooLarge,
        => |e| return e,
    }) {
        if (tokens.items.len > 0) {
            var constructor_result: TreeConstructor.RunResult = undefined;
            for (tokens.items) |*token, i| {
                constructor_result = self.constructor.run(token.*) catch |err| switch (err) {
                    error.AbortParsing => {
                        self.abort();
                        break;
                    },
                    error.OutOfMemory,
                    error.Utf8CannotEncodeSurrogateHalf,
                    error.CodepointTooLarge,
                    => |e| return e,
                    error.DomException => @panic("TODO Handle DOM Exceptions"),
                };
                token.deinit(self.tokenizer.allocator);
                assert(constructor_result.new_tokenizer_state == null or i == tokens.items.len - 1);
            }
            tokens.clearRetainingCapacity();

            if (constructor_result.new_tokenizer_state) |state| self.tokenizer.setState(state);
            self.tokenizer.setAdjustedCurrentNodeIsNotInHtmlNamespace(constructor_result.adjusted_current_node_is_not_in_html_namespace);
        }
    }
}

/// Implements HTML's "abort a parser" algorithm
/// https://html.spec.whatwg.org/multipage/parsing.html#abort-a-parser
fn abort(self: *Self) void {
    // TODO: The rest of this algorithm.
    self.input = &[0]u21{};
}

/// Returns the Document node associated with this parser.
pub fn getDocument(self: Self) *Document {
    return self.constructor.document;
}

/// Returns all of the parse errors that were encountered.
/// If the error handling strategy is `ignore`, the slice will be empty.
/// If the error handling strategy is `abort`, the slice will have at most 1 element.
/// If the error handling strategy is `report`, the slice can have any number of elements.
pub fn errors(self: Self) []const ParseError {
    return switch (self.tokenizer.error_handler) {
        .ignore => &[0]ParseError{},
        .abort => |err| if (err) |*e| e else &[0]ParseError{},
        .report => |list| list.items,
    };
}

test "Parser usage" {
    const string = "<!doctype html><html>asdf</body hello=world>";
    const input = &rem.util.utf8DecodeStringComptime(string);
    const allocator = std.testing.allocator;

    var dom = Dom{ .allocator = allocator };
    defer dom.deinit();

    var parser = try init(&dom, input, allocator, .ignore, false);
    defer parser.deinit();
    try parser.run();
}

test "Parser usage, fragment case" {
    const string = "<span class=pizza>tacos</span>";
    const input = &rem.util.utf8DecodeStringComptime(string);
    const allocator = std.testing.allocator;

    var dom = Dom{ .allocator = allocator };
    defer dom.deinit();
    const context = try dom.makeElement(.html_div);

    var parser = try initFragment(&dom, context, input, allocator, .ignore, false, .no_quirks);
    defer parser.deinit();
    try parser.run();
}
