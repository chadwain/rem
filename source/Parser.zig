// Copyright (C) 2021-2024 Chadwain Holness
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//! The Parser wraps the Tokenizer and the TreeConstructor.
//! It handles the execution and the passing of messages between the two objects.

const rem = @import("../rem.zig");
const Dom = @import("Dom.zig");
const Document = Dom.Document;
const Element = Dom.Element;

const Token = @import("token.zig").Token;
const Tokenizer = @import("Tokenizer.zig");
const tree_construction = @import("tree_construction.zig");
const TreeConstructor = tree_construction.TreeConstructor;

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const ArrayListUnmanaged = std.ArrayListUnmanaged;

input_stream: InputStream,
tokenizer_initial_state: Tokenizer.State,
tokenizer_initial_last_start_tag: ?Tokenizer.LastStartTag,
constructor: TreeConstructor,
allocator: Allocator,
error_handler: ErrorHandler,

const Self = @This();

const InputStream = struct {
    text: []const u21,
    position: usize = 0,
    eof: bool = false,
};

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
    /// The error that caused the parser to stop can be seen by calling `errors`.
    abort,
    /// The parser will continue to run when it encounters an error.
    /// All errors that are encountered will be saved to a list, which can be accessed by calling `errors`.
    report,
};

pub const ErrorHandler = union(OnError) {
    ignore,
    abort: ?ParseError,
    report: ArrayListUnmanaged(ParseError),

    fn init(on_error: OnError) ErrorHandler {
        return switch (on_error) {
            .ignore => .ignore,
            .abort => .{ .abort = null },
            .report => .{ .report = .{} },
        };
    }

    fn deinit(error_handler: *ErrorHandler, allocator: Allocator) void {
        switch (error_handler.*) {
            .ignore, .abort => {},
            .report => |*list| list.deinit(allocator),
        }
    }

    fn sendError(error_handler: *ErrorHandler, allocator: Allocator, err: ParseError) !void {
        switch (error_handler.*) {
            .ignore => {},
            .abort => |*the_error| {
                the_error.* = err;
                return error.AbortParsing;
            },
            .report => |*list| try list.append(allocator, err),
        }
    }
};

/// Create a new HTML5 parser.
pub fn init(
    dom: *Dom,
    /// Must not be freed while being used by the parser.
    input: []const u21,
    allocator: Allocator,
    on_error: OnError,
    scripting: bool,
) !Self {
    const document = try dom.makeDocument();

    return Self{
        .input_stream = InputStream{ .text = input },
        .tokenizer_initial_state = .Data,
        .tokenizer_initial_last_start_tag = null,
        .constructor = TreeConstructor.init(dom, document, allocator, .{ .scripting = scripting }),
        .allocator = allocator,
        .error_handler = ErrorHandler.init(on_error),
    };
}

/// Create a new HTML5 fragment parser.
// Follows https://html.spec.whatwg.org/multipage/parsing.html#parsing-html-fragments
pub fn initFragment(
    dom: *Dom,
    context: *Element,
    /// Must not be freed while being used by the parser.
    input: []const u21,
    allocator: Allocator,
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

    var result = Self{
        .input_stream = InputStream{ .text = input },
        .tokenizer_initial_state = initial_state,
        .tokenizer_initial_last_start_tag = null,
        .constructor = TreeConstructor.init(dom, document, allocator, .{
            .fragment_context = context,
            .scripting = scripting,
        }),
        // Step 12
        .allocator = allocator,
        .error_handler = ErrorHandler.init(on_error),
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
    const should_be_html_integration_point = if (context.element_type == .mathml_annotation_xml) blk: {
        const eql = rem.util.eqlIgnoreCase2;
        const encoding = context.getAttribute(.{ .prefix = .none, .namespace = .none, .local_name = "encoding" }) orelse break :blk false;
        break :blk eql("text/html", encoding) or eql("application/xhtml+xml", encoding);
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
    self.constructor.deinit();
    self.error_handler.deinit(self.allocator);
}

/// Runs the tokenization and tree construction steps to completion.
pub fn run(self: *Self) !void {
    var tokenizer = Tokenizer.init(self, self.tokenizer_initial_state, self.tokenizer_initial_last_start_tag);
    defer tokenizer.deinit();
    while (!tokenizer.eof) {
        tokenizer.run() catch |err| switch (err) {
            error.AbortParsing => return self.abort(),
            error.OutOfMemory,
            error.Utf8CannotEncodeSurrogateHalf,
            error.CodepointTooLarge,
            => |e| return e,
        };

        const tokens = tokenizer.tokens.items;
        if (tokens.len > 0) {
            var constructor_result: TreeConstructor.RunResult = undefined;
            for (tokens, 0..) |*token, i| {
                constructor_result = self.constructor.run(token.*) catch |err| switch (err) {
                    error.AbortParsing => @panic("TODO abort parsing"),
                    error.OutOfMemory,
                    error.Utf8CannotEncodeSurrogateHalf,
                    error.CodepointTooLarge,
                    => @panic("TODO Handle errors in parsing"),
                    error.DomException => @panic("TODO Handle DOM Exceptions"),
                };
                assert(constructor_result.new_tokenizer_state == null or i == tokens.len - 1);
            }

            if (constructor_result.new_tokenizer_state) |state| {
                tokenizer.setState(state);
                tokenizer.setLastStartTag(constructor_result.new_tokenizer_last_start_tag);
            }
            tokenizer.setAdjustedCurrentNodeIsNotInHtmlNamespace(constructor_result.adjusted_current_node_is_not_in_html_namespace);
        }
    }
}

/// Create a new HTML5 parser for testing purposes.
pub fn initTokenizerOnly(
    /// Must not be freed while being used by the parser.
    input: []const u21,
    allocator: Allocator,
    on_error: OnError,
    tokenizer_initial_state: Tokenizer.State,
    tokenizer_initial_last_start_tag: ?Tokenizer.LastStartTag,
) !Self {
    return Self{
        .input_stream = InputStream{ .text = input },
        .tokenizer_initial_state = tokenizer_initial_state,
        .tokenizer_initial_last_start_tag = tokenizer_initial_last_start_tag,
        .constructor = undefined,
        .allocator = allocator,
        .error_handler = ErrorHandler.init(on_error),
    };
}

pub fn runTokenizerOnly(self: *Self, token_sink: *std.ArrayList(Token)) !void {
    var tokenizer = Tokenizer.init(self, self.tokenizer_initial_state, self.tokenizer_initial_last_start_tag);
    defer tokenizer.deinit();
    while (!tokenizer.eof) {
        tokenizer.run() catch |err| switch (err) {
            error.AbortParsing => return self.abort(),
            error.OutOfMemory,
            error.Utf8CannotEncodeSurrogateHalf,
            error.CodepointTooLarge,
            => |e| return e,
        };

        const old_len = token_sink.items.len;
        try token_sink.resize(old_len + tokenizer.tokens.items.len);
        tokenizer.moveTokens(token_sink.items[old_len..]);
    }
}

/// Frees the memory associated with the parser.
pub fn deinitTokenizerOnly(self: *Self) void {
    self.error_handler.deinit(self.allocator);
}

pub fn parseError(parser: *Self, err: ParseError) !void {
    try parser.error_handler.sendError(parser.allocator, err);
}

/// Implements HTML's "abort a parser" algorithm
/// https://html.spec.whatwg.org/multipage/parsing.html#abort-a-parser
fn abort(self: *Self) void {
    _ = self;
    // TODO: The rest of this algorithm.
    // self.input = &[0]u21{};
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
    return switch (self.error_handler) {
        .ignore => &[0]ParseError{},
        .abort => |err| if (err) |*e| @as([*]const ParseError, @ptrCast(e))[0..1] else &[0]ParseError{},
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
