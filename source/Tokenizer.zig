// Copyright (C) 2021-2022 Chadwain Holness
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

test "Tokenizer usage" {
    const allocator = std.testing.allocator;

    const string = "<!doctype><HTML>asdf</body hello=world>";
    var input: []const u21 = &rem.util.utf8DecodeStringComptime(string);

    var all_tokens = std.ArrayList(Token).init(allocator);
    defer {
        for (all_tokens.items) |*t| t.deinit(allocator);
        all_tokens.deinit();
    }

    var error_handler = ErrorHandler{ .report = ArrayList(ParseError).init(allocator) };
    defer error_handler.report.deinit();

    var tokenizer = init(allocator, &all_tokens, &error_handler);
    defer tokenizer.deinit();

    while (try tokenizer.run(&input)) {}

    const expected_tokens = &[8]Token{
        .{ .doctype = .{ .name = null, .public_identifier = null, .system_identifier = null, .force_quirks = true } },
        .{ .start_tag = .{ .name = "html", .attributes = .{}, .self_closing = false } },
        .{ .character = .{ .data = 'a' } },
        .{ .character = .{ .data = 's' } },
        .{ .character = .{ .data = 'd' } },
        .{ .character = .{ .data = 'f' } },
        .{ .end_tag = .{ .name = "body" } },
        .eof,
    };

    const expected_parse_errors = &[2]ParseError{
        .MissingDOCTYPEName,
        .EndTagWithAttributes,
    };

    try std.testing.expectEqual(@as(usize, 8), all_tokens.items.len);
    for (all_tokens.items) |token, i| {
        try std.testing.expect(token.eql(expected_tokens[i]));
    }
    try std.testing.expectEqualSlices(ParseError, expected_parse_errors, error_handler.report.items);
}

const Self = @This();
const rem = @import("../rem.zig");
const named_characters_data = @import("./character_reference_data.zig");
const Token = rem.token.Token;
const Attributes = rem.token.TokenStartTag.Attributes;
const ParseError = rem.Parser.ParseError;
const ErrorHandler = rem.Parser.ErrorHandler;

const std = @import("std");
const assert = std.debug.assert;
const ArrayList = std.ArrayList;
const ArrayListUnmanaged = std.ArrayListUnmanaged;
const StringHashMapUnmanaged = std.StringHashMapUnmanaged;
const Allocator = std.mem.Allocator;

const debug = @import("builtin").mode == .Debug;

const REPLACEMENT_CHARACTER = '\u{FFFD}';
const TREAT_AS_ANYTHING_ELSE = '\u{FFFF}';

state: State = .Data,
return_state: State = undefined,
character_reference_code: u21 = 0,
current_tag_name: ArrayListUnmanaged(u8) = .{},
current_tag_attributes: Attributes = .{},
current_tag_self_closing: bool = false,
current_tag_type: enum { Start, End } = undefined,
last_start_tag_name: []u8 = &[_]u8{},
generic_buffer: ArrayListUnmanaged(u8) = .{},
current_attribute_value_result_location: ?*[]const u8 = null,
current_doctype_name: ArrayListUnmanaged(u8) = .{},
current_doctype_public_identifier: ArrayListUnmanaged(u8) = .{},
current_doctype_system_identifier: ArrayListUnmanaged(u8) = .{},
current_doctype_force_quirks: bool = false,
current_doctype_name_is_missing: bool = true,
current_doctype_public_identifier_is_missing: bool = true,
current_doctype_system_identifier_is_missing: bool = true,
current_comment_data: ArrayListUnmanaged(u8) = .{},
temp_buffer: ArrayListUnmanaged(u21) = .{},
adjusted_current_node_is_not_in_html_namespace: bool = false,

reconsumed_input_char: ?u21 = undefined,
should_reconsume: bool = false,
previous_char_was_carriage_return: bool = false,
reached_eof: bool = false,
/// Stores codepoints that were read from the input stream but were not consumed.
/// This buffer has a maximum length of 32, which is the length of the longest named character reference,
/// ignoring the leading ampersand (namely '&CounterClockwiseContourIntegral;').
replayed_characters: [32]u21 = undefined,
replayed_characters_len: u6 = 0,
allocator: Allocator,

tokens: *ArrayList(Token),
error_handler: *ErrorHandler,

/// Create a new HTML5 tokenizer.
pub fn init(
    allocator: Allocator,
    token_sink: *ArrayList(Token),
    error_handler: *ErrorHandler,
) Self {
    return initState(allocator, .Data, token_sink, error_handler);
}

/// Create a new HTML5 tokenizer, and change to a particular state.
pub fn initState(
    allocator: Allocator,
    state: State,
    token_sink: *ArrayList(Token),
    error_handler: *ErrorHandler,
) Self {
    return Self{
        .allocator = allocator,
        .state = state,
        .tokens = token_sink,
        .error_handler = error_handler,
    };
}

/// Free the memory owned by the tokenizer.
pub fn deinit(self: *Self) void {
    self.current_tag_name.deinit(self.allocator);
    var attr_it = self.current_tag_attributes.iterator();
    while (attr_it.next()) |entry| {
        self.allocator.free(entry.key_ptr.*);
        self.allocator.free(entry.value_ptr.*);
    }
    self.current_tag_attributes.deinit(self.allocator);
    self.allocator.free(self.last_start_tag_name);
    self.generic_buffer.deinit(self.allocator);
    self.current_doctype_name.deinit(self.allocator);
    self.current_doctype_public_identifier.deinit(self.allocator);
    self.current_doctype_system_identifier.deinit(self.allocator);
    self.current_comment_data.deinit(self.allocator);
    self.temp_buffer.deinit(self.allocator);
}

/// Runs the tokenizer on the given input.
/// The tokenizer will consume 1 or more characters from input.
/// It will shrink input by the amount of characters consumed.
/// It will output 0 or more tokens to the token sink and 0 or more parse errors to the parse error sink.
/// The memory taken up by these tokens and parse errors are owned by the user.
///
/// Between every call to this function, the user must:
///     1. Change the tokenizer's state via setState, if appropriate.
///     2. Call setAdjustedCurrentNodeIsNotInHtmlNamespace with an appropriate value.
///     3. Change the input stream, if appropriate.
pub fn run(self: *Self, input: *[]const u21) !bool {
    if (self.reached_eof) return false;
    try processInput(self, input);
    return true;
}

pub fn setState(self: *Self, new_state: State) void {
    self.state = new_state;
}

pub fn setAdjustedCurrentNodeIsNotInHtmlNamespace(self: *Self, value: bool) void {
    self.adjusted_current_node_is_not_in_html_namespace = value;
}

pub const Error = error{
    OutOfMemory,
    AbortParsing,
    Utf8CannotEncodeSurrogateHalf,
    CodepointTooLarge,
};

pub const State = enum {
    Data,
    RCDATA,
    RAWTEXT,
    ScriptData,
    PLAINTEXT,
    TagOpen,
    EndTagOpen,
    TagName,
    RAWTEXTLessThanSign,
    RAWTEXTEndTagOpen,
    RAWTEXTEndTagName,
    ScriptDataEscapeStart,
    ScriptDataEscapeStartDash,
    ScriptDataEscaped,
    ScriptDataEscapedDash,
    ScriptDataEscapedDashDash,
    ScriptDataEscapedLessThanSign,
    ScriptDataEscapedEndTagOpen,
    ScriptDataEscapedEndTagName,
    ScriptDataDoubleEscapeStart,
    ScriptDataDoubleEscaped,
    ScriptDataDoubleEscapedDash,
    ScriptDataDoubleEscapedDashDash,
    ScriptDataDoubleEscapedLessThanSign,
    ScriptDataDoubleEscapeEnd,
    BeforeAttributeName,
    AttributeName,
    BeforeAttributeValue,
    AttributeValueDoubleQuoted,
    AttributeValueSingleQuoted,
    AttributeValueUnquoted,
    SelfClosingStartTag,
    BogusComment,
    MarkupDeclarationOpen,
    CommentStart,
    CommentStartDash,
    Comment,
    CommentLessThanSign,
    CommentLessThanSignBang,
    CommentLessThanSignBangDash,
    CommentLessThanSignBangDashDash,
    CommentEndDash,
    CommentEnd,
    CommentEndBang,
    DOCTYPE,
    BeforeDOCTYPEName,
    DOCTYPEName,
    AfterDOCTYPEName,
    AfterDOCTYPEPublicKeyword,
    AfterDOCTYPESystemKeyword,
    BogusDOCTYPE,
    CDATASection,
    CDATASectionBracket,
    CDATASectionEnd,
    CharacterReference,
    NamedCharacterReference,
    AmbiguousAmpersand,
    NumericCharacterReference,
    HexadecimalCharacterReferenceStart,
    DecimalCharacterReferenceStart,
    HexadecimalCharacterReference,
    DecimalCharacterReference,
    NumericCharacterReferenceEnd,
};

fn consumeReplayedCharacters(self: *Self, count: u6) void {
    for (self.replayed_characters[count..self.replayed_characters_len]) |c, i| {
        self.replayed_characters[i] = c;
    }
    self.replayed_characters_len -= count;
}

fn replayCharacters(self: *Self, codepoints: []const u21) void {
    if (debug) {
        if (codepoints.len <= self.replayed_characters_len) {
            for (codepoints) |c, i| {
                assert(self.replayed_characters[i] == c);
            }
        } else {
            for (self.replayed_characters[0..self.replayed_characters_len]) |c, i| {
                assert(codepoints[i] == c);
            }
        }
    }

    if (codepoints.len > self.replayed_characters_len) {
        for (codepoints[self.replayed_characters_len..]) |c, i| {
            self.replayed_characters[self.replayed_characters_len + i] = c;
        }
        self.replayed_characters_len = @intCast(u6, codepoints.len);
    }
}

/// Returns what would be the next input character in the input stream,
/// taking into account that it could be a replayed character.
/// A value of `null` represents the "EOF" character.
fn nextInputStreamChar(self: *Self, input: *[]const u21, replayed_characters_index: *u6) ?u21 {
    if (replayed_characters_index.* < self.replayed_characters_len) {
        const character = self.replayed_characters[replayed_characters_index.*];
        replayed_characters_index.* += 1;
        return character;
    } else {
        if (input.*.len == 0) return null;
        const character = input.*[0];
        input.* = input.*[1..];
        return character;
    }
}

/// Returns either the next input character in the input stream, or
/// the previous input character to be reconsumed.
/// Normalizes newlines according to §13.2.3.5 "Preprocessing the input stream" of the HTML standard.
fn nextInputChar(self: *Self, input: *[]const u21) !?u21 {
    if (self.should_reconsume) {
        self.should_reconsume = false;
        return self.reconsumed_input_char;
    } else {
        var replayed_characters_index: u6 = 0;
        defer self.consumeReplayedCharacters(replayed_characters_index);

        var next_char = self.nextInputStreamChar(input, &replayed_characters_index);

        if (next_char) |character| {
            if (character == '\n' and self.previous_char_was_carriage_return) {
                next_char = self.nextInputStreamChar(input, &replayed_characters_index);
            }
        }

        if (next_char) |*character| {
            if (character.* == '\r') {
                character.* = '\n';
                self.previous_char_was_carriage_return = true;
            } else {
                self.previous_char_was_carriage_return = false;
            }

            try self.checkInputCharacterForErrors(character.*);
        }

        self.reconsumed_input_char = next_char;
        return next_char;
    }
}

/// Returns either the next input character in the input stream, or
/// the previous input character to be reconsumed.
/// Does not modify the state of the tokenizer.
/// Normalizes newlines according to §13.2.3.5 "Preprocessing the input stream" of the HTML standard.
fn peekInputChar(self: *Self, input: *[]const u21) ?u21 {
    if (self.should_reconsume) {
        return self.reconsumed_input_char;
    } else {
        var replayed_characters_index: u6 = 0;
        var replayed: []const u21 = &[_]u21{};
        defer self.replayCharacters(replayed);

        var next_char = self.nextInputStreamChar(input, &replayed_characters_index) orelse return null;
        replayed = &[1]u21{next_char};

        if (next_char == '\n' and self.previous_char_was_carriage_return) {
            next_char = self.nextInputStreamChar(input, &replayed_characters_index) orelse return null;
            replayed = &[2]u21{ '\n', next_char };
        }

        if (next_char == '\r') {
            next_char = '\n';
        }

        return next_char;
    }
}

/// Scans the next characters in the input stream to see if they are equal to `string`.
/// If so, consumes those characters and returns `true`. Otherwise, adds any read characters
/// to the list of replayed characters and returns `false`.
fn consumeCharsIfEql(self: *Self, input: *[]const u21, comptime string: []const u8) bool {
    comptime assert(string.len <= 7);
    comptime assert(std.mem.indexOfScalar(u8, string, '\r') == null);
    const decoded_string = rem.util.utf8DecodeStringComptime(string);
    return consumeCharsIfEqlGeneric(self, input, &decoded_string, caseSensitiveEql);
}

/// Scans the next characters in the input stream to see if they are equal to `string` in
/// a case-insensitive manner.
/// If so, consumes those characters and returns `true`. Otherwise, adds any read characters
/// to the list of replayed characters and returns `false`.
fn consumeCharsIfCaseInsensitiveEql(self: *Self, input: *[]const u21, comptime string: []const u8) bool {
    comptime assert(string.len <= 7);
    comptime assert(std.mem.indexOfScalar(u8, string, '\r') == null);
    const decoded_string = rem.util.utf8DecodeStringComptime(string);
    return consumeCharsIfEqlGeneric(self, input, &decoded_string, caseInsensitiveEql);
}

fn consumeCharsIfEqlGeneric(self: *Self, input: *[]const u21, decoded_string: []const u21, comptime eqlFn: fn (u21, u21) bool) bool {
    var read_characters: [7]u21 = undefined;
    var read_characters_len: u6 = 0;

    var replayed_characters_index: u6 = 0;
    for (decoded_string) |character| {
        const next_char = self.nextInputStreamChar(input, &replayed_characters_index) orelse break;
        read_characters[read_characters_len] = next_char;
        read_characters_len += 1;
        if (!eqlFn(next_char, character)) break;
    } else {
        self.consumeReplayedCharacters(replayed_characters_index);
        return true;
    }

    self.replayCharacters(read_characters[0..read_characters_len]);
    return false;
}

/// Check if a character that was just taken from the input stream
/// is a valid character.
/// Implements §13.2.3.5 "Preprocessing the input stream" of the HTML standard.
fn checkInputCharacterForErrors(self: *Self, character: u21) !void {
    switch (character) {
        0xD800...0xDFFF => try self.parseError(.SurrogateInInputStream),
        0xFDD0...0xFDEF,
        0xFFFE,
        0xFFFF,
        0x1FFFE,
        0x1FFFF,
        0x2FFFE,
        0x2FFFF,
        0x3FFFE,
        0x3FFFF,
        0x4FFFE,
        0x4FFFF,
        0x5FFFE,
        0x5FFFF,
        0x6FFFE,
        0x6FFFF,
        0x7FFFE,
        0x7FFFF,
        0x8FFFE,
        0x8FFFF,
        0x9FFFE,
        0x9FFFF,
        0xAFFFE,
        0xAFFFF,
        0xBFFFE,
        0xBFFFF,
        0xCFFFE,
        0xCFFFF,
        0xDFFFE,
        0xDFFFF,
        0xEFFFE,
        0xEFFFF,
        0xFFFFE,
        0xFFFFF,
        0x10FFFE,
        0x10FFFF,
        => try self.parseError(.NoncharacterInInputStream),
        0x01...0x08,
        0x0B,
        0x0E...0x1F,
        0x7F...0x9F,
        => try self.parseError(.ControlCharacterInInputStream),
        0x0D => unreachable, // This character would have been turned into 0x0A.
        else => {},
    }
}

fn reconsume(self: *Self, new_state: State) void {
    self.should_reconsume = true;
    self.state = new_state;
}

fn switchToReturnState(self: *Self) void {
    self.state = self.return_state;
    self.return_state = undefined;
}

fn reconsumeInReturnState(self: *Self) void {
    self.reconsume(self.return_state);
}

fn toCharacterReferenceState(self: *Self, return_state: State) void {
    self.state = .CharacterReference;
    self.return_state = return_state;
}

fn createDOCTYPEToken(self: *Self) void {
    assert(self.current_doctype_name.items.len == 0);
    assert(self.current_doctype_public_identifier.items.len == 0);
    assert(self.current_doctype_system_identifier.items.len == 0);
}

fn createStartTagToken(self: *Self) void {
    assert(self.current_tag_name.items.len == 0);
    assert(self.current_tag_attributes.count() == 0);
    self.current_tag_type = .Start;
}

fn createEndTagToken(self: *Self) void {
    assert(self.current_tag_name.items.len == 0);
    assert(self.current_tag_attributes.count() == 0);
    self.current_tag_type = .End;
}

fn createAttribute(self: *Self) void {
    assert(self.generic_buffer.items.len == 0);
}

fn createCommentToken(self: *Self) void {
    assert(self.current_comment_data.items.len == 0);
}

fn isAppropriateEndTag(self: *Self) bool {
    // Looking at the tokenizer logic, it seems that is no way to reach this function without current_tag_name
    // having at least 1 ASCII character in it. So we don't have to worry about making sure it has non-zero length.
    //
    // Notice that this gets called from the states that end in "TagName", and that those states
    // can only be reached by reconsuming an ASCII character from an associated "TagOpen" state.
    return std.mem.eql(u8, self.last_start_tag_name, self.current_tag_name.items);
}

fn makeCurrentTagSelfClosing(self: *Self) void {
    self.current_tag_self_closing = true;
}

fn currentDOCTYPETokenForceQuirks(self: *Self) void {
    self.current_doctype_force_quirks = true;
}

fn markCurrentDOCTYPENameNotMissing(self: *Self) void {
    self.current_doctype_name_is_missing = false;
}

fn markCurrentDOCTYPEPublicIdentifierNotMissing(self: *Self) void {
    self.current_doctype_public_identifier_is_missing = false;
}

fn markCurrentDOCTYPESystemIdentifierNotMissing(self: *Self) void {
    self.current_doctype_system_identifier_is_missing = false;
}

fn appendCurrentTagName(self: *Self, character: u21) !void {
    var code_units: [4]u8 = undefined;
    const len = try std.unicode.utf8Encode(character, &code_units);
    try self.current_tag_name.appendSlice(self.allocator, code_units[0..len]);
}

fn resetCurrentTagName(self: *Self) void {
    self.current_tag_name.clearRetainingCapacity();
}

fn appendCurrentAttributeName(self: *Self, character: u21) !void {
    var code_units: [4]u8 = undefined;
    const len = try std.unicode.utf8Encode(character, &code_units);
    try self.generic_buffer.appendSlice(self.allocator, code_units[0..len]);
}

fn appendCurrentAttributeValue(self: *Self, character: u21) !void {
    var code_units: [4]u8 = undefined;
    const len = try std.unicode.utf8Encode(character, &code_units);
    try self.generic_buffer.appendSlice(self.allocator, code_units[0..len]);
}

fn finishAttributeName(self: *Self) !void {
    const get_result = try self.current_tag_attributes.getOrPut(self.allocator, self.generic_buffer.items);
    errdefer if (!get_result.found_existing) self.current_tag_attributes.removeByPtr(get_result.key_ptr);

    defer self.generic_buffer.clearRetainingCapacity();
    if (get_result.found_existing) {
        try self.parseError(.DuplicateAttribute);
    } else {
        get_result.key_ptr.* = try self.allocator.dupe(u8, self.generic_buffer.items);
        get_result.value_ptr.* = "";
        self.current_attribute_value_result_location = get_result.value_ptr;
    }
}

fn finishAttributeValue(self: *Self) !void {
    const value = try self.allocator.dupe(u8, self.generic_buffer.items);
    self.generic_buffer.clearRetainingCapacity();
    if (self.current_attribute_value_result_location) |ptr| {
        ptr.* = value;
        self.current_attribute_value_result_location = null;
    } else {
        self.allocator.free(value);
    }
}

fn appendDOCTYPEName(self: *Self, character: u21) !void {
    var code_units: [4]u8 = undefined;
    const len = try std.unicode.utf8Encode(character, &code_units);
    try self.current_doctype_name.appendSlice(self.allocator, code_units[0..len]);
}

fn appendDOCTYPEPublicIdentifier(self: *Self, character: u21) !void {
    var code_units: [4]u8 = undefined;
    const len = try std.unicode.utf8Encode(character, &code_units);
    try self.current_doctype_public_identifier.appendSlice(self.allocator, code_units[0..len]);
}

fn appendDOCTYPESystemIdentifier(self: *Self, character: u21) !void {
    var code_units: [4]u8 = undefined;
    const len = try std.unicode.utf8Encode(character, &code_units);
    try self.current_doctype_system_identifier.appendSlice(self.allocator, code_units[0..len]);
}

fn appendComment(self: *Self, character: u21) !void {
    var code_units: [4]u8 = undefined;
    const len = try std.unicode.utf8Encode(character, &code_units);
    try self.current_comment_data.appendSlice(self.allocator, code_units[0..len]);
}

fn appendCommentString(self: *Self, comptime string: []const u8) !void {
    try self.current_comment_data.appendSlice(self.allocator, string);
}

fn appendTempBuffer(self: *Self, character: u21) !void {
    try self.temp_buffer.append(self.allocator, character);
}

fn clearTempBuffer(self: *Self) void {
    self.temp_buffer.clearRetainingCapacity();
}

fn emitDOCTYPE(self: *Self) !void {
    const token = try self.tokens.addOne();

    const name = self.current_doctype_name.toOwnedSlice(self.allocator);
    if (self.current_doctype_name_is_missing) assert(name.len == 0);

    const public_identifier = self.current_doctype_public_identifier.toOwnedSlice(self.allocator);
    if (self.current_doctype_public_identifier_is_missing) assert(public_identifier.len == 0);

    const system_identifier = self.current_doctype_system_identifier.toOwnedSlice(self.allocator);
    if (self.current_doctype_system_identifier_is_missing) assert(system_identifier.len == 0);

    token.* = Token{ .doctype = .{
        .name = if (self.current_doctype_name_is_missing) null else name,
        .public_identifier = if (self.current_doctype_public_identifier_is_missing) null else public_identifier,
        .system_identifier = if (self.current_doctype_system_identifier_is_missing) null else system_identifier,
        .force_quirks = self.current_doctype_force_quirks,
    } };

    self.current_doctype_name_is_missing = true;
    self.current_doctype_public_identifier_is_missing = true;
    self.current_doctype_system_identifier_is_missing = true;
    self.current_doctype_force_quirks = false;
}

fn emitCharacter(self: *Self, character: u21) !void {
    try self.tokens.append(Token{ .character = .{ .data = character } });
}

fn emitString(self: *Self, comptime string: []const u8) !void {
    for (rem.util.utf8DecodeStringComptime(string)) |character| {
        try emitCharacter(self, character);
    }
}

fn emitTempBufferCharacters(self: *Self) !void {
    for (self.temp_buffer.items) |character| {
        try self.emitCharacter(character);
    }
}

fn emitComment(self: *Self) !void {
    const data = self.current_comment_data.toOwnedSlice(self.allocator);
    errdefer self.allocator.free(data);
    try self.tokens.append(Token{ .comment = .{ .data = data } });
}

fn emitEOF(self: *Self) !void {
    self.reached_eof = true;
    try self.tokens.append(Token{ .eof = {} });
}

fn emitCurrentTag(self: *Self) !void {
    const name = self.current_tag_name.toOwnedSlice(self.allocator);
    errdefer self.allocator.free(name);
    switch (self.current_tag_type) {
        .Start => {
            self.last_start_tag_name = try self.allocator.realloc(self.last_start_tag_name, name.len);
            std.mem.copy(u8, self.last_start_tag_name, name);
            try self.tokens.append(Token{ .start_tag = .{
                .name = name,
                .attributes = self.current_tag_attributes,
                .self_closing = self.current_tag_self_closing,
            } });
            self.current_tag_attributes = .{};
        },
        .End => {
            // TODO: Don't store any attributes in the first place
            if (self.current_tag_attributes.count() > 0) {
                var iterator = self.current_tag_attributes.iterator();
                while (iterator.next()) |attr| {
                    self.allocator.free(attr.key_ptr.*);
                    self.allocator.free(attr.value_ptr.*);
                }
                self.current_tag_attributes.clearRetainingCapacity();
                try self.parseError(.EndTagWithAttributes);
            }
            if (self.current_tag_self_closing) {
                try self.parseError(.EndTagWithTrailingSolidus);
            }
            try self.tokens.append(Token{ .end_tag = .{
                .name = name,
            } });
        },
    }

    self.current_tag_self_closing = false;
    self.current_tag_type = undefined;
}

fn flushCharacterReference(self: *Self) !void {
    if (self.isPartOfAnAttribute()) {
        for (self.temp_buffer.items) |character| {
            var code_units: [4]u8 = undefined;
            const len = try std.unicode.utf8Encode(character, &code_units);
            try self.generic_buffer.appendSlice(self.allocator, code_units[0..len]);
        }
    } else {
        for (self.temp_buffer.items) |character| {
            try self.emitCharacter(character);
        }
    }
}

fn findNamedCharacterReference(self: *Self, input: *[]const u21) !named_characters_data.Value {
    var node = named_characters_data.root;
    var replayed_characters_index: u6 = 0;
    var character_reference_consumed_codepoints_count: usize = 1;
    var last_matched_named_character_value = named_characters_data.Value{ null, null };
    while (true) {
        const character = self.nextInputStreamChar(input, &replayed_characters_index) orelse break;
        try self.appendTempBuffer(character);
        const key_index = node.find(character) orelse break;

        if (node.child(key_index)) |c_node| {
            const new_value = node.value(key_index);
            if (new_value[0] != null) {
                // Partial match found.
                character_reference_consumed_codepoints_count = self.temp_buffer.items.len;
                last_matched_named_character_value = new_value;
            }
            node = c_node;
        } else {
            // Complete match found.
            character_reference_consumed_codepoints_count = self.temp_buffer.items.len;
            last_matched_named_character_value = node.value(key_index);
            break;
        }
    }

    self.consumeReplayedCharacters(std.math.min(replayed_characters_index, character_reference_consumed_codepoints_count));
    self.replayCharacters(self.temp_buffer.items[character_reference_consumed_codepoints_count..]);
    self.temp_buffer.shrinkRetainingCapacity(character_reference_consumed_codepoints_count);
    // There is no need to check the consumed characters for errors (controls, surrogates, noncharacters)
    // beacuse we've just determined that they form a valid character reference.
    return last_matched_named_character_value;
}

fn characterReferenceCodeAddDigit(self: *Self, comptime base: comptime_int, digit: u21) void {
    self.character_reference_code = self.character_reference_code *| base +| digit;
}

fn parseError(self: *Self, err: ParseError) !void {
    try self.error_handler.sendError(err);
}

fn tempBufferEql(self: *Self, comptime string: []const u8) bool {
    return std.mem.eql(u21, self.temp_buffer.items, &rem.util.utf8DecodeStringComptime(string));
}

fn tempBufferLast(self: *Self) u21 {
    return self.temp_buffer.items[self.temp_buffer.items.len - 1];
}

fn isPartOfAnAttribute(self: *Self) bool {
    return switch (self.return_state) {
        .AttributeValueDoubleQuoted,
        .AttributeValueSingleQuoted,
        .AttributeValueUnquoted,
        => true,
        else => false,
    };
}

fn adjustedCurrentNodeIsNotInHtmlNamespace(self: *Self) bool {
    return self.adjusted_current_node_is_not_in_html_namespace;
}

fn processInput(t: *Self, input: *[]const u21) !void {
    switch (t.state) {
        .Data => {
            if (try t.nextInputChar(input)) |current_input_char| {
                switch (current_input_char) {
                    '&' => t.toCharacterReferenceState(.Data),
                    '<' => t.setState(.TagOpen),
                    0x00 => {
                        try t.parseError(.UnexpectedNullCharacter);
                        try t.emitCharacter(0x00);
                    },
                    else => |c| try t.emitCharacter(c),
                }
            } else {
                try t.emitEOF();
            }
        },
        .RAWTEXT => {
            if (try t.nextInputChar(input)) |current_input_char| {
                switch (current_input_char) {
                    '<' => t.setState(.RAWTEXTLessThanSign),
                    0x00 => {
                        try t.parseError(.UnexpectedNullCharacter);
                        try t.emitCharacter(REPLACEMENT_CHARACTER);
                    },
                    else => |c| try t.emitCharacter(c),
                }
            } else {
                try t.emitEOF();
            }
        },
        .PLAINTEXT => {
            while (try t.nextInputChar(input)) |current_input_char| {
                switch (current_input_char) {
                    0x00 => {
                        try t.parseError(.UnexpectedNullCharacter);
                        try t.emitCharacter(REPLACEMENT_CHARACTER);
                    },
                    else => |c| try t.emitCharacter(c),
                }
            } else {
                return t.emitEOF();
            }
        },
        .TagOpen => {
            if (try t.nextInputChar(input)) |current_input_char| {
                switch (current_input_char) {
                    '!' => t.setState(.MarkupDeclarationOpen),
                    '/' => t.setState(.EndTagOpen),
                    'A'...'Z', 'a'...'z' => {
                        t.createStartTagToken();
                        t.reconsume(.TagName);
                    },
                    '?' => {
                        try t.parseError(.UnexpectedQuestionMarkInsteadOfTagName);
                        t.createCommentToken();
                        t.reconsume(.BogusComment);
                    },
                    else => {
                        try t.parseError(.InvalidFirstCharacterOfTagName);
                        try t.emitCharacter('<');
                        t.reconsume(.Data);
                    },
                }
            } else {
                try t.parseError(.EOFBeforeTagName);
                try t.emitCharacter('<');
                try t.emitEOF();
            }
        },
        .EndTagOpen => {
            if (try t.nextInputChar(input)) |current_input_char| {
                switch (current_input_char) {
                    'A'...'Z', 'a'...'z' => {
                        t.createEndTagToken();
                        t.reconsume(.TagName);
                    },
                    '>' => {
                        try t.parseError(.MissingEndTagName);
                        t.setState(.Data);
                    },
                    else => {
                        try t.parseError(.InvalidFirstCharacterOfTagName);
                        t.createCommentToken();
                        t.reconsume(.BogusComment);
                    },
                }
            } else {
                try t.parseError(.EOFBeforeTagName);
                try t.emitString("</");
                try t.emitEOF();
            }
        },
        .TagName => {
            if (try t.nextInputChar(input)) |current_input_char| {
                switch (current_input_char) {
                    '\t', '\n', 0x0C, ' ' => t.setState(.BeforeAttributeName),
                    '/' => t.setState(.SelfClosingStartTag),
                    '>' => {
                        t.setState(.Data);
                        try t.emitCurrentTag();
                    },
                    'A'...'Z' => |c| try t.appendCurrentTagName(toLowercase(c)),
                    0x00 => {
                        try t.parseError(.UnexpectedNullCharacter);
                        try t.appendCurrentTagName(REPLACEMENT_CHARACTER);
                    },
                    else => |c| try t.appendCurrentTagName(c),
                }
            } else {
                try t.parseError(.EOFInTag);
                try t.emitEOF();
            }
        },
        .RCDATA => {
            while (try t.nextInputChar(input)) |current_input_char| {
                switch (current_input_char) {
                    '&' => return t.toCharacterReferenceState(.RCDATA),
                    0x00 => {
                        try t.parseError(.UnexpectedNullCharacter);
                        try t.emitCharacter(REPLACEMENT_CHARACTER);
                    },
                    else => |c| try t.emitCharacter(c),
                    '<' => {
                        // RCDATALessThanSign
                        if ((try t.nextInputChar(input)) != @as(u21, '/')) {
                            try t.emitCharacter('<');
                            t.reconsume(.RCDATA);
                            continue;
                        }

                        // RCDATAEndTagOpen
                        t.clearTempBuffer();
                        switch ((try t.nextInputChar(input)) orelse TREAT_AS_ANYTHING_ELSE) {
                            'A'...'Z', 'a'...'z' => {
                                t.createEndTagToken();
                                t.reconsume(.RCDATA);
                                // RCDATAEndTagName
                                return endTagName(t, input, .RCDATA);
                            },
                            else => {
                                try t.emitString("</");
                                t.reconsume(.RCDATA);
                            },
                        }
                    },
                }
            } else {
                return t.emitEOF();
            }
        },
        .RAWTEXTLessThanSign => {
            switch ((try t.nextInputChar(input)) orelse TREAT_AS_ANYTHING_ELSE) {
                '/' => {
                    t.clearTempBuffer();
                    t.setState(.RAWTEXTEndTagOpen);
                },
                else => {
                    try t.emitCharacter('<');
                    t.reconsume(.RAWTEXT);
                },
            }
        },
        .RAWTEXTEndTagOpen => {
            switch ((try t.nextInputChar(input)) orelse TREAT_AS_ANYTHING_ELSE) {
                'A'...'Z', 'a'...'z' => {
                    t.createEndTagToken();
                    t.reconsume(.RAWTEXTEndTagName);
                },
                else => {
                    try t.emitString("</");
                    t.reconsume(.RAWTEXT);
                },
            }
        },
        .RAWTEXTEndTagName => try endTagName(t, input, .RAWTEXT),
        .ScriptData => {
            var current_input_char = try t.nextInputChar(input);
            while (current_input_char) |char| switch (char) {
                0x00 => {
                    try t.parseError(.UnexpectedNullCharacter);
                    try t.emitCharacter(REPLACEMENT_CHARACTER);
                    current_input_char = try t.nextInputChar(input);
                },
                else => {
                    try t.emitCharacter(char);
                    current_input_char = try t.nextInputChar(input);
                },
                '<' => {
                    // t.setState(.ScriptDataLessThanSign)
                    current_input_char = try t.nextInputChar(input);
                    switch (current_input_char orelse TREAT_AS_ANYTHING_ELSE) {
                        else => {
                            try t.emitCharacter('<');
                            continue;
                        },
                        '/' => {
                            t.clearTempBuffer();
                            // t.setState(.ScriptDataEndTagOpen);
                            current_input_char = try t.nextInputChar(input);
                            switch (current_input_char orelse TREAT_AS_ANYTHING_ELSE) {
                                'A'...'Z', 'a'...'z' => {
                                    t.createEndTagToken();
                                    // ScriptDataEndTagName
                                    t.reconsume(.ScriptData);
                                    try endTagName(t, input, .ScriptData);
                                    return;
                                },
                                else => {
                                    try t.emitString("</");
                                },
                            }
                        },
                        '!' => {
                            try t.emitString("<!");
                            t.setState(.ScriptDataEscapeStart);
                            return;
                        },
                    }
                },
            } else {
                try t.emitEOF();
            }
        },
        .ScriptDataEscapeStart => {
            switch ((try t.nextInputChar(input)) orelse TREAT_AS_ANYTHING_ELSE) {
                '-' => {
                    t.setState(.ScriptDataEscapeStartDash);
                    try t.emitCharacter('-');
                },
                else => t.reconsume(.ScriptData),
            }
        },
        .ScriptDataEscapeStartDash => {
            switch ((try t.nextInputChar(input)) orelse TREAT_AS_ANYTHING_ELSE) {
                '-' => {
                    t.setState(.ScriptDataEscapedDashDash);
                    try t.emitCharacter('-');
                },
                else => t.reconsume(.ScriptData),
            }
        },
        .ScriptDataEscaped => {
            if (try t.nextInputChar(input)) |current_input_char| {
                switch (current_input_char) {
                    '-' => {
                        t.setState(.ScriptDataEscapedDash);
                        try t.emitCharacter('-');
                    },
                    '<' => t.setState(.ScriptDataEscapedLessThanSign),
                    0x00 => {
                        try t.parseError(.UnexpectedNullCharacter);
                        try t.emitCharacter(REPLACEMENT_CHARACTER);
                    },
                    else => |c| try t.emitCharacter(c),
                }
            } else {
                try t.parseError(.EOFInScriptHtmlCommentLikeText);
                try t.emitEOF();
            }
        },
        .ScriptDataEscapedDash => {
            if (try t.nextInputChar(input)) |current_input_char| {
                switch (current_input_char) {
                    '-' => {
                        t.setState(.ScriptDataEscapedDashDash);
                        try t.emitCharacter('-');
                    },
                    '<' => t.setState(.ScriptDataEscapedLessThanSign),
                    0x00 => {
                        try t.parseError(.UnexpectedNullCharacter);
                        t.setState(.ScriptDataEscaped);
                        try t.emitCharacter(REPLACEMENT_CHARACTER);
                    },
                    else => |c| {
                        t.setState(.ScriptDataEscaped);
                        try t.emitCharacter(c);
                    },
                }
            } else {
                try t.parseError(.EOFInScriptHtmlCommentLikeText);
                try t.emitEOF();
            }
        },
        .ScriptDataEscapedDashDash => {
            if (try t.nextInputChar(input)) |current_input_char| {
                switch (current_input_char) {
                    '-' => try t.emitCharacter('-'),
                    '<' => t.setState(.ScriptDataEscapedLessThanSign),
                    '>' => {
                        t.setState(.ScriptData);
                        try t.emitCharacter('>');
                    },
                    0x00 => {
                        try t.parseError(.UnexpectedNullCharacter);
                        t.setState(.ScriptDataEscaped);
                        try t.emitCharacter(REPLACEMENT_CHARACTER);
                    },
                    else => |c| {
                        t.setState(.ScriptDataEscaped);
                        try t.emitCharacter(c);
                    },
                }
            } else {
                try t.parseError(.EOFInScriptHtmlCommentLikeText);
                try t.emitEOF();
            }
        },
        .ScriptDataEscapedLessThanSign => {
            switch ((try t.nextInputChar(input)) orelse TREAT_AS_ANYTHING_ELSE) {
                '/' => {
                    t.clearTempBuffer();
                    t.setState(.ScriptDataEscapedEndTagOpen);
                },
                'A'...'Z', 'a'...'z' => {
                    t.clearTempBuffer();
                    try t.emitCharacter('<');
                    t.reconsume(.ScriptDataDoubleEscapeStart);
                },
                else => {
                    try t.emitCharacter('<');
                    t.reconsume(.ScriptDataEscaped);
                },
            }
        },
        .ScriptDataEscapedEndTagOpen => {
            switch ((try t.nextInputChar(input)) orelse TREAT_AS_ANYTHING_ELSE) {
                'A'...'Z', 'a'...'z' => {
                    t.createEndTagToken();
                    t.reconsume(.ScriptDataEscapedEndTagName);
                },
                else => {
                    try t.emitString("</");
                    t.reconsume(.ScriptDataEscaped);
                },
            }
        },
        .ScriptDataEscapedEndTagName => try endTagName(t, input, .ScriptDataEscaped),
        .ScriptDataDoubleEscapeStart => {
            switch ((try t.nextInputChar(input)) orelse TREAT_AS_ANYTHING_ELSE) {
                '\t', '\n', 0x0C, ' ', '/', '>' => |c| {
                    t.setState(if (t.tempBufferEql("script")) .ScriptDataDoubleEscaped else .ScriptDataEscaped);
                    try t.emitCharacter(c);
                },
                'A'...'Z' => |c| {
                    try t.appendTempBuffer(toLowercase(c));
                    try t.emitCharacter(c);
                },
                'a'...'z' => |c| {
                    try t.appendTempBuffer(c);
                    try t.emitCharacter(c);
                },
                else => t.reconsume(.ScriptDataEscaped),
            }
        },
        .ScriptDataDoubleEscaped => {
            if (try t.nextInputChar(input)) |current_input_char| {
                switch (current_input_char) {
                    '-' => {
                        t.setState(.ScriptDataDoubleEscapedDash);
                        try t.emitCharacter('-');
                    },
                    '<' => {
                        t.setState(.ScriptDataDoubleEscapedLessThanSign);
                        try t.emitCharacter('<');
                    },
                    0x00 => {
                        try t.parseError(.UnexpectedNullCharacter);
                        try t.emitCharacter(REPLACEMENT_CHARACTER);
                    },
                    else => |c| try t.emitCharacter(c),
                }
            } else {
                try t.parseError(.EOFInScriptHtmlCommentLikeText);
                try t.emitEOF();
            }
        },
        .ScriptDataDoubleEscapedDash => {
            if (try t.nextInputChar(input)) |current_input_char| {
                switch (current_input_char) {
                    '-' => {
                        t.setState(.ScriptDataDoubleEscapedDashDash);
                        try t.emitCharacter('-');
                    },
                    '<' => {
                        t.setState(.ScriptDataDoubleEscapedLessThanSign);
                        try t.emitCharacter('<');
                    },
                    0x00 => {
                        try t.parseError(.UnexpectedNullCharacter);
                        t.setState(.ScriptDataDoubleEscaped);
                        try t.emitCharacter(REPLACEMENT_CHARACTER);
                    },
                    else => |c| {
                        t.setState(.ScriptDataDoubleEscaped);
                        try t.emitCharacter(c);
                    },
                }
            } else {
                try t.parseError(.EOFInScriptHtmlCommentLikeText);
                try t.emitEOF();
            }
        },
        .ScriptDataDoubleEscapedDashDash => {
            if (try t.nextInputChar(input)) |current_input_char| {
                switch (current_input_char) {
                    '-' => try t.emitCharacter('-'),
                    '<' => {
                        t.setState(.ScriptDataDoubleEscapedLessThanSign);
                        try t.emitCharacter('<');
                    },
                    '>' => {
                        t.setState(.ScriptData);
                        try t.emitCharacter('>');
                    },
                    0x00 => {
                        try t.parseError(.UnexpectedNullCharacter);
                        t.setState(.ScriptDataDoubleEscaped);
                        try t.emitCharacter(REPLACEMENT_CHARACTER);
                    },
                    else => |c| {
                        t.setState(.ScriptDataDoubleEscaped);
                        try t.emitCharacter(c);
                    },
                }
            } else {
                try t.parseError(.EOFInScriptHtmlCommentLikeText);
                try t.emitEOF();
            }
        },
        .ScriptDataDoubleEscapedLessThanSign => {
            switch ((try t.nextInputChar(input)) orelse TREAT_AS_ANYTHING_ELSE) {
                '/' => {
                    t.clearTempBuffer();
                    t.setState(.ScriptDataDoubleEscapeEnd);
                    try t.emitCharacter('/');
                },
                else => t.reconsume(.ScriptDataDoubleEscaped),
            }
        },
        // Nearly identical to ScriptDataDoubleEscapeStart.
        .ScriptDataDoubleEscapeEnd => {
            switch ((try t.nextInputChar(input)) orelse TREAT_AS_ANYTHING_ELSE) {
                '\t', '\n', 0x0C, ' ', '/', '>' => |c| {
                    t.setState(if (t.tempBufferEql("script")) .ScriptDataEscaped else .ScriptDataDoubleEscaped);
                    try t.emitCharacter(c);
                },
                'A'...'Z' => |c| {
                    try t.appendTempBuffer(toLowercase(c));
                    try t.emitCharacter(c);
                },
                'a'...'z' => |c| {
                    try t.appendTempBuffer(c);
                    try t.emitCharacter(c);
                },
                else => t.reconsume(.ScriptDataDoubleEscaped),
            }
        },
        .BeforeAttributeName => {
            // Handle '/', '>', and EOF using the rules for AfterAttributeName
            if (try t.nextInputChar(input)) |current_input_char| switch (current_input_char) {
                '\t', '\n', 0x0C, ' ' => {},
                '/' => t.setState(.SelfClosingStartTag),
                '>' => {
                    try t.emitCurrentTag();
                    t.setState(.Data);
                },
                '=' => {
                    try t.parseError(.UnexpectedEqualsSignBeforeAttributeName);
                    t.createAttribute();
                    try t.appendCurrentAttributeName('=');
                    t.setState(.AttributeName);
                },
                else => {
                    t.createAttribute();
                    t.reconsume(.AttributeName);
                },
            } else {
                try t.parseError(.EOFInTag);
                try t.emitEOF();
                return;
            }
        },
        .AttributeName => {
            // Make end-of-file (null) be handled the same as '>'
            while (true) {
                switch ((try t.nextInputChar(input)) orelse '>') {
                    '\t', '\n', 0x0C, ' ', '/', '>' => {
                        try t.finishAttributeName();
                        t.reconsume(.AttributeName);
                        break;
                    },
                    '=' => {
                        try t.finishAttributeName();
                        return t.setState(.BeforeAttributeValue);
                    },
                    'A'...'Z' => |c| try t.appendCurrentAttributeName(toLowercase(c)),
                    0x00 => {
                        try t.parseError(.UnexpectedNullCharacter);
                        try t.appendCurrentAttributeName(REPLACEMENT_CHARACTER);
                    },
                    '"', '\'', '<' => |c| {
                        try t.parseError(.UnexpectedCharacterInAttributeName);
                        try t.appendCurrentAttributeName(c);
                    },
                    else => |c| try t.appendCurrentAttributeName(c),
                }
            }

            // AfterAttributeName
            while (true) {
                if (try t.nextInputChar(input)) |current_input_char| {
                    switch (current_input_char) {
                        '\t', '\n', 0x0C, ' ' => {},
                        '/' => return t.setState(.SelfClosingStartTag),
                        '=' => return t.setState(.BeforeAttributeValue),
                        '>' => {
                            t.setState(.Data);
                            try t.emitCurrentTag();
                            return;
                        },
                        else => {
                            t.createAttribute();
                            return t.reconsume(.AttributeName);
                        },
                    }
                } else {
                    try t.parseError(.EOFInTag);
                    try t.emitEOF();
                    return;
                }
            }
        },
        .BeforeAttributeValue => {
            switch ((try t.nextInputChar(input)) orelse TREAT_AS_ANYTHING_ELSE) {
                '\t', '\n', 0x0C, ' ' => {},
                '"' => t.setState(.AttributeValueDoubleQuoted),
                '\'' => t.setState(.AttributeValueSingleQuoted),
                '>' => {
                    try t.parseError(.MissingAttributeValue);
                    t.setState(.Data);
                    try t.emitCurrentTag();
                },
                else => t.reconsume(.AttributeValueUnquoted),
            }
        },
        .AttributeValueDoubleQuoted => try attributeValueQuoted(t, input, .AttributeValueDoubleQuoted),
        .AttributeValueSingleQuoted => try attributeValueQuoted(t, input, .AttributeValueSingleQuoted),
        .AttributeValueUnquoted => {
            if (try t.nextInputChar(input)) |current_input_char| {
                switch (current_input_char) {
                    '\t', '\n', 0x0C, ' ' => {
                        try t.finishAttributeValue();
                        t.setState(.BeforeAttributeName);
                    },
                    '&' => t.toCharacterReferenceState(.AttributeValueUnquoted),
                    '>' => {
                        try t.finishAttributeValue();
                        t.setState(.Data);
                        try t.emitCurrentTag();
                    },
                    0x00 => {
                        try t.parseError(.UnexpectedNullCharacter);
                        try t.appendCurrentAttributeValue(REPLACEMENT_CHARACTER);
                    },
                    else => |c| {
                        switch (c) {
                            '"', '\'', '<', '=', '`' => try t.parseError(.UnexpectedCharacterInUnquotedAttributeValue),
                            else => {},
                        }
                        try t.appendCurrentAttributeValue(c);
                    },
                }
            } else {
                try t.parseError(.EOFInTag);
                try t.emitEOF();
            }
        },
        .SelfClosingStartTag => {
            if (try t.nextInputChar(input)) |current_input_char| {
                switch (current_input_char) {
                    '>' => {
                        t.makeCurrentTagSelfClosing();
                        t.setState(.Data);
                        try t.emitCurrentTag();
                    },
                    else => {
                        try t.parseError(.UnexpectedSolidusInTag);
                        t.reconsume(.BeforeAttributeName);
                    },
                }
            } else {
                try t.parseError(.EOFInTag);
                try t.emitEOF();
            }
        },
        .BogusComment => {
            if (try t.nextInputChar(input)) |current_input_char| {
                switch (current_input_char) {
                    '>' => {
                        t.setState(.Data);
                        try t.emitComment();
                    },
                    0x00 => {
                        try t.parseError(.UnexpectedNullCharacter);
                        try t.appendComment(REPLACEMENT_CHARACTER);
                    },
                    else => |c| try t.appendComment(c),
                }
            } else {
                try t.emitComment();
                try t.emitEOF();
            }
        },
        .MarkupDeclarationOpen => {
            if (t.consumeCharsIfEql(input, "--")) {
                t.createCommentToken();
                t.setState(.CommentStart);
            } else if (t.consumeCharsIfCaseInsensitiveEql(input, "DOCTYPE")) {
                t.setState(.DOCTYPE);
            } else if (t.consumeCharsIfEql(input, "[CDATA[")) {
                if (t.adjustedCurrentNodeIsNotInHtmlNamespace()) {
                    t.setState(.CDATASection);
                } else {
                    try t.parseError(.CDATAInHtmlContent);
                    t.createCommentToken();
                    try t.appendCommentString("[CDATA[");
                    t.setState(.BogusComment);
                }
            } else {
                try t.parseError(.IncorrectlyOpenedComment);
                t.createCommentToken();
                t.setState(.BogusComment);
            }
        },
        .CommentStart => {
            switch ((try t.nextInputChar(input)) orelse TREAT_AS_ANYTHING_ELSE) {
                '-' => t.setState(.CommentStartDash),
                '>' => {
                    try t.parseError(.AbruptClosingOfEmptyComment);
                    t.setState(.Data);
                    try t.emitComment();
                },
                else => t.reconsume(.Comment),
            }
        },
        .CommentStartDash => {
            if (try t.nextInputChar(input)) |current_input_char| {
                switch (current_input_char) {
                    '-' => t.setState(.CommentEnd),
                    '>' => {
                        try t.parseError(.AbruptClosingOfEmptyComment);
                        t.setState(.Data);
                        try t.emitComment();
                    },
                    else => {
                        try t.appendComment('-');
                        t.reconsume(.Comment);
                    },
                }
            } else {
                try t.parseError(.EOFInComment);
                try t.emitComment();
                try t.emitEOF();
            }
        },
        .Comment => {
            if (try t.nextInputChar(input)) |current_input_char| {
                switch (current_input_char) {
                    '<' => {
                        try t.appendComment('<');
                        t.setState(.CommentLessThanSign);
                    },
                    '-' => t.setState(.CommentEndDash),
                    0x00 => {
                        try t.parseError(.UnexpectedNullCharacter);
                        try t.appendComment(REPLACEMENT_CHARACTER);
                    },
                    else => |c| try t.appendComment(c),
                }
            } else {
                try t.parseError(.EOFInComment);
                try t.emitComment();
                try t.emitEOF();
            }
        },
        .CommentLessThanSign => {
            switch ((try t.nextInputChar(input)) orelse TREAT_AS_ANYTHING_ELSE) {
                '!' => {
                    try t.appendComment('!');
                    t.setState(.CommentLessThanSignBang);
                },
                '<' => try t.appendComment('<'),
                else => t.reconsume(.Comment),
            }
        },
        .CommentLessThanSignBang => {
            switch ((try t.nextInputChar(input)) orelse TREAT_AS_ANYTHING_ELSE) {
                '-' => t.setState(.CommentLessThanSignBangDash),
                else => t.reconsume(.Comment),
            }
        },
        .CommentLessThanSignBangDash => {
            switch ((try t.nextInputChar(input)) orelse TREAT_AS_ANYTHING_ELSE) {
                '-' => t.setState(.CommentLessThanSignBangDashDash),
                else => t.reconsume(.CommentEndDash),
            }
        },
        .CommentLessThanSignBangDashDash => {
            // Make end-of-file (null) be handled the same as '>'
            switch ((try t.nextInputChar(input)) orelse '>') {
                '>' => t.reconsume(.CommentEnd),
                else => {
                    try t.parseError(.NestedComment);
                    t.reconsume(.CommentEnd);
                },
            }
        },
        .CommentEndDash => {
            if (try t.nextInputChar(input)) |current_input_char| {
                switch (current_input_char) {
                    '-' => t.setState(.CommentEnd),
                    else => {
                        try t.appendComment('-');
                        t.reconsume(.Comment);
                    },
                }
            } else {
                try t.parseError(.EOFInComment);
                try t.emitComment();
                try t.emitEOF();
            }
        },
        .CommentEnd => {
            if (try t.nextInputChar(input)) |current_input_char| {
                switch (current_input_char) {
                    '>' => {
                        t.setState(.Data);
                        try t.emitComment();
                    },
                    '!' => t.setState(.CommentEndBang),
                    '-' => try t.appendComment('-'),
                    else => {
                        try t.appendComment('-');
                        try t.appendComment('-');
                        t.reconsume(.Comment);
                    },
                }
            } else {
                try t.parseError(.EOFInComment);
                try t.emitComment();
                try t.emitEOF();
            }
        },
        .CommentEndBang => {
            if (try t.nextInputChar(input)) |current_input_char| {
                switch (current_input_char) {
                    '-' => {
                        try t.appendComment('-');
                        try t.appendComment('-');
                        try t.appendComment('!');
                        t.setState(.CommentEndDash);
                    },
                    '>' => {
                        try t.parseError(.IncorrectlyClosedComment);
                        t.setState(.Data);
                        try t.emitComment();
                    },
                    else => {
                        try t.appendComment('-');
                        try t.appendComment('-');
                        try t.appendComment('!');
                        t.reconsume(.Comment);
                    },
                }
            } else {
                try t.parseError(.EOFInComment);
                try t.emitComment();
                try t.emitEOF();
            }
        },
        .DOCTYPE => {
            if (try t.nextInputChar(input)) |current_input_char| {
                switch (current_input_char) {
                    '\t', '\n', 0x0C, ' ' => t.setState(.BeforeDOCTYPEName),
                    '>' => t.reconsume(.BeforeDOCTYPEName),
                    else => {
                        try t.parseError(.MissingWhitespaceBeforeDOCTYPEName);
                        t.reconsume(.BeforeDOCTYPEName);
                    },
                }
            } else {
                try t.parseError(.EOFInDOCTYPE);
                t.createDOCTYPEToken();
                t.currentDOCTYPETokenForceQuirks();
                try t.emitDOCTYPE();
                try t.emitEOF();
            }
        },
        .BeforeDOCTYPEName => {
            if (try t.nextInputChar(input)) |current_input_char| {
                switch (current_input_char) {
                    '\t', '\n', 0x0C, ' ' => {},
                    'A'...'Z' => |c| {
                        t.createDOCTYPEToken();
                        t.markCurrentDOCTYPENameNotMissing();
                        try t.appendDOCTYPEName(toLowercase(c));
                        t.setState(.DOCTYPEName);
                    },
                    0x00 => {
                        try t.parseError(.UnexpectedNullCharacter);
                        t.createDOCTYPEToken();
                        t.markCurrentDOCTYPENameNotMissing();
                        try t.appendDOCTYPEName(REPLACEMENT_CHARACTER);
                        t.setState(.DOCTYPEName);
                    },
                    '>' => {
                        try t.parseError(.MissingDOCTYPEName);
                        t.createDOCTYPEToken();
                        t.currentDOCTYPETokenForceQuirks();
                        t.setState(.Data);
                        try t.emitDOCTYPE();
                    },
                    else => |c| {
                        t.createDOCTYPEToken();
                        t.markCurrentDOCTYPENameNotMissing();
                        try t.appendDOCTYPEName(c);
                        t.setState(.DOCTYPEName);
                    },
                }
            } else {
                try t.parseError(.EOFInDOCTYPE);
                t.createDOCTYPEToken();
                t.currentDOCTYPETokenForceQuirks();
                try t.emitDOCTYPE();
                try t.emitEOF();
            }
        },
        .DOCTYPEName => {
            if (try t.nextInputChar(input)) |current_input_char| {
                switch (current_input_char) {
                    '\t', '\n', 0x0C, ' ' => t.setState(.AfterDOCTYPEName),
                    '>' => {
                        t.setState(.Data);
                        try t.emitDOCTYPE();
                    },
                    'A'...'Z' => |c| try t.appendDOCTYPEName(toLowercase(c)),
                    0x00 => {
                        try t.parseError(.UnexpectedNullCharacter);
                        try t.appendDOCTYPEName(REPLACEMENT_CHARACTER);
                    },
                    else => |c| try t.appendDOCTYPEName(c),
                }
            } else {
                try t.parseError(.EOFInDOCTYPE);
                t.currentDOCTYPETokenForceQuirks();
                try t.emitDOCTYPE();
                try t.emitEOF();
            }
        },
        .AfterDOCTYPEName => {
            if (try t.nextInputChar(input)) |current_input_char| {
                switch (current_input_char) {
                    '\t', '\n', 0x0C, ' ' => {},
                    '>' => {
                        t.setState(.Data);
                        try t.emitDOCTYPE();
                    },
                    else => |c| {
                        if (caseInsensitiveEql(c, 'P') and t.consumeCharsIfCaseInsensitiveEql(input, "UBLIC")) {
                            t.setState(.AfterDOCTYPEPublicKeyword);
                        } else if (caseInsensitiveEql(c, 'S') and t.consumeCharsIfCaseInsensitiveEql(input, "YSTEM")) {
                            t.setState(.AfterDOCTYPESystemKeyword);
                        } else {
                            try t.parseError(.InvalidCharacterSequenceAfterDOCTYPEName);
                            t.currentDOCTYPETokenForceQuirks();
                            t.reconsume(.BogusDOCTYPE);
                        }
                    },
                }
            } else {
                try t.parseError(.EOFInDOCTYPE);
                t.currentDOCTYPETokenForceQuirks();
                try t.emitDOCTYPE();
                try t.emitEOF();
            }
        },
        .AfterDOCTYPEPublicKeyword => try afterDOCTYPEPublicOrSystemKeyword(t, input, .public),
        .AfterDOCTYPESystemKeyword => try afterDOCTYPEPublicOrSystemKeyword(t, input, .system),
        .BogusDOCTYPE => {
            if (try t.nextInputChar(input)) |current_input_char| {
                switch (current_input_char) {
                    '>' => {
                        t.setState(.Data);
                        try t.emitDOCTYPE();
                    },
                    0x00 => try t.parseError(.UnexpectedNullCharacter),
                    else => {},
                }
            } else {
                try t.emitDOCTYPE();
                try t.emitEOF();
            }
        },
        .CDATASection => {
            if (try t.nextInputChar(input)) |current_input_char| {
                switch (current_input_char) {
                    ']' => t.setState(.CDATASectionBracket),
                    else => |c| try t.emitCharacter(c),
                }
            } else {
                try t.parseError(.EOFInCDATA);
                try t.emitEOF();
            }
        },
        .CDATASectionBracket => {
            switch ((try t.nextInputChar(input)) orelse TREAT_AS_ANYTHING_ELSE) {
                ']' => t.setState(.CDATASectionEnd),
                else => {
                    try t.emitCharacter(']');
                    t.reconsume(.CDATASection);
                },
            }
        },
        .CDATASectionEnd => {
            switch ((try t.nextInputChar(input)) orelse TREAT_AS_ANYTHING_ELSE) {
                ']' => try t.emitCharacter(']'),
                '>' => t.setState(.Data),
                else => {
                    try t.emitString("]]");
                    t.reconsume(.CDATASection);
                },
            }
        },
        .CharacterReference => {
            // NOTE: This is not exactly as the spec says, but should yield the same results.
            t.clearTempBuffer();
            try t.appendTempBuffer('&');
            switch (t.peekInputChar(input) orelse TREAT_AS_ANYTHING_ELSE) {
                '0'...'9', 'A'...'Z', 'a'...'z' => {
                    t.setState(.NamedCharacterReference);
                },
                '#' => {
                    _ = try t.nextInputChar(input);
                    try t.appendTempBuffer('#');
                    t.setState(.NumericCharacterReference);
                },
                else => {
                    _ = try t.nextInputChar(input);
                    try t.flushCharacterReference();
                    t.reconsumeInReturnState();
                },
            }
        },
        .NamedCharacterReference => {
            const chars = try t.findNamedCharacterReference(input);
            const match_found = chars[0] != null;
            if (match_found) {
                const historical_reasons = t.isPartOfAnAttribute() and
                    t.tempBufferLast() != ';' and
                    switch (t.peekInputChar(input) orelse TREAT_AS_ANYTHING_ELSE) {
                    '=', '0'...'9', 'A'...'Z', 'a'...'z' => true,
                    else => false,
                };
                if (historical_reasons) {
                    try t.flushCharacterReference();
                    t.switchToReturnState();
                } else {
                    if (t.tempBufferLast() != ';') {
                        try t.parseError(.MissingSemicolonAfterCharacterReference);
                    }
                    t.clearTempBuffer();
                    try t.appendTempBuffer(chars[0].?);
                    if (chars[1]) |c| try t.appendTempBuffer(c);
                    try t.flushCharacterReference();
                    t.switchToReturnState();
                }
            } else {
                try t.flushCharacterReference();
                t.setState(.AmbiguousAmpersand);
            }
        },
        .AmbiguousAmpersand => {
            switch ((try t.nextInputChar(input)) orelse TREAT_AS_ANYTHING_ELSE) {
                '0'...'9', 'A'...'Z', 'a'...'z' => |c| if (t.isPartOfAnAttribute()) try t.appendCurrentAttributeValue(c) else try t.emitCharacter(c),
                ';' => {
                    try t.parseError(.UnknownNamedCharacterReference);
                    t.reconsumeInReturnState();
                },
                else => t.reconsumeInReturnState(),
            }
        },
        .NumericCharacterReference => {
            t.character_reference_code = 0;
            switch ((try t.nextInputChar(input)) orelse TREAT_AS_ANYTHING_ELSE) {
                'x', 'X' => |c| {
                    try t.appendTempBuffer(c);
                    t.setState(.HexadecimalCharacterReferenceStart);
                },
                else => t.reconsume(.DecimalCharacterReferenceStart),
            }
        },
        .HexadecimalCharacterReferenceStart => {
            switch ((try t.nextInputChar(input)) orelse TREAT_AS_ANYTHING_ELSE) {
                '0'...'9', 'A'...'F', 'a'...'f' => t.reconsume(.HexadecimalCharacterReference),
                else => {
                    try t.parseError(.AbsenceOfDigitsInNumericCharacterReference);
                    try t.flushCharacterReference();
                    t.reconsumeInReturnState();
                },
            }
        },
        .DecimalCharacterReferenceStart => {
            switch ((try t.nextInputChar(input)) orelse TREAT_AS_ANYTHING_ELSE) {
                '0'...'9' => t.reconsume(.DecimalCharacterReference),
                else => {
                    try t.parseError(.AbsenceOfDigitsInNumericCharacterReference);
                    try t.flushCharacterReference();
                    t.reconsumeInReturnState();
                },
            }
        },
        .HexadecimalCharacterReference => {
            switch ((try t.nextInputChar(input)) orelse TREAT_AS_ANYTHING_ELSE) {
                '0'...'9' => |c| t.characterReferenceCodeAddDigit(16, decimalCharToNumber(c)),
                'A'...'F' => |c| t.characterReferenceCodeAddDigit(16, upperHexCharToNumber(c)),
                'a'...'f' => |c| t.characterReferenceCodeAddDigit(16, lowerHexCharToNumber(c)),
                ';' => t.setState(.NumericCharacterReferenceEnd),
                else => {
                    try t.parseError(.MissingSemicolonAfterCharacterReference);
                    t.reconsume(.NumericCharacterReferenceEnd);
                },
            }
        },
        .DecimalCharacterReference => {
            switch ((try t.nextInputChar(input)) orelse TREAT_AS_ANYTHING_ELSE) {
                '0'...'9' => |c| t.characterReferenceCodeAddDigit(10, decimalCharToNumber(c)),
                ';' => t.setState(.NumericCharacterReferenceEnd),
                else => {
                    try t.parseError(.MissingSemicolonAfterCharacterReference);
                    t.reconsume(.NumericCharacterReferenceEnd);
                },
            }
        },
        .NumericCharacterReferenceEnd => {
            switch (t.character_reference_code) {
                0x00 => {
                    try t.parseError(.NullCharacterReference);
                    t.character_reference_code = REPLACEMENT_CHARACTER;
                },
                0x10FFFF + 1...std.math.maxInt(@TypeOf(t.character_reference_code)) => {
                    try t.parseError(.CharacterReferenceOutsideUnicodeRange);
                    t.character_reference_code = REPLACEMENT_CHARACTER;
                },
                0xD800...0xDFFF => {
                    try t.parseError(.SurrogateCharacterReference);
                    t.character_reference_code = REPLACEMENT_CHARACTER;
                },
                0xFDD0...0xFDEF,
                0xFFFE,
                0xFFFF,
                0x1FFFE,
                0x1FFFF,
                0x2FFFE,
                0x2FFFF,
                0x3FFFE,
                0x3FFFF,
                0x4FFFE,
                0x4FFFF,
                0x5FFFE,
                0x5FFFF,
                0x6FFFE,
                0x6FFFF,
                0x7FFFE,
                0x7FFFF,
                0x8FFFE,
                0x8FFFF,
                0x9FFFE,
                0x9FFFF,
                0xAFFFE,
                0xAFFFF,
                0xBFFFE,
                0xBFFFF,
                0xCFFFE,
                0xCFFFF,
                0xDFFFE,
                0xDFFFF,
                0xEFFFE,
                0xEFFFF,
                0xFFFFE,
                0xFFFFF,
                0x10FFFE,
                0x10FFFF,
                => try t.parseError(.NoncharacterCharacterReference),
                0x01...0x08, 0x0B, 0x0D...0x1F => try t.parseError(.ControlCharacterReference),
                0x7F...0x9F => |c| {
                    try t.parseError(.ControlCharacterReference);
                    switch (c) {
                        0x80 => t.character_reference_code = 0x20AC,
                        0x82 => t.character_reference_code = 0x201A,
                        0x83 => t.character_reference_code = 0x0192,
                        0x84 => t.character_reference_code = 0x201E,
                        0x85 => t.character_reference_code = 0x2026,
                        0x86 => t.character_reference_code = 0x2020,
                        0x87 => t.character_reference_code = 0x2021,
                        0x88 => t.character_reference_code = 0x02C6,
                        0x89 => t.character_reference_code = 0x2030,
                        0x8A => t.character_reference_code = 0x0160,
                        0x8B => t.character_reference_code = 0x2039,
                        0x8C => t.character_reference_code = 0x0152,
                        0x8E => t.character_reference_code = 0x017D,
                        0x91 => t.character_reference_code = 0x2018,
                        0x92 => t.character_reference_code = 0x2019,
                        0x93 => t.character_reference_code = 0x201C,
                        0x94 => t.character_reference_code = 0x201D,
                        0x95 => t.character_reference_code = 0x2022,
                        0x96 => t.character_reference_code = 0x2013,
                        0x97 => t.character_reference_code = 0x2014,
                        0x98 => t.character_reference_code = 0x02DC,
                        0x99 => t.character_reference_code = 0x2122,
                        0x9A => t.character_reference_code = 0x0161,
                        0x9B => t.character_reference_code = 0x203A,
                        0x9C => t.character_reference_code = 0x0153,
                        0x9E => t.character_reference_code = 0x017E,
                        0x9F => t.character_reference_code = 0x0178,
                        else => {},
                    }
                },
                else => {},
            }
            t.clearTempBuffer();
            try t.appendTempBuffer(t.character_reference_code);
            try t.flushCharacterReference();
            t.switchToReturnState();
        },
    }
}

fn skipHtmlWhitespace(t: *Self, input: *[]const u21) !void {
    while (true) switch ((try t.nextInputChar(input)) orelse TREAT_AS_ANYTHING_ELSE) {
        '\t', '\n', 0x0C, ' ' => {},
        else => return t.reconsume(t.state),
    };
}

fn endTagName(t: *Self, input: *[]const u21, next_state: State) !void {
    while (try t.nextInputChar(input)) |current_input_char| {
        switch (current_input_char) {
            '\t', '\n', 0x0C, ' ' => {
                if (t.isAppropriateEndTag()) {
                    t.setState(.BeforeAttributeName);
                    return;
                }
                break;
            },
            '/' => {
                if (t.isAppropriateEndTag()) {
                    t.setState(.SelfClosingStartTag);
                    return;
                }
                break;
            },
            '>' => {
                if (t.isAppropriateEndTag()) {
                    t.setState(.Data);
                    try t.emitCurrentTag();
                    return;
                }
                break;
            },
            'A'...'Z' => |c| {
                try t.appendCurrentTagName(toLowercase(c));
                try t.appendTempBuffer(c);
            },
            'a'...'z' => |c| {
                try t.appendCurrentTagName(c);
                try t.appendTempBuffer(c);
            },
            else => break,
        }
    }

    t.resetCurrentTagName();
    try t.emitString("</");
    try t.emitTempBufferCharacters();
    t.reconsume(next_state);
}

fn attributeValueQuoted(t: *Self, input: *[]const u21, comptime return_state: State) !void {
    const quote = switch (return_state) {
        .AttributeValueSingleQuoted => '\'',
        .AttributeValueDoubleQuoted => '"',
        else => unreachable,
    };

    while (try t.nextInputChar(input)) |current_input_char| {
        switch (current_input_char) {
            quote => {
                try t.finishAttributeValue();
                break;
            },
            '&' => {
                t.toCharacterReferenceState(return_state);
                return;
            },
            0x00 => {
                try t.parseError(.UnexpectedNullCharacter);
                try t.appendCurrentAttributeValue(REPLACEMENT_CHARACTER);
            },
            else => |c| try t.appendCurrentAttributeValue(c),
        }
    } else {
        try t.parseError(.EOFInTag);
        try t.emitEOF();
        return;
    }

    // AfterAttributeValueQuoted
    if (try t.nextInputChar(input)) |current_input_char| {
        switch (current_input_char) {
            '\t', '\n', 0x0C, ' ' => return t.setState(.BeforeAttributeName),
            '/' => return t.setState(.SelfClosingStartTag),
            '>' => {
                try t.emitCurrentTag();
                return t.setState(.Data);
            },
            else => {
                try t.parseError(.MissingWhitespaceBetweenAttributes);
                return t.reconsume(.BeforeAttributeName);
            },
        }
    } else {
        try t.parseError(.EOFInTag);
        try t.emitEOF();
        return;
    }
}

fn eofInDoctype(t: *Self) !void {
    try t.parseError(.EOFInDOCTYPE);
    t.currentDOCTYPETokenForceQuirks();
    try t.emitDOCTYPE();
    try t.emitEOF();
}

const PublicOrSystem = enum { public, system };

fn afterDOCTYPEPublicOrSystemKeyword(t: *Self, input: *[]const u21, public_or_system: PublicOrSystem) !void {
    // AfterDOCTYPEPublicKeyword
    // AfterDOCTYPESystemKeyword
    if (try t.nextInputChar(input)) |current_input_char| {
        switch (current_input_char) {
            '\t', '\n', 0x0C, ' ' => {},
            '"', '\'' => |quote| {
                const err: ParseError = switch (public_or_system) {
                    .public => .MissingWhitespaceAfterDOCTYPEPublicKeyword,
                    .system => .MissingWhitespaceAfterDOCTYPESystemKeyword,
                };
                try t.parseError(err);
                return doctypePublicOrSystemIdentifier(t, input, public_or_system, quote);
            },
            '>' => {
                const err: ParseError = switch (public_or_system) {
                    .public => .MissingDOCTYPEPublicIdentifier,
                    .system => .MissingDOCTYPESystemIdentifier,
                };
                try t.parseError(err);
                t.currentDOCTYPETokenForceQuirks();
                try t.emitDOCTYPE();
                return t.setState(.Data);
            },
            else => {
                const err: ParseError = switch (public_or_system) {
                    .public => .MissingQuoteBeforeDOCTYPEPublicIdentifier,
                    .system => .MissingQuoteBeforeDOCTYPESystemIdentifier,
                };
                try t.parseError(err);
                t.currentDOCTYPETokenForceQuirks();
                return t.reconsume(.BogusDOCTYPE);
            },
        }
    } else {
        return eofInDoctype(t);
    }

    // BeforeDOCTYPEPublicIdentifier
    // BeforeDOCTYPESystemIdentifier
    try skipHtmlWhitespace(t, input);
    if (try t.nextInputChar(input)) |current_input_char| {
        switch (current_input_char) {
            '\t', '\n', 0x0C, ' ' => unreachable,
            '"', '\'' => |quote| return doctypePublicOrSystemIdentifier(t, input, public_or_system, quote),
            '>' => {
                const err: ParseError = switch (public_or_system) {
                    .public => .MissingDOCTYPEPublicIdentifier,
                    .system => .MissingDOCTYPESystemIdentifier,
                };
                try t.parseError(err);
                t.currentDOCTYPETokenForceQuirks();
                try t.emitDOCTYPE();
                return t.setState(.Data);
            },
            else => {
                const err: ParseError = switch (public_or_system) {
                    .public => .MissingQuoteBeforeDOCTYPEPublicIdentifier,
                    .system => .MissingQuoteBeforeDOCTYPESystemIdentifier,
                };
                try t.parseError(err);
                t.currentDOCTYPETokenForceQuirks();
                return t.reconsume(.BogusDOCTYPE);
            },
        }
    } else {
        return eofInDoctype(t);
    }
}

fn doctypePublicOrSystemIdentifier(t: *Self, input: *[]const u21, public_or_system: PublicOrSystem, quote: u21) Error!void {
    // DOCTYPEPublicIdentifierDoubleQuoted
    // DOCTYPEPublicIdentifierSingleQuoted
    // DOCTYPESystemIdentifierDoubleQuoted
    // DOCTYPESystemIdentifierSingleQuoted

    const markNotMissing = switch (public_or_system) {
        .public => markCurrentDOCTYPEPublicIdentifierNotMissing,
        .system => markCurrentDOCTYPESystemIdentifierNotMissing,
    };
    markNotMissing(t);

    const append = switch (public_or_system) {
        .public => appendDOCTYPEPublicIdentifier,
        .system => appendDOCTYPESystemIdentifier,
    };
    while (try t.nextInputChar(input)) |current_input_char| {
        if (current_input_char == quote) {
            const afterIdentifier = switch (public_or_system) {
                .public => afterDOCTYPEPublicIdentifier,
                .system => afterDOCTYPESystemIdentifier,
            };
            return afterIdentifier(t, input);
        } else if (current_input_char == 0x00) {
            try t.parseError(.UnexpectedNullCharacter);
            try append(t, REPLACEMENT_CHARACTER);
        } else if (current_input_char == '>') {
            const err: ParseError = switch (public_or_system) {
                .public => .AbruptDOCTYPEPublicIdentifier,
                .system => .AbruptDOCTYPESystemIdentifier,
            };
            try t.parseError(err);
            t.currentDOCTYPETokenForceQuirks();
            try t.emitDOCTYPE();
            return t.setState(.Data);
        } else {
            try append(t, current_input_char);
        }
    } else {
        return eofInDoctype(t);
    }
}

fn afterDOCTYPEPublicIdentifier(t: *Self, input: *[]const u21) !void {
    if (try t.nextInputChar(input)) |current_input_char| {
        switch (current_input_char) {
            '\t', '\n', 0x0C, ' ' => {},
            '>' => {
                try t.emitDOCTYPE();
                return t.setState(.Data);
            },
            '"', '\'' => |quote| {
                try t.parseError(.MissingWhitespaceBetweenDOCTYPEPublicAndSystemIdentifiers);
                return doctypePublicOrSystemIdentifier(t, input, .system, quote);
            },
            else => {
                try t.parseError(.MissingQuoteBeforeDOCTYPESystemIdentifier);
                t.currentDOCTYPETokenForceQuirks();
                return t.reconsume(.BogusDOCTYPE);
            },
        }
    } else {
        return eofInDoctype(t);
    }

    // BetweenDOCTYPEPublicAndSystemIdentifiers
    try skipHtmlWhitespace(t, input);
    if (try t.nextInputChar(input)) |current_input_char| {
        switch (current_input_char) {
            '\t', '\n', 0x0C, ' ' => unreachable,
            '>' => {
                try t.emitDOCTYPE();
                return t.setState(.Data);
            },
            '"', '\'' => |quote| {
                return doctypePublicOrSystemIdentifier(t, input, .system, quote);
            },
            else => {
                try t.parseError(.MissingQuoteBeforeDOCTYPESystemIdentifier);
                t.currentDOCTYPETokenForceQuirks();
                return t.reconsume(.BogusDOCTYPE);
            },
        }
    } else {
        return eofInDoctype(t);
    }
}

fn afterDOCTYPESystemIdentifier(t: *Self, input: *[]const u21) !void {
    try skipHtmlWhitespace(t, input);
    if (try t.nextInputChar(input)) |current_input_char| {
        switch (current_input_char) {
            '\t', '\n', 0x0C, ' ' => unreachable,
            '>' => {
                try t.emitDOCTYPE();
                return t.setState(.Data);
            },
            else => {
                try t.parseError(.UnexpectedCharacterAfterDOCTYPESystemIdentifier);
                return t.reconsume(.BogusDOCTYPE);
            },
        }
    } else {
        return eofInDoctype(t);
    }
}

fn toLowercase(character: u21) u21 {
    return switch (character) {
        'A'...'Z' => character + 0x20,
        else => unreachable,
    };
}

fn caseSensitiveEql(c1: u21, c2: u21) bool {
    return c1 == c2;
}

fn caseInsensitiveEql(c1: u21, c2: u21) bool {
    const c1_lower = switch (c1) {
        'A'...'Z' => |c| toLowercase(c),
        else => |c| c,
    };
    const c2_lower = switch (c2) {
        'A'...'Z' => |c| toLowercase(c),
        else => |c| c,
    };
    return c1_lower == c2_lower;
}

fn decimalCharToNumber(c: u21) u21 {
    return c - 0x30;
}

fn upperHexCharToNumber(c: u21) u21 {
    return c - 0x37;
}

fn lowerHexCharToNumber(c: u21) u21 {
    return c - 0x57;
}
