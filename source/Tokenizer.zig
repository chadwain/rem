// Copyright (C) 2021-2022 Chadwain Holness
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

test "Tokenizer usage" {
    const allocator = std.testing.allocator;

    const string = "<!doctype><HTML>asdf</body hello=world>";
    const input: []const u21 = &rem.util.utf8DecodeStringComptime(string);

    var all_tokens = std.ArrayList(Token).init(allocator);
    defer {
        for (all_tokens.items) |*t| t.deinit(allocator);
        all_tokens.deinit();
    }

    var error_handler = ErrorHandler{ .report = ArrayList(ParseError).init(allocator) };
    defer error_handler.report.deinit();

    var tokenizer = init(allocator, input, &all_tokens, &error_handler);
    defer tokenizer.deinit();

    var run_frame = async tokenizer.run();
    while (tokenizer.frame) |frame| resume frame;
    try nosuspend await run_frame;

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

const Tokenizer = @This();
const rem = @import("../rem.zig");
const named_characters = @import("./named_characters.zig");
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
input: InputStream,
frame: ?anyframe = null,
last_start_tag_name: []u8 = &[_]u8{},
adjusted_current_node_is_not_in_html_namespace: bool = false,

reached_eof: bool = false,
allocator: Allocator,

tokens: *ArrayList(Token),
error_handler: *ErrorHandler,

/// Create a new HTML5 tokenizer.
pub fn init(
    allocator: Allocator,
    input: []const u21,
    token_sink: *ArrayList(Token),
    error_handler: *ErrorHandler,
) Tokenizer {
    return initState(allocator, input, .Data, token_sink, error_handler);
}

/// Create a new HTML5 tokenizer, and change to a particular state.
pub fn initState(
    allocator: Allocator,
    input: []const u21,
    state: State,
    token_sink: *ArrayList(Token),
    error_handler: *ErrorHandler,
) Tokenizer {
    return Tokenizer{
        .allocator = allocator,
        .input = .{ .chars = input },
        .state = state,
        .tokens = token_sink,
        .error_handler = error_handler,
    };
}

/// Free the memory owned by the tokenizer.
pub fn deinit(tokenizer: *Tokenizer) void {
    tokenizer.allocator.free(tokenizer.last_start_tag_name);
}

/// Runs the tokenizer on the given input.
/// On each iteration, it will output 0 or more tokens to the token sink and 0 or more parse errors to the parse error sink.
/// The memory taken up by these tokens and parse errors are owned by the user.
///
/// Between every suspension of this function, the user must:
///     1. Change the tokenizer's state via setState, if appropriate.
///     2. Call setAdjustedCurrentNodeIsNotInHtmlNamespace with an appropriate value.
///     3. Change the input stream, if appropriate.
pub fn run(tokenizer: *Tokenizer) !void {
    defer tokenizer.frame = null;
    while (!tokenizer.reached_eof) {
        try processInput(tokenizer);
        suspend {
            tokenizer.frame = @frame();
        }
    }
}

pub fn setState(tokenizer: *Tokenizer, new_state: State) void {
    tokenizer.state = new_state;
}

pub fn setAdjustedCurrentNodeIsNotInHtmlNamespace(tokenizer: *Tokenizer, value: bool) void {
    tokenizer.adjusted_current_node_is_not_in_html_namespace = value;
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
    CDATASection,
};

const InputStream = struct {
    chars: []const u21,
    position: usize = 0,
    eof: bool = false,
    reconsume: bool = false,
};

/// Returns the next input character in the input stream.
/// Performs §13.2.3.5 "Preprocessing the input stream" of the HTML standard.
fn next(tokenizer: *Tokenizer) !?u21 {
    const re = tokenizer.input.reconsume;
    const char = tokenizer.nextNoErrorCheck();
    if (!re and char != null) {
        try tokenizer.checkInputCharacterForErrors(char.?);
    }
    return char;
}

fn nextNoErrorCheck(tokenizer: *Tokenizer) ?u21 {
    if (tokenizer.input.position >= tokenizer.input.chars.len) {
        tokenizer.input.eof = true;
        return null;
    }

    var char = tokenizer.input.chars[tokenizer.input.position];
    tokenizer.input.position += 1;
    if (char == '\r') {
        char = '\n';
        if (tokenizer.input.position < tokenizer.input.chars.len and tokenizer.input.chars[tokenizer.input.position] == '\n') {
            tokenizer.input.position += 1;
        }
    }

    tokenizer.input.reconsume = false;

    return char;
}

fn nextIgnoreEof(tokenizer: *Tokenizer) !u21 {
    const char = try tokenizer.next();
    return char orelse TREAT_AS_ANYTHING_ELSE;
}

fn peekIgnoreEof(tokenizer: *Tokenizer) !u21 {
    const char = try tokenizer.nextIgnoreEof();
    tokenizer.back();
    return char;
}

fn back(tokenizer: *Tokenizer) void {
    if (tokenizer.input.eof) {
        tokenizer.input.eof = false;
        return;
    }

    const previous = tokenizer.input.chars[tokenizer.input.position - 1];
    if (previous == '\n' and tokenizer.input.position > 2 and tokenizer.input.chars[tokenizer.input.position - 2] == '\r') {
        tokenizer.input.position -= 2;
    } else {
        tokenizer.input.position -= 1;
    }
}

/// Scans the next characters in the input stream to see if they are equal to `string`.
/// If so, consumes those characters and returns `true`. Otherwise, adds any read characters
/// to the list of replayed characters and returns `false`.
fn consumeCharsIfEql(tokenizer: *Tokenizer, comptime string: []const u8) bool {
    const decoded_string = rem.util.utf8DecodeStringComptime(string);
    return consumeCharsIfEqlGeneric(tokenizer, &decoded_string, caseSensitiveEql);
}

/// Scans the next characters in the input stream to see if they are equal to `string` in
/// a case-insensitive manner.
/// If so, consumes those characters and returns `true`. Otherwise, adds any read characters
/// to the list of replayed characters and returns `false`.
fn consumeCharsIfCaseInsensitiveEql(tokenizer: *Tokenizer, comptime string: []const u8) bool {
    const decoded_string = rem.util.utf8DecodeStringComptime(string);
    return consumeCharsIfEqlGeneric(tokenizer, &decoded_string, caseInsensitiveEql);
}

fn consumeCharsIfEqlGeneric(tokenizer: *Tokenizer, decoded_string: []const u21, comptime eqlFn: fn (u21, u21) bool) bool {
    var index: usize = 0;
    while (index < decoded_string.len) {
        const string_char = decoded_string[index];
        index += 1;
        const next_char = tokenizer.nextNoErrorCheck() orelse break;
        if (!eqlFn(string_char, next_char)) break;
    } else {
        return true;
    }

    while (index > 0) : (index -= 1) {
        tokenizer.back();
    }
    return false;
}

/// Check if a character that was just taken from the input stream
/// is a valid character.
/// Implements §13.2.3.5 "Preprocessing the input stream" of the HTML standard.
fn checkInputCharacterForErrors(tokenizer: *Tokenizer, character: u21) !void {
    switch (character) {
        0xD800...0xDFFF => try tokenizer.parseError(.SurrogateInInputStream),
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
        => try tokenizer.parseError(.NoncharacterInInputStream),
        0x01...0x08,
        0x0B,
        0x0E...0x1F,
        0x7F...0x9F,
        => try tokenizer.parseError(.ControlCharacterInInputStream),
        0x0D => unreachable, // This character would have been turned into 0x0A.
        else => {},
    }
}

fn reconsume(tokenizer: *Tokenizer) void {
    tokenizer.back();
    tokenizer.input.reconsume = true;
}

fn isAppropriateEndTag(tokenizer: *Tokenizer, tag_data: *const TagData) bool {
    // Looking at the tokenizer logic, it seems that is no way to reach this function without current_tag_name
    // having at least 1 ASCII character in it. So we don't have to worry about making sure it has non-zero length.
    //
    // Notice that this gets called from the states that end in "TagName", and that those states
    // can only be reached by reconsuming an ASCII character from an associated "TagOpen" state.
    return std.mem.eql(u8, tokenizer.last_start_tag_name, tag_data.name.items);
}

fn appendComment(tokenizer: *Tokenizer, character: u21) !void {
    var code_units: [4]u8 = undefined;
    const len = try std.unicode.utf8Encode(character, &code_units);
    try tokenizer.current_comment_data.appendSlice(tokenizer.allocator, code_units[0..len]);
}

fn appendCommentString(tokenizer: *Tokenizer, comptime string: []const u8) !void {
    try tokenizer.current_comment_data.appendSlice(tokenizer.allocator, string);
}

fn appendChar(data: *ArrayList(u8), character: u21) !void {
    var code_units: [4]u8 = undefined;
    const len = try std.unicode.utf8Encode(character, &code_units);
    try data.appendSlice(code_units[0..len]);
}

fn appendCharUnmanaged(data: *ArrayListUnmanaged(u8), allocator: Allocator, character: u21) !void {
    var code_units: [4]u8 = undefined;
    const len = try std.unicode.utf8Encode(character, &code_units);
    try data.appendSlice(allocator, code_units[0..len]);
}

fn appendString(data: *ArrayList(u8), string: []const u8) !void {
    try data.appendSlice(string);
}

fn emitCharacter(tokenizer: *Tokenizer, character: u21) !void {
    try tokenizer.tokens.append(Token{ .character = .{ .data = character } });
}

fn emitString(tokenizer: *Tokenizer, comptime string: []const u8) !void {
    for (rem.util.utf8DecodeStringComptime(string)) |character| {
        try emitCharacter(tokenizer, character);
    }
}

fn emitComment(tokenizer: *Tokenizer) !void {
    const data = tokenizer.current_comment_data.toOwnedSlice(tokenizer.allocator);
    errdefer tokenizer.allocator.free(data);
    try tokenizer.tokens.append(Token{ .comment = .{ .data = data } });
}

fn emitCommentData(tokenizer: *Tokenizer, comment_data: []const u8) !void {
    try tokenizer.tokens.append(Token{ .comment = .{ .data = comment_data } });
}

fn emitEOF(tokenizer: *Tokenizer) !void {
    tokenizer.reached_eof = true;
    try tokenizer.tokens.append(Token{ .eof = .{} });
}

fn parseError(tokenizer: *Tokenizer, err: ParseError) !void {
    try tokenizer.error_handler.sendError(err);
}

fn adjustedCurrentNodeIsNotInHtmlNamespace(tokenizer: *Tokenizer) bool {
    return tokenizer.adjusted_current_node_is_not_in_html_namespace;
}

fn processInput(tokenizer: *Tokenizer) !void {
    switch (tokenizer.state) {
        .Data => {
            while (try tokenizer.next()) |char| switch (char) {
                '&' => try characterReference(tokenizer, null),
                '<' => return tagOpen(tokenizer),
                0x00 => {
                    try tokenizer.parseError(.UnexpectedNullCharacter);
                    try tokenizer.emitCharacter(0x00);
                },
                else => |c| try tokenizer.emitCharacter(c),
            } else {
                return tokenizer.emitEOF();
            }
        },
        .RAWTEXT => {
            while (try tokenizer.next()) |char| switch (char) {
                0x00 => {
                    try tokenizer.parseError(.UnexpectedNullCharacter);
                    try tokenizer.emitCharacter(REPLACEMENT_CHARACTER);
                },
                else => |c| try tokenizer.emitCharacter(c),
                '<' => {
                    // RAWTEXTLessThanSign
                    if ((try tokenizer.nextIgnoreEof()) != '/') {
                        try tokenizer.emitCharacter('<');
                        tokenizer.reconsume();
                        continue;
                    }

                    return nonDataEndTagOpen(tokenizer);
                },
            } else {
                return tokenizer.emitEOF();
            }
        },
        .PLAINTEXT => while (true) {
            if (try tokenizer.next()) |char| switch (char) {
                0x00 => {
                    try tokenizer.parseError(.UnexpectedNullCharacter);
                    try tokenizer.emitCharacter(REPLACEMENT_CHARACTER);
                },
                else => |c| try tokenizer.emitCharacter(c),
            } else {
                return tokenizer.emitEOF();
            }
        },
        .RCDATA => {
            while (try tokenizer.next()) |char| {
                switch (char) {
                    '&' => try characterReference(tokenizer, null),
                    0x00 => {
                        try tokenizer.parseError(.UnexpectedNullCharacter);
                        try tokenizer.emitCharacter(REPLACEMENT_CHARACTER);
                    },
                    else => |c| try tokenizer.emitCharacter(c),
                    '<' => {
                        // RCDATALessThanSign
                        if ((try tokenizer.nextIgnoreEof()) != '/') {
                            try tokenizer.emitCharacter('<');
                            tokenizer.reconsume();
                            continue;
                        }

                        return nonDataEndTagOpen(tokenizer);
                    },
                }
            } else {
                return tokenizer.emitEOF();
            }
        },
        .ScriptData => return scriptData(tokenizer),
        .CDATASection => {
            while (try tokenizer.next()) |char| switch (char) {
                ']' => {
                    if (consumeCharsIfEql(tokenizer, "]>")) {
                        return tokenizer.setState(.Data);
                    } else {
                        try tokenizer.emitCharacter(']');
                    }
                },
                else => |c| try tokenizer.emitCharacter(c),
            } else {
                try tokenizer.parseError(.EOFInCDATA);
                try tokenizer.emitEOF();
            }
        },
    }
}

fn characterReference(tokenizer: *Tokenizer, tag_data: ?*TagData) !void {
    var buffer = ArrayListUnmanaged(u21){};
    defer buffer.deinit(tokenizer.allocator);
    try buffer.append(tokenizer.allocator, '&');

    switch (try tokenizer.nextIgnoreEof()) {
        '0'...'9', 'A'...'Z', 'a'...'z' => {
            tokenizer.back();
            return namedCharacterReference(tokenizer, tag_data, &buffer);
        },
        '#' => {
            try buffer.append(tokenizer.allocator, '#');
            return numericCharacterReference(tokenizer, tag_data, &buffer);
        },
        else => {
            tokenizer.back();
            return flushCharacterReference(tokenizer, tag_data, &buffer);
        },
    }
}

fn namedCharacterReference(tokenizer: *Tokenizer, tag_data: ?*TagData, buffer: *ArrayListUnmanaged(u21)) !void {
    const chars = try findNamedCharacterReference(tokenizer, buffer);
    const match_found = chars[0] != null;
    if (match_found) {
        const historical_reasons = if (tag_data != null and buffer.items[buffer.items.len - 1] != ';')
            switch (try tokenizer.peekIgnoreEof()) {
                '=', '0'...'9', 'A'...'Z', 'a'...'z' => true,
                else => false,
            }
        else
            false;

        if (historical_reasons) {
            return flushCharacterReference(tokenizer, tag_data, buffer);
        } else {
            if (buffer.items[buffer.items.len - 1] != ';') {
                try tokenizer.parseError(.MissingSemicolonAfterCharacterReference);
            }
            buffer.clearRetainingCapacity();
            try buffer.append(tokenizer.allocator, chars[0].?);
            if (chars[1]) |c| try buffer.append(tokenizer.allocator, c);
            return flushCharacterReference(tokenizer, tag_data, buffer);
        }
    } else {
        try flushCharacterReference(tokenizer, tag_data, buffer);
        return ambiguousAmpersand(tokenizer, tag_data, buffer);
    }
}

fn findNamedCharacterReference(tokenizer: *Tokenizer, buffer: *ArrayListUnmanaged(u21)) !named_characters.Value {
    var last_index_with_value = named_characters.root_index;
    var entry = named_characters.root_index.entry();
    var character_reference_consumed_codepoints_count: usize = 1;

    while (true) {
        const character = tokenizer.nextNoErrorCheck() orelse {
            tokenizer.back();
            break;
        };
        try buffer.append(tokenizer.allocator, character);
        const child_index = entry.findChild(character) orelse break;
        entry = child_index.entry();

        if (entry.has_children) {
            if (entry.has_value) {
                // Partial match found.
                character_reference_consumed_codepoints_count = buffer.items.len;
                last_index_with_value = child_index;
            }
        } else {
            // Complete match found.
            character_reference_consumed_codepoints_count = buffer.items.len;
            last_index_with_value = child_index;
            break;
        }
    }

    while (buffer.items.len > character_reference_consumed_codepoints_count) {
        tokenizer.back();
        buffer.items.len -= 1;
    }

    // There is no need to check the consumed characters for errors (controls, surrogates, noncharacters)
    // beacuse we've just determined that they form a valid character reference.
    return last_index_with_value.value();
}

fn ambiguousAmpersand(tokenizer: *Tokenizer, tag_data: ?*TagData, buffer: *ArrayListUnmanaged(u21)) !void {
    while (true) switch (try tokenizer.nextIgnoreEof()) {
        '0'...'9', 'A'...'Z', 'a'...'z' => |c| try buffer.append(tokenizer.allocator, c),
        ';' => break try tokenizer.parseError(.UnknownNamedCharacterReference),
        else => break,
    };

    try flushCharacterReference(tokenizer, tag_data, buffer);
    tokenizer.reconsume();
}

fn numericCharacterReference(tokenizer: *Tokenizer, tag_data: ?*TagData, buffer: *ArrayListUnmanaged(u21)) !void {
    var character_reference_code: u21 = 0;
    switch (try tokenizer.nextIgnoreEof()) {
        'x', 'X' => |x| {
            try buffer.append(tokenizer.allocator, x);

            // HexadecimalCharacterReferenceStart
            switch (try tokenizer.nextIgnoreEof()) {
                '0'...'9', 'A'...'F', 'a'...'f' => {
                    tokenizer.reconsume();

                    // HexadecimalCharacterReference
                    while (true) switch (try tokenizer.nextIgnoreEof()) {
                        '0'...'9' => |c| characterReferenceCodeAddDigit(&character_reference_code, 16, decimalCharToNumber(c)),
                        'A'...'F' => |c| characterReferenceCodeAddDigit(&character_reference_code, 16, upperHexCharToNumber(c)),
                        'a'...'f' => |c| characterReferenceCodeAddDigit(&character_reference_code, 16, lowerHexCharToNumber(c)),
                        ';' => break,
                        else => {
                            try tokenizer.parseError(.MissingSemicolonAfterCharacterReference);
                            break tokenizer.reconsume();
                        },
                    };
                },
                else => return noDigitsInNumericCharacterReference(tokenizer, tag_data, buffer),
            }
        },
        // DecimalCharacterReferenceStart
        '0'...'9' => {
            tokenizer.reconsume();

            // DecimalCharacterReference
            while (true) switch (try tokenizer.nextIgnoreEof()) {
                '0'...'9' => |c| characterReferenceCodeAddDigit(&character_reference_code, 10, decimalCharToNumber(c)),
                ';' => break,
                else => {
                    try tokenizer.parseError(.MissingSemicolonAfterCharacterReference);
                    break tokenizer.reconsume();
                },
            };
        },
        else => return noDigitsInNumericCharacterReference(tokenizer, tag_data, buffer),
    }

    // NumericCharacterReferenceEnd
    switch (character_reference_code) {
        0x00 => {
            try tokenizer.parseError(.NullCharacterReference);
            character_reference_code = REPLACEMENT_CHARACTER;
        },
        0x10FFFF + 1...std.math.maxInt(@TypeOf(character_reference_code)) => {
            try tokenizer.parseError(.CharacterReferenceOutsideUnicodeRange);
            character_reference_code = REPLACEMENT_CHARACTER;
        },
        0xD800...0xDFFF => {
            try tokenizer.parseError(.SurrogateCharacterReference);
            character_reference_code = REPLACEMENT_CHARACTER;
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
        => try tokenizer.parseError(.NoncharacterCharacterReference),
        0x01...0x08, 0x0B, 0x0D...0x1F => try tokenizer.parseError(.ControlCharacterReference),
        0x7F...0x9F => |c| {
            try tokenizer.parseError(.ControlCharacterReference);
            switch (c) {
                0x80 => character_reference_code = 0x20AC,
                0x82 => character_reference_code = 0x201A,
                0x83 => character_reference_code = 0x0192,
                0x84 => character_reference_code = 0x201E,
                0x85 => character_reference_code = 0x2026,
                0x86 => character_reference_code = 0x2020,
                0x87 => character_reference_code = 0x2021,
                0x88 => character_reference_code = 0x02C6,
                0x89 => character_reference_code = 0x2030,
                0x8A => character_reference_code = 0x0160,
                0x8B => character_reference_code = 0x2039,
                0x8C => character_reference_code = 0x0152,
                0x8E => character_reference_code = 0x017D,
                0x91 => character_reference_code = 0x2018,
                0x92 => character_reference_code = 0x2019,
                0x93 => character_reference_code = 0x201C,
                0x94 => character_reference_code = 0x201D,
                0x95 => character_reference_code = 0x2022,
                0x96 => character_reference_code = 0x2013,
                0x97 => character_reference_code = 0x2014,
                0x98 => character_reference_code = 0x02DC,
                0x99 => character_reference_code = 0x2122,
                0x9A => character_reference_code = 0x0161,
                0x9B => character_reference_code = 0x203A,
                0x9C => character_reference_code = 0x0153,
                0x9E => character_reference_code = 0x017E,
                0x9F => character_reference_code = 0x0178,
                else => {},
            }
        },
        else => {},
    }

    buffer.clearRetainingCapacity();
    try buffer.append(tokenizer.allocator, character_reference_code);
    try flushCharacterReference(tokenizer, tag_data, buffer);
}

fn characterReferenceCodeAddDigit(character_reference_code: *u21, comptime base: comptime_int, digit: u21) void {
    character_reference_code.* = character_reference_code.* *| base +| digit;
}

fn noDigitsInNumericCharacterReference(tokenizer: *Tokenizer, tag_data: ?*TagData, buffer: *ArrayListUnmanaged(u21)) !void {
    try tokenizer.parseError(.AbsenceOfDigitsInNumericCharacterReference);
    try flushCharacterReference(tokenizer, tag_data, buffer);
    tokenizer.reconsume();
}

fn flushCharacterReference(tokenizer: *Tokenizer, tag_data_optional: ?*TagData, buffer: *ArrayListUnmanaged(u21)) !void {
    if (tag_data_optional) |tag_data| {
        for (buffer.items) |character| {
            try tag_data.appendCurrentAttributeValue(character);
        }
    } else {
        for (buffer.items) |character| {
            try tokenizer.emitCharacter(character);
        }
    }
    buffer.clearRetainingCapacity();
}

fn markupDeclarationOpen(tokenizer: *Tokenizer) !void {
    if (tokenizer.consumeCharsIfEql("--")) {
        return comment(tokenizer);
    } else if (tokenizer.consumeCharsIfCaseInsensitiveEql("DOCTYPE")) {
        return doctype(tokenizer);
    } else if (tokenizer.consumeCharsIfEql("[CDATA[")) {
        if (tokenizer.adjustedCurrentNodeIsNotInHtmlNamespace()) {
            tokenizer.setState(.CDATASection);
        } else {
            try tokenizer.parseError(.CDATAInHtmlContent);
            for ("[CDATA[") |_| tokenizer.back();
            return bogusComment(tokenizer);
        }
    } else {
        try tokenizer.parseError(.IncorrectlyOpenedComment);
        return bogusComment(tokenizer);
    }
}

fn bogusComment(tokenizer: *Tokenizer) !void {
    var comment_data = ArrayListUnmanaged(u8){};
    defer comment_data.deinit(tokenizer.allocator);

    while (try tokenizer.next()) |char| switch (char) {
        '>' => break,
        0x00 => {
            try tokenizer.parseError(.UnexpectedNullCharacter);
            try appendCharUnmanaged(&comment_data, tokenizer.allocator, REPLACEMENT_CHARACTER);
        },
        else => |c| try appendCharUnmanaged(&comment_data, tokenizer.allocator, c),
    } else {
        tokenizer.back();
    }

    try tokenizer.emitCommentData(comment_data.toOwnedSlice(tokenizer.allocator));
}

const TagData = struct {
    name: ArrayListUnmanaged(u8) = .{},
    attributes: Attributes = .{},
    current_attribute_value_result_location: ?*[]const u8 = undefined,
    buffer: ArrayListUnmanaged(u8) = .{},
    self_closing: bool = false,
    start_or_end: StartOrEnd,
    allocator: Allocator,

    const StartOrEnd = enum { Start, End };

    fn init(start_or_end: StartOrEnd, allocator: Allocator) TagData {
        return .{ .start_or_end = start_or_end, .allocator = allocator };
    }

    fn deinit(tag_data: *TagData) void {
        tag_data.name.deinit(tag_data.allocator);
        tag_data.buffer.deinit(tag_data.allocator);
        var iterator = tag_data.attributes.iterator();
        while (iterator.next()) |attr| {
            tag_data.allocator.free(attr.key_ptr.*);
            tag_data.allocator.free(attr.value_ptr.*);
        }
        tag_data.attributes.deinit(tag_data.allocator);
    }

    fn appendName(tag_data: *TagData, char: u21) !void {
        try appendCharUnmanaged(&tag_data.name, tag_data.allocator, char);
    }

    fn appendCurrentAttributeName(tag_data: *TagData, char: u21) !void {
        try appendCharUnmanaged(&tag_data.buffer, tag_data.allocator, char);
    }

    fn appendCurrentAttributeValue(tag_data: *TagData, char: u21) !void {
        try appendCharUnmanaged(&tag_data.buffer, tag_data.allocator, char);
    }

    fn finishAttributeName(tag_data: *TagData, tokenizer: *Tokenizer) !void {
        const attribute_name = tag_data.buffer.toOwnedSlice(tag_data.allocator);
        errdefer tag_data.allocator.free(attribute_name);

        const get_result = try tag_data.attributes.getOrPut(tag_data.allocator, attribute_name);

        if (get_result.found_existing) {
            try tokenizer.parseError(.DuplicateAttribute);
            tag_data.allocator.free(attribute_name);
            tag_data.current_attribute_value_result_location = null;
        } else {
            get_result.value_ptr.* = "";
            tag_data.current_attribute_value_result_location = get_result.value_ptr;
        }
    }

    fn finishAttributeValue(tag_data: *TagData) void {
        const attribute_value = tag_data.buffer.toOwnedSlice(tag_data.allocator);
        if (tag_data.current_attribute_value_result_location) |ptr| {
            ptr.* = attribute_value;
        } else {
            tag_data.allocator.free(attribute_value);
        }
        tag_data.current_attribute_value_result_location = undefined;
    }
};

fn emitTag(tokenizer: *Tokenizer, tag_data: *TagData) !void {
    const name = tag_data.name.toOwnedSlice(tag_data.allocator);
    errdefer tag_data.allocator.free(name);

    switch (tag_data.start_or_end) {
        .Start => {
            tokenizer.last_start_tag_name = try tokenizer.allocator.realloc(tokenizer.last_start_tag_name, name.len);
            std.mem.copy(u8, tokenizer.last_start_tag_name, name);
            const token = Token{ .start_tag = .{
                .name = name,
                .attributes = tag_data.attributes,
                .self_closing = tag_data.self_closing,
            } };
            tag_data.attributes = .{};
            try tokenizer.tokens.append(token);
        },
        .End => {
            // TODO: Don't store any attributes in the first place
            if (tag_data.attributes.count() > 0) {
                var iterator = tag_data.attributes.iterator();
                while (iterator.next()) |attr| {
                    tag_data.allocator.free(attr.key_ptr.*);
                    tag_data.allocator.free(attr.value_ptr.*);
                }
                tag_data.attributes.clearRetainingCapacity();
                try tokenizer.parseError(.EndTagWithAttributes);
            }

            if (tag_data.self_closing) {
                try tokenizer.parseError(.EndTagWithTrailingSolidus);
            }

            try tokenizer.tokens.append(Token{ .end_tag = .{
                .name = name,
            } });
        },
    }
}

fn tagOpen(tokenizer: *Tokenizer) !void {
    if (try tokenizer.next()) |char| switch (char) {
        '!' => return markupDeclarationOpen(tokenizer),
        '/' => return endTagOpen(tokenizer),
        'A'...'Z', 'a'...'z' => {
            tokenizer.reconsume();
            return tagName(tokenizer, .Start);
        },
        '?' => {
            try tokenizer.parseError(.UnexpectedQuestionMarkInsteadOfTagName);
            tokenizer.reconsume();
            return bogusComment(tokenizer);
        },
        else => {
            try tokenizer.parseError(.InvalidFirstCharacterOfTagName);
            try tokenizer.emitCharacter('<');
            return tokenizer.reconsume();
        },
    } else {
        try tokenizer.parseError(.EOFBeforeTagName);
        try tokenizer.emitCharacter('<');
        try tokenizer.emitEOF();
    }
}

fn endTagOpen(tokenizer: *Tokenizer) !void {
    if (try tokenizer.next()) |char| {
        switch (char) {
            'A'...'Z', 'a'...'z' => {
                tokenizer.reconsume();
                return tagName(tokenizer, .End);
            },
            '>' => try tokenizer.parseError(.MissingEndTagName),
            else => {
                try tokenizer.parseError(.InvalidFirstCharacterOfTagName);
                tokenizer.reconsume();
                return bogusComment(tokenizer);
            },
        }
    } else {
        try tokenizer.parseError(.EOFBeforeTagName);
        try tokenizer.emitString("</");
        try tokenizer.emitEOF();
    }
}

fn nonDataEndTagOpen(tokenizer: *Tokenizer) !void {
    switch (try tokenizer.nextIgnoreEof()) {
        'A'...'Z', 'a'...'z' => {
            tokenizer.reconsume();
            return nonDataEndTagName(tokenizer);
        },
        else => {
            try tokenizer.emitString("</");
            tokenizer.reconsume();
        },
    }
}

fn nonDataEndTagName(tokenizer: *Tokenizer) !void {
    var tag_data = TagData.init(.End, tokenizer.allocator);
    defer tag_data.deinit();

    while (try tokenizer.next()) |char| {
        switch (char) {
            '\t', '\n', 0x0C, ' ' => {
                if (tokenizer.isAppropriateEndTag(&tag_data)) {
                    return attribute(tokenizer, &tag_data);
                }
                break;
            },
            '/' => {
                if (tokenizer.isAppropriateEndTag(&tag_data)) {
                    return selfClosingStartTag(tokenizer, &tag_data);
                }
                break;
            },
            '>' => {
                if (tokenizer.isAppropriateEndTag(&tag_data)) {
                    try emitTag(tokenizer, &tag_data);
                    return tokenizer.setState(.Data);
                }
                break;
            },
            'A'...'Z', 'a'...'z' => |c| try tag_data.appendName(toLowercase(c)),
            else => break,
        }
    }

    try tokenizer.emitString("</");
    for (tag_data.name.items) |c| try tokenizer.emitCharacter(c);
    tokenizer.reconsume();
}

fn tagName(tokenizer: *Tokenizer, start_or_end: TagData.StartOrEnd) !void {
    var tag_data = TagData.init(start_or_end, tokenizer.allocator);
    defer tag_data.deinit();

    while (try tokenizer.next()) |current_input_char| {
        switch (current_input_char) {
            '\t', '\n', 0x0C, ' ' => return attribute(tokenizer, &tag_data),
            '/' => return selfClosingStartTag(tokenizer, &tag_data),
            '>' => return try emitTag(tokenizer, &tag_data),
            0x00 => {
                try tokenizer.parseError(.UnexpectedNullCharacter);
                try tag_data.appendName(REPLACEMENT_CHARACTER);
            },
            else => |c| try tag_data.appendName(toLowercase(c)),
        }
    } else {
        try tokenizer.parseError(.EOFInTag);
        try tokenizer.emitEOF();
    }
}

const AttributeState = enum {
    BeforeName,
    Name,
    Value,
    Slash,
    Done,
    Eof,
};

fn attribute(tokenizer: *Tokenizer, tag_data: *TagData) !void {
    return attributeLoop(tokenizer, tag_data, .BeforeName);
}

fn selfClosingStartTag(tokenizer: *Tokenizer, tag_data: *TagData) !void {
    return attributeLoop(tokenizer, tag_data, .Slash);
}

fn attributeLoop(tokenizer: *Tokenizer, tag_data: *TagData, initial_state: AttributeState) !void {
    var state: AttributeState = initial_state;
    while (true) {
        switch (state) {
            .BeforeName => state = try beforeAttributeName(tokenizer, tag_data),
            .Name => state = try attributeName(tokenizer, tag_data),
            .Value => state = try beforeAttributeValue(tokenizer, tag_data),
            .Slash => state = try attributeSlash(tokenizer, tag_data),
            .Done => break try emitTag(tokenizer, tag_data),
            .Eof => break try tokenizer.emitEOF(),
        }
    }
}

fn beforeAttributeName(tokenizer: *Tokenizer, tag_data: *TagData) !AttributeState {
    // Make end-of-file (null) be handled the same as '>'
    while (true) switch ((try tokenizer.next()) orelse '>') {
        '\t', '\n', 0x0C, ' ' => {},
        '/', '>' => {
            tokenizer.reconsume();
            return try afterAttributeName(tokenizer);
        },
        '=' => {
            try tokenizer.parseError(.UnexpectedEqualsSignBeforeAttributeName);
            try tag_data.appendCurrentAttributeName('=');
            return .Name;
        },
        else => {
            tokenizer.reconsume();
            return .Name;
        },
    };
}

fn attributeName(tokenizer: *Tokenizer, tag_data: *TagData) !AttributeState {
    // Make end-of-file (null) be handled the same as '>'
    while (true) switch ((try tokenizer.next()) orelse '>') {
        '\t', '\n', 0x0C, ' ', '/', '>' => {
            try tag_data.finishAttributeName(tokenizer);
            tokenizer.reconsume();
            return try afterAttributeName(tokenizer);
        },
        '=' => {
            try tag_data.finishAttributeName(tokenizer);
            return .Value;
        },
        0x00 => {
            try tokenizer.parseError(.UnexpectedNullCharacter);
            try tag_data.appendCurrentAttributeName(REPLACEMENT_CHARACTER);
        },
        '"', '\'', '<' => |c| {
            try tokenizer.parseError(.UnexpectedCharacterInAttributeName);
            try tag_data.appendCurrentAttributeName(c);
        },
        else => |c| try tag_data.appendCurrentAttributeName(toLowercase(c)),
    };
}

fn afterAttributeName(tokenizer: *Tokenizer) !AttributeState {
    while (true) {
        if (try tokenizer.next()) |current_input_char| {
            switch (current_input_char) {
                '\t', '\n', 0x0C, ' ' => {},
                '/' => return .Slash,
                '=' => return .Value,
                '>' => return attributeEnd(tokenizer),
                else => {
                    tokenizer.reconsume();
                    return AttributeState.Name;
                },
            }
        } else {
            return try eofInTag(tokenizer);
        }
    }
}

fn beforeAttributeValue(tokenizer: *Tokenizer, tag_data: *TagData) !AttributeState {
    while (true) switch (try tokenizer.nextIgnoreEof()) {
        '\t', '\n', 0x0C, ' ' => {},
        '"' => return attributeValueQuoted(tokenizer, tag_data, .Double),
        '\'' => return attributeValueQuoted(tokenizer, tag_data, .Single),
        '>' => {
            try tokenizer.parseError(.MissingAttributeValue);
            return attributeEnd(tokenizer);
        },
        else => {
            tokenizer.reconsume();
            return attributeValueUnquoted(tokenizer, tag_data);
        },
    };
}

const QuoteStyle = enum { Single, Double };

fn attributeValueQuoted(tokenizer: *Tokenizer, tag_data: *TagData, comptime quote_style: QuoteStyle) !AttributeState {
    const quote = switch (quote_style) {
        .Single => '\'',
        .Double => '"',
    };

    while (try tokenizer.next()) |current_input_char| {
        switch (current_input_char) {
            quote => break tag_data.finishAttributeValue(),
            '&' => try characterReference(tokenizer, tag_data),
            0x00 => {
                try tokenizer.parseError(.UnexpectedNullCharacter);
                try tag_data.appendCurrentAttributeValue(REPLACEMENT_CHARACTER);
            },
            else => |c| try tag_data.appendCurrentAttributeValue(c),
        }
    } else {
        return try eofInTag(tokenizer);
    }

    // AfterAttributeValueQuoted
    if (try tokenizer.next()) |current_input_char| {
        switch (current_input_char) {
            '\t', '\n', 0x0C, ' ' => return AttributeState.BeforeName,
            '/' => return AttributeState.Slash,
            '>' => return attributeEnd(tokenizer),
            else => {
                try tokenizer.parseError(.MissingWhitespaceBetweenAttributes);
                tokenizer.reconsume();
                return AttributeState.BeforeName;
            },
        }
    } else {
        return try eofInTag(tokenizer);
    }
}

fn attributeValueUnquoted(tokenizer: *Tokenizer, tag_data: *TagData) !AttributeState {
    while (try tokenizer.next()) |current_input_char| switch (current_input_char) {
        '\t', '\n', 0x0C, ' ' => {
            tag_data.finishAttributeValue();
            return AttributeState.BeforeName;
        },
        '&' => try characterReference(tokenizer, tag_data),
        '>' => {
            tag_data.finishAttributeValue();
            return attributeEnd(tokenizer);
        },
        0x00 => {
            try tokenizer.parseError(.UnexpectedNullCharacter);
            try tag_data.appendCurrentAttributeValue(REPLACEMENT_CHARACTER);
        },
        '"', '\'', '<', '=', '`' => |c| {
            try tokenizer.parseError(.UnexpectedCharacterInUnquotedAttributeValue);
            try tag_data.appendCurrentAttributeValue(c);
        },
        else => |c| try tag_data.appendCurrentAttributeValue(c),
    } else {
        return try eofInTag(tokenizer);
    }
}

fn attributeSlash(tokenizer: *Tokenizer, tag_data: *TagData) !AttributeState {
    if (try tokenizer.next()) |current_input_char| {
        switch (current_input_char) {
            '>' => {
                tag_data.self_closing = true;
                return attributeEnd(tokenizer);
            },
            else => {
                try tokenizer.parseError(.UnexpectedSolidusInTag);
                tokenizer.reconsume();
                return AttributeState.BeforeName;
            },
        }
    } else {
        return try eofInTag(tokenizer);
    }
}

fn attributeEnd(tokenizer: *Tokenizer) AttributeState {
    tokenizer.setState(.Data);
    return .Done;
}

fn eofInTag(tokenizer: *Tokenizer) !AttributeState {
    try tokenizer.parseError(.EOFInTag);
    return .Eof;
}

const CommentState = enum {
    Normal,
    EndDash,
    End,
    Done,
};

fn comment(tokenizer: *Tokenizer) !void {
    var comment_data = ArrayList(u8).init(tokenizer.allocator);
    errdefer comment_data.deinit();

    var state = try commentStart(tokenizer, &comment_data);
    while (true) {
        switch (state) {
            .Normal => state = try commentNormal(tokenizer, &comment_data),
            .EndDash => state = try commentEndDash(tokenizer, &comment_data),
            .End => state = try commentEnd(tokenizer, &comment_data),
            .Done => break,
        }
    }

    try tokenizer.emitCommentData(comment_data.toOwnedSlice());
}

fn commentStart(tokenizer: *Tokenizer, comment_data: *ArrayList(u8)) !CommentState {
    switch (try tokenizer.nextIgnoreEof()) {
        '-' => {
            // CommentStartDash
            switch ((try tokenizer.next()) orelse return try eofInComment(tokenizer)) {
                '-' => return .End,
                '>' => return try abruptCommentClose(tokenizer),
                else => {
                    try comment_data.append('-');
                    tokenizer.reconsume();
                    return .Normal;
                },
            }
        },
        '>' => return try abruptCommentClose(tokenizer),
        else => {
            tokenizer.reconsume();
            return .Normal;
        },
    }
}

fn commentNormal(tokenizer: *Tokenizer, comment_data: *ArrayList(u8)) !CommentState {
    while (try tokenizer.next()) |current_input_char| switch (current_input_char) {
        '<' => {
            try comment_data.append('<');

            // CommentLessThanSign
            while (true) switch (try tokenizer.nextIgnoreEof()) {
                '!' => {
                    try comment_data.append('!');

                    // CommentLessThanSignBang
                    if ((try tokenizer.nextIgnoreEof()) != '-') {
                        tokenizer.reconsume();
                        break;
                    }

                    // CommentLessThanSignBangDash
                    if ((try tokenizer.nextIgnoreEof()) != '-') {
                        tokenizer.reconsume();
                        return CommentState.EndDash;
                    }

                    // CommentLessThanSignBangDashDash
                    // Make end-of-file (null) be handled the same as '>'
                    if ((try tokenizer.next()) orelse '>' != '>') {
                        try tokenizer.parseError(.NestedComment);
                    }
                    tokenizer.reconsume();
                    return .End;
                },
                '<' => try comment_data.append('<'),
                else => {
                    tokenizer.reconsume();
                    break;
                },
            };
        },
        '-' => return .EndDash,
        0x00 => {
            try tokenizer.parseError(.UnexpectedNullCharacter);
            try appendChar(comment_data, REPLACEMENT_CHARACTER);
        },
        else => |c| try appendChar(comment_data, c),
    } else {
        return try eofInComment(tokenizer);
    }
}

fn commentEndDash(tokenizer: *Tokenizer, comment_data: *ArrayList(u8)) !CommentState {
    switch ((try tokenizer.next()) orelse return try eofInComment(tokenizer)) {
        '-' => return CommentState.End,
        else => {
            try comment_data.append('-');
            tokenizer.reconsume();
            return CommentState.Normal;
        },
    }
}

fn commentEnd(tokenizer: *Tokenizer, comment_data: *ArrayList(u8)) !CommentState {
    while (try tokenizer.next()) |current_input_char| switch (current_input_char) {
        '>' => return .Done,
        '!' => return try commentEndBang(tokenizer, comment_data),
        '-' => try comment_data.append('-'),
        else => {
            try comment_data.appendSlice("--");
            tokenizer.reconsume();
            return CommentState.Normal;
        },
    } else {
        return try eofInComment(tokenizer);
    }
}

fn commentEndBang(tokenizer: *Tokenizer, comment_data: *ArrayList(u8)) !CommentState {
    switch ((try tokenizer.next()) orelse return try eofInComment(tokenizer)) {
        '-' => {
            try comment_data.appendSlice("--!");
            return CommentState.EndDash;
        },
        '>' => return incorrectlyClosedComment(tokenizer),
        else => {
            try comment_data.appendSlice("--!");
            tokenizer.reconsume();
            return CommentState.Normal;
        },
    }
}

fn eofInComment(tokenizer: *Tokenizer) !CommentState {
    try tokenizer.parseError(.EOFInComment);
    tokenizer.back();
    return .Done;
}

fn abruptCommentClose(tokenizer: *Tokenizer) !CommentState {
    try tokenizer.parseError(.AbruptClosingOfEmptyComment);
    return .Done;
}

fn incorrectlyClosedComment(tokenizer: *Tokenizer) !CommentState {
    try tokenizer.parseError(.IncorrectlyClosedComment);
    return .Done;
}

const DoctypeState = enum {
    Done,
    Eof,
};

const DoctypeData = struct {
    name: ?ArrayList(u8) = null,
    public_identifier: ?ArrayList(u8) = null,
    system_identifier: ?ArrayList(u8) = null,
    force_quirks: bool = false,

    fn deinit(doctype_data: *DoctypeData) void {
        if (doctype_data.name) |name| name.deinit();
        if (doctype_data.public_identifier) |public_identifier| public_identifier.deinit();
        if (doctype_data.system_identifier) |system_identifier| system_identifier.deinit();
    }
};

fn doctype(tokenizer: *Tokenizer) !void {
    var doctype_data = DoctypeData{};
    defer doctype_data.deinit();

    const state = try doctypeStart(tokenizer, &doctype_data);

    const doctype_token = Token{ .doctype = .{
        .name = if (doctype_data.name) |*name| name.toOwnedSlice() else null,
        .public_identifier = if (doctype_data.public_identifier) |*public_identifier| public_identifier.toOwnedSlice() else null,
        .system_identifier = if (doctype_data.system_identifier) |*system_identifier| system_identifier.toOwnedSlice() else null,
        .force_quirks = doctype_data.force_quirks,
    } };
    try tokenizer.tokens.append(doctype_token);

    if (state == .Eof) {
        try tokenizer.emitEOF();
    }
}

fn doctypeStart(tokenizer: *Tokenizer, doctype_data: *DoctypeData) !DoctypeState {
    if (try tokenizer.next()) |current_input_char| {
        switch (current_input_char) {
            '\t', '\n', 0x0C, ' ' => {},
            '>' => tokenizer.reconsume(),
            else => {
                try tokenizer.parseError(.MissingWhitespaceBeforeDOCTYPEName);
                tokenizer.reconsume();
            },
        }
        return try beforeDoctypeName(tokenizer, doctype_data);
    } else {
        return try eofInDoctype(tokenizer, doctype_data);
    }
}

fn beforeDoctypeName(tokenizer: *Tokenizer, doctype_data: *DoctypeData) !DoctypeState {
    while (try tokenizer.next()) |current_input_char| {
        switch (current_input_char) {
            '\t', '\n', 0x0C, ' ' => {},
            '>' => {
                try tokenizer.parseError(.MissingDOCTYPEName);
                doctype_data.force_quirks = true;
                return DoctypeState.Done;
            },
            else => {
                tokenizer.reconsume();
                return try doctypeName(tokenizer, doctype_data);
            },
        }
    } else {
        return try eofInDoctype(tokenizer, doctype_data);
    }
}

fn doctypeName(tokenizer: *Tokenizer, doctype_data: *DoctypeData) !DoctypeState {
    doctype_data.name = ArrayList(u8).init(tokenizer.allocator);
    const doctype_name_data = &doctype_data.name.?;

    while (try tokenizer.next()) |current_input_char| {
        switch (current_input_char) {
            '\t', '\n', 0x0C, ' ' => return afterDoctypeName(tokenizer, doctype_data),
            '>' => return DoctypeState.Done,
            0x00 => {
                try tokenizer.parseError(.UnexpectedNullCharacter);
                try appendChar(doctype_name_data, REPLACEMENT_CHARACTER);
            },
            else => |c| try appendChar(doctype_name_data, toLowercase(c)),
        }
    } else {
        return try eofInDoctype(tokenizer, doctype_data);
    }
}

fn afterDoctypeName(tokenizer: *Tokenizer, doctype_data: *DoctypeData) !DoctypeState {
    while (try tokenizer.next()) |current_input_char| {
        switch (current_input_char) {
            '\t', '\n', 0x0C, ' ' => {},
            '>' => return DoctypeState.Done,
            else => |c| {
                if (caseInsensitiveEql(c, 'P') and tokenizer.consumeCharsIfCaseInsensitiveEql("UBLIC")) {
                    return afterDOCTYPEPublicOrSystemKeyword(tokenizer, doctype_data, .public);
                } else if (caseInsensitiveEql(c, 'S') and tokenizer.consumeCharsIfCaseInsensitiveEql("YSTEM")) {
                    return afterDOCTYPEPublicOrSystemKeyword(tokenizer, doctype_data, .system);
                } else {
                    try tokenizer.parseError(.InvalidCharacterSequenceAfterDOCTYPEName);
                    doctype_data.force_quirks = true;
                    tokenizer.reconsume();
                    return bogusDOCTYPE(tokenizer);
                }
            },
        }
    } else {
        return try eofInDoctype(tokenizer, doctype_data);
    }
}

const PublicOrSystem = enum { public, system };

fn afterDOCTYPEPublicOrSystemKeyword(tokenizer: *Tokenizer, doctype_data: *DoctypeData, public_or_system: PublicOrSystem) !DoctypeState {
    // AfterDOCTYPEPublicKeyword
    // AfterDOCTYPESystemKeyword
    if (try tokenizer.next()) |current_input_char| {
        switch (current_input_char) {
            '\t', '\n', 0x0C, ' ' => {},
            '"', '\'' => |quote| {
                const err: ParseError = switch (public_or_system) {
                    .public => .MissingWhitespaceAfterDOCTYPEPublicKeyword,
                    .system => .MissingWhitespaceAfterDOCTYPESystemKeyword,
                };
                try tokenizer.parseError(err);
                return doctypePublicOrSystemIdentifier(tokenizer, doctype_data, public_or_system, quote);
            },
            '>' => {
                const err: ParseError = switch (public_or_system) {
                    .public => .MissingDOCTYPEPublicIdentifier,
                    .system => .MissingDOCTYPESystemIdentifier,
                };
                try tokenizer.parseError(err);
                doctype_data.force_quirks = true;
                return DoctypeState.Done;
            },
            else => {
                const err: ParseError = switch (public_or_system) {
                    .public => .MissingQuoteBeforeDOCTYPEPublicIdentifier,
                    .system => .MissingQuoteBeforeDOCTYPESystemIdentifier,
                };
                try tokenizer.parseError(err);
                doctype_data.force_quirks = true;
                tokenizer.reconsume();
                return bogusDOCTYPE(tokenizer);
            },
        }
    } else {
        return try eofInDoctype(tokenizer, doctype_data);
    }

    // BeforeDOCTYPEPublicIdentifier
    // BeforeDOCTYPESystemIdentifier
    while (try tokenizer.next()) |current_input_char| {
        switch (current_input_char) {
            '\t', '\n', 0x0C, ' ' => {},
            '"', '\'' => |quote| return doctypePublicOrSystemIdentifier(tokenizer, doctype_data, public_or_system, quote),
            '>' => {
                const err: ParseError = switch (public_or_system) {
                    .public => .MissingDOCTYPEPublicIdentifier,
                    .system => .MissingDOCTYPESystemIdentifier,
                };
                try tokenizer.parseError(err);
                doctype_data.force_quirks = true;
                return DoctypeState.Done;
            },
            else => {
                const err: ParseError = switch (public_or_system) {
                    .public => .MissingQuoteBeforeDOCTYPEPublicIdentifier,
                    .system => .MissingQuoteBeforeDOCTYPESystemIdentifier,
                };
                try tokenizer.parseError(err);
                doctype_data.force_quirks = true;
                tokenizer.reconsume();
                return bogusDOCTYPE(tokenizer);
            },
        }
    } else {
        return try eofInDoctype(tokenizer, doctype_data);
    }
}

fn doctypePublicOrSystemIdentifier(tokenizer: *Tokenizer, doctype_data: *DoctypeData, public_or_system: PublicOrSystem, quote: u21) Error!DoctypeState {
    // DOCTYPEPublicIdentifierDoubleQuoted
    // DOCTYPEPublicIdentifierSingleQuoted
    // DOCTYPESystemIdentifierDoubleQuoted
    // DOCTYPESystemIdentifierSingleQuoted

    const identifier_data_optional = switch (public_or_system) {
        .public => &doctype_data.public_identifier,
        .system => &doctype_data.system_identifier,
    };
    identifier_data_optional.* = ArrayList(u8).init(tokenizer.allocator);
    const identifier_data = &identifier_data_optional.*.?;

    while (try tokenizer.next()) |current_input_char| {
        if (current_input_char == quote) {
            const afterIdentifier = switch (public_or_system) {
                .public => afterDOCTYPEPublicIdentifier,
                .system => afterDOCTYPESystemIdentifier,
            };
            return afterIdentifier(tokenizer, doctype_data);
        } else if (current_input_char == 0x00) {
            try tokenizer.parseError(.UnexpectedNullCharacter);
            try appendChar(identifier_data, REPLACEMENT_CHARACTER);
        } else if (current_input_char == '>') {
            const err: ParseError = switch (public_or_system) {
                .public => .AbruptDOCTYPEPublicIdentifier,
                .system => .AbruptDOCTYPESystemIdentifier,
            };
            try tokenizer.parseError(err);
            doctype_data.force_quirks = true;
            return DoctypeState.Done;
        } else {
            try appendChar(identifier_data, current_input_char);
        }
    } else {
        return try eofInDoctype(tokenizer, doctype_data);
    }
}

fn afterDOCTYPEPublicIdentifier(tokenizer: *Tokenizer, doctype_data: *DoctypeData) !DoctypeState {
    if (try tokenizer.next()) |current_input_char| {
        switch (current_input_char) {
            '\t', '\n', 0x0C, ' ' => {},
            '>' => return DoctypeState.Done,
            '"', '\'' => |quote| {
                try tokenizer.parseError(.MissingWhitespaceBetweenDOCTYPEPublicAndSystemIdentifiers);
                return doctypePublicOrSystemIdentifier(tokenizer, doctype_data, .system, quote);
            },
            else => {
                try tokenizer.parseError(.MissingQuoteBeforeDOCTYPESystemIdentifier);
                doctype_data.force_quirks = true;
                tokenizer.reconsume();
                return bogusDOCTYPE(tokenizer);
            },
        }
    } else {
        return try eofInDoctype(tokenizer, doctype_data);
    }

    // BetweenDOCTYPEPublicAndSystemIdentifiers
    while (try tokenizer.next()) |current_input_char| {
        switch (current_input_char) {
            '\t', '\n', 0x0C, ' ' => {},
            '>' => return DoctypeState.Done,
            '"', '\'' => |quote| {
                return doctypePublicOrSystemIdentifier(tokenizer, doctype_data, .system, quote);
            },
            else => {
                try tokenizer.parseError(.MissingQuoteBeforeDOCTYPESystemIdentifier);
                doctype_data.force_quirks = true;
                tokenizer.reconsume();
                return bogusDOCTYPE(tokenizer);
            },
        }
    } else {
        return try eofInDoctype(tokenizer, doctype_data);
    }
}

fn afterDOCTYPESystemIdentifier(tokenizer: *Tokenizer, doctype_data: *DoctypeData) !DoctypeState {
    while (try tokenizer.next()) |current_input_char| {
        switch (current_input_char) {
            '\t', '\n', 0x0C, ' ' => {},
            '>' => return DoctypeState.Done,
            else => {
                try tokenizer.parseError(.UnexpectedCharacterAfterDOCTYPESystemIdentifier);
                tokenizer.reconsume();
                return bogusDOCTYPE(tokenizer);
            },
        }
    } else {
        return try eofInDoctype(tokenizer, doctype_data);
    }
}

fn eofInDoctype(tokenizer: *Tokenizer, doctype_data: *DoctypeData) !DoctypeState {
    try tokenizer.parseError(.EOFInDOCTYPE);
    doctype_data.force_quirks = true;
    return .Eof;
}

fn bogusDOCTYPE(tokenizer: *Tokenizer) !DoctypeState {
    while (try tokenizer.next()) |current_input_char| switch (current_input_char) {
        '>' => return DoctypeState.Done,
        0x00 => try tokenizer.parseError(.UnexpectedNullCharacter),
        else => {},
    } else {
        return .Eof;
    }
}

const ScriptState = enum {
    Normal,
    Escaped,
    DoubleEscaped,
};

fn scriptData(tokenizer: *Tokenizer) !void {
    var next_state: ?ScriptState = .Normal;
    while (next_state) |state| {
        next_state = switch (state) {
            .Normal => try scriptDataNormal(tokenizer),
            .Escaped => try scriptDataEscaped(tokenizer),
            .DoubleEscaped => try scriptDataDoubleEscaped(tokenizer),
        };
    }
}

fn scriptDataNormal(tokenizer: *Tokenizer) !?ScriptState {
    while (try tokenizer.next()) |char| switch (char) {
        0x00 => {
            try tokenizer.parseError(.UnexpectedNullCharacter);
            try tokenizer.emitCharacter(REPLACEMENT_CHARACTER);
        },
        else => try tokenizer.emitCharacter(char),
        '<' => {
            // ScriptDataLessThanSign
            switch (try tokenizer.nextIgnoreEof()) {
                else => {
                    try tokenizer.emitCharacter('<');
                    tokenizer.reconsume();
                    continue;
                },
                // ScriptDataEndTagOpen
                '/' => {
                    try nonDataEndTagOpen(tokenizer);
                    if (tokenizer.state != .ScriptData) return null;
                },
                '!' => {
                    try tokenizer.emitString("<!");

                    // ScriptDataEscapeStart
                    if ((try tokenizer.nextIgnoreEof()) != '-') {
                        tokenizer.reconsume();
                        continue;
                    }
                    try tokenizer.emitCharacter('-');

                    // ScriptDataEscapeStartDash
                    if ((try tokenizer.nextIgnoreEof()) != '-') {
                        tokenizer.reconsume();
                        continue;
                    }
                    try tokenizer.emitCharacter('-');

                    // ScriptDataEscapedDashDash
                    return try scriptDataEscapedOrDoubleEscapedDashDash(tokenizer, .Normal);
                },
            }
        },
    } else {
        try tokenizer.emitEOF();
        return null;
    }
}

fn scriptDataEscaped(tokenizer: *Tokenizer) !?ScriptState {
    while (try tokenizer.next()) |current_input_char| {
        switch (current_input_char) {
            '-' => {
                try tokenizer.emitCharacter('-');

                // ScriptDataEscapedDash
                if ((try tokenizer.nextIgnoreEof()) != '-') {
                    tokenizer.reconsume();
                    continue;
                }
                try tokenizer.emitCharacter('-');

                // ScriptDataEscapedDashDash
                return try scriptDataEscapedOrDoubleEscapedDashDash(tokenizer, .Escaped);
            },
            // ScriptDataEscapedLessThanSign
            '<' => switch (try tokenizer.nextIgnoreEof()) {
                '/' => {
                    try nonDataEndTagOpen(tokenizer);
                    if (tokenizer.state != .ScriptData) return null;
                },
                'A'...'Z', 'a'...'z' => {
                    try tokenizer.emitCharacter('<');
                    tokenizer.reconsume();

                    // ScriptDataDoubleEscapeStart
                    return try scriptDataDoubleEscapeStartOrEnd(tokenizer, .Escaped);
                },
                else => {
                    try tokenizer.emitCharacter('<');
                    tokenizer.reconsume();
                },
            },
            0x00 => {
                try tokenizer.parseError(.UnexpectedNullCharacter);
                try tokenizer.emitCharacter(REPLACEMENT_CHARACTER);
            },
            else => |c| try tokenizer.emitCharacter(c),
        }
    } else {
        try tokenizer.parseError(.EOFInScriptHtmlCommentLikeText);
        try tokenizer.emitEOF();
        return null;
    }
}

fn scriptDataDoubleEscaped(tokenizer: *Tokenizer) !?ScriptState {
    while (try tokenizer.next()) |current_input_char| {
        switch (current_input_char) {
            '-' => {
                try tokenizer.emitCharacter('-');

                // ScriptDataDoubleEscapedDash
                if ((try tokenizer.nextIgnoreEof()) != '-') {
                    tokenizer.reconsume();
                    continue;
                }
                try tokenizer.emitCharacter('-');

                // ScriptDataDoubleEscapedDashDash
                return try scriptDataEscapedOrDoubleEscapedDashDash(tokenizer, .DoubleEscaped);
            },
            '<' => {
                try tokenizer.emitCharacter('<');

                // ScriptDataDoubleEscapedLessThanSign
                if ((try tokenizer.nextIgnoreEof()) != '/') {
                    tokenizer.reconsume();
                    continue;
                }

                try tokenizer.emitCharacter('/');

                // ScriptDataDoubleEscapeEnd
                return try scriptDataDoubleEscapeStartOrEnd(tokenizer, .DoubleEscaped);
            },
            0x00 => {
                try tokenizer.parseError(.UnexpectedNullCharacter);
                try tokenizer.emitCharacter(REPLACEMENT_CHARACTER);
            },
            else => |c| try tokenizer.emitCharacter(c),
        }
    } else {
        try tokenizer.parseError(.EOFInScriptHtmlCommentLikeText);
        try tokenizer.emitEOF();
        return null;
    }
}

fn scriptDataDoubleEscapeStartOrEnd(tokenizer: *Tokenizer, script_state: ScriptState) !ScriptState {
    const script = "script";
    var num_matching_chars: u3 = 0;
    var matches: ?bool = null;
    while (true) switch (try tokenizer.nextIgnoreEof()) {
        '\t', '\n', 0x0C, ' ', '/', '>' => |c| {
            try tokenizer.emitCharacter(c);
            if (matches orelse false) {
                return switch (script_state) {
                    .Normal => unreachable,
                    .Escaped => .DoubleEscaped,
                    .DoubleEscaped => .Escaped,
                };
            } else {
                return script_state;
            }
        },
        'A'...'Z', 'a'...'z' => |c| {
            try tokenizer.emitCharacter(c);
            if (matches == null) {
                if (script[num_matching_chars] == toLowercase(c)) {
                    num_matching_chars += 1;
                    if (num_matching_chars == script.len) {
                        matches = true;
                    }
                } else {
                    matches = false;
                }
            } else {
                matches = false;
            }
        },
        else => {
            tokenizer.reconsume();
            return script_state;
        },
    };
}

fn scriptDataEscapedOrDoubleEscapedDashDash(tokenizer: *Tokenizer, script_state: ScriptState) !?ScriptState {
    while (true) switch (try tokenizer.nextIgnoreEof()) {
        '-' => try tokenizer.emitCharacter('-'),
        '>' => {
            try tokenizer.emitCharacter('>');
            return .Normal;
        },
        else => {
            tokenizer.reconsume();
            const next_state: ScriptState = switch (script_state) {
                .Normal, .Escaped => .Escaped,
                .DoubleEscaped => .DoubleEscaped,
            };
            return next_state;
        },
    };
}

fn toLowercase(character: u21) u21 {
    return switch (character) {
        'A'...'Z' => character + 0x20,
        else => character,
    };
}

fn caseSensitiveEql(c1: u21, c2: u21) bool {
    return c1 == c2;
}

fn caseInsensitiveEql(c1: u21, c2: u21) bool {
    return toLowercase(c1) == toLowercase(c2);
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
