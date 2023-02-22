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

    while (try tokenizer.run()) {}

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
input: InputStream,
current_tag_name: ArrayListUnmanaged(u8) = .{},
current_tag_attributes: Attributes = .{},
current_tag_self_closing: bool = false,
current_tag_type: enum { Start, End } = undefined,
last_start_tag_name: []u8 = &[_]u8{},
generic_buffer: ArrayListUnmanaged(u8) = .{},
current_attribute_value_result_location: ?*[]const u8 = null,
current_comment_data: ArrayListUnmanaged(u8) = .{},
temp_buffer: ArrayListUnmanaged(u21) = .{},
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
) Self {
    return initState(allocator, input, .Data, token_sink, error_handler);
}

/// Create a new HTML5 tokenizer, and change to a particular state.
pub fn initState(
    allocator: Allocator,
    input: []const u21,
    state: State,
    token_sink: *ArrayList(Token),
    error_handler: *ErrorHandler,
) Self {
    return Self{
        .allocator = allocator,
        .input = .{ .chars = input },
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
pub fn run(self: *Self) !bool {
    if (self.reached_eof) return false;
    try processInput(self);
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
fn next(self: *Self) !?u21 {
    const re = self.input.reconsume;
    const char = self.nextNoErrorCheck();
    if (!re and char != null) {
        try self.checkInputCharacterForErrors(char.?);
    }
    return char;
}

fn nextNoErrorCheck(self: *Self) ?u21 {
    if (self.input.position >= self.input.chars.len) {
        self.input.eof = true;
        return null;
    }

    var char = self.input.chars[self.input.position];
    self.input.position += 1;
    if (char == '\r') {
        char = '\n';
        if (self.input.position < self.input.chars.len and self.input.chars[self.input.position] == '\n') {
            self.input.position += 1;
        }
    }

    self.input.reconsume = false;

    return char;
}

fn nextIgnoreEof(self: *Self) !u21 {
    const char = try self.next();
    return char orelse TREAT_AS_ANYTHING_ELSE;
}

fn peekIgnoreEof(self: *Self) !u21 {
    const char = try self.nextIgnoreEof();
    self.back();
    return char;
}

fn back(self: *Self) void {
    if (self.input.eof) {
        self.input.eof = false;
        return;
    }

    const previous = self.input.chars[self.input.position - 1];
    if (previous == '\n' and self.input.position > 2 and self.input.chars[self.input.position - 2] == '\r') {
        self.input.position -= 2;
    } else {
        self.input.position -= 1;
    }
}

/// Scans the next characters in the input stream to see if they are equal to `string`.
/// If so, consumes those characters and returns `true`. Otherwise, adds any read characters
/// to the list of replayed characters and returns `false`.
fn consumeCharsIfEql(self: *Self, comptime string: []const u8) bool {
    const decoded_string = rem.util.utf8DecodeStringComptime(string);
    return consumeCharsIfEqlGeneric(self, &decoded_string, caseSensitiveEql);
}

/// Scans the next characters in the input stream to see if they are equal to `string` in
/// a case-insensitive manner.
/// If so, consumes those characters and returns `true`. Otherwise, adds any read characters
/// to the list of replayed characters and returns `false`.
fn consumeCharsIfCaseInsensitiveEql(self: *Self, comptime string: []const u8) bool {
    const decoded_string = rem.util.utf8DecodeStringComptime(string);
    return consumeCharsIfEqlGeneric(self, &decoded_string, caseInsensitiveEql);
}

fn consumeCharsIfEqlGeneric(self: *Self, decoded_string: []const u21, comptime eqlFn: fn (u21, u21) bool) bool {
    var index: usize = 0;
    while (index < decoded_string.len) {
        const string_char = decoded_string[index];
        index += 1;
        const next_char = self.nextNoErrorCheck() orelse break;
        if (!eqlFn(string_char, next_char)) break;
    } else {
        return true;
    }

    while (index > 0) : (index -= 1) {
        self.back();
    }
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

fn reconsume(self: *Self) void {
    self.back();
    self.input.reconsume = true;
}

fn isAppropriateEndTag(t: *Self, tag_data: *const TagData) bool {
    // Looking at the tokenizer logic, it seems that is no way to reach this function without current_tag_name
    // having at least 1 ASCII character in it. So we don't have to worry about making sure it has non-zero length.
    //
    // Notice that this gets called from the states that end in "TagName", and that those states
    // can only be reached by reconsuming an ASCII character from an associated "TagOpen" state.
    return std.mem.eql(u8, t.last_start_tag_name, tag_data.name.items);
}

fn appendComment(self: *Self, character: u21) !void {
    var code_units: [4]u8 = undefined;
    const len = try std.unicode.utf8Encode(character, &code_units);
    try self.current_comment_data.appendSlice(self.allocator, code_units[0..len]);
}

fn appendCommentString(self: *Self, comptime string: []const u8) !void {
    try self.current_comment_data.appendSlice(self.allocator, string);
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

fn appendTempBuffer(self: *Self, character: u21) !void {
    try self.temp_buffer.append(self.allocator, character);
}

fn clearTempBuffer(self: *Self) void {
    self.temp_buffer.clearRetainingCapacity();
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

fn emitCommentData(self: *Self, comment_data: []const u8) !void {
    try self.tokens.append(Token{ .comment = .{ .data = comment_data } });
}

fn emitEOF(self: *Self) !void {
    self.reached_eof = true;
    try self.tokens.append(Token{ .eof = {} });
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

fn adjustedCurrentNodeIsNotInHtmlNamespace(self: *Self) bool {
    return self.adjusted_current_node_is_not_in_html_namespace;
}

fn processInput(t: *Self) !void {
    switch (t.state) {
        .Data => {
            while (try t.next()) |char| switch (char) {
                '&' => try characterReference(t, null),
                '<' => return tagOpen(t),
                0x00 => {
                    try t.parseError(.UnexpectedNullCharacter);
                    try t.emitCharacter(0x00);
                },
                else => |c| try t.emitCharacter(c),
            } else {
                return t.emitEOF();
            }
        },
        .RAWTEXT => {
            while (try t.next()) |char| switch (char) {
                0x00 => {
                    try t.parseError(.UnexpectedNullCharacter);
                    try t.emitCharacter(REPLACEMENT_CHARACTER);
                },
                else => |c| try t.emitCharacter(c),
                '<' => {
                    // RAWTEXTLessThanSign
                    if ((try t.nextIgnoreEof()) != '/') {
                        try t.emitCharacter('<');
                        t.reconsume();
                        continue;
                    }

                    return nonDataEndTagOpen(t);
                },
            } else {
                try t.emitEOF();
            }
        },
        .PLAINTEXT => while (true) {
            if (try t.next()) |char| switch (char) {
                0x00 => {
                    try t.parseError(.UnexpectedNullCharacter);
                    try t.emitCharacter(REPLACEMENT_CHARACTER);
                },
                else => |c| try t.emitCharacter(c),
            } else {
                return t.emitEOF();
            }
        },
        .RCDATA => {
            while (try t.next()) |char| {
                switch (char) {
                    '&' => try characterReference(t, null),
                    0x00 => {
                        try t.parseError(.UnexpectedNullCharacter);
                        try t.emitCharacter(REPLACEMENT_CHARACTER);
                    },
                    else => |c| try t.emitCharacter(c),
                    '<' => {
                        // RCDATALessThanSign
                        if ((try t.nextIgnoreEof()) != '/') {
                            try t.emitCharacter('<');
                            t.reconsume();
                            continue;
                        }

                        return nonDataEndTagOpen(t);
                    },
                }
            } else {
                return t.emitEOF();
            }
        },
        .ScriptData => return scriptData(t),
        .CDATASection => while (true) {
            if (try t.next()) |char| switch (char) {
                ']' => {
                    // CDATASectionBracket
                    if ((try t.nextIgnoreEof()) != ']') {
                        try t.emitCharacter(']');
                        t.back();
                        continue;
                    }

                    // CDATASectionEnd
                    while (true) {
                        switch (try t.nextIgnoreEof()) {
                            ']' => try t.emitCharacter(']'),
                            '>' => return t.setState(.Data),
                            else => {
                                try t.emitString("]]");
                                t.back();
                                break;
                            },
                        }
                    }
                },
                else => |c| try t.emitCharacter(c),
            } else {
                try t.parseError(.EOFInCDATA);
                try t.emitEOF();
                return;
            }
        },
    }
}

fn characterReference(t: *Self, tag_data: ?*TagData) !void {
    t.clearTempBuffer();
    try t.appendTempBuffer('&');
    switch (try t.nextIgnoreEof()) {
        '0'...'9', 'A'...'Z', 'a'...'z' => {
            t.back();
            return namedCharacterReference(t, tag_data);
        },
        '#' => {
            try t.appendTempBuffer('#');
            return numericCharacterReference(t, tag_data);
        },
        else => {
            t.back();
            return flushCharacterReference(t, tag_data);
        },
    }
}

fn namedCharacterReference(t: *Self, tag_data: ?*TagData) !void {
    const chars = try t.findNamedCharacterReference();
    const match_found = chars[0] != null;
    if (match_found) {
        const historical_reasons = if (tag_data != null and t.tempBufferLast() != ';')
            switch (try t.peekIgnoreEof()) {
                '=', '0'...'9', 'A'...'Z', 'a'...'z' => true,
                else => false,
            }
        else
            false;

        if (historical_reasons) {
            return flushCharacterReference(t, tag_data);
        } else {
            if (t.tempBufferLast() != ';') {
                try t.parseError(.MissingSemicolonAfterCharacterReference);
            }
            t.clearTempBuffer();
            try t.appendTempBuffer(chars[0].?);
            if (chars[1]) |c| try t.appendTempBuffer(c);
            return flushCharacterReference(t, tag_data);
        }
    } else {
        try flushCharacterReference(t, tag_data);
        return ambiguousAmpersand(t, tag_data);
    }
}

fn findNamedCharacterReference(self: *Self) !named_characters_data.Value {
    var node = named_characters_data.root;
    var character_reference_consumed_codepoints_count: usize = 1;
    var last_matched_named_character_value = named_characters_data.Value{ null, null };
    while (true) {
        const character = self.nextNoErrorCheck() orelse {
            self.back();
            break;
        };
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

    while (self.temp_buffer.items.len > character_reference_consumed_codepoints_count) {
        self.back();
        self.temp_buffer.items.len -= 1;
    }

    // There is no need to check the consumed characters for errors (controls, surrogates, noncharacters)
    // beacuse we've just determined that they form a valid character reference.
    return last_matched_named_character_value;
}

fn ambiguousAmpersand(t: *Self, tag_data: ?*TagData) !void {
    while (true) switch (try t.nextIgnoreEof()) {
        //'0'...'9', 'A'...'Z', 'a'...'z' => |c| switch (is_part_of_an_attribute) {
        //    .Yes => try t.appendCurrentAttributeValue(c),
        //    .No => try t.emitCharacter(c),
        //},
        '0'...'9', 'A'...'Z', 'a'...'z' => |c| try t.appendTempBuffer(c),
        ';' => break try t.parseError(.UnknownNamedCharacterReference),
        else => break,
    };

    try flushCharacterReference(t, tag_data);
    t.reconsume();
}

fn numericCharacterReference(t: *Self, tag_data: ?*TagData) !void {
    var character_reference_code: u21 = 0;
    switch (try t.nextIgnoreEof()) {
        'x', 'X' => |x| {
            try t.appendTempBuffer(x);

            // HexadecimalCharacterReferenceStart
            switch (try t.nextIgnoreEof()) {
                '0'...'9', 'A'...'F', 'a'...'f' => {
                    t.reconsume();

                    // HexadecimalCharacterReference
                    while (true) switch (try t.nextIgnoreEof()) {
                        '0'...'9' => |c| characterReferenceCodeAddDigit(&character_reference_code, 16, decimalCharToNumber(c)),
                        'A'...'F' => |c| characterReferenceCodeAddDigit(&character_reference_code, 16, upperHexCharToNumber(c)),
                        'a'...'f' => |c| characterReferenceCodeAddDigit(&character_reference_code, 16, lowerHexCharToNumber(c)),
                        ';' => break,
                        else => {
                            try t.parseError(.MissingSemicolonAfterCharacterReference);
                            break t.reconsume();
                        },
                    };
                },
                else => return noDigitsInNumericCharacterReference(t, tag_data),
            }
        },
        // DecimalCharacterReferenceStart
        '0'...'9' => {
            t.reconsume();

            // DecimalCharacterReference
            while (true) switch (try t.nextIgnoreEof()) {
                '0'...'9' => |c| characterReferenceCodeAddDigit(&character_reference_code, 10, decimalCharToNumber(c)),
                ';' => break,
                else => {
                    try t.parseError(.MissingSemicolonAfterCharacterReference);
                    break t.reconsume();
                },
            };
        },
        else => return noDigitsInNumericCharacterReference(t, tag_data),
    }

    // NumericCharacterReferenceEnd
    switch (character_reference_code) {
        0x00 => {
            try t.parseError(.NullCharacterReference);
            character_reference_code = REPLACEMENT_CHARACTER;
        },
        0x10FFFF + 1...std.math.maxInt(@TypeOf(character_reference_code)) => {
            try t.parseError(.CharacterReferenceOutsideUnicodeRange);
            character_reference_code = REPLACEMENT_CHARACTER;
        },
        0xD800...0xDFFF => {
            try t.parseError(.SurrogateCharacterReference);
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
        => try t.parseError(.NoncharacterCharacterReference),
        0x01...0x08, 0x0B, 0x0D...0x1F => try t.parseError(.ControlCharacterReference),
        0x7F...0x9F => |c| {
            try t.parseError(.ControlCharacterReference);
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
    t.clearTempBuffer();
    try t.appendTempBuffer(character_reference_code);
    try flushCharacterReference(t, tag_data);
}

fn characterReferenceCodeAddDigit(character_reference_code: *u21, comptime base: comptime_int, digit: u21) void {
    character_reference_code.* = character_reference_code.* *| base +| digit;
}

fn noDigitsInNumericCharacterReference(t: *Self, tag_data: ?*TagData) !void {
    try t.parseError(.AbsenceOfDigitsInNumericCharacterReference);
    try flushCharacterReference(t, tag_data);
    t.reconsume();
}

fn flushCharacterReference(t: *Self, tag_data_optional: ?*TagData) !void {
    if (tag_data_optional) |tag_data| {
        for (t.temp_buffer.items) |character| {
            try tag_data.appendCurrentAttributeValue(character);
        }
    } else {
        for (t.temp_buffer.items) |character| {
            try t.emitCharacter(character);
        }
    }
    t.clearTempBuffer();
}

fn markupDeclarationOpen(t: *Self) !void {
    if (t.consumeCharsIfEql("--")) {
        return comment(t);
    } else if (t.consumeCharsIfCaseInsensitiveEql("DOCTYPE")) {
        return doctype(t);
    } else if (t.consumeCharsIfEql("[CDATA[")) {
        if (t.adjustedCurrentNodeIsNotInHtmlNamespace()) {
            t.setState(.CDATASection);
        } else {
            try t.parseError(.CDATAInHtmlContent);
            for ("[CDATA[") |_| t.back();
            return bogusComment(t);
        }
    } else {
        try t.parseError(.IncorrectlyOpenedComment);
        return bogusComment(t);
    }
}

fn bogusComment(t: *Self) !void {
    var comment_data = ArrayListUnmanaged(u8){};
    defer comment_data.deinit(t.allocator);

    while (try t.next()) |char| switch (char) {
        '>' => break,
        0x00 => {
            try t.parseError(.UnexpectedNullCharacter);
            try appendCharUnmanaged(&comment_data, t.allocator, REPLACEMENT_CHARACTER);
        },
        else => |c| try appendCharUnmanaged(&comment_data, t.allocator, c),
    } else {
        t.back();
    }

    try t.emitCommentData(comment_data.toOwnedSlice(t.allocator));
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

    fn finishAttributeName(tag_data: *TagData, t: *Self) !void {
        const attribute_name = tag_data.buffer.toOwnedSlice(tag_data.allocator);
        errdefer tag_data.allocator.free(attribute_name);

        const get_result = try tag_data.attributes.getOrPut(tag_data.allocator, attribute_name);

        if (get_result.found_existing) {
            try t.parseError(.DuplicateAttribute);
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

fn emitTag(t: *Self, tag_data: *TagData) !void {
    const name = tag_data.name.toOwnedSlice(tag_data.allocator);
    errdefer tag_data.allocator.free(name);

    switch (tag_data.start_or_end) {
        .Start => {
            t.last_start_tag_name = try t.allocator.realloc(t.last_start_tag_name, name.len);
            std.mem.copy(u8, t.last_start_tag_name, name);
            const token = Token{ .start_tag = .{
                .name = name,
                .attributes = tag_data.attributes,
                .self_closing = tag_data.self_closing,
            } };
            tag_data.attributes = .{};
            try t.tokens.append(token);
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
                try t.parseError(.EndTagWithAttributes);
            }

            if (tag_data.self_closing) {
                try t.parseError(.EndTagWithTrailingSolidus);
            }

            try t.tokens.append(Token{ .end_tag = .{
                .name = name,
            } });
        },
    }
}

fn tagOpen(t: *Self) !void {
    if (try t.next()) |char| switch (char) {
        '!' => return markupDeclarationOpen(t),
        '/' => return endTagOpen(t),
        'A'...'Z', 'a'...'z' => {
            t.reconsume();
            return tagName(t, .Start);
        },
        '?' => {
            try t.parseError(.UnexpectedQuestionMarkInsteadOfTagName);
            t.reconsume();
            return bogusComment(t);
        },
        else => {
            try t.parseError(.InvalidFirstCharacterOfTagName);
            try t.emitCharacter('<');
            return t.reconsume();
        },
    } else {
        try t.parseError(.EOFBeforeTagName);
        try t.emitCharacter('<');
        try t.emitEOF();
    }
}

fn endTagOpen(t: *Self) !void {
    if (try t.next()) |char| {
        switch (char) {
            'A'...'Z', 'a'...'z' => {
                t.reconsume();
                return tagName(t, .End);
            },
            '>' => try t.parseError(.MissingEndTagName),
            else => {
                try t.parseError(.InvalidFirstCharacterOfTagName);
                t.reconsume();
                return bogusComment(t);
            },
        }
    } else {
        try t.parseError(.EOFBeforeTagName);
        try t.emitString("</");
        try t.emitEOF();
    }
}

fn nonDataEndTagOpen(t: *Self) !void {
    switch (try t.nextIgnoreEof()) {
        'A'...'Z', 'a'...'z' => {
            t.reconsume();
            return nonDataEndTagName(t);
        },
        else => {
            try t.emitString("</");
            t.reconsume();
        },
    }
}

fn nonDataEndTagName(t: *Self) !void {
    var tag_data = TagData.init(.End, t.allocator);
    defer tag_data.deinit();

    while (try t.next()) |char| {
        switch (char) {
            '\t', '\n', 0x0C, ' ' => {
                if (t.isAppropriateEndTag(&tag_data)) {
                    return attribute(t, &tag_data);
                }
                break;
            },
            '/' => {
                if (t.isAppropriateEndTag(&tag_data)) {
                    return selfClosingStartTag(t, &tag_data);
                }
                break;
            },
            '>' => {
                if (t.isAppropriateEndTag(&tag_data)) {
                    try emitTag(t, &tag_data);
                    return t.setState(.Data);
                }
                break;
            },
            'A'...'Z' => |c| try tag_data.appendName(toLowercase(c)),
            'a'...'z' => |c| try tag_data.appendName(c),
            else => break,
        }
    }

    try t.emitString("</");
    for (tag_data.name.items) |c| try t.emitCharacter(c);
    t.reconsume();
}

fn tagName(t: *Self, start_or_end: TagData.StartOrEnd) !void {
    var tag_data = TagData.init(start_or_end, t.allocator);
    defer tag_data.deinit();

    while (try t.next()) |current_input_char| {
        switch (current_input_char) {
            '\t', '\n', 0x0C, ' ' => return attribute(t, &tag_data),
            '/' => return selfClosingStartTag(t, &tag_data),
            '>' => return try emitTag(t, &tag_data),
            'A'...'Z' => |c| try tag_data.appendName(toLowercase(c)),
            0x00 => {
                try t.parseError(.UnexpectedNullCharacter);
                try tag_data.appendName(REPLACEMENT_CHARACTER);
            },
            else => |c| try tag_data.appendName(c),
        }
    } else {
        try t.parseError(.EOFInTag);
        try t.emitEOF();
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

fn attribute(t: *Self, tag_data: *TagData) !void {
    return attributeLoop(t, tag_data, .BeforeName);
}

fn selfClosingStartTag(t: *Self, tag_data: *TagData) !void {
    return attributeLoop(t, tag_data, .Slash);
}

fn attributeLoop(t: *Self, tag_data: *TagData, initial_state: AttributeState) !void {
    var state: AttributeState = initial_state;
    while (true) {
        switch (state) {
            .BeforeName => state = try beforeAttributeName(t, tag_data),
            .Name => state = try attributeName(t, tag_data),
            .Value => state = try beforeAttributeValue(t, tag_data),
            .Slash => state = try attributeSlash(t, tag_data),
            .Done => break try emitTag(t, tag_data),
            .Eof => break try t.emitEOF(),
        }
    }
}

fn beforeAttributeName(t: *Self, tag_data: *TagData) !AttributeState {
    // Make end-of-file (null) be handled the same as '>'
    while (true) switch ((try t.next()) orelse '>') {
        '\t', '\n', 0x0C, ' ' => {},
        '/', '>' => {
            t.reconsume();
            return try afterAttributeName(t);
        },
        '=' => {
            try t.parseError(.UnexpectedEqualsSignBeforeAttributeName);
            try tag_data.appendCurrentAttributeName('=');
            return .Name;
        },
        else => {
            t.reconsume();
            return .Name;
        },
    };
}

fn attributeName(t: *Self, tag_data: *TagData) !AttributeState {
    // Make end-of-file (null) be handled the same as '>'
    while (true) switch ((try t.next()) orelse '>') {
        '\t', '\n', 0x0C, ' ', '/', '>' => {
            try tag_data.finishAttributeName(t);
            t.reconsume();
            return try afterAttributeName(t);
        },
        '=' => {
            try tag_data.finishAttributeName(t);
            return .Value;
        },
        'A'...'Z' => |c| try tag_data.appendCurrentAttributeName(toLowercase(c)),
        0x00 => {
            try t.parseError(.UnexpectedNullCharacter);
            try tag_data.appendCurrentAttributeName(REPLACEMENT_CHARACTER);
        },
        '"', '\'', '<' => |c| {
            try t.parseError(.UnexpectedCharacterInAttributeName);
            try tag_data.appendCurrentAttributeName(c);
        },
        else => |c| try tag_data.appendCurrentAttributeName(c),
    };
}

fn afterAttributeName(t: *Self) !AttributeState {
    while (true) {
        if (try t.next()) |current_input_char| {
            switch (current_input_char) {
                '\t', '\n', 0x0C, ' ' => {},
                '/' => return .Slash,
                '=' => return .Value,
                '>' => return attributeEnd(t),
                else => {
                    t.reconsume();
                    return AttributeState.Name;
                },
            }
        } else {
            return try eofInTag(t);
        }
    }
}

fn beforeAttributeValue(t: *Self, tag_data: *TagData) !AttributeState {
    while (true) switch (try t.nextIgnoreEof()) {
        '\t', '\n', 0x0C, ' ' => {},
        '"' => return attributeValueQuoted(t, tag_data, .Double),
        '\'' => return attributeValueQuoted(t, tag_data, .Single),
        '>' => {
            try t.parseError(.MissingAttributeValue);
            return attributeEnd(t);
        },
        else => {
            t.reconsume();
            return attributeValueUnquoted(t, tag_data);
        },
    };
}

const QuoteStyle = enum { Single, Double };

fn attributeValueQuoted(t: *Self, tag_data: *TagData, comptime quote_style: QuoteStyle) !AttributeState {
    const quote = switch (quote_style) {
        .Single => '\'',
        .Double => '"',
    };

    while (try t.next()) |current_input_char| {
        switch (current_input_char) {
            quote => break tag_data.finishAttributeValue(),
            '&' => try characterReference(t, tag_data),
            0x00 => {
                try t.parseError(.UnexpectedNullCharacter);
                try tag_data.appendCurrentAttributeValue(REPLACEMENT_CHARACTER);
            },
            else => |c| try tag_data.appendCurrentAttributeValue(c),
        }
    } else {
        return try eofInTag(t);
    }

    // AfterAttributeValueQuoted
    if (try t.next()) |current_input_char| {
        switch (current_input_char) {
            '\t', '\n', 0x0C, ' ' => return AttributeState.BeforeName,
            '/' => return AttributeState.Slash,
            '>' => return attributeEnd(t),
            else => {
                try t.parseError(.MissingWhitespaceBetweenAttributes);
                t.reconsume();
                return AttributeState.BeforeName;
            },
        }
    } else {
        return try eofInTag(t);
    }
}

fn attributeValueUnquoted(t: *Self, tag_data: *TagData) !AttributeState {
    while (try t.next()) |current_input_char| switch (current_input_char) {
        '\t', '\n', 0x0C, ' ' => {
            tag_data.finishAttributeValue();
            return AttributeState.BeforeName;
        },
        '&' => try characterReference(t, tag_data),
        '>' => {
            tag_data.finishAttributeValue();
            return attributeEnd(t);
        },
        0x00 => {
            try t.parseError(.UnexpectedNullCharacter);
            try tag_data.appendCurrentAttributeValue(REPLACEMENT_CHARACTER);
        },
        '"', '\'', '<', '=', '`' => |c| {
            try t.parseError(.UnexpectedCharacterInUnquotedAttributeValue);
            try tag_data.appendCurrentAttributeValue(c);
        },
        else => |c| try tag_data.appendCurrentAttributeValue(c),
    } else {
        return try eofInTag(t);
    }
}

fn attributeSlash(t: *Self, tag_data: *TagData) !AttributeState {
    if (try t.next()) |current_input_char| {
        switch (current_input_char) {
            '>' => {
                tag_data.self_closing = true;
                return attributeEnd(t);
            },
            else => {
                try t.parseError(.UnexpectedSolidusInTag);
                t.reconsume();
                return AttributeState.BeforeName;
            },
        }
    } else {
        return try eofInTag(t);
    }
}

fn attributeEnd(t: *Self) AttributeState {
    t.setState(.Data);
    return .Done;
}

fn eofInTag(t: *Self) !AttributeState {
    try t.parseError(.EOFInTag);
    return .Eof;
}

const CommentState = enum {
    Normal,
    EndDash,
    End,
    Done,
};

fn comment(t: *Self) !void {
    var comment_data = ArrayList(u8).init(t.allocator);
    errdefer comment_data.deinit();

    var state = try commentStart(t, &comment_data);
    while (true) {
        switch (state) {
            .Normal => state = try commentNormal(t, &comment_data),
            .EndDash => state = try commentEndDash(t, &comment_data),
            .End => state = try commentEnd(t, &comment_data),
            .Done => break,
        }
    }

    try t.emitCommentData(comment_data.toOwnedSlice());
}

fn commentStart(t: *Self, comment_data: *ArrayList(u8)) !CommentState {
    switch (try t.nextIgnoreEof()) {
        '-' => {
            // CommentStartDash
            switch ((try t.next()) orelse return try eofInComment(t)) {
                '-' => return .End,
                '>' => return try abruptCommentClose(t),
                else => {
                    try comment_data.append('-');
                    t.reconsume();
                    return .Normal;
                },
            }
        },
        '>' => return try abruptCommentClose(t),
        else => {
            t.reconsume();
            return .Normal;
        },
    }
}

fn commentNormal(t: *Self, comment_data: *ArrayList(u8)) !CommentState {
    while (try t.next()) |current_input_char| switch (current_input_char) {
        '<' => {
            try comment_data.append('<');

            // CommentLessThanSign
            while (true) switch (try t.nextIgnoreEof()) {
                '!' => {
                    try comment_data.append('!');

                    // CommentLessThanSignBang
                    if ((try t.nextIgnoreEof()) != '-') {
                        t.reconsume();
                        break;
                    }

                    // CommentLessThanSignBangDash
                    if ((try t.nextIgnoreEof()) != '-') {
                        t.reconsume();
                        return CommentState.EndDash;
                    }

                    // CommentLessThanSignBangDashDash
                    // Make end-of-file (null) be handled the same as '>'
                    if ((try t.next()) orelse '>' != '>') {
                        try t.parseError(.NestedComment);
                    }
                    t.reconsume();
                    return .End;
                },
                '<' => try comment_data.append('<'),
                else => {
                    t.reconsume();
                    break;
                },
            };
        },
        '-' => return .EndDash,
        0x00 => {
            try t.parseError(.UnexpectedNullCharacter);
            try appendChar(comment_data, REPLACEMENT_CHARACTER);
        },
        else => |c| try appendChar(comment_data, c),
    } else {
        return try eofInComment(t);
    }
}

fn commentEndDash(t: *Self, comment_data: *ArrayList(u8)) !CommentState {
    switch ((try t.next()) orelse return try eofInComment(t)) {
        '-' => return CommentState.End,
        else => {
            try comment_data.append('-');
            t.reconsume();
            return CommentState.Normal;
        },
    }
}

fn commentEnd(t: *Self, comment_data: *ArrayList(u8)) !CommentState {
    while (try t.next()) |current_input_char| switch (current_input_char) {
        '>' => return .Done,
        '!' => return try commentEndBang(t, comment_data),
        '-' => try comment_data.append('-'),
        else => {
            try comment_data.appendSlice("--");
            t.reconsume();
            return CommentState.Normal;
        },
    } else {
        return try eofInComment(t);
    }
}

fn commentEndBang(t: *Self, comment_data: *ArrayList(u8)) !CommentState {
    switch ((try t.next()) orelse return try eofInComment(t)) {
        '-' => {
            try comment_data.appendSlice("--!");
            return CommentState.EndDash;
        },
        '>' => return incorrectlyClosedComment(t),
        else => {
            try comment_data.appendSlice("--!");
            t.reconsume();
            return CommentState.Normal;
        },
    }
}

fn eofInComment(t: *Self) !CommentState {
    try t.parseError(.EOFInComment);
    t.back();
    return .Done;
}

fn abruptCommentClose(t: *Self) !CommentState {
    try t.parseError(.AbruptClosingOfEmptyComment);
    return .Done;
}

fn incorrectlyClosedComment(t: *Self) !CommentState {
    try t.parseError(.IncorrectlyClosedComment);
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

fn doctype(t: *Self) !void {
    var doctype_data = DoctypeData{};
    defer doctype_data.deinit();

    const state = try doctypeStart(t, &doctype_data);

    const doctype_token = Token{ .doctype = .{
        .name = if (doctype_data.name) |*name| name.toOwnedSlice() else null,
        .public_identifier = if (doctype_data.public_identifier) |*public_identifier| public_identifier.toOwnedSlice() else null,
        .system_identifier = if (doctype_data.system_identifier) |*system_identifier| system_identifier.toOwnedSlice() else null,
        .force_quirks = doctype_data.force_quirks,
    } };
    try t.tokens.append(doctype_token);

    if (state == .Eof) {
        try t.emitEOF();
    }
}

fn doctypeStart(t: *Self, doctype_data: *DoctypeData) !DoctypeState {
    if (try t.next()) |current_input_char| {
        switch (current_input_char) {
            '\t', '\n', 0x0C, ' ' => {},
            '>' => t.reconsume(),
            else => {
                try t.parseError(.MissingWhitespaceBeforeDOCTYPEName);
                t.reconsume();
            },
        }
        return try beforeDoctypeName(t, doctype_data);
    } else {
        return try eofInDoctype(t, doctype_data);
    }
}

fn beforeDoctypeName(t: *Self, doctype_data: *DoctypeData) !DoctypeState {
    while (try t.next()) |current_input_char| {
        switch (current_input_char) {
            '\t', '\n', 0x0C, ' ' => {},
            '>' => {
                try t.parseError(.MissingDOCTYPEName);
                doctype_data.force_quirks = true;
                return DoctypeState.Done;
            },
            else => {
                t.reconsume();
                return try doctypeName(t, doctype_data);
            },
        }
    } else {
        return try eofInDoctype(t, doctype_data);
    }
}

fn doctypeName(t: *Self, doctype_data: *DoctypeData) !DoctypeState {
    doctype_data.name = ArrayList(u8).init(t.allocator);
    const doctype_name_data = &doctype_data.name.?;

    while (try t.next()) |current_input_char| {
        switch (current_input_char) {
            '\t', '\n', 0x0C, ' ' => return afterDoctypeName(t, doctype_data),
            '>' => return DoctypeState.Done,
            'A'...'Z' => |c| try appendChar(doctype_name_data, toLowercase(c)),
            0x00 => {
                try t.parseError(.UnexpectedNullCharacter);
                try appendChar(doctype_name_data, REPLACEMENT_CHARACTER);
            },
            else => |c| try appendChar(doctype_name_data, c),
        }
    } else {
        return try eofInDoctype(t, doctype_data);
    }
}

fn afterDoctypeName(t: *Self, doctype_data: *DoctypeData) !DoctypeState {
    while (try t.next()) |current_input_char| {
        switch (current_input_char) {
            '\t', '\n', 0x0C, ' ' => {},
            '>' => return DoctypeState.Done,
            else => |c| {
                if (caseInsensitiveEql(c, 'P') and t.consumeCharsIfCaseInsensitiveEql("UBLIC")) {
                    return afterDOCTYPEPublicOrSystemKeyword(t, doctype_data, .public);
                } else if (caseInsensitiveEql(c, 'S') and t.consumeCharsIfCaseInsensitiveEql("YSTEM")) {
                    return afterDOCTYPEPublicOrSystemKeyword(t, doctype_data, .system);
                } else {
                    try t.parseError(.InvalidCharacterSequenceAfterDOCTYPEName);
                    doctype_data.force_quirks = true;
                    t.reconsume();
                    return bogusDOCTYPE(t);
                }
            },
        }
    } else {
        return try eofInDoctype(t, doctype_data);
    }
}

const PublicOrSystem = enum { public, system };

fn afterDOCTYPEPublicOrSystemKeyword(t: *Self, doctype_data: *DoctypeData, public_or_system: PublicOrSystem) !DoctypeState {
    // AfterDOCTYPEPublicKeyword
    // AfterDOCTYPESystemKeyword
    if (try t.next()) |current_input_char| {
        switch (current_input_char) {
            '\t', '\n', 0x0C, ' ' => {},
            '"', '\'' => |quote| {
                const err: ParseError = switch (public_or_system) {
                    .public => .MissingWhitespaceAfterDOCTYPEPublicKeyword,
                    .system => .MissingWhitespaceAfterDOCTYPESystemKeyword,
                };
                try t.parseError(err);
                return doctypePublicOrSystemIdentifier(t, doctype_data, public_or_system, quote);
            },
            '>' => {
                const err: ParseError = switch (public_or_system) {
                    .public => .MissingDOCTYPEPublicIdentifier,
                    .system => .MissingDOCTYPESystemIdentifier,
                };
                try t.parseError(err);
                doctype_data.force_quirks = true;
                return DoctypeState.Done;
            },
            else => {
                const err: ParseError = switch (public_or_system) {
                    .public => .MissingQuoteBeforeDOCTYPEPublicIdentifier,
                    .system => .MissingQuoteBeforeDOCTYPESystemIdentifier,
                };
                try t.parseError(err);
                doctype_data.force_quirks = true;
                t.reconsume();
                return bogusDOCTYPE(t);
            },
        }
    } else {
        return try eofInDoctype(t, doctype_data);
    }

    // BeforeDOCTYPEPublicIdentifier
    // BeforeDOCTYPESystemIdentifier
    while (try t.next()) |current_input_char| {
        switch (current_input_char) {
            '\t', '\n', 0x0C, ' ' => {},
            '"', '\'' => |quote| return doctypePublicOrSystemIdentifier(t, doctype_data, public_or_system, quote),
            '>' => {
                const err: ParseError = switch (public_or_system) {
                    .public => .MissingDOCTYPEPublicIdentifier,
                    .system => .MissingDOCTYPESystemIdentifier,
                };
                try t.parseError(err);
                doctype_data.force_quirks = true;
                return DoctypeState.Done;
            },
            else => {
                const err: ParseError = switch (public_or_system) {
                    .public => .MissingQuoteBeforeDOCTYPEPublicIdentifier,
                    .system => .MissingQuoteBeforeDOCTYPESystemIdentifier,
                };
                try t.parseError(err);
                doctype_data.force_quirks = true;
                t.reconsume();
                return bogusDOCTYPE(t);
            },
        }
    } else {
        return try eofInDoctype(t, doctype_data);
    }
}

fn doctypePublicOrSystemIdentifier(t: *Self, doctype_data: *DoctypeData, public_or_system: PublicOrSystem, quote: u21) Error!DoctypeState {
    // DOCTYPEPublicIdentifierDoubleQuoted
    // DOCTYPEPublicIdentifierSingleQuoted
    // DOCTYPESystemIdentifierDoubleQuoted
    // DOCTYPESystemIdentifierSingleQuoted

    const identifier_data_optional = switch (public_or_system) {
        .public => &doctype_data.public_identifier,
        .system => &doctype_data.system_identifier,
    };
    identifier_data_optional.* = ArrayList(u8).init(t.allocator);
    const identifier_data = &identifier_data_optional.*.?;

    while (try t.next()) |current_input_char| {
        if (current_input_char == quote) {
            const afterIdentifier = switch (public_or_system) {
                .public => afterDOCTYPEPublicIdentifier,
                .system => afterDOCTYPESystemIdentifier,
            };
            return afterIdentifier(t, doctype_data);
        } else if (current_input_char == 0x00) {
            try t.parseError(.UnexpectedNullCharacter);
            try appendChar(identifier_data, REPLACEMENT_CHARACTER);
        } else if (current_input_char == '>') {
            const err: ParseError = switch (public_or_system) {
                .public => .AbruptDOCTYPEPublicIdentifier,
                .system => .AbruptDOCTYPESystemIdentifier,
            };
            try t.parseError(err);
            doctype_data.force_quirks = true;
            return DoctypeState.Done;
        } else {
            try appendChar(identifier_data, current_input_char);
        }
    } else {
        return try eofInDoctype(t, doctype_data);
    }
}

fn afterDOCTYPEPublicIdentifier(t: *Self, doctype_data: *DoctypeData) !DoctypeState {
    if (try t.next()) |current_input_char| {
        switch (current_input_char) {
            '\t', '\n', 0x0C, ' ' => {},
            '>' => return DoctypeState.Done,
            '"', '\'' => |quote| {
                try t.parseError(.MissingWhitespaceBetweenDOCTYPEPublicAndSystemIdentifiers);
                return doctypePublicOrSystemIdentifier(t, doctype_data, .system, quote);
            },
            else => {
                try t.parseError(.MissingQuoteBeforeDOCTYPESystemIdentifier);
                doctype_data.force_quirks = true;
                t.reconsume();
                return bogusDOCTYPE(t);
            },
        }
    } else {
        return try eofInDoctype(t, doctype_data);
    }

    // BetweenDOCTYPEPublicAndSystemIdentifiers
    while (try t.next()) |current_input_char| {
        switch (current_input_char) {
            '\t', '\n', 0x0C, ' ' => {},
            '>' => return DoctypeState.Done,
            '"', '\'' => |quote| {
                return doctypePublicOrSystemIdentifier(t, doctype_data, .system, quote);
            },
            else => {
                try t.parseError(.MissingQuoteBeforeDOCTYPESystemIdentifier);
                doctype_data.force_quirks = true;
                t.reconsume();
                return bogusDOCTYPE(t);
            },
        }
    } else {
        return try eofInDoctype(t, doctype_data);
    }
}

fn afterDOCTYPESystemIdentifier(t: *Self, doctype_data: *DoctypeData) !DoctypeState {
    while (try t.next()) |current_input_char| {
        switch (current_input_char) {
            '\t', '\n', 0x0C, ' ' => {},
            '>' => return DoctypeState.Done,
            else => {
                try t.parseError(.UnexpectedCharacterAfterDOCTYPESystemIdentifier);
                t.reconsume();
                return bogusDOCTYPE(t);
            },
        }
    } else {
        return try eofInDoctype(t, doctype_data);
    }
}

fn eofInDoctype(t: *Self, doctype_data: *DoctypeData) !DoctypeState {
    try t.parseError(.EOFInDOCTYPE);
    doctype_data.force_quirks = true;
    return .Eof;
}

fn bogusDOCTYPE(t: *Self) !DoctypeState {
    while (try t.next()) |current_input_char| switch (current_input_char) {
        '>' => return DoctypeState.Done,
        0x00 => try t.parseError(.UnexpectedNullCharacter),
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

fn scriptData(t: *Self) !void {
    var next_state: ?ScriptState = .Normal;
    while (next_state) |state| {
        next_state = switch (state) {
            .Normal => try scriptDataNormal(t),
            .Escaped => try scriptDataEscaped(t),
            .DoubleEscaped => try scriptDataDoubleEscaped(t),
        };
    }
}

fn scriptDataNormal(t: *Self) !?ScriptState {
    while (try t.next()) |char| switch (char) {
        0x00 => {
            try t.parseError(.UnexpectedNullCharacter);
            try t.emitCharacter(REPLACEMENT_CHARACTER);
        },
        else => try t.emitCharacter(char),
        '<' => {
            // ScriptDataLessThanSign
            switch (try t.nextIgnoreEof()) {
                else => {
                    try t.emitCharacter('<');
                    t.reconsume();
                    continue;
                },
                // ScriptDataEndTagOpen
                '/' => {
                    try nonDataEndTagOpen(t);
                    if (t.state != .ScriptData) return null;
                },
                '!' => {
                    try t.emitString("<!");

                    // ScriptDataEscapeStart
                    if ((try t.nextIgnoreEof()) != '-') {
                        t.reconsume();
                        continue;
                    }
                    try t.emitCharacter('-');

                    // ScriptDataEscapeStartDash
                    if ((try t.nextIgnoreEof()) != '-') {
                        t.reconsume();
                        continue;
                    }
                    try t.emitCharacter('-');

                    // ScriptDataEscapedDashDash
                    return try scriptDataEscapedOrDoubleEscapedDashDash(t, .Normal);
                },
            }
        },
    } else {
        try t.emitEOF();
        return null;
    }
}

fn scriptDataEscaped(t: *Self) !?ScriptState {
    while (try t.next()) |current_input_char| {
        switch (current_input_char) {
            '-' => {
                try t.emitCharacter('-');

                // ScriptDataEscapedDash
                if ((try t.nextIgnoreEof()) != '-') {
                    t.reconsume();
                    continue;
                }
                try t.emitCharacter('-');

                // ScriptDataEscapedDashDash
                return try scriptDataEscapedOrDoubleEscapedDashDash(t, .Escaped);
            },
            // ScriptDataEscapedLessThanSign
            '<' => switch (try t.nextIgnoreEof()) {
                '/' => {
                    try nonDataEndTagOpen(t);
                    if (t.state != .ScriptData) return null;
                },
                'A'...'Z', 'a'...'z' => {
                    t.clearTempBuffer();
                    try t.emitCharacter('<');
                    t.reconsume();

                    // ScriptDataDoubleEscapeStart
                    return try scriptDataDoubleEscapeStartOrEnd(t, .Escaped);
                },
                else => {
                    try t.emitCharacter('<');
                    t.reconsume();
                },
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
        return null;
    }
}

fn scriptDataDoubleEscaped(t: *Self) !?ScriptState {
    while (try t.next()) |current_input_char| {
        switch (current_input_char) {
            '-' => {
                try t.emitCharacter('-');

                // ScriptDataDoubleEscapedDash
                if ((try t.nextIgnoreEof()) != '-') {
                    t.reconsume();
                    continue;
                }
                try t.emitCharacter('-');

                // ScriptDataDoubleEscapedDashDash
                return try scriptDataEscapedOrDoubleEscapedDashDash(t, .DoubleEscaped);
            },
            '<' => {
                try t.emitCharacter('<');

                // ScriptDataDoubleEscapedLessThanSign
                if ((try t.nextIgnoreEof()) != '/') {
                    t.reconsume();
                    continue;
                }

                t.clearTempBuffer();
                try t.emitCharacter('/');

                // ScriptDataDoubleEscapeEnd
                return try scriptDataDoubleEscapeStartOrEnd(t, .DoubleEscaped);
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
        return null;
    }
}

fn scriptDataDoubleEscapeStartOrEnd(t: *Self, script_state: ScriptState) !ScriptState {
    // TODO: Get rid of this use of the temp buffer
    while (true) switch (try t.nextIgnoreEof()) {
        '\t', '\n', 0x0C, ' ', '/', '>' => |c| {
            try t.emitCharacter(c);
            if (t.tempBufferEql("script")) {
                return switch (script_state) {
                    .Normal => unreachable,
                    .Escaped => .DoubleEscaped,
                    .DoubleEscaped => .Escaped,
                };
            } else {
                return script_state;
            }
        },
        'A'...'Z' => |c| {
            try t.appendTempBuffer(toLowercase(c));
            try t.emitCharacter(c);
        },
        'a'...'z' => |c| {
            try t.appendTempBuffer(c);
            try t.emitCharacter(c);
        },
        else => {
            t.reconsume();
            return script_state;
        },
    };
}

fn scriptDataEscapedOrDoubleEscapedDashDash(t: *Self, script_state: ScriptState) !?ScriptState {
    while (true) switch (try t.nextIgnoreEof()) {
        '-' => try t.emitCharacter('-'),
        '>' => {
            try t.emitCharacter('>');
            return .Normal;
        },
        else => {
            t.reconsume();
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
