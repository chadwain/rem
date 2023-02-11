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
    CDATASection,
    TagName,
    SelfClosingStartTag,
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

fn processInput(t: *Self, input: *[]const u21) !void {
    switch (t.state) {
        .Data => {
            if (try t.nextInputChar(input)) |current_input_char| {
                switch (current_input_char) {
                    '&' => try characterReference(t, input, IsPartOfAnAttribute.No),
                    '<' => return tagOpen(t, input),
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
            while (try t.nextInputChar(input)) |current_input_char| switch (current_input_char) {
                0x00 => {
                    try t.parseError(.UnexpectedNullCharacter);
                    try t.emitCharacter(REPLACEMENT_CHARACTER);
                },
                else => |c| try t.emitCharacter(c),
                '<' => {
                    // t.setState(.RAWTEXTLessThanSign);
                    if ((try t.nextInputChar(input)) != @as(u21, '/')) {
                        try t.emitCharacter('<');
                        t.reconsume(.RAWTEXT);
                        continue;
                    }

                    return nonDataEndTagOpen(t, input);
                },
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
        .TagName => {
            if (try t.nextInputChar(input)) |current_input_char| {
                switch (current_input_char) {
                    '\t', '\n', 0x0C, ' ' => return attribute(t, input),
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
                    '&' => try characterReference(t, input, IsPartOfAnAttribute.No),
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

                        return nonDataEndTagOpen(t, input);
                    },
                }
            } else {
                return t.emitEOF();
            }
        },
        .ScriptData => return scriptData(t, input),
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
                        t.reconsume(t.state);
                        return attribute(t, input);
                    },
                }
            } else {
                try t.parseError(.EOFInTag);
                try t.emitEOF();
            }
        },
        .CDATASection => {
            while (try t.nextInputChar(input)) |current_input_char| {
                switch (current_input_char) {
                    ']' => {
                        // CDATASectionBracket
                        if ((try t.nextInputChar(input)) != @as(u21, ']')) {
                            try t.emitCharacter(']');
                            t.reconsume(.CDATASection);
                            continue;
                        }

                        // CDATASectionEnd
                        while (true) switch ((try t.nextInputChar(input)) orelse TREAT_AS_ANYTHING_ELSE) {
                            ']' => try t.emitCharacter(']'),
                            '>' => return t.setState(.Data),
                            else => {
                                try t.emitString("]]");
                                t.reconsume(.CDATASection);
                                break;
                            },
                        };
                    },
                    else => |c| try t.emitCharacter(c),
                }
            } else {
                try t.parseError(.EOFInCDATA);
                try t.emitEOF();
                return;
            }
        },
    }
}

fn skipHtmlWhitespace(t: *Self, input: *[]const u21) !void {
    while (true) switch ((try t.nextInputChar(input)) orelse TREAT_AS_ANYTHING_ELSE) {
        '\t', '\n', 0x0C, ' ' => {},
        else => return t.reconsume(t.state),
    };
}

const IsPartOfAnAttribute = enum { Yes, No };

fn characterReference(t: *Self, input: *[]const u21, is_part_of_an_attribute: IsPartOfAnAttribute) !void {
    // NOTE: This is not exactly as the spec says, but should yield the same results.
    t.clearTempBuffer();
    try t.appendTempBuffer('&');
    switch (t.peekInputChar(input) orelse TREAT_AS_ANYTHING_ELSE) {
        '0'...'9', 'A'...'Z', 'a'...'z' => {
            return namedCharacterReference(t, input, is_part_of_an_attribute);
        },
        '#' => {
            _ = try t.nextInputChar(input);
            try t.appendTempBuffer('#');
            return numericCharacterReference(t, input, is_part_of_an_attribute);
        },
        else => try t.flushCharacterReference(is_part_of_an_attribute),
    }
}

fn namedCharacterReference(t: *Self, input: *[]const u21, is_part_of_an_attribute: IsPartOfAnAttribute) !void {
    const chars = try t.findNamedCharacterReference(input);
    const match_found = chars[0] != null;
    if (match_found) {
        const historical_reasons = is_part_of_an_attribute == .Yes and
            t.tempBufferLast() != ';' and
            switch (t.peekInputChar(input) orelse TREAT_AS_ANYTHING_ELSE) {
            '=', '0'...'9', 'A'...'Z', 'a'...'z' => true,
            else => false,
        };
        if (historical_reasons) {
            try t.flushCharacterReference(is_part_of_an_attribute);
        } else {
            if (t.tempBufferLast() != ';') {
                try t.parseError(.MissingSemicolonAfterCharacterReference);
            }
            t.clearTempBuffer();
            try t.appendTempBuffer(chars[0].?);
            if (chars[1]) |c| try t.appendTempBuffer(c);
            try t.flushCharacterReference(is_part_of_an_attribute);
        }
    } else {
        try t.flushCharacterReference(is_part_of_an_attribute);
        return ambiguousAmpersand(t, input, is_part_of_an_attribute);
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

fn ambiguousAmpersand(t: *Self, input: *[]const u21, is_part_of_an_attribute: IsPartOfAnAttribute) !void {
    while (true) switch ((try t.nextInputChar(input)) orelse TREAT_AS_ANYTHING_ELSE) {
        '0'...'9', 'A'...'Z', 'a'...'z' => |c| switch (is_part_of_an_attribute) {
            .Yes => try t.appendCurrentAttributeValue(c),
            .No => try t.emitCharacter(c),
        },
        ';' => {
            try t.parseError(.UnknownNamedCharacterReference);
            return t.reconsume(t.state);
        },
        else => return t.reconsume(t.state),
    };
}

fn numericCharacterReference(t: *Self, input: *[]const u21, is_part_of_an_attribute: IsPartOfAnAttribute) !void {
    var character_reference_code: u21 = 0;
    switch ((try t.nextInputChar(input)) orelse TREAT_AS_ANYTHING_ELSE) {
        'x', 'X' => |x| {
            try t.appendTempBuffer(x);

            // HexadecimalCharacterReferenceStart
            switch ((try t.nextInputChar(input)) orelse TREAT_AS_ANYTHING_ELSE) {
                '0'...'9', 'A'...'F', 'a'...'f' => {
                    t.reconsume(t.state);

                    // HexadecimalCharacterReference
                    while (true) switch ((try t.nextInputChar(input)) orelse TREAT_AS_ANYTHING_ELSE) {
                        '0'...'9' => |c| characterReferenceCodeAddDigit(&character_reference_code, 16, decimalCharToNumber(c)),
                        'A'...'F' => |c| characterReferenceCodeAddDigit(&character_reference_code, 16, upperHexCharToNumber(c)),
                        'a'...'f' => |c| characterReferenceCodeAddDigit(&character_reference_code, 16, lowerHexCharToNumber(c)),
                        ';' => break,
                        else => {
                            try t.parseError(.MissingSemicolonAfterCharacterReference);
                            break t.reconsume(t.state);
                        },
                    };
                },
                else => return noDigitsInNumericCharacterReference(t, is_part_of_an_attribute),
            }
        },
        // DecimalCharacterReferenceStart
        '0'...'9' => {
            t.reconsume(t.state);

            // DecimalCharacterReference
            while (true) switch ((try t.nextInputChar(input)) orelse TREAT_AS_ANYTHING_ELSE) {
                '0'...'9' => |c| characterReferenceCodeAddDigit(&character_reference_code, 10, decimalCharToNumber(c)),
                ';' => break,
                else => {
                    try t.parseError(.MissingSemicolonAfterCharacterReference);
                    break t.reconsume(t.state);
                },
            };
        },
        else => return noDigitsInNumericCharacterReference(t, is_part_of_an_attribute),
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
    try t.flushCharacterReference(is_part_of_an_attribute);
}

fn characterReferenceCodeAddDigit(character_reference_code: *u21, comptime base: comptime_int, digit: u21) void {
    character_reference_code.* = character_reference_code.* *| base +| digit;
}

fn noDigitsInNumericCharacterReference(t: *Self, is_part_of_an_attribute: IsPartOfAnAttribute) !void {
    try t.parseError(.AbsenceOfDigitsInNumericCharacterReference);
    try t.flushCharacterReference(is_part_of_an_attribute);
    t.reconsume(t.state);
}

fn flushCharacterReference(self: *Self, is_part_of_an_attribute: IsPartOfAnAttribute) !void {
    switch (is_part_of_an_attribute) {
        .Yes => for (self.temp_buffer.items) |character| {
            var code_units: [4]u8 = undefined;
            const len = try std.unicode.utf8Encode(character, &code_units);
            try self.generic_buffer.appendSlice(self.allocator, code_units[0..len]);
        },
        .No => for (self.temp_buffer.items) |character| {
            try self.emitCharacter(character);
        },
    }
}

fn tagOpen(t: *Self, input: *[]const u21) !void {
    if (try t.nextInputChar(input)) |current_input_char| {
        switch (current_input_char) {
            '!' => return markupDeclarationOpen(t, input),
            '/' => return endTagOpen(t, input),
            'A'...'Z', 'a'...'z' => {
                t.createStartTagToken();
                t.reconsume(.TagName);
            },
            '?' => {
                try t.parseError(.UnexpectedQuestionMarkInsteadOfTagName);
                t.createCommentToken();
                t.reconsume(t.state);
                return bogusComment(t, input);
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
}

fn endTagOpen(t: *Self, input: *[]const u21) !void {
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
                t.reconsume(t.state);
                return bogusComment(t, input);
            },
        }
    } else {
        try t.parseError(.EOFBeforeTagName);
        try t.emitString("</");
        try t.emitEOF();
    }
}

fn markupDeclarationOpen(t: *Self, input: *[]const u21) !void {
    if (t.consumeCharsIfEql(input, "--")) {
        t.createCommentToken();
        return commentStart(t, input);
    } else if (t.consumeCharsIfCaseInsensitiveEql(input, "DOCTYPE")) {
        return doctype(t, input);
    } else if (t.consumeCharsIfEql(input, "[CDATA[")) {
        if (t.adjustedCurrentNodeIsNotInHtmlNamespace()) {
            t.setState(.CDATASection);
        } else {
            try t.parseError(.CDATAInHtmlContent);
            t.createCommentToken();
            try t.appendCommentString("[CDATA[");
            return bogusComment(t, input);
        }
    } else {
        try t.parseError(.IncorrectlyOpenedComment);
        t.createCommentToken();
        return bogusComment(t, input);
    }
}

fn bogusComment(t: *Self, input: *[]const u21) !void {
    while (try t.nextInputChar(input)) |current_input_char| switch (current_input_char) {
        '>' => {
            try t.emitComment();
            return t.setState(.Data);
        },
        0x00 => {
            try t.parseError(.UnexpectedNullCharacter);
            try t.appendComment(REPLACEMENT_CHARACTER);
        },
        else => |c| try t.appendComment(c),
    } else {
        try t.emitComment();
        try t.emitEOF();
    }
}

fn nonDataEndTagOpen(t: *Self, input: *[]const u21) !void {
    t.clearTempBuffer();
    switch ((try t.nextInputChar(input)) orelse TREAT_AS_ANYTHING_ELSE) {
        'A'...'Z', 'a'...'z' => {
            t.createEndTagToken();
            t.reconsume(t.state);
            return endTagName(t, input);
        },
        else => {
            try t.emitString("</");
            t.reconsume(t.state);
        },
    }
}

fn endTagName(t: *Self, input: *[]const u21) !void {
    while (try t.nextInputChar(input)) |current_input_char| {
        switch (current_input_char) {
            '\t', '\n', 0x0C, ' ' => {
                if (t.isAppropriateEndTag()) {
                    return attribute(t, input);
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
    t.reconsume(t.state);
}

const AttributeState = enum {
    BeforeName,
    Name,
    AfterName,
    Value,
};

fn attribute(t: *Self, input: *[]const u21) !void {
    var next_state: ?AttributeState = .BeforeName;
    while (next_state) |state| {
        next_state = switch (state) {
            .BeforeName => try beforeAttributeName(t, input),
            .Name => try attributeName(t, input),
            .AfterName => try afterAttributeName(t, input),
            .Value => try beforeAttributeValue(t, input),
        };
    }
}

fn beforeAttributeName(t: *Self, input: *[]const u21) !AttributeState {
    // Make end-of-file (null) be handled the same as '>'
    while (true) switch ((try t.nextInputChar(input)) orelse '>') {
        '\t', '\n', 0x0C, ' ' => {},
        '/', '>' => {
            t.reconsume(t.state);
            return .AfterName;
        },
        '=' => {
            try t.parseError(.UnexpectedEqualsSignBeforeAttributeName);
            t.createAttribute();
            try t.appendCurrentAttributeName('=');
            return .Name;
        },
        else => {
            t.createAttribute();
            t.reconsume(t.state);
            return .Name;
        },
    };
}

fn attributeName(t: *Self, input: *[]const u21) !AttributeState {
    // Make end-of-file (null) be handled the same as '>'
    while (true) switch ((try t.nextInputChar(input)) orelse '>') {
        '\t', '\n', 0x0C, ' ', '/', '>' => {
            try t.finishAttributeName();
            t.reconsume(t.state);
            return .AfterName;
        },
        '=' => {
            try t.finishAttributeName();
            t.setState(t.state);
            return .Value;
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
    };
}

fn afterAttributeName(t: *Self, input: *[]const u21) !?AttributeState {
    while (true) {
        if (try t.nextInputChar(input)) |current_input_char| {
            switch (current_input_char) {
                '\t', '\n', 0x0C, ' ' => {},
                '/' => {
                    t.setState(.SelfClosingStartTag);
                    return null;
                },
                '=' => return .Value,
                '>' => {
                    try t.emitCurrentTag();
                    t.setState(.Data);
                    return null;
                },
                else => {
                    t.createAttribute();
                    t.reconsume(t.state);
                    return AttributeState.Name;
                },
            }
        } else {
            return try eofInTag(t);
        }
    }
}

fn beforeAttributeValue(t: *Self, input: *[]const u21) !?AttributeState {
    while (true) switch ((try t.nextInputChar(input)) orelse TREAT_AS_ANYTHING_ELSE) {
        '\t', '\n', 0x0C, ' ' => {},
        '"' => return attributeValueQuoted(t, input, .Double),
        '\'' => return attributeValueQuoted(t, input, .Single),
        '>' => {
            try t.parseError(.MissingAttributeValue);
            try t.emitCurrentTag();
            t.setState(.Data);
            return null;
        },
        else => {
            t.reconsume(t.state);
            return attributeValueUnquoted(t, input);
        },
    };
}

const QuoteStyle = enum { Single, Double };

fn attributeValueQuoted(t: *Self, input: *[]const u21, comptime quote_style: QuoteStyle) !?AttributeState {
    const quote = switch (quote_style) {
        .Single => '\'',
        .Double => '"',
    };

    while (try t.nextInputChar(input)) |current_input_char| {
        switch (current_input_char) {
            quote => {
                try t.finishAttributeValue();
                break;
            },
            '&' => try characterReference(t, input, IsPartOfAnAttribute.Yes),
            0x00 => {
                try t.parseError(.UnexpectedNullCharacter);
                try t.appendCurrentAttributeValue(REPLACEMENT_CHARACTER);
            },
            else => |c| try t.appendCurrentAttributeValue(c),
        }
    } else {
        return try eofInTag(t);
    }

    // AfterAttributeValueQuoted
    if (try t.nextInputChar(input)) |current_input_char| {
        switch (current_input_char) {
            '\t', '\n', 0x0C, ' ' => return AttributeState.BeforeName,
            '/' => {
                t.setState(.SelfClosingStartTag);
                return null;
            },
            '>' => {
                try t.emitCurrentTag();
                t.setState(.Data);
                return null;
            },
            else => {
                try t.parseError(.MissingWhitespaceBetweenAttributes);
                t.reconsume(t.state);
                return AttributeState.BeforeName;
            },
        }
    } else {
        return try eofInTag(t);
    }
}

fn attributeValueUnquoted(t: *Self, input: *[]const u21) !?AttributeState {
    while (try t.nextInputChar(input)) |current_input_char| switch (current_input_char) {
        '\t', '\n', 0x0C, ' ' => {
            try t.finishAttributeValue();
            t.setState(t.state);
            return AttributeState.BeforeName;
        },
        '&' => try characterReference(t, input, IsPartOfAnAttribute.Yes),
        '>' => {
            try t.finishAttributeValue();
            try t.emitCurrentTag();
            t.setState(.Data);
            return null;
        },
        0x00 => {
            try t.parseError(.UnexpectedNullCharacter);
            try t.appendCurrentAttributeValue(REPLACEMENT_CHARACTER);
        },
        '"', '\'', '<', '=', '`' => |c| {
            try t.parseError(.UnexpectedCharacterInUnquotedAttributeValue);
            try t.appendCurrentAttributeValue(c);
        },
        else => |c| try t.appendCurrentAttributeValue(c),
    } else {
        return try eofInTag(t);
    }
}

fn eofInTag(t: *Self) !?AttributeState {
    try t.parseError(.EOFInTag);
    try t.emitEOF();
    return null;
}

const CommentState = enum {
    Normal,
    EndDash,
    End,
};

fn commentStart(t: *Self, input: *[]const u21) !void {
    var next_state: ?CommentState = next_state: {
        switch ((try t.nextInputChar(input)) orelse TREAT_AS_ANYTHING_ELSE) {
            '-' => {
                // CommentStartDash
                switch ((try t.nextInputChar(input)) orelse break :next_state try eofInComment(t)) {
                    '-' => break :next_state .End,
                    '>' => break :next_state try abruptCommentClose(t),
                    else => {
                        try t.appendComment('-');
                        t.reconsume(t.state);
                        break :next_state .Normal;
                    },
                }
            },
            '>' => break :next_state try abruptCommentClose(t),
            else => {
                t.reconsume(t.state);
                break :next_state .Normal;
            },
        }
    };

    while (next_state) |state| {
        next_state = switch (state) {
            .Normal => try comment(t, input),
            .EndDash => try commentEndDash(t, input),
            .End => try commentEnd(t, input),
        };
    }
}

fn comment(t: *Self, input: *[]const u21) !?CommentState {
    while (try t.nextInputChar(input)) |current_input_char| switch (current_input_char) {
        '<' => {
            try t.appendComment('<');

            // CommentLessThanSign
            while (true) switch ((try t.nextInputChar(input)) orelse TREAT_AS_ANYTHING_ELSE) {
                '!' => {
                    try t.appendComment('!');

                    // CommentLessThanSignBang
                    if ((try t.nextInputChar(input)) != @as(u21, '-')) {
                        t.reconsume(t.state);
                        break;
                    }

                    // CommentLessThanSignBangDash
                    if ((try t.nextInputChar(input)) != @as(u21, '-')) {
                        t.reconsume(t.state);
                        return CommentState.EndDash;
                    }

                    // CommentLessThanSignBangDashDash
                    // Make end-of-file (null) be handled the same as '>'
                    if ((try t.nextInputChar(input)) orelse '>' != '>') {
                        try t.parseError(.NestedComment);
                    }
                    t.reconsume(t.state);
                    return .End;
                },
                '<' => try t.appendComment('<'),
                else => {
                    t.reconsume(t.state);
                    break;
                },
            };
        },
        '-' => return .EndDash,
        0x00 => {
            try t.parseError(.UnexpectedNullCharacter);
            try t.appendComment(REPLACEMENT_CHARACTER);
        },
        else => |c| try t.appendComment(c),
    } else {
        return try eofInComment(t);
    }
}

fn commentEndDash(t: *Self, input: *[]const u21) !?CommentState {
    switch ((try t.nextInputChar(input)) orelse return try eofInComment(t)) {
        '-' => return CommentState.End,
        else => {
            try t.appendComment('-');
            t.reconsume(t.state);
            return CommentState.Normal;
        },
    }
}

fn commentEnd(t: *Self, input: *[]const u21) !?CommentState {
    while (try t.nextInputChar(input)) |current_input_char| switch (current_input_char) {
        '>' => {
            try t.emitComment();
            return null;
        },
        '!' => return try commentEndBang(t, input),
        '-' => try t.appendComment('-'),
        else => {
            try t.appendComment('-');
            try t.appendComment('-');
            t.reconsume(t.state);
            return CommentState.Normal;
        },
    } else {
        return try eofInComment(t);
    }
}

fn commentEndBang(t: *Self, input: *[]const u21) !?CommentState {
    switch ((try t.nextInputChar(input)) orelse return try eofInComment(t)) {
        '-' => {
            try t.appendComment('-');
            try t.appendComment('-');
            try t.appendComment('!');
            return CommentState.EndDash;
        },
        '>' => return incorrectlyClosedComment(t),
        else => {
            try t.appendComment('-');
            try t.appendComment('-');
            try t.appendComment('!');
            t.reconsume(t.state);
            return CommentState.Normal;
        },
    }
}

fn eofInComment(t: *Self) !?CommentState {
    try t.parseError(.EOFInComment);
    try t.emitComment();
    try t.emitEOF();
    return null;
}

fn abruptCommentClose(t: *Self) !?CommentState {
    try t.parseError(.AbruptClosingOfEmptyComment);
    try t.emitComment();
    return null;
}

fn incorrectlyClosedComment(t: *Self) !?CommentState {
    try t.parseError(.IncorrectlyClosedComment);
    try t.emitComment();
    return null;
}

const DoctypeState = enum {
    BeforeName,
    Name,
    AfterName,
};

fn doctype(t: *Self, input: *[]const u21) !void {
    t.createDOCTYPEToken();
    var next_state: ?DoctypeState = next_state: {
        if (try t.nextInputChar(input)) |current_input_char| {
            switch (current_input_char) {
                '\t', '\n', 0x0C, ' ' => {},
                '>' => t.reconsume(t.state),
                else => {
                    try t.parseError(.MissingWhitespaceBeforeDOCTYPEName);
                    t.reconsume(t.state);
                },
            }
            break :next_state .BeforeName;
        } else {
            break :next_state try eofInDoctype(t);
        }
    };

    while (next_state) |state| {
        next_state = switch (state) {
            .BeforeName => try beforeDoctypeName(t, input),
            .Name => try doctypeName(t, input),
            .AfterName => try afterDoctypeName(t, input),
        };
    }
}

fn beforeDoctypeName(t: *Self, input: *[]const u21) !?DoctypeState {
    while (try t.nextInputChar(input)) |current_input_char| {
        switch (current_input_char) {
            '\t', '\n', 0x0C, ' ' => {},
            'A'...'Z' => |c| {
                t.markCurrentDOCTYPENameNotMissing();
                try t.appendDOCTYPEName(toLowercase(c));
                return DoctypeState.Name;
            },
            0x00 => {
                try t.parseError(.UnexpectedNullCharacter);
                t.markCurrentDOCTYPENameNotMissing();
                try t.appendDOCTYPEName(REPLACEMENT_CHARACTER);
                return DoctypeState.Name;
            },
            '>' => {
                try t.parseError(.MissingDOCTYPEName);
                t.currentDOCTYPETokenForceQuirks();
                return try doctypeEnd(t);
            },
            else => |c| {
                t.markCurrentDOCTYPENameNotMissing();
                try t.appendDOCTYPEName(c);
                return DoctypeState.Name;
            },
        }
    } else {
        return try eofInDoctype(t);
    }
}

fn doctypeName(t: *Self, input: *[]const u21) !?DoctypeState {
    while (try t.nextInputChar(input)) |current_input_char| {
        switch (current_input_char) {
            '\t', '\n', 0x0C, ' ' => return DoctypeState.AfterName,
            '>' => return try doctypeEnd(t),
            'A'...'Z' => |c| try t.appendDOCTYPEName(toLowercase(c)),
            0x00 => {
                try t.parseError(.UnexpectedNullCharacter);
                try t.appendDOCTYPEName(REPLACEMENT_CHARACTER);
            },
            else => |c| try t.appendDOCTYPEName(c),
        }
    } else {
        return try eofInDoctype(t);
    }
}

fn afterDoctypeName(t: *Self, input: *[]const u21) !?DoctypeState {
    while (try t.nextInputChar(input)) |current_input_char| {
        switch (current_input_char) {
            '\t', '\n', 0x0C, ' ' => {},
            '>' => return try doctypeEnd(t),
            else => |c| {
                if (caseInsensitiveEql(c, 'P') and t.consumeCharsIfCaseInsensitiveEql(input, "UBLIC")) {
                    return afterDOCTYPEPublicOrSystemKeyword(t, input, .public);
                } else if (caseInsensitiveEql(c, 'S') and t.consumeCharsIfCaseInsensitiveEql(input, "YSTEM")) {
                    return afterDOCTYPEPublicOrSystemKeyword(t, input, .system);
                } else {
                    try t.parseError(.InvalidCharacterSequenceAfterDOCTYPEName);
                    t.currentDOCTYPETokenForceQuirks();
                    t.reconsume(t.state);
                    return bogusDOCTYPE(t, input);
                }
            },
        }
    } else {
        return try eofInDoctype(t);
    }
}

const PublicOrSystem = enum { public, system };

fn afterDOCTYPEPublicOrSystemKeyword(t: *Self, input: *[]const u21, public_or_system: PublicOrSystem) !?DoctypeState {
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
                return try doctypeEnd(t);
            },
            else => {
                const err: ParseError = switch (public_or_system) {
                    .public => .MissingQuoteBeforeDOCTYPEPublicIdentifier,
                    .system => .MissingQuoteBeforeDOCTYPESystemIdentifier,
                };
                try t.parseError(err);
                t.currentDOCTYPETokenForceQuirks();
                t.reconsume(t.state);
                return bogusDOCTYPE(t, input);
            },
        }
    } else {
        return try eofInDoctype(t);
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
                return try doctypeEnd(t);
            },
            else => {
                const err: ParseError = switch (public_or_system) {
                    .public => .MissingQuoteBeforeDOCTYPEPublicIdentifier,
                    .system => .MissingQuoteBeforeDOCTYPESystemIdentifier,
                };
                try t.parseError(err);
                t.currentDOCTYPETokenForceQuirks();
                t.reconsume(t.state);
                return bogusDOCTYPE(t, input);
            },
        }
    } else {
        return try eofInDoctype(t);
    }
}

fn doctypePublicOrSystemIdentifier(t: *Self, input: *[]const u21, public_or_system: PublicOrSystem, quote: u21) Error!?DoctypeState {
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
            return try doctypeEnd(t);
        } else {
            try append(t, current_input_char);
        }
    } else {
        return try eofInDoctype(t);
    }
}

fn afterDOCTYPEPublicIdentifier(t: *Self, input: *[]const u21) !?DoctypeState {
    if (try t.nextInputChar(input)) |current_input_char| {
        switch (current_input_char) {
            '\t', '\n', 0x0C, ' ' => {},
            '>' => return try doctypeEnd(t),
            '"', '\'' => |quote| {
                try t.parseError(.MissingWhitespaceBetweenDOCTYPEPublicAndSystemIdentifiers);
                return doctypePublicOrSystemIdentifier(t, input, .system, quote);
            },
            else => {
                try t.parseError(.MissingQuoteBeforeDOCTYPESystemIdentifier);
                t.currentDOCTYPETokenForceQuirks();
                t.reconsume(t.state);
                return bogusDOCTYPE(t, input);
            },
        }
    } else {
        return try eofInDoctype(t);
    }

    // BetweenDOCTYPEPublicAndSystemIdentifiers
    try skipHtmlWhitespace(t, input);
    if (try t.nextInputChar(input)) |current_input_char| {
        switch (current_input_char) {
            '\t', '\n', 0x0C, ' ' => unreachable,
            '>' => return try doctypeEnd(t),
            '"', '\'' => |quote| {
                return doctypePublicOrSystemIdentifier(t, input, .system, quote);
            },
            else => {
                try t.parseError(.MissingQuoteBeforeDOCTYPESystemIdentifier);
                t.currentDOCTYPETokenForceQuirks();
                t.reconsume(t.state);
                return bogusDOCTYPE(t, input);
            },
        }
    } else {
        return try eofInDoctype(t);
    }
}

fn afterDOCTYPESystemIdentifier(t: *Self, input: *[]const u21) !?DoctypeState {
    try skipHtmlWhitespace(t, input);
    if (try t.nextInputChar(input)) |current_input_char| {
        switch (current_input_char) {
            '\t', '\n', 0x0C, ' ' => unreachable,
            '>' => return try doctypeEnd(t),
            else => {
                try t.parseError(.UnexpectedCharacterAfterDOCTYPESystemIdentifier);
                t.reconsume(t.state);
                return bogusDOCTYPE(t, input);
            },
        }
    } else {
        return try eofInDoctype(t);
    }
}

fn doctypeEnd(t: *Self) !?DoctypeState {
    try t.emitDOCTYPE();
    t.setState(.Data);
    return null;
}

fn eofInDoctype(t: *Self) !?DoctypeState {
    try t.parseError(.EOFInDOCTYPE);
    t.currentDOCTYPETokenForceQuirks();
    try t.emitDOCTYPE();
    try t.emitEOF();
    return null;
}

fn bogusDOCTYPE(t: *Self, input: *[]const u21) !?DoctypeState {
    while (try t.nextInputChar(input)) |current_input_char| switch (current_input_char) {
        '>' => {
            try t.emitDOCTYPE();
            t.setState(.Data);
            return null;
        },
        0x00 => try t.parseError(.UnexpectedNullCharacter),
        else => {},
    } else {
        try t.emitDOCTYPE();
        try t.emitEOF();
        return null;
    }
}

const ScriptState = enum {
    Normal,
    Escaped,
    DoubleEscaped,
};

fn scriptData(t: *Self, input: *[]const u21) !void {
    var next_state: ?ScriptState = .Normal;
    while (next_state) |state| {
        next_state = switch (state) {
            .Normal => try scriptDataNormal(t, input),
            .Escaped => try scriptDataEscaped(t, input),
            .DoubleEscaped => try scriptDataDoubleEscaped(t, input),
        };
    }
}

fn scriptDataNormal(t: *Self, input: *[]const u21) !?ScriptState {
    while (try t.nextInputChar(input)) |char| switch (char) {
        0x00 => {
            try t.parseError(.UnexpectedNullCharacter);
            try t.emitCharacter(REPLACEMENT_CHARACTER);
        },
        else => try t.emitCharacter(char),
        '<' => {
            // ScriptDataLessThanSign
            switch ((try t.nextInputChar(input)) orelse TREAT_AS_ANYTHING_ELSE) {
                else => {
                    try t.emitCharacter('<');
                    t.reconsume(.ScriptData);
                    continue;
                },
                // ScriptDataEndTagOpen
                '/' => {
                    try nonDataEndTagOpen(t, input);
                    if (t.state != .ScriptData) return null;
                },
                '!' => {
                    try t.emitString("<!");

                    // ScriptDataEscapeStart
                    if ((try t.nextInputChar(input)) != @as(u21, '-')) {
                        t.reconsume(.ScriptData);
                        continue;
                    }
                    try t.emitCharacter('-');

                    // ScriptDataEscapeStartDash
                    if ((try t.nextInputChar(input)) != @as(u21, '-')) {
                        t.reconsume(.ScriptData);
                        continue;
                    }
                    try t.emitCharacter('-');

                    // ScriptDataEscapedDashDash
                    return try scriptDataEscapedOrDoubleEscapedDashDash(t, input, .Normal);
                },
            }
        },
    } else {
        try t.emitEOF();
        return null;
    }
}

fn scriptDataEscaped(t: *Self, input: *[]const u21) !?ScriptState {
    while (try t.nextInputChar(input)) |current_input_char| {
        switch (current_input_char) {
            '-' => {
                try t.emitCharacter('-');

                // ScriptDataEscapedDash
                if ((try t.nextInputChar(input)) != @as(u21, '-')) {
                    t.reconsume(.ScriptData);
                    continue;
                }
                try t.emitCharacter('-');

                // ScriptDataEscapedDashDash
                return try scriptDataEscapedOrDoubleEscapedDashDash(t, input, .Escaped);
            },
            // ScriptDataEscapedLessThanSign
            '<' => switch ((try t.nextInputChar(input)) orelse TREAT_AS_ANYTHING_ELSE) {
                '/' => {
                    try nonDataEndTagOpen(t, input);
                    if (t.state != .ScriptData) return null;
                },
                'A'...'Z', 'a'...'z' => {
                    t.clearTempBuffer();
                    try t.emitCharacter('<');
                    t.reconsume(t.state);

                    // ScriptDataDoubleEscapeStart
                    return try scriptDataDoubleEscapeStartOrEnd(t, input, .Escaped);
                },
                else => {
                    try t.emitCharacter('<');
                    t.reconsume(.ScriptData);
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

fn scriptDataDoubleEscaped(t: *Self, input: *[]const u21) !?ScriptState {
    while (try t.nextInputChar(input)) |current_input_char| {
        switch (current_input_char) {
            '-' => {
                try t.emitCharacter('-');

                // ScriptDataDoubleEscapedDash
                if ((try t.nextInputChar(input)) != @as(u21, '-')) {
                    t.reconsume(.ScriptData);
                    continue;
                }
                try t.emitCharacter('-');

                // ScriptDataDoubleEscapedDashDash
                return try scriptDataEscapedOrDoubleEscapedDashDash(t, input, .DoubleEscaped);
            },
            '<' => {
                try t.emitCharacter('<');

                // ScriptDataDoubleEscapedLessThanSign
                if ((try t.nextInputChar(input)) != @as(u21, '/')) {
                    t.reconsume(.ScriptData);
                    continue;
                }

                t.clearTempBuffer();
                try t.emitCharacter('/');

                // ScriptDataDoubleEscapeEnd
                return try scriptDataDoubleEscapeStartOrEnd(t, input, .DoubleEscaped);
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

fn scriptDataDoubleEscapeStartOrEnd(t: *Self, input: *[]const u21, script_state: ScriptState) !ScriptState {
    // TODO: Get rid of this use of the temp buffer
    while (true) switch ((try t.nextInputChar(input)) orelse TREAT_AS_ANYTHING_ELSE) {
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
            t.reconsume(t.state);
            return script_state;
        },
    };
}

fn scriptDataEscapedOrDoubleEscapedDashDash(t: *Self, input: *[]const u21, script_state: ScriptState) !?ScriptState {
    while (true) switch ((try t.nextInputChar(input)) orelse TREAT_AS_ANYTHING_ELSE) {
        '-' => try t.emitCharacter('-'),
        '>' => {
            try t.emitCharacter('>');
            return .Normal;
        },
        else => {
            t.reconsume(.ScriptData);
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
