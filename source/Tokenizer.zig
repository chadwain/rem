// Copyright (C) 2021-2024 Chadwain Holness
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

// TODO: The memory management here is very messy. Make life easier by using an arena allocator.

const Tokenizer = @This();
const rem = @import("../rem.zig");
const named_characters = @import("named_characters.zig");
const Token = @import("token.zig").Token;
const Attributes = Token.StartTag.Attributes;
const Parser = @import("Parser.zig");
const ParseError = Parser.ParseError;

const std = @import("std");
const ArrayList = std.ArrayList;
const ArrayListUnmanaged = std.ArrayListUnmanaged;
const Allocator = std.mem.Allocator;

const REPLACEMENT_CHARACTER = '\u{FFFD}';
const TREAT_AS_ANYTHING_ELSE = '\u{FFFF}';

state: State,
eof: bool = false,
last_start_tag: LastStartTag,
adjusted_current_node_is_not_in_html_namespace: bool = false,
parser: *Parser,
tokens: ArrayListUnmanaged(Token) = .{},
allocator: Allocator,

pub fn init(parser: *Parser, state: State, last_start_tag: ?LastStartTag) Tokenizer {
    std.debug.assert(state != .Eof);
    return Tokenizer{
        .state = state,
        .last_start_tag = last_start_tag orelse undefined,
        .parser = parser,
        .allocator = parser.allocator,
    };
}

pub fn deinit(tokenizer: *Tokenizer) void {
    for (tokenizer.tokens.items) |*token| {
        token.deinit(tokenizer.allocator);
    }
    tokenizer.tokens.deinit(tokenizer.allocator);
}

pub fn run(tokenizer: *Tokenizer) !void {
    for (tokenizer.tokens.items) |*token| {
        token.deinit(tokenizer.allocator);
    }
    tokenizer.tokens.clearRetainingCapacity();

    switch (tokenizer.state) {
        .Data => try data(tokenizer),
        .RAWTEXT => try rawText(tokenizer),
        .RCDATA => try rcData(tokenizer),
        .CDATASection => try cDataSection(tokenizer),
        .PLAINTEXT => try plainText(tokenizer),
        .ScriptData => try scriptData(tokenizer),
        .Eof => try sendEof(tokenizer),
    }
}

pub const Error = error{
    AbortParsing,
    OutOfMemory,
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
    Eof,
};

/// The list of all possible start tags which, when processed in the tree construction phase,
/// may cause the tokenizer to switch to the RCDATA, RAWTEXT, ScriptData, or PLAINTEXT states.
pub const LastStartTag = enum {
    iframe,
    noembed,
    noframes,
    noscript,
    plaintext,
    script,
    style,
    textarea,
    title,
    xmp,

    pub fn fromString(string: []const u8) ?LastStartTag {
        const map = std.StaticStringMap(LastStartTag).initComptime(.{
            .{ "iframe", .iframe },
            .{ "noembed", .noembed },
            .{ "noframes", .noframes },
            .{ "noscript", .noscript },
            .{ "plaintext", .plaintext },
            .{ "style", .style },
            .{ "textarea", .textarea },
            .{ "title", .title },
            .{ "script", .script },
            .{ "xmp", .xmp },
        });
        return map.get(string);
    }
};

pub fn setState(tokenizer: *Tokenizer, new_state: State) void {
    tokenizer.state = new_state;
}

pub fn setLastStartTag(tokenizer: *Tokenizer, last_start_tag: LastStartTag) void {
    tokenizer.last_start_tag = last_start_tag;
}

pub fn setAdjustedCurrentNodeIsNotInHtmlNamespace(tokenizer: *Tokenizer, value: bool) void {
    tokenizer.adjusted_current_node_is_not_in_html_namespace = value;
}

pub fn moveTokens(tokenizer: *Tokenizer, dest: []Token) void {
    std.debug.assert(dest.len == tokenizer.tokens.items.len);
    @memcpy(dest, tokenizer.tokens.items);
    tokenizer.tokens.clearRetainingCapacity();
}

/// Returns the next input character in the input stream.
/// Implements §13.2.3.5 "Preprocessing the input stream" of the HTML standard.
fn next(tokenizer: *Tokenizer) !?u21 {
    const char = nextNoErrorCheck(tokenizer);
    if (char) |c| {
        try checkInputCharacterForErrors(tokenizer, c);
    }
    return char;
}

fn nextNoErrorCheck(tokenizer: *Tokenizer) ?u21 {
    std.debug.assert(tokenizer.parser.input_stream.position <= tokenizer.parser.input_stream.text.len);

    if (tokenizer.parser.input_stream.position == tokenizer.parser.input_stream.text.len) {
        tokenizer.parser.input_stream.eof = true;
        return null;
    }

    var char = tokenizer.parser.input_stream.text[tokenizer.parser.input_stream.position];
    tokenizer.parser.input_stream.position += 1;
    if (char == '\r') {
        char = '\n';
        if (tokenizer.parser.input_stream.position < tokenizer.parser.input_stream.text.len and
            tokenizer.parser.input_stream.text[tokenizer.parser.input_stream.position] == '\n')
        {
            tokenizer.parser.input_stream.position += 1;
        }
    }

    return char;
}

/// Undoes a call to `nextNoErrorCheck`.
fn undo(tokenizer: *Tokenizer) void {
    if (tokenizer.parser.input_stream.eof) {
        tokenizer.parser.input_stream.eof = false;
        return;
    }

    const previous = tokenizer.parser.input_stream.text[tokenizer.parser.input_stream.position - 1];
    if (previous == '\n' and tokenizer.parser.input_stream.position >= 2 and
        tokenizer.parser.input_stream.text[tokenizer.parser.input_stream.position - 2] == '\r')
    {
        tokenizer.parser.input_stream.position -= 2;
    } else {
        tokenizer.parser.input_stream.position -= 1;
    }
}

fn nextIgnoreEofNoErrorCheck(tokenizer: *Tokenizer) u21 {
    return nextNoErrorCheck(tokenizer) orelse TREAT_AS_ANYTHING_ELSE;
}

fn peekIgnoreEof(tokenizer: *Tokenizer) u21 {
    const char = nextIgnoreEofNoErrorCheck(tokenizer);
    undo(tokenizer);
    return char;
}

/// Given a character from the input stream, this function checks to see if that
/// character is a surrogate, noncharacter, or control character, and if so,
/// emits a parse error.
/// Implements part of §13.2.3.5 "Preprocessing the input stream" of the HTML standard.
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
        const next_char = nextNoErrorCheck(tokenizer) orelse break;
        if (!eqlFn(string_char, next_char)) break;
    } else {
        return true;
    }

    while (index > 0) : (index -= 1) {
        undo(tokenizer);
    }
    return false;
}

fn emitToken(tokenizer: *Tokenizer, token: Token) !void {
    try tokenizer.tokens.append(tokenizer.allocator, token);
}

fn emitCharacter(tokenizer: *Tokenizer, character: u21) !void {
    try tokenizer.emitToken(Token{ .character = .{ .data = character } });
}

fn emitString(tokenizer: *Tokenizer, comptime string: []const u8) !void {
    for (rem.util.utf8DecodeStringComptime(string)) |character| {
        try emitCharacter(tokenizer, character);
    }
}

fn parseError(tokenizer: *Tokenizer, err: Parser.ParseError) !void {
    try tokenizer.parser.parseError(err);
}

fn adjustedCurrentNodeIsNotInHtmlNamespace(tokenizer: *Tokenizer) bool {
    return tokenizer.adjusted_current_node_is_not_in_html_namespace;
}

fn sendEof(tokenizer: *Tokenizer) !void {
    try tokenizer.emitToken(.eof);
    tokenizer.eof = true;
}

fn data(tokenizer: *Tokenizer) !void {
    while (try next(tokenizer)) |char| switch (char) {
        '&' => try characterReference(tokenizer, null),
        '<' => return tagOpen(tokenizer),
        0x00 => {
            try tokenizer.parseError(.UnexpectedNullCharacter);
            try tokenizer.emitCharacter(0x00);
        },
        else => |c| try tokenizer.emitCharacter(c),
    } else {
        return tokenizer.setState(.Eof);
    }
}

fn markupDeclarationOpen(tokenizer: *Tokenizer) !void {
    if (consumeCharsIfEql(tokenizer, "--")) {
        return comment(tokenizer);
    } else if (consumeCharsIfCaseInsensitiveEql(tokenizer, "DOCTYPE")) {
        return doctype(tokenizer);
    } else if (consumeCharsIfEql(tokenizer, "[CDATA[")) {
        if (tokenizer.adjustedCurrentNodeIsNotInHtmlNamespace()) {
            return tokenizer.setState(.CDATASection);
        } else {
            try tokenizer.parseError(.CDATAInHtmlContent);
            for ("[CDATA[") |_| undo(tokenizer);
            return bogusComment(tokenizer);
        }
    } else {
        try tokenizer.parseError(.IncorrectlyOpenedComment);
        return bogusComment(tokenizer);
    }
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
        try appendChar(&tag_data.name, tag_data.allocator, char);
    }

    fn appendCurrentAttributeName(tag_data: *TagData, char: u21) !void {
        try appendChar(&tag_data.buffer, tag_data.allocator, char);
    }

    fn appendCurrentAttributeValue(tag_data: *TagData, char: u21) !void {
        try appendChar(&tag_data.buffer, tag_data.allocator, char);
    }

    fn finishAttributeName(tag_data: *TagData, tokenizer: *Tokenizer) !void {
        const attribute_name = try tag_data.buffer.toOwnedSlice(tag_data.allocator);
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

    fn finishAttributeValue(tag_data: *TagData) !void {
        const attribute_value = try tag_data.buffer.toOwnedSlice(tag_data.allocator);
        if (tag_data.current_attribute_value_result_location) |ptr| {
            ptr.* = attribute_value;
        } else {
            tag_data.allocator.free(attribute_value);
        }
        tag_data.current_attribute_value_result_location = undefined;
    }
};

fn emitTag(tokenizer: *Tokenizer, tag_data: *TagData) !void {
    const name = try tag_data.name.toOwnedSlice(tag_data.allocator);
    errdefer tag_data.allocator.free(name);

    switch (tag_data.start_or_end) {
        .Start => {
            const token = Token{ .start_tag = .{
                .name = name,
                .attributes = tag_data.attributes,
                .self_closing = tag_data.self_closing,
            } };
            tag_data.attributes = .{};
            try tokenizer.emitToken(token);
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

            tokenizer.last_start_tag = undefined;

            const token = Token{ .end_tag = .{
                .name = name,
            } };
            try tokenizer.emitToken(token);
        },
    }
}

fn tagOpen(tokenizer: *Tokenizer) !void {
    if (nextNoErrorCheck(tokenizer)) |char| switch (char) {
        '!' => return markupDeclarationOpen(tokenizer),
        '/' => return endTagOpen(tokenizer),
        'A'...'Z', 'a'...'z' => {
            undo(tokenizer);
            return tagName(tokenizer, .Start);
        },
        '?' => {
            try tokenizer.parseError(.UnexpectedQuestionMarkInsteadOfTagName);
            undo(tokenizer);
            return bogusComment(tokenizer);
        },
        else => {
            try tokenizer.parseError(.InvalidFirstCharacterOfTagName);
            try tokenizer.emitCharacter('<');
            return undo(tokenizer);
        },
    } else {
        try tokenizer.parseError(.EOFBeforeTagName);
        try tokenizer.emitCharacter('<');
        return tokenizer.setState(.Eof);
    }
}

fn endTagOpen(tokenizer: *Tokenizer) !void {
    if (nextNoErrorCheck(tokenizer)) |char| {
        switch (char) {
            'A'...'Z', 'a'...'z' => {
                undo(tokenizer);
                return tagName(tokenizer, .End);
            },
            '>' => try tokenizer.parseError(.MissingEndTagName),
            else => {
                try tokenizer.parseError(.InvalidFirstCharacterOfTagName);
                undo(tokenizer);
                return bogusComment(tokenizer);
            },
        }
    } else {
        try tokenizer.parseError(.EOFBeforeTagName);
        try tokenizer.emitString("</");
        return tokenizer.setState(.Eof);
    }
}

fn tagName(tokenizer: *Tokenizer, start_or_end: TagData.StartOrEnd) !void {
    var tag_data = TagData.init(start_or_end, tokenizer.allocator);
    defer tag_data.deinit();

    while (try next(tokenizer)) |current_input_char| {
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
        return tokenizer.setState(.Eof);
    }
}

fn nonDataEndTagOpen(tokenizer: *Tokenizer) !void {
    switch (nextIgnoreEofNoErrorCheck(tokenizer)) {
        'A'...'Z', 'a'...'z' => {
            undo(tokenizer);
            return nonDataEndTagName(tokenizer);
        },
        else => {
            try tokenizer.emitString("</");
            undo(tokenizer);
        },
    }
}

fn nonDataEndTagName(tokenizer: *Tokenizer) !void {
    var tag_data = TagData.init(.End, tokenizer.allocator);
    defer tag_data.deinit();

    while (nextNoErrorCheck(tokenizer)) |char| {
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
    undo(tokenizer);
}

fn isAppropriateEndTag(tokenizer: *Tokenizer, tag_data: *const TagData) bool {
    return tokenizer.last_start_tag == LastStartTag.fromString(tag_data.name.items);
}

const AttributeState = enum {
    BeforeName,
    Name,
    Value,
    Slash,
};

fn attribute(tokenizer: *Tokenizer, tag_data: *TagData) !void {
    return attributeLoop(tokenizer, tag_data, .BeforeName);
}

fn selfClosingStartTag(tokenizer: *Tokenizer, tag_data: *TagData) !void {
    return attributeLoop(tokenizer, tag_data, .Slash);
}

fn attributeLoop(tokenizer: *Tokenizer, tag_data: *TagData, initial_state: AttributeState) !void {
    var next_state: ?AttributeState = initial_state;
    while (next_state) |state| {
        next_state = switch (state) {
            .BeforeName => try beforeAttributeName(tokenizer, tag_data),
            .Name => try attributeName(tokenizer, tag_data),
            .Value => try beforeAttributeValue(tokenizer, tag_data),
            .Slash => try attributeSlash(tokenizer, tag_data),
        };
    }
}

fn beforeAttributeName(tokenizer: *Tokenizer, tag_data: *TagData) !?AttributeState {
    // Make end-of-file (null) be handled the same as '>'
    while (true) switch (nextNoErrorCheck(tokenizer) orelse '>') {
        '\t', '\n', 0x0C, ' ' => {},
        '/', '>' => {
            undo(tokenizer);
            return try afterAttributeName(tokenizer, tag_data);
        },
        '=' => {
            try tokenizer.parseError(.UnexpectedEqualsSignBeforeAttributeName);
            try tag_data.appendCurrentAttributeName('=');
            return AttributeState.Name;
        },
        else => {
            undo(tokenizer);
            return AttributeState.Name;
        },
    };
}

fn attributeName(tokenizer: *Tokenizer, tag_data: *TagData) !?AttributeState {
    // Make end-of-file (null) be handled the same as '>'
    while (true) switch ((try next(tokenizer)) orelse '>') {
        '\t', '\n', 0x0C, ' ', '/', '>' => {
            try tag_data.finishAttributeName(tokenizer);
            undo(tokenizer);
            return try afterAttributeName(tokenizer, tag_data);
        },
        '=' => {
            try tag_data.finishAttributeName(tokenizer);
            return AttributeState.Value;
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

fn afterAttributeName(tokenizer: *Tokenizer, tag_data: *TagData) !?AttributeState {
    while (nextNoErrorCheck(tokenizer)) |current_input_char| {
        switch (current_input_char) {
            '\t', '\n', 0x0C, ' ' => {},
            '/' => return AttributeState.Slash,
            '=' => return AttributeState.Value,
            '>' => return try attributeEnd(tokenizer, tag_data),
            else => {
                undo(tokenizer);
                return AttributeState.Name;
            },
        }
    } else {
        return try eofInTag(tokenizer);
    }
}

fn beforeAttributeValue(tokenizer: *Tokenizer, tag_data: *TagData) !?AttributeState {
    while (true) switch (nextIgnoreEofNoErrorCheck(tokenizer)) {
        '\t', '\n', 0x0C, ' ' => {},
        '"' => return attributeValueQuoted(tokenizer, tag_data, .Double),
        '\'' => return attributeValueQuoted(tokenizer, tag_data, .Single),
        '>' => {
            try tokenizer.parseError(.MissingAttributeValue);
            return try attributeEnd(tokenizer, tag_data);
        },
        else => {
            undo(tokenizer);
            return attributeValueUnquoted(tokenizer, tag_data);
        },
    };
}

const QuoteStyle = enum { Single, Double };

fn attributeValueQuoted(tokenizer: *Tokenizer, tag_data: *TagData, comptime quote_style: QuoteStyle) !?AttributeState {
    const quote = switch (quote_style) {
        .Single => '\'',
        .Double => '"',
    };

    while (try next(tokenizer)) |current_input_char| {
        switch (current_input_char) {
            quote => break try tag_data.finishAttributeValue(),
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
    if (nextNoErrorCheck(tokenizer)) |current_input_char| {
        switch (current_input_char) {
            '\t', '\n', 0x0C, ' ' => return AttributeState.BeforeName,
            '/' => return AttributeState.Slash,
            '>' => return try attributeEnd(tokenizer, tag_data),
            else => {
                try tokenizer.parseError(.MissingWhitespaceBetweenAttributes);
                undo(tokenizer);
                return AttributeState.BeforeName;
            },
        }
    } else {
        return try eofInTag(tokenizer);
    }
}

fn attributeValueUnquoted(tokenizer: *Tokenizer, tag_data: *TagData) !?AttributeState {
    while (try next(tokenizer)) |current_input_char| switch (current_input_char) {
        '\t', '\n', 0x0C, ' ' => {
            try tag_data.finishAttributeValue();
            return AttributeState.BeforeName;
        },
        '&' => try characterReference(tokenizer, tag_data),
        '>' => {
            try tag_data.finishAttributeValue();
            return try attributeEnd(tokenizer, tag_data);
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

fn attributeSlash(tokenizer: *Tokenizer, tag_data: *TagData) !?AttributeState {
    if (nextNoErrorCheck(tokenizer)) |current_input_char| {
        switch (current_input_char) {
            '>' => {
                tag_data.self_closing = true;
                return try attributeEnd(tokenizer, tag_data);
            },
            else => {
                try tokenizer.parseError(.UnexpectedSolidusInTag);
                undo(tokenizer);
                return AttributeState.BeforeName;
            },
        }
    } else {
        return try eofInTag(tokenizer);
    }
}

fn attributeEnd(tokenizer: *Tokenizer, tag_data: *TagData) !?AttributeState {
    tokenizer.setState(.Data);
    try emitTag(tokenizer, tag_data);
    return null;
}

fn eofInTag(tokenizer: *Tokenizer) !?AttributeState {
    try tokenizer.parseError(.EOFInTag);
    tokenizer.setState(.Eof);
    return null;
}

fn characterReference(tokenizer: *Tokenizer, tag_data: ?*TagData) !void {
    // By assumption, the '&' character has just been consumed.
    var num_consumed_chars: usize = 1;

    switch (nextIgnoreEofNoErrorCheck(tokenizer)) {
        '0'...'9', 'A'...'Z', 'a'...'z' => {
            undo(tokenizer);
            return namedCharacterReference(tokenizer, tag_data, &num_consumed_chars);
        },
        '#' => {
            num_consumed_chars += 1;
            return numericCharacterReference(tokenizer, tag_data, &num_consumed_chars);
        },
        else => {
            undo(tokenizer);
            return flushCharacterReference(tokenizer, tag_data, &num_consumed_chars);
        },
    }
}

fn namedCharacterReference(tokenizer: *Tokenizer, tag_data: ?*TagData, num_consumed_chars: *usize) !void {
    const result = try findNamedCharacterReference(tokenizer, num_consumed_chars);
    const match_found = result.chars[0] != null;
    if (match_found) {
        const dont_emit_chars = if (tag_data != null and !result.ends_with_semicolon)
            switch (peekIgnoreEof(tokenizer)) {
                '=', '0'...'9', 'A'...'Z', 'a'...'z' => true,
                else => false,
            }
        else
            false;

        if (dont_emit_chars) {
            return flushCharacterReference(tokenizer, tag_data, num_consumed_chars);
        } else {
            if (!result.ends_with_semicolon) {
                try tokenizer.parseError(.MissingSemicolonAfterCharacterReference);
            }
            try characterReferenceEmitCharacter(tokenizer, tag_data, result.chars[0].?);
            if (result.chars[1]) |second| try characterReferenceEmitCharacter(tokenizer, tag_data, second);
        }
    } else {
        try flushCharacterReference(tokenizer, tag_data, num_consumed_chars);
        return ambiguousAmpersand(tokenizer, tag_data);
    }
}

const FindNamedCharacterReferenceResult = struct {
    chars: named_characters.Value,
    ends_with_semicolon: bool,
};

fn findNamedCharacterReference(tokenizer: *Tokenizer, num_consumed_chars: *usize) !FindNamedCharacterReferenceResult {
    var last_index_with_value = named_characters.root_index;
    var ends_with_semicolon: bool = false;

    var entry = named_characters.root_index.entry();
    var num_pending_chars: usize = 0;

    while (true) {
        const character = nextNoErrorCheck(tokenizer) orelse {
            undo(tokenizer);
            break;
        };
        num_pending_chars += 1;
        const child_index = entry.findChild(character) orelse break;
        entry = child_index.entry();

        if (entry.has_children) {
            if (entry.has_value) {
                // Partial match found.
                num_consumed_chars.* += num_pending_chars;
                num_pending_chars = 0;
                last_index_with_value = child_index;
                ends_with_semicolon = character == ';';
            }
        } else {
            // Complete match found.
            num_consumed_chars.* += num_pending_chars;
            num_pending_chars = 0;
            last_index_with_value = child_index;
            ends_with_semicolon = character == ';';
            break;
        }
    }

    while (num_pending_chars > 0) : (num_pending_chars -= 1) {
        undo(tokenizer);
    }

    // There is no need to check the consumed characters for errors (controls, surrogates, noncharacters)
    // beacuse we've just determined that they form a valid character reference.
    return FindNamedCharacterReferenceResult{ .chars = last_index_with_value.value(), .ends_with_semicolon = ends_with_semicolon };
}

fn ambiguousAmpersand(tokenizer: *Tokenizer, tag_data: ?*TagData) !void {
    while (true) switch (nextIgnoreEofNoErrorCheck(tokenizer)) {
        '0'...'9', 'A'...'Z', 'a'...'z' => |c| try characterReferenceEmitCharacter(tokenizer, tag_data, c),
        ';' => break try tokenizer.parseError(.UnknownNamedCharacterReference),
        else => break,
    };

    undo(tokenizer);
}

fn numericCharacterReference(tokenizer: *Tokenizer, tag_data: ?*TagData, num_consumed_chars: *usize) !void {
    var character_reference_code: u21 = 0;
    switch (nextIgnoreEofNoErrorCheck(tokenizer)) {
        'x', 'X' => {
            num_consumed_chars.* += 1;

            // HexadecimalCharacterReferenceStart
            switch (nextIgnoreEofNoErrorCheck(tokenizer)) {
                '0'...'9', 'A'...'F', 'a'...'f' => {
                    undo(tokenizer);

                    // HexadecimalCharacterReference
                    while (true) switch (nextIgnoreEofNoErrorCheck(tokenizer)) {
                        '0'...'9' => |c| characterReferenceCodeAddDigit(&character_reference_code, 16, decimalCharToNumber(c)),
                        'A'...'F' => |c| characterReferenceCodeAddDigit(&character_reference_code, 16, upperHexCharToNumber(c)),
                        'a'...'f' => |c| characterReferenceCodeAddDigit(&character_reference_code, 16, lowerHexCharToNumber(c)),
                        ';' => break,
                        else => {
                            try tokenizer.parseError(.MissingSemicolonAfterCharacterReference);
                            break undo(tokenizer);
                        },
                    };
                },
                else => return noDigitsInNumericCharacterReference(tokenizer, tag_data, num_consumed_chars),
            }
        },
        // DecimalCharacterReferenceStart
        '0'...'9' => {
            undo(tokenizer);

            // DecimalCharacterReference
            while (true) switch (nextIgnoreEofNoErrorCheck(tokenizer)) {
                '0'...'9' => |c| characterReferenceCodeAddDigit(&character_reference_code, 10, decimalCharToNumber(c)),
                ';' => break,
                else => {
                    try tokenizer.parseError(.MissingSemicolonAfterCharacterReference);
                    break undo(tokenizer);
                },
            };
        },
        else => return noDigitsInNumericCharacterReference(tokenizer, tag_data, num_consumed_chars),
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

    try characterReferenceEmitCharacter(tokenizer, tag_data, character_reference_code);
}

fn characterReferenceCodeAddDigit(character_reference_code: *u21, comptime base: comptime_int, digit: u21) void {
    character_reference_code.* = character_reference_code.* *| base +| digit;
}

fn noDigitsInNumericCharacterReference(tokenizer: *Tokenizer, tag_data: ?*TagData, num_consumed_chars: *const usize) !void {
    try tokenizer.parseError(.AbsenceOfDigitsInNumericCharacterReference);
    undo(tokenizer);
    try flushCharacterReference(tokenizer, tag_data, num_consumed_chars);
}

fn flushCharacterReference(tokenizer: *Tokenizer, tag_data: ?*TagData, num_consumed_chars: *const usize) !void {
    var i = num_consumed_chars.*;
    while (i > 0) : (i -= 1) {
        undo(tokenizer);
    }

    i = num_consumed_chars.*;
    while (i > 0) : (i -= 1) {
        const character = nextNoErrorCheck(tokenizer).?;
        try characterReferenceEmitCharacter(tokenizer, tag_data, character);
    }
}

fn characterReferenceEmitCharacter(tokenizer: *Tokenizer, tag_data: ?*TagData, character: u21) !void {
    if (tag_data) |td| {
        try td.appendCurrentAttributeValue(character);
    } else {
        try tokenizer.emitCharacter(character);
    }
}

const CommentState = enum {
    Normal,
    EndDash,
    End,
};

fn comment(tokenizer: *Tokenizer) !void {
    var comment_data = ArrayListUnmanaged(u8){};
    defer comment_data.deinit(tokenizer.allocator);

    var next_state: ?CommentState = try commentStart(tokenizer, &comment_data);
    while (next_state) |state| {
        next_state = switch (state) {
            .Normal => try commentNormal(tokenizer, &comment_data),
            .EndDash => try commentEndDash(tokenizer, &comment_data),
            .End => try commentEnd(tokenizer, &comment_data),
        };
    }

    try tokenizer.emitComment(&comment_data);
}

fn commentStart(tokenizer: *Tokenizer, comment_data: *ArrayListUnmanaged(u8)) !?CommentState {
    switch (nextIgnoreEofNoErrorCheck(tokenizer)) {
        '-' => {
            // CommentStartDash
            switch (nextNoErrorCheck(tokenizer) orelse return try eofInComment(tokenizer)) {
                '-' => return CommentState.End,
                '>' => return try abruptCommentClose(tokenizer),
                else => {
                    try comment_data.append(tokenizer.allocator, '-');
                    undo(tokenizer);
                    return CommentState.Normal;
                },
            }
        },
        '>' => return try abruptCommentClose(tokenizer),
        else => {
            undo(tokenizer);
            return CommentState.Normal;
        },
    }
}

fn commentNormal(tokenizer: *Tokenizer, comment_data: *ArrayListUnmanaged(u8)) !?CommentState {
    while (try next(tokenizer)) |current_input_char| switch (current_input_char) {
        '<' => {
            try comment_data.append(tokenizer.allocator, '<');

            // CommentLessThanSign
            while (true) switch (nextIgnoreEofNoErrorCheck(tokenizer)) {
                '!' => {
                    try comment_data.append(tokenizer.allocator, '!');

                    // CommentLessThanSignBang
                    if (nextIgnoreEofNoErrorCheck(tokenizer) != '-') {
                        undo(tokenizer);
                        break;
                    }

                    // CommentLessThanSignBangDash
                    if (nextIgnoreEofNoErrorCheck(tokenizer) != '-') {
                        undo(tokenizer);
                        return CommentState.EndDash;
                    }

                    // CommentLessThanSignBangDashDash
                    // Make end-of-file (null) be handled the same as '>'
                    if (nextNoErrorCheck(tokenizer) orelse '>' != '>') {
                        try tokenizer.parseError(.NestedComment);
                    }
                    undo(tokenizer);
                    return CommentState.End;
                },
                '<' => try comment_data.append(tokenizer.allocator, '<'),
                else => {
                    undo(tokenizer);
                    break;
                },
            };
        },
        '-' => return CommentState.EndDash,
        0x00 => {
            try tokenizer.parseError(.UnexpectedNullCharacter);
            try appendChar(comment_data, tokenizer.allocator, REPLACEMENT_CHARACTER);
        },
        else => |c| try appendChar(comment_data, tokenizer.allocator, c),
    } else {
        return try eofInComment(tokenizer);
    }
}

fn commentEndDash(tokenizer: *Tokenizer, comment_data: *ArrayListUnmanaged(u8)) !?CommentState {
    switch (nextNoErrorCheck(tokenizer) orelse return try eofInComment(tokenizer)) {
        '-' => return CommentState.End,
        else => {
            try comment_data.append(tokenizer.allocator, '-');
            undo(tokenizer);
            return CommentState.Normal;
        },
    }
}

fn commentEnd(tokenizer: *Tokenizer, comment_data: *ArrayListUnmanaged(u8)) !?CommentState {
    while (nextNoErrorCheck(tokenizer)) |current_input_char| switch (current_input_char) {
        '>' => return null,
        '!' => return try commentEndBang(tokenizer, comment_data),
        '-' => try comment_data.append(tokenizer.allocator, '-'),
        else => {
            try comment_data.appendSlice(tokenizer.allocator, "--");
            undo(tokenizer);
            return CommentState.Normal;
        },
    } else {
        return try eofInComment(tokenizer);
    }
}

fn commentEndBang(tokenizer: *Tokenizer, comment_data: *ArrayListUnmanaged(u8)) !?CommentState {
    switch (nextNoErrorCheck(tokenizer) orelse return try eofInComment(tokenizer)) {
        '-' => {
            try comment_data.appendSlice(tokenizer.allocator, "--!");
            return CommentState.EndDash;
        },
        '>' => return incorrectlyClosedComment(tokenizer),
        else => {
            try comment_data.appendSlice(tokenizer.allocator, "--!");
            undo(tokenizer);
            return CommentState.Normal;
        },
    }
}

fn bogusComment(tokenizer: *Tokenizer) !void {
    var comment_data = ArrayListUnmanaged(u8){};
    defer comment_data.deinit(tokenizer.allocator);

    while (try next(tokenizer)) |char| switch (char) {
        '>' => break,
        0x00 => {
            try tokenizer.parseError(.UnexpectedNullCharacter);
            try appendChar(&comment_data, tokenizer.allocator, REPLACEMENT_CHARACTER);
        },
        else => |c| try appendChar(&comment_data, tokenizer.allocator, c),
    } else {
        tokenizer.setState(.Eof);
    }

    try tokenizer.emitComment(&comment_data);
}

fn emitComment(tokenizer: *Tokenizer, comment_data: *ArrayListUnmanaged(u8)) !void {
    const owned = try comment_data.toOwnedSlice(tokenizer.allocator);
    errdefer tokenizer.allocator.free(owned);
    try tokenizer.emitToken(Token{ .comment = .{ .data = owned } });
}

fn eofInComment(tokenizer: *Tokenizer) !?CommentState {
    try tokenizer.parseError(.EOFInComment);
    tokenizer.setState(.Eof);
    return null;
}

fn abruptCommentClose(tokenizer: *Tokenizer) !?CommentState {
    try tokenizer.parseError(.AbruptClosingOfEmptyComment);
    return null;
}

fn incorrectlyClosedComment(tokenizer: *Tokenizer) !?CommentState {
    try tokenizer.parseError(.IncorrectlyClosedComment);
    return null;
}

const DoctypeData = struct {
    name: ?ArrayListUnmanaged(u8) = null,
    public_identifier: ?ArrayListUnmanaged(u8) = null,
    system_identifier: ?ArrayListUnmanaged(u8) = null,
    force_quirks: bool = false,

    fn deinit(doctype_data: *DoctypeData, allocator: Allocator) void {
        if (doctype_data.name) |*name| name.deinit(allocator);
        if (doctype_data.public_identifier) |*public_identifier| public_identifier.deinit(allocator);
        if (doctype_data.system_identifier) |*system_identifier| system_identifier.deinit(allocator);
    }
};

fn doctype(tokenizer: *Tokenizer) !void {
    var doctype_data = DoctypeData{};
    defer doctype_data.deinit(tokenizer.allocator);

    try doctypeStart(tokenizer, &doctype_data);

    const name_owned = if (doctype_data.name) |*name| try name.toOwnedSlice(tokenizer.allocator) else null;
    errdefer if (name_owned) |name| tokenizer.allocator.free(name);

    const public_identifier_owned =
        if (doctype_data.public_identifier) |*public_identifier| try public_identifier.toOwnedSlice(tokenizer.allocator) else null;
    errdefer if (public_identifier_owned) |public_identifier| tokenizer.allocator.free(public_identifier);

    const system_identifier_owned =
        if (doctype_data.system_identifier) |*system_identifier| try system_identifier.toOwnedSlice(tokenizer.allocator) else null;
    errdefer if (system_identifier_owned) |system_identifier| tokenizer.allocator.free(system_identifier);

    const doctype_token = Token{ .doctype = .{
        .name = name_owned,
        .public_identifier = public_identifier_owned,
        .system_identifier = system_identifier_owned,
        .force_quirks = doctype_data.force_quirks,
    } };
    try tokenizer.emitToken(doctype_token);
}

fn doctypeStart(tokenizer: *Tokenizer, doctype_data: *DoctypeData) !void {
    if (nextNoErrorCheck(tokenizer)) |current_input_char| {
        switch (current_input_char) {
            '\t', '\n', 0x0C, ' ' => {},
            '>' => undo(tokenizer),
            else => {
                try tokenizer.parseError(.MissingWhitespaceBeforeDOCTYPEName);
                undo(tokenizer);
            },
        }
        return try beforeDoctypeName(tokenizer, doctype_data);
    } else {
        return try eofInDoctype(tokenizer, doctype_data);
    }
}

fn beforeDoctypeName(tokenizer: *Tokenizer, doctype_data: *DoctypeData) !void {
    while (nextNoErrorCheck(tokenizer)) |current_input_char| {
        switch (current_input_char) {
            '\t', '\n', 0x0C, ' ' => {},
            '>' => {
                try tokenizer.parseError(.MissingDOCTYPEName);
                doctype_data.force_quirks = true;
                return;
            },
            else => {
                undo(tokenizer);
                return try doctypeName(tokenizer, doctype_data);
            },
        }
    } else {
        return try eofInDoctype(tokenizer, doctype_data);
    }
}

fn doctypeName(tokenizer: *Tokenizer, doctype_data: *DoctypeData) !void {
    doctype_data.name = ArrayListUnmanaged(u8){};
    const doctype_name_data = &doctype_data.name.?;

    while (try next(tokenizer)) |current_input_char| {
        switch (current_input_char) {
            '\t', '\n', 0x0C, ' ' => return afterDoctypeName(tokenizer, doctype_data),
            '>' => return,
            0x00 => {
                try tokenizer.parseError(.UnexpectedNullCharacter);
                try appendChar(doctype_name_data, tokenizer.allocator, REPLACEMENT_CHARACTER);
            },
            else => |c| try appendChar(doctype_name_data, tokenizer.allocator, toLowercase(c)),
        }
    } else {
        return try eofInDoctype(tokenizer, doctype_data);
    }
}

fn afterDoctypeName(tokenizer: *Tokenizer, doctype_data: *DoctypeData) !void {
    while (nextNoErrorCheck(tokenizer)) |current_input_char| {
        switch (current_input_char) {
            '\t', '\n', 0x0C, ' ' => {},
            '>' => return,
            else => |c| {
                if (caseInsensitiveEql(c, 'P') and consumeCharsIfCaseInsensitiveEql(tokenizer, "UBLIC")) {
                    return afterDOCTYPEPublicOrSystemKeyword(tokenizer, doctype_data, .public);
                } else if (caseInsensitiveEql(c, 'S') and consumeCharsIfCaseInsensitiveEql(tokenizer, "YSTEM")) {
                    return afterDOCTYPEPublicOrSystemKeyword(tokenizer, doctype_data, .system);
                } else {
                    try tokenizer.parseError(.InvalidCharacterSequenceAfterDOCTYPEName);
                    doctype_data.force_quirks = true;
                    undo(tokenizer);
                    return bogusDOCTYPE(tokenizer);
                }
            },
        }
    } else {
        return try eofInDoctype(tokenizer, doctype_data);
    }
}

const PublicOrSystem = enum { public, system };

fn afterDOCTYPEPublicOrSystemKeyword(tokenizer: *Tokenizer, doctype_data: *DoctypeData, public_or_system: PublicOrSystem) !void {
    // AfterDOCTYPEPublicKeyword
    // AfterDOCTYPESystemKeyword
    if (nextNoErrorCheck(tokenizer)) |current_input_char| {
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
                return;
            },
            else => {
                const err: ParseError = switch (public_or_system) {
                    .public => .MissingQuoteBeforeDOCTYPEPublicIdentifier,
                    .system => .MissingQuoteBeforeDOCTYPESystemIdentifier,
                };
                try tokenizer.parseError(err);
                doctype_data.force_quirks = true;
                undo(tokenizer);
                return bogusDOCTYPE(tokenizer);
            },
        }
    } else {
        return try eofInDoctype(tokenizer, doctype_data);
    }

    // BeforeDOCTYPEPublicIdentifier
    // BeforeDOCTYPESystemIdentifier
    while (nextNoErrorCheck(tokenizer)) |current_input_char| {
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
                return;
            },
            else => {
                const err: ParseError = switch (public_or_system) {
                    .public => .MissingQuoteBeforeDOCTYPEPublicIdentifier,
                    .system => .MissingQuoteBeforeDOCTYPESystemIdentifier,
                };
                try tokenizer.parseError(err);
                doctype_data.force_quirks = true;
                undo(tokenizer);
                return bogusDOCTYPE(tokenizer);
            },
        }
    } else {
        return try eofInDoctype(tokenizer, doctype_data);
    }
}

fn doctypePublicOrSystemIdentifier(tokenizer: *Tokenizer, doctype_data: *DoctypeData, public_or_system: PublicOrSystem, quote: u21) Error!void {
    // DOCTYPEPublicIdentifierDoubleQuoted
    // DOCTYPEPublicIdentifierSingleQuoted
    // DOCTYPESystemIdentifierDoubleQuoted
    // DOCTYPESystemIdentifierSingleQuoted

    const identifier_data_optional = switch (public_or_system) {
        .public => &doctype_data.public_identifier,
        .system => &doctype_data.system_identifier,
    };
    identifier_data_optional.* = ArrayListUnmanaged(u8){};
    const identifier_data = &identifier_data_optional.*.?;

    while (try next(tokenizer)) |current_input_char| {
        if (current_input_char == quote) {
            const afterIdentifier = switch (public_or_system) {
                .public => &afterDOCTYPEPublicIdentifier,
                .system => &afterDOCTYPESystemIdentifier,
            };
            return afterIdentifier(tokenizer, doctype_data);
        } else if (current_input_char == 0x00) {
            try tokenizer.parseError(.UnexpectedNullCharacter);
            try appendChar(identifier_data, tokenizer.allocator, REPLACEMENT_CHARACTER);
        } else if (current_input_char == '>') {
            const err: ParseError = switch (public_or_system) {
                .public => .AbruptDOCTYPEPublicIdentifier,
                .system => .AbruptDOCTYPESystemIdentifier,
            };
            try tokenizer.parseError(err);
            doctype_data.force_quirks = true;
            return;
        } else {
            try appendChar(identifier_data, tokenizer.allocator, current_input_char);
        }
    } else {
        return try eofInDoctype(tokenizer, doctype_data);
    }
}

fn afterDOCTYPEPublicIdentifier(tokenizer: *Tokenizer, doctype_data: *DoctypeData) !void {
    if (nextNoErrorCheck(tokenizer)) |current_input_char| {
        switch (current_input_char) {
            '\t', '\n', 0x0C, ' ' => {},
            '>' => return,
            '"', '\'' => |quote| {
                try tokenizer.parseError(.MissingWhitespaceBetweenDOCTYPEPublicAndSystemIdentifiers);
                return doctypePublicOrSystemIdentifier(tokenizer, doctype_data, .system, quote);
            },
            else => {
                try tokenizer.parseError(.MissingQuoteBeforeDOCTYPESystemIdentifier);
                doctype_data.force_quirks = true;
                undo(tokenizer);
                return bogusDOCTYPE(tokenizer);
            },
        }
    } else {
        return try eofInDoctype(tokenizer, doctype_data);
    }

    // BetweenDOCTYPEPublicAndSystemIdentifiers
    while (nextNoErrorCheck(tokenizer)) |current_input_char| {
        switch (current_input_char) {
            '\t', '\n', 0x0C, ' ' => {},
            '>' => return,
            '"', '\'' => |quote| {
                return doctypePublicOrSystemIdentifier(tokenizer, doctype_data, .system, quote);
            },
            else => {
                try tokenizer.parseError(.MissingQuoteBeforeDOCTYPESystemIdentifier);
                doctype_data.force_quirks = true;
                undo(tokenizer);
                return bogusDOCTYPE(tokenizer);
            },
        }
    } else {
        return try eofInDoctype(tokenizer, doctype_data);
    }
}

fn afterDOCTYPESystemIdentifier(tokenizer: *Tokenizer, doctype_data: *DoctypeData) !void {
    while (nextNoErrorCheck(tokenizer)) |current_input_char| {
        switch (current_input_char) {
            '\t', '\n', 0x0C, ' ' => {},
            '>' => return,
            else => {
                try tokenizer.parseError(.UnexpectedCharacterAfterDOCTYPESystemIdentifier);
                undo(tokenizer);
                return bogusDOCTYPE(tokenizer);
            },
        }
    } else {
        return try eofInDoctype(tokenizer, doctype_data);
    }
}

fn eofInDoctype(tokenizer: *Tokenizer, doctype_data: *DoctypeData) !void {
    try tokenizer.parseError(.EOFInDOCTYPE);
    doctype_data.force_quirks = true;
    return tokenizer.setState(.Eof);
}

fn bogusDOCTYPE(tokenizer: *Tokenizer) !void {
    while (try next(tokenizer)) |current_input_char| switch (current_input_char) {
        '>' => return,
        0x00 => try tokenizer.parseError(.UnexpectedNullCharacter),
        else => {},
    } else {
        return tokenizer.setState(.Eof);
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
    while (try next(tokenizer)) |char| switch (char) {
        0x00 => {
            try tokenizer.parseError(.UnexpectedNullCharacter);
            try tokenizer.emitCharacter(REPLACEMENT_CHARACTER);
        },
        else => try tokenizer.emitCharacter(char),
        '<' => {
            // ScriptDataLessThanSign
            switch (nextIgnoreEofNoErrorCheck(tokenizer)) {
                else => {
                    try tokenizer.emitCharacter('<');
                    undo(tokenizer);
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
                    if (nextIgnoreEofNoErrorCheck(tokenizer) != '-') {
                        undo(tokenizer);
                        continue;
                    }
                    try tokenizer.emitCharacter('-');

                    // ScriptDataEscapeStartDash
                    if (nextIgnoreEofNoErrorCheck(tokenizer) != '-') {
                        undo(tokenizer);
                        continue;
                    }
                    try tokenizer.emitCharacter('-');

                    // ScriptDataEscapedDashDash
                    return try scriptDataEscapedOrDoubleEscapedDashDash(tokenizer, .Normal);
                },
            }
        },
    } else {
        tokenizer.setState(.Eof);
        return null;
    }
}

fn scriptDataEscaped(tokenizer: *Tokenizer) !?ScriptState {
    while (try next(tokenizer)) |current_input_char| {
        switch (current_input_char) {
            '-' => {
                try tokenizer.emitCharacter('-');

                // ScriptDataEscapedDash
                if (nextIgnoreEofNoErrorCheck(tokenizer) != '-') {
                    undo(tokenizer);
                    continue;
                }
                try tokenizer.emitCharacter('-');

                // ScriptDataEscapedDashDash
                return try scriptDataEscapedOrDoubleEscapedDashDash(tokenizer, .Escaped);
            },
            // ScriptDataEscapedLessThanSign
            '<' => switch (nextIgnoreEofNoErrorCheck(tokenizer)) {
                '/' => {
                    try nonDataEndTagOpen(tokenizer);
                    if (tokenizer.state != .ScriptData) return null;
                },
                'A'...'Z', 'a'...'z' => {
                    try tokenizer.emitCharacter('<');
                    undo(tokenizer);

                    // ScriptDataDoubleEscapeStart
                    return try scriptDataDoubleEscapeStartOrEnd(tokenizer, .Escaped);
                },
                else => {
                    try tokenizer.emitCharacter('<');
                    undo(tokenizer);
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
        tokenizer.setState(.Eof);
        return null;
    }
}

fn scriptDataDoubleEscaped(tokenizer: *Tokenizer) !?ScriptState {
    while (try next(tokenizer)) |current_input_char| {
        switch (current_input_char) {
            '-' => {
                try tokenizer.emitCharacter('-');

                // ScriptDataDoubleEscapedDash
                if (nextIgnoreEofNoErrorCheck(tokenizer) != '-') {
                    undo(tokenizer);
                    continue;
                }
                try tokenizer.emitCharacter('-');

                // ScriptDataDoubleEscapedDashDash
                return try scriptDataEscapedOrDoubleEscapedDashDash(tokenizer, .DoubleEscaped);
            },
            '<' => {
                try tokenizer.emitCharacter('<');

                // ScriptDataDoubleEscapedLessThanSign
                if (nextIgnoreEofNoErrorCheck(tokenizer) != '/') {
                    undo(tokenizer);
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
        tokenizer.setState(.Eof);
        return null;
    }
}

fn scriptDataDoubleEscapeStartOrEnd(tokenizer: *Tokenizer, script_state: ScriptState) !ScriptState {
    const script = "script";
    var num_matching_chars: u3 = 0;
    var matches: ?bool = null;
    while (true) switch (nextIgnoreEofNoErrorCheck(tokenizer)) {
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
            undo(tokenizer);
            return script_state;
        },
    };
}

fn scriptDataEscapedOrDoubleEscapedDashDash(tokenizer: *Tokenizer, script_state: ScriptState) !?ScriptState {
    while (true) switch (nextIgnoreEofNoErrorCheck(tokenizer)) {
        '-' => try tokenizer.emitCharacter('-'),
        '>' => {
            try tokenizer.emitCharacter('>');
            return .Normal;
        },
        else => {
            undo(tokenizer);
            const next_state: ScriptState = switch (script_state) {
                .Normal, .Escaped => .Escaped,
                .DoubleEscaped => .DoubleEscaped,
            };
            return next_state;
        },
    };
}

fn rawText(tokenizer: *Tokenizer) !void {
    while (try next(tokenizer)) |char| switch (char) {
        0x00 => {
            try tokenizer.parseError(.UnexpectedNullCharacter);
            try tokenizer.emitCharacter(REPLACEMENT_CHARACTER);
        },
        else => |c| try tokenizer.emitCharacter(c),
        '<' => {
            // RAWTEXTLessThanSign
            if (nextIgnoreEofNoErrorCheck(tokenizer) != '/') {
                try tokenizer.emitCharacter('<');
                undo(tokenizer);
                continue;
            }

            return nonDataEndTagOpen(tokenizer);
        },
    } else {
        return tokenizer.setState(.Eof);
    }
}

fn plainText(tokenizer: *Tokenizer) !void {
    while (true) {
        if (try next(tokenizer)) |char| switch (char) {
            0x00 => {
                try tokenizer.parseError(.UnexpectedNullCharacter);
                try tokenizer.emitCharacter(REPLACEMENT_CHARACTER);
            },
            else => |c| try tokenizer.emitCharacter(c),
        } else {
            return tokenizer.setState(.Eof);
        }
    }
}

fn rcData(tokenizer: *Tokenizer) !void {
    while (try next(tokenizer)) |char| {
        switch (char) {
            '&' => try characterReference(tokenizer, null),
            0x00 => {
                try tokenizer.parseError(.UnexpectedNullCharacter);
                try tokenizer.emitCharacter(REPLACEMENT_CHARACTER);
            },
            else => |c| try tokenizer.emitCharacter(c),
            '<' => {
                // RCDATALessThanSign
                if (nextIgnoreEofNoErrorCheck(tokenizer) != '/') {
                    try tokenizer.emitCharacter('<');
                    undo(tokenizer);
                    continue;
                }

                return nonDataEndTagOpen(tokenizer);
            },
        }
    } else {
        return tokenizer.setState(.Eof);
    }
}

fn cDataSection(tokenizer: *Tokenizer) !void {
    while (try next(tokenizer)) |char| switch (char) {
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
        return tokenizer.setState(.Eof);
    }
}

fn appendChar(list: *ArrayListUnmanaged(u8), allocator: Allocator, character: u21) !void {
    var code_units: [4]u8 = undefined;
    const len = try std.unicode.utf8Encode(character, &code_units);
    try list.appendSlice(allocator, code_units[0..len]);
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
