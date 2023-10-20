// Copyright (C) 2021-2023 Chadwain Holness
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

const Tokenizer = @This();
const rem = @import("../rem.zig");
const named_characters = @import("./named_characters.zig");
const Token = @import("./token.zig").Token;
const Attributes = Token.StartTag.Attributes;
const Parser = @import("./Parser.zig");
const ParseError = Parser.ParseError;

const std = @import("std");
const ArrayList = std.ArrayList;
const ArrayListUnmanaged = std.ArrayListUnmanaged;
const Allocator = std.mem.Allocator;

const REPLACEMENT_CHARACTER = '\u{FFFD}';
const TREAT_AS_ANYTHING_ELSE = '\u{FFFF}';

state: State = .Data,
eof: bool = false,
last_start_tag: LastStartTag = undefined,
adjusted_current_node_is_not_in_html_namespace: bool = false,
allocator: Allocator,
status: Status = .{},

pub const Status = struct {
    frame: ?anyframe = null,
    tokens: ArrayListUnmanaged(Token) = .{},

    pub fn setState(status: *Status, new_state: State, last_start_tag: LastStartTag) void {
        const tokenizer = @fieldParentPtr(Tokenizer, "status", status);
        tokenizer.setNewState(new_state);
        tokenizer.last_start_tag = last_start_tag;
    }

    pub fn setAdjustedCurrentNodeIsNotInHtmlNamespace(status: *Status, value: bool) void {
        const tokenizer = @fieldParentPtr(Tokenizer, "status", status);
        tokenizer.adjusted_current_node_is_not_in_html_namespace = value;
    }

    pub fn abort(status: *Status) void {
        const tokenizer = @fieldParentPtr(Tokenizer, "status", status);
        tokenizer.state = .Eof;
    }
};

pub fn run(parser: *Parser, state: State, last_start_tag: ?LastStartTag, status: **Status) !void {
    std.debug.assert(state != .Eof);

    var tokenizer = Tokenizer{
        .allocator = parser.allocator,
        .state = state,
    };
    defer {
        for (tokenizer.status.tokens.items) |*token| token.deinit(tokenizer.allocator);
        tokenizer.status.tokens.deinit(tokenizer.allocator);
        tokenizer.status.frame = null;
    }
    if (last_start_tag) |lst| tokenizer.last_start_tag = lst;
    status.* = &tokenizer.status;

    while (!tokenizer.eof) {
        switch (tokenizer.state) {
            .Data => try data(parser, &tokenizer),
            .RAWTEXT => try rawText(parser, &tokenizer),
            .RCDATA => try rcData(parser, &tokenizer),
            .CDATASection => try cDataSection(parser, &tokenizer),
            .PLAINTEXT => try plainText(parser, &tokenizer),
            .ScriptData => try scriptData(parser, &tokenizer),
            .Eof => try eof(&tokenizer),
        }

        suspend {
            tokenizer.status.frame = @frame();
        }
        tokenizer.status.tokens.clearRetainingCapacity();
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
        const map = std.ComptimeStringMap(LastStartTag, .{
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

fn setNewState(tokenizer: *Tokenizer, new_state: State) void {
    tokenizer.state = new_state;
}

/// Returns the next input character in the input stream.
/// Implements §13.2.3.5 "Preprocessing the input stream" of the HTML standard.
fn next(parser: *Parser) !?u21 {
    const char = nextNoErrorCheck(parser);
    if (char) |c| {
        try checkInputCharacterForErrors(parser, c);
    }
    return char;
}

fn nextNoErrorCheck(parser: *Parser) ?u21 {
    std.debug.assert(parser.input_stream.position <= parser.input_stream.text.len);

    if (parser.input_stream.position == parser.input_stream.text.len) {
        parser.input_stream.eof = true;
        return null;
    }

    var char = parser.input_stream.text[parser.input_stream.position];
    parser.input_stream.position += 1;
    if (char == '\r') {
        char = '\n';
        if (parser.input_stream.position < parser.input_stream.text.len and parser.input_stream.text[parser.input_stream.position] == '\n') {
            parser.input_stream.position += 1;
        }
    }

    return char;
}

/// Undoes a call to `nextNoErrorCheck`.
fn undo(parser: *Parser) void {
    if (parser.input_stream.eof) {
        parser.input_stream.eof = false;
        return;
    }

    const previous = parser.input_stream.text[parser.input_stream.position - 1];
    if (previous == '\n' and parser.input_stream.position >= 2 and parser.input_stream.text[parser.input_stream.position - 2] == '\r') {
        parser.input_stream.position -= 2;
    } else {
        parser.input_stream.position -= 1;
    }
}

fn nextIgnoreEofNoErrorCheck(parser: *Parser) u21 {
    return nextNoErrorCheck(parser) orelse TREAT_AS_ANYTHING_ELSE;
}

fn peekIgnoreEof(parser: *Parser) u21 {
    const char = nextIgnoreEofNoErrorCheck(parser);
    undo(parser);
    return char;
}

/// Given a character from the input stream, this function checks to see if that
/// character is a surrogate, noncharacter, or control character, and if so,
/// emits a parse error.
/// Implements part of §13.2.3.5 "Preprocessing the input stream" of the HTML standard.
fn checkInputCharacterForErrors(parser: *Parser, character: u21) !void {
    switch (character) {
        0xD800...0xDFFF => try parser.parseError(.SurrogateInInputStream),
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
        => try parser.parseError(.NoncharacterInInputStream),
        0x01...0x08,
        0x0B,
        0x0E...0x1F,
        0x7F...0x9F,
        => try parser.parseError(.ControlCharacterInInputStream),
        0x0D => unreachable, // This character would have been turned into 0x0A.
        else => {},
    }
}

/// Scans the next characters in the input stream to see if they are equal to `string`.
/// If so, consumes those characters and returns `true`. Otherwise, adds any read characters
/// to the list of replayed characters and returns `false`.
fn consumeCharsIfEql(parser: *Parser, comptime string: []const u8) bool {
    const decoded_string = rem.util.utf8DecodeStringComptime(string);
    return consumeCharsIfEqlGeneric(parser, &decoded_string, caseSensitiveEql);
}

/// Scans the next characters in the input stream to see if they are equal to `string` in
/// a case-insensitive manner.
/// If so, consumes those characters and returns `true`. Otherwise, adds any read characters
/// to the list of replayed characters and returns `false`.
fn consumeCharsIfCaseInsensitiveEql(parser: *Parser, comptime string: []const u8) bool {
    const decoded_string = rem.util.utf8DecodeStringComptime(string);
    return consumeCharsIfEqlGeneric(parser, &decoded_string, caseInsensitiveEql);
}

fn consumeCharsIfEqlGeneric(parser: *Parser, decoded_string: []const u21, comptime eqlFn: fn (u21, u21) bool) bool {
    var index: usize = 0;
    while (index < decoded_string.len) {
        const string_char = decoded_string[index];
        index += 1;
        const next_char = nextNoErrorCheck(parser) orelse break;
        if (!eqlFn(string_char, next_char)) break;
    } else {
        return true;
    }

    while (index > 0) : (index -= 1) {
        undo(parser);
    }
    return false;
}

fn emitToken(tokenizer: *Tokenizer, token: Token) !void {
    try tokenizer.status.tokens.append(tokenizer.allocator, token);
}

fn emitCharacter(tokenizer: *Tokenizer, character: u21) !void {
    try tokenizer.emitToken(Token{ .character = .{ .data = character } });
}

fn emitString(tokenizer: *Tokenizer, comptime string: []const u8) !void {
    for (rem.util.utf8DecodeStringComptime(string)) |character| {
        try emitCharacter(tokenizer, character);
    }
}

fn adjustedCurrentNodeIsNotInHtmlNamespace(tokenizer: *Tokenizer) bool {
    return tokenizer.adjusted_current_node_is_not_in_html_namespace;
}

fn eof(tokenizer: *Tokenizer) !void {
    try tokenizer.emitToken(.eof);
    tokenizer.eof = true;
}

fn data(parser: *Parser, tokenizer: *Tokenizer) !void {
    while (try next(parser)) |char| switch (char) {
        '&' => try characterReference(parser, tokenizer, null),
        '<' => return tagOpen(parser, tokenizer),
        0x00 => {
            try parser.parseError(.UnexpectedNullCharacter);
            try tokenizer.emitCharacter(0x00);
        },
        else => |c| try tokenizer.emitCharacter(c),
    } else {
        return tokenizer.setNewState(.Eof);
    }
}

fn markupDeclarationOpen(parser: *Parser, tokenizer: *Tokenizer) !void {
    if (consumeCharsIfEql(parser, "--")) {
        return comment(parser, tokenizer);
    } else if (consumeCharsIfCaseInsensitiveEql(parser, "DOCTYPE")) {
        return doctype(parser, tokenizer);
    } else if (consumeCharsIfEql(parser, "[CDATA[")) {
        if (tokenizer.adjustedCurrentNodeIsNotInHtmlNamespace()) {
            return tokenizer.setNewState(.CDATASection);
        } else {
            try parser.parseError(.CDATAInHtmlContent);
            for ("[CDATA[") |_| undo(parser);
            return bogusComment(parser, tokenizer);
        }
    } else {
        try parser.parseError(.IncorrectlyOpenedComment);
        return bogusComment(parser, tokenizer);
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

    fn finishAttributeName(tag_data: *TagData, parser: *Parser) !void {
        const attribute_name = tag_data.buffer.toOwnedSlice(tag_data.allocator);
        errdefer tag_data.allocator.free(attribute_name);

        const get_result = try tag_data.attributes.getOrPut(tag_data.allocator, attribute_name);

        if (get_result.found_existing) {
            try parser.parseError(.DuplicateAttribute);
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

fn emitTag(parser: *Parser, tokenizer: *Tokenizer, tag_data: *TagData) !void {
    const name = tag_data.name.toOwnedSlice(tag_data.allocator);
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
                try parser.parseError(.EndTagWithAttributes);
            }

            if (tag_data.self_closing) {
                try parser.parseError(.EndTagWithTrailingSolidus);
            }

            tokenizer.last_start_tag = undefined;

            const token = Token{ .end_tag = .{
                .name = name,
            } };
            try tokenizer.emitToken(token);
        },
    }
}

fn tagOpen(parser: *Parser, tokenizer: *Tokenizer) !void {
    if (nextNoErrorCheck(parser)) |char| switch (char) {
        '!' => return markupDeclarationOpen(parser, tokenizer),
        '/' => return endTagOpen(parser, tokenizer),
        'A'...'Z', 'a'...'z' => {
            undo(parser);
            return tagName(parser, tokenizer, .Start);
        },
        '?' => {
            try parser.parseError(.UnexpectedQuestionMarkInsteadOfTagName);
            undo(parser);
            return bogusComment(parser, tokenizer);
        },
        else => {
            try parser.parseError(.InvalidFirstCharacterOfTagName);
            try tokenizer.emitCharacter('<');
            return undo(parser);
        },
    } else {
        try parser.parseError(.EOFBeforeTagName);
        try tokenizer.emitCharacter('<');
        return tokenizer.setNewState(.Eof);
    }
}

fn endTagOpen(parser: *Parser, tokenizer: *Tokenizer) !void {
    if (nextNoErrorCheck(parser)) |char| {
        switch (char) {
            'A'...'Z', 'a'...'z' => {
                undo(parser);
                return tagName(parser, tokenizer, .End);
            },
            '>' => try parser.parseError(.MissingEndTagName),
            else => {
                try parser.parseError(.InvalidFirstCharacterOfTagName);
                undo(parser);
                return bogusComment(parser, tokenizer);
            },
        }
    } else {
        try parser.parseError(.EOFBeforeTagName);
        try tokenizer.emitString("</");
        return tokenizer.setNewState(.Eof);
    }
}

fn tagName(parser: *Parser, tokenizer: *Tokenizer, start_or_end: TagData.StartOrEnd) !void {
    var tag_data = TagData.init(start_or_end, tokenizer.allocator);
    defer tag_data.deinit();

    while (try next(parser)) |current_input_char| {
        switch (current_input_char) {
            '\t', '\n', 0x0C, ' ' => return attribute(parser, tokenizer, &tag_data),
            '/' => return selfClosingStartTag(parser, tokenizer, &tag_data),
            '>' => return try emitTag(parser, tokenizer, &tag_data),
            0x00 => {
                try parser.parseError(.UnexpectedNullCharacter);
                try tag_data.appendName(REPLACEMENT_CHARACTER);
            },
            else => |c| try tag_data.appendName(toLowercase(c)),
        }
    } else {
        try parser.parseError(.EOFInTag);
        return tokenizer.setNewState(.Eof);
    }
}

fn nonDataEndTagOpen(parser: *Parser, tokenizer: *Tokenizer) !void {
    switch (nextIgnoreEofNoErrorCheck(parser)) {
        'A'...'Z', 'a'...'z' => {
            undo(parser);
            return nonDataEndTagName(parser, tokenizer);
        },
        else => {
            try tokenizer.emitString("</");
            undo(parser);
        },
    }
}

fn nonDataEndTagName(parser: *Parser, tokenizer: *Tokenizer) !void {
    var tag_data = TagData.init(.End, tokenizer.allocator);
    defer tag_data.deinit();

    while (nextNoErrorCheck(parser)) |char| {
        switch (char) {
            '\t', '\n', 0x0C, ' ' => {
                if (tokenizer.isAppropriateEndTag(&tag_data)) {
                    return attribute(parser, tokenizer, &tag_data);
                }
                break;
            },
            '/' => {
                if (tokenizer.isAppropriateEndTag(&tag_data)) {
                    return selfClosingStartTag(parser, tokenizer, &tag_data);
                }
                break;
            },
            '>' => {
                if (tokenizer.isAppropriateEndTag(&tag_data)) {
                    try emitTag(parser, tokenizer, &tag_data);
                    return tokenizer.setNewState(.Data);
                }
                break;
            },
            'A'...'Z', 'a'...'z' => |c| try tag_data.appendName(toLowercase(c)),
            else => break,
        }
    }

    try tokenizer.emitString("</");
    for (tag_data.name.items) |c| try tokenizer.emitCharacter(c);
    undo(parser);
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

fn attribute(parser: *Parser, tokenizer: *Tokenizer, tag_data: *TagData) !void {
    return attributeLoop(parser, tokenizer, tag_data, .BeforeName);
}

fn selfClosingStartTag(parser: *Parser, tokenizer: *Tokenizer, tag_data: *TagData) !void {
    return attributeLoop(parser, tokenizer, tag_data, .Slash);
}

fn attributeLoop(parser: *Parser, tokenizer: *Tokenizer, tag_data: *TagData, initial_state: AttributeState) !void {
    var next_state: ?AttributeState = initial_state;
    while (next_state) |state| {
        next_state = switch (state) {
            .BeforeName => try beforeAttributeName(parser, tokenizer, tag_data),
            .Name => try attributeName(parser, tokenizer, tag_data),
            .Value => try beforeAttributeValue(parser, tokenizer, tag_data),
            .Slash => try attributeSlash(parser, tokenizer, tag_data),
        };
    }
}

fn beforeAttributeName(parser: *Parser, tokenizer: *Tokenizer, tag_data: *TagData) !?AttributeState {
    // Make end-of-file (null) be handled the same as '>'
    while (true) switch (nextNoErrorCheck(parser) orelse '>') {
        '\t', '\n', 0x0C, ' ' => {},
        '/', '>' => {
            undo(parser);
            return try afterAttributeName(parser, tokenizer, tag_data);
        },
        '=' => {
            try parser.parseError(.UnexpectedEqualsSignBeforeAttributeName);
            try tag_data.appendCurrentAttributeName('=');
            return AttributeState.Name;
        },
        else => {
            undo(parser);
            return AttributeState.Name;
        },
    };
}

fn attributeName(parser: *Parser, tokenizer: *Tokenizer, tag_data: *TagData) !?AttributeState {
    // Make end-of-file (null) be handled the same as '>'
    while (true) switch ((try next(parser)) orelse '>') {
        '\t', '\n', 0x0C, ' ', '/', '>' => {
            try tag_data.finishAttributeName(parser);
            undo(parser);
            return try afterAttributeName(parser, tokenizer, tag_data);
        },
        '=' => {
            try tag_data.finishAttributeName(parser);
            return AttributeState.Value;
        },
        0x00 => {
            try parser.parseError(.UnexpectedNullCharacter);
            try tag_data.appendCurrentAttributeName(REPLACEMENT_CHARACTER);
        },
        '"', '\'', '<' => |c| {
            try parser.parseError(.UnexpectedCharacterInAttributeName);
            try tag_data.appendCurrentAttributeName(c);
        },
        else => |c| try tag_data.appendCurrentAttributeName(toLowercase(c)),
    };
}

fn afterAttributeName(parser: *Parser, tokenizer: *Tokenizer, tag_data: *TagData) !?AttributeState {
    while (nextNoErrorCheck(parser)) |current_input_char| {
        switch (current_input_char) {
            '\t', '\n', 0x0C, ' ' => {},
            '/' => return AttributeState.Slash,
            '=' => return AttributeState.Value,
            '>' => return try attributeEnd(parser, tokenizer, tag_data),
            else => {
                undo(parser);
                return AttributeState.Name;
            },
        }
    } else {
        return try eofInTag(parser, tokenizer);
    }
}

fn beforeAttributeValue(parser: *Parser, tokenizer: *Tokenizer, tag_data: *TagData) !?AttributeState {
    while (true) switch (nextIgnoreEofNoErrorCheck(parser)) {
        '\t', '\n', 0x0C, ' ' => {},
        '"' => return attributeValueQuoted(parser, tokenizer, tag_data, .Double),
        '\'' => return attributeValueQuoted(parser, tokenizer, tag_data, .Single),
        '>' => {
            try parser.parseError(.MissingAttributeValue);
            return try attributeEnd(parser, tokenizer, tag_data);
        },
        else => {
            undo(parser);
            return attributeValueUnquoted(parser, tokenizer, tag_data);
        },
    };
}

const QuoteStyle = enum { Single, Double };

fn attributeValueQuoted(parser: *Parser, tokenizer: *Tokenizer, tag_data: *TagData, comptime quote_style: QuoteStyle) !?AttributeState {
    const quote = switch (quote_style) {
        .Single => '\'',
        .Double => '"',
    };

    while (try next(parser)) |current_input_char| {
        switch (current_input_char) {
            quote => break tag_data.finishAttributeValue(),
            '&' => try characterReference(parser, tokenizer, tag_data),
            0x00 => {
                try parser.parseError(.UnexpectedNullCharacter);
                try tag_data.appendCurrentAttributeValue(REPLACEMENT_CHARACTER);
            },
            else => |c| try tag_data.appendCurrentAttributeValue(c),
        }
    } else {
        return try eofInTag(parser, tokenizer);
    }

    // AfterAttributeValueQuoted
    if (nextNoErrorCheck(parser)) |current_input_char| {
        switch (current_input_char) {
            '\t', '\n', 0x0C, ' ' => return AttributeState.BeforeName,
            '/' => return AttributeState.Slash,
            '>' => return try attributeEnd(parser, tokenizer, tag_data),
            else => {
                try parser.parseError(.MissingWhitespaceBetweenAttributes);
                undo(parser);
                return AttributeState.BeforeName;
            },
        }
    } else {
        return try eofInTag(parser, tokenizer);
    }
}

fn attributeValueUnquoted(parser: *Parser, tokenizer: *Tokenizer, tag_data: *TagData) !?AttributeState {
    while (try next(parser)) |current_input_char| switch (current_input_char) {
        '\t', '\n', 0x0C, ' ' => {
            tag_data.finishAttributeValue();
            return AttributeState.BeforeName;
        },
        '&' => try characterReference(parser, tokenizer, tag_data),
        '>' => {
            tag_data.finishAttributeValue();
            return try attributeEnd(parser, tokenizer, tag_data);
        },
        0x00 => {
            try parser.parseError(.UnexpectedNullCharacter);
            try tag_data.appendCurrentAttributeValue(REPLACEMENT_CHARACTER);
        },
        '"', '\'', '<', '=', '`' => |c| {
            try parser.parseError(.UnexpectedCharacterInUnquotedAttributeValue);
            try tag_data.appendCurrentAttributeValue(c);
        },
        else => |c| try tag_data.appendCurrentAttributeValue(c),
    } else {
        return try eofInTag(parser, tokenizer);
    }
}

fn attributeSlash(parser: *Parser, tokenizer: *Tokenizer, tag_data: *TagData) !?AttributeState {
    if (nextNoErrorCheck(parser)) |current_input_char| {
        switch (current_input_char) {
            '>' => {
                tag_data.self_closing = true;
                return try attributeEnd(parser, tokenizer, tag_data);
            },
            else => {
                try parser.parseError(.UnexpectedSolidusInTag);
                undo(parser);
                return AttributeState.BeforeName;
            },
        }
    } else {
        return try eofInTag(parser, tokenizer);
    }
}

fn attributeEnd(parser: *Parser, tokenizer: *Tokenizer, tag_data: *TagData) !?AttributeState {
    tokenizer.setNewState(.Data);
    try emitTag(parser, tokenizer, tag_data);
    return null;
}

fn eofInTag(parser: *Parser, tokenizer: *Tokenizer) !?AttributeState {
    try parser.parseError(.EOFInTag);
    tokenizer.setNewState(.Eof);
    return null;
}

fn characterReference(parser: *Parser, tokenizer: *Tokenizer, tag_data: ?*TagData) !void {
    // By assumption, the '&' character has just been consumed.
    var num_consumed_chars: usize = 1;

    switch (nextIgnoreEofNoErrorCheck(parser)) {
        '0'...'9', 'A'...'Z', 'a'...'z' => {
            undo(parser);
            return namedCharacterReference(parser, tokenizer, tag_data, &num_consumed_chars);
        },
        '#' => {
            num_consumed_chars += 1;
            return numericCharacterReference(parser, tokenizer, tag_data, &num_consumed_chars);
        },
        else => {
            undo(parser);
            return flushCharacterReference(parser, tokenizer, tag_data, &num_consumed_chars);
        },
    }
}

fn namedCharacterReference(parser: *Parser, tokenizer: *Tokenizer, tag_data: ?*TagData, num_consumed_chars: *usize) !void {
    const result = try findNamedCharacterReference(parser, num_consumed_chars);
    const match_found = result.chars[0] != null;
    if (match_found) {
        const dont_emit_chars = if (tag_data != null and !result.ends_with_semicolon)
            switch (peekIgnoreEof(parser)) {
                '=', '0'...'9', 'A'...'Z', 'a'...'z' => true,
                else => false,
            }
        else
            false;

        if (dont_emit_chars) {
            return flushCharacterReference(parser, tokenizer, tag_data, num_consumed_chars);
        } else {
            if (!result.ends_with_semicolon) {
                try parser.parseError(.MissingSemicolonAfterCharacterReference);
            }
            try characterReferenceEmitCharacter(tokenizer, tag_data, result.chars[0].?);
            if (result.chars[1]) |second| try characterReferenceEmitCharacter(tokenizer, tag_data, second);
        }
    } else {
        try flushCharacterReference(parser, tokenizer, tag_data, num_consumed_chars);
        return ambiguousAmpersand(parser, tokenizer, tag_data);
    }
}

const FindNamedCharacterReferenceResult = struct {
    chars: named_characters.Value,
    ends_with_semicolon: bool,
};

fn findNamedCharacterReference(parser: *Parser, num_consumed_chars: *usize) !FindNamedCharacterReferenceResult {
    var last_index_with_value = named_characters.root_index;
    var ends_with_semicolon: bool = false;

    var entry = named_characters.root_index.entry();
    var num_pending_chars: usize = 0;

    while (true) {
        const character = nextNoErrorCheck(parser) orelse {
            undo(parser);
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
        undo(parser);
    }

    // There is no need to check the consumed characters for errors (controls, surrogates, noncharacters)
    // beacuse we've just determined that they form a valid character reference.
    return FindNamedCharacterReferenceResult{ .chars = last_index_with_value.value(), .ends_with_semicolon = ends_with_semicolon };
}

fn ambiguousAmpersand(parser: *Parser, tokenizer: *Tokenizer, tag_data: ?*TagData) !void {
    while (true) switch (nextIgnoreEofNoErrorCheck(parser)) {
        '0'...'9', 'A'...'Z', 'a'...'z' => |c| try characterReferenceEmitCharacter(tokenizer, tag_data, c),
        ';' => break try parser.parseError(.UnknownNamedCharacterReference),
        else => break,
    };

    undo(parser);
}

fn numericCharacterReference(parser: *Parser, tokenizer: *Tokenizer, tag_data: ?*TagData, num_consumed_chars: *usize) !void {
    var character_reference_code: u21 = 0;
    switch (nextIgnoreEofNoErrorCheck(parser)) {
        'x', 'X' => {
            num_consumed_chars.* += 1;

            // HexadecimalCharacterReferenceStart
            switch (nextIgnoreEofNoErrorCheck(parser)) {
                '0'...'9', 'A'...'F', 'a'...'f' => {
                    undo(parser);

                    // HexadecimalCharacterReference
                    while (true) switch (nextIgnoreEofNoErrorCheck(parser)) {
                        '0'...'9' => |c| characterReferenceCodeAddDigit(&character_reference_code, 16, decimalCharToNumber(c)),
                        'A'...'F' => |c| characterReferenceCodeAddDigit(&character_reference_code, 16, upperHexCharToNumber(c)),
                        'a'...'f' => |c| characterReferenceCodeAddDigit(&character_reference_code, 16, lowerHexCharToNumber(c)),
                        ';' => break,
                        else => {
                            try parser.parseError(.MissingSemicolonAfterCharacterReference);
                            break undo(parser);
                        },
                    };
                },
                else => return noDigitsInNumericCharacterReference(parser, tokenizer, tag_data, num_consumed_chars),
            }
        },
        // DecimalCharacterReferenceStart
        '0'...'9' => {
            undo(parser);

            // DecimalCharacterReference
            while (true) switch (nextIgnoreEofNoErrorCheck(parser)) {
                '0'...'9' => |c| characterReferenceCodeAddDigit(&character_reference_code, 10, decimalCharToNumber(c)),
                ';' => break,
                else => {
                    try parser.parseError(.MissingSemicolonAfterCharacterReference);
                    break undo(parser);
                },
            };
        },
        else => return noDigitsInNumericCharacterReference(parser, tokenizer, tag_data, num_consumed_chars),
    }

    // NumericCharacterReferenceEnd
    switch (character_reference_code) {
        0x00 => {
            try parser.parseError(.NullCharacterReference);
            character_reference_code = REPLACEMENT_CHARACTER;
        },
        0x10FFFF + 1...std.math.maxInt(@TypeOf(character_reference_code)) => {
            try parser.parseError(.CharacterReferenceOutsideUnicodeRange);
            character_reference_code = REPLACEMENT_CHARACTER;
        },
        0xD800...0xDFFF => {
            try parser.parseError(.SurrogateCharacterReference);
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
        => try parser.parseError(.NoncharacterCharacterReference),
        0x01...0x08, 0x0B, 0x0D...0x1F => try parser.parseError(.ControlCharacterReference),
        0x7F...0x9F => |c| {
            try parser.parseError(.ControlCharacterReference);
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

fn noDigitsInNumericCharacterReference(parser: *Parser, tokenizer: *Tokenizer, tag_data: ?*TagData, num_consumed_chars: *const usize) !void {
    try parser.parseError(.AbsenceOfDigitsInNumericCharacterReference);
    undo(parser);
    try flushCharacterReference(parser, tokenizer, tag_data, num_consumed_chars);
}

fn flushCharacterReference(parser: *Parser, tokenizer: *Tokenizer, tag_data: ?*TagData, num_consumed_chars: *const usize) !void {
    var i = num_consumed_chars.*;
    while (i > 0) : (i -= 1) {
        undo(parser);
    }

    i = num_consumed_chars.*;
    while (i > 0) : (i -= 1) {
        const character = nextNoErrorCheck(parser).?;
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

fn comment(parser: *Parser, tokenizer: *Tokenizer) !void {
    var comment_data = ArrayListUnmanaged(u8){};
    defer comment_data.deinit(tokenizer.allocator);

    var next_state: ?CommentState = try commentStart(parser, tokenizer, &comment_data);
    while (next_state) |state| {
        next_state = switch (state) {
            .Normal => try commentNormal(parser, tokenizer, &comment_data),
            .EndDash => try commentEndDash(parser, tokenizer, &comment_data),
            .End => try commentEnd(parser, tokenizer, &comment_data),
        };
    }

    try tokenizer.emitComment(&comment_data);
}

fn commentStart(parser: *Parser, tokenizer: *Tokenizer, comment_data: *ArrayListUnmanaged(u8)) !?CommentState {
    switch (nextIgnoreEofNoErrorCheck(parser)) {
        '-' => {
            // CommentStartDash
            switch (nextNoErrorCheck(parser) orelse return try eofInComment(parser, tokenizer)) {
                '-' => return CommentState.End,
                '>' => return try abruptCommentClose(parser),
                else => {
                    try comment_data.append(tokenizer.allocator, '-');
                    undo(parser);
                    return CommentState.Normal;
                },
            }
        },
        '>' => return try abruptCommentClose(parser),
        else => {
            undo(parser);
            return CommentState.Normal;
        },
    }
}

fn commentNormal(parser: *Parser, tokenizer: *Tokenizer, comment_data: *ArrayListUnmanaged(u8)) !?CommentState {
    while (try next(parser)) |current_input_char| switch (current_input_char) {
        '<' => {
            try comment_data.append(tokenizer.allocator, '<');

            // CommentLessThanSign
            while (true) switch (nextIgnoreEofNoErrorCheck(parser)) {
                '!' => {
                    try comment_data.append(tokenizer.allocator, '!');

                    // CommentLessThanSignBang
                    if (nextIgnoreEofNoErrorCheck(parser) != '-') {
                        undo(parser);
                        break;
                    }

                    // CommentLessThanSignBangDash
                    if (nextIgnoreEofNoErrorCheck(parser) != '-') {
                        undo(parser);
                        return CommentState.EndDash;
                    }

                    // CommentLessThanSignBangDashDash
                    // Make end-of-file (null) be handled the same as '>'
                    if (nextNoErrorCheck(parser) orelse '>' != '>') {
                        try parser.parseError(.NestedComment);
                    }
                    undo(parser);
                    return CommentState.End;
                },
                '<' => try comment_data.append(tokenizer.allocator, '<'),
                else => {
                    undo(parser);
                    break;
                },
            };
        },
        '-' => return CommentState.EndDash,
        0x00 => {
            try parser.parseError(.UnexpectedNullCharacter);
            try appendChar(comment_data, tokenizer.allocator, REPLACEMENT_CHARACTER);
        },
        else => |c| try appendChar(comment_data, tokenizer.allocator, c),
    } else {
        return try eofInComment(parser, tokenizer);
    }
}

fn commentEndDash(parser: *Parser, tokenizer: *Tokenizer, comment_data: *ArrayListUnmanaged(u8)) !?CommentState {
    switch (nextNoErrorCheck(parser) orelse return try eofInComment(parser, tokenizer)) {
        '-' => return CommentState.End,
        else => {
            try comment_data.append(tokenizer.allocator, '-');
            undo(parser);
            return CommentState.Normal;
        },
    }
}

fn commentEnd(parser: *Parser, tokenizer: *Tokenizer, comment_data: *ArrayListUnmanaged(u8)) !?CommentState {
    while (nextNoErrorCheck(parser)) |current_input_char| switch (current_input_char) {
        '>' => return null,
        '!' => return try commentEndBang(parser, tokenizer, comment_data),
        '-' => try comment_data.append(tokenizer.allocator, '-'),
        else => {
            try comment_data.appendSlice(tokenizer.allocator, "--");
            undo(parser);
            return CommentState.Normal;
        },
    } else {
        return try eofInComment(parser, tokenizer);
    }
}

fn commentEndBang(parser: *Parser, tokenizer: *Tokenizer, comment_data: *ArrayListUnmanaged(u8)) !?CommentState {
    switch (nextNoErrorCheck(parser) orelse return try eofInComment(parser, tokenizer)) {
        '-' => {
            try comment_data.appendSlice(tokenizer.allocator, "--!");
            return CommentState.EndDash;
        },
        '>' => return incorrectlyClosedComment(parser),
        else => {
            try comment_data.appendSlice(tokenizer.allocator, "--!");
            undo(parser);
            return CommentState.Normal;
        },
    }
}

fn bogusComment(parser: *Parser, tokenizer: *Tokenizer) !void {
    var comment_data = ArrayListUnmanaged(u8){};
    defer comment_data.deinit(tokenizer.allocator);

    while (try next(parser)) |char| switch (char) {
        '>' => break,
        0x00 => {
            try parser.parseError(.UnexpectedNullCharacter);
            try appendChar(&comment_data, tokenizer.allocator, REPLACEMENT_CHARACTER);
        },
        else => |c| try appendChar(&comment_data, tokenizer.allocator, c),
    } else {
        tokenizer.setNewState(.Eof);
    }

    try tokenizer.emitComment(&comment_data);
}

fn emitComment(tokenizer: *Tokenizer, comment_data: *ArrayListUnmanaged(u8)) !void {
    const owned = comment_data.toOwnedSlice(tokenizer.allocator);
    try tokenizer.emitToken(Token{ .comment = .{ .data = owned } });
}

fn eofInComment(parser: *Parser, tokenizer: *Tokenizer) !?CommentState {
    try parser.parseError(.EOFInComment);
    tokenizer.setNewState(.Eof);
    return null;
}

fn abruptCommentClose(parser: *Parser) !?CommentState {
    try parser.parseError(.AbruptClosingOfEmptyComment);
    return null;
}

fn incorrectlyClosedComment(parser: *Parser) !?CommentState {
    try parser.parseError(.IncorrectlyClosedComment);
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

fn doctype(parser: *Parser, tokenizer: *Tokenizer) !void {
    var doctype_data = DoctypeData{};
    defer doctype_data.deinit(tokenizer.allocator);

    try doctypeStart(parser, tokenizer, &doctype_data);

    const doctype_token = Token{ .doctype = .{
        .name = if (doctype_data.name) |*name| name.toOwnedSlice(tokenizer.allocator) else null,
        .public_identifier = if (doctype_data.public_identifier) |*public_identifier| public_identifier.toOwnedSlice(tokenizer.allocator) else null,
        .system_identifier = if (doctype_data.system_identifier) |*system_identifier| system_identifier.toOwnedSlice(tokenizer.allocator) else null,
        .force_quirks = doctype_data.force_quirks,
    } };
    try tokenizer.emitToken(doctype_token);
}

fn doctypeStart(parser: *Parser, tokenizer: *Tokenizer, doctype_data: *DoctypeData) !void {
    if (nextNoErrorCheck(parser)) |current_input_char| {
        switch (current_input_char) {
            '\t', '\n', 0x0C, ' ' => {},
            '>' => undo(parser),
            else => {
                try parser.parseError(.MissingWhitespaceBeforeDOCTYPEName);
                undo(parser);
            },
        }
        return try beforeDoctypeName(parser, tokenizer, doctype_data);
    } else {
        return try eofInDoctype(parser, tokenizer, doctype_data);
    }
}

fn beforeDoctypeName(parser: *Parser, tokenizer: *Tokenizer, doctype_data: *DoctypeData) !void {
    while (nextNoErrorCheck(parser)) |current_input_char| {
        switch (current_input_char) {
            '\t', '\n', 0x0C, ' ' => {},
            '>' => {
                try parser.parseError(.MissingDOCTYPEName);
                doctype_data.force_quirks = true;
                return;
            },
            else => {
                undo(parser);
                return try doctypeName(parser, tokenizer, doctype_data);
            },
        }
    } else {
        return try eofInDoctype(parser, tokenizer, doctype_data);
    }
}

fn doctypeName(parser: *Parser, tokenizer: *Tokenizer, doctype_data: *DoctypeData) !void {
    doctype_data.name = ArrayListUnmanaged(u8){};
    const doctype_name_data = &doctype_data.name.?;

    while (try next(parser)) |current_input_char| {
        switch (current_input_char) {
            '\t', '\n', 0x0C, ' ' => return afterDoctypeName(parser, tokenizer, doctype_data),
            '>' => return,
            0x00 => {
                try parser.parseError(.UnexpectedNullCharacter);
                try appendChar(doctype_name_data, tokenizer.allocator, REPLACEMENT_CHARACTER);
            },
            else => |c| try appendChar(doctype_name_data, tokenizer.allocator, toLowercase(c)),
        }
    } else {
        return try eofInDoctype(parser, tokenizer, doctype_data);
    }
}

fn afterDoctypeName(parser: *Parser, tokenizer: *Tokenizer, doctype_data: *DoctypeData) !void {
    while (nextNoErrorCheck(parser)) |current_input_char| {
        switch (current_input_char) {
            '\t', '\n', 0x0C, ' ' => {},
            '>' => return,
            else => |c| {
                if (caseInsensitiveEql(c, 'P') and consumeCharsIfCaseInsensitiveEql(parser, "UBLIC")) {
                    return afterDOCTYPEPublicOrSystemKeyword(parser, tokenizer, doctype_data, .public);
                } else if (caseInsensitiveEql(c, 'S') and consumeCharsIfCaseInsensitiveEql(parser, "YSTEM")) {
                    return afterDOCTYPEPublicOrSystemKeyword(parser, tokenizer, doctype_data, .system);
                } else {
                    try parser.parseError(.InvalidCharacterSequenceAfterDOCTYPEName);
                    doctype_data.force_quirks = true;
                    undo(parser);
                    return bogusDOCTYPE(parser, tokenizer);
                }
            },
        }
    } else {
        return try eofInDoctype(parser, tokenizer, doctype_data);
    }
}

const PublicOrSystem = enum { public, system };

fn afterDOCTYPEPublicOrSystemKeyword(parser: *Parser, tokenizer: *Tokenizer, doctype_data: *DoctypeData, public_or_system: PublicOrSystem) !void {
    // AfterDOCTYPEPublicKeyword
    // AfterDOCTYPESystemKeyword
    if (nextNoErrorCheck(parser)) |current_input_char| {
        switch (current_input_char) {
            '\t', '\n', 0x0C, ' ' => {},
            '"', '\'' => |quote| {
                const err: ParseError = switch (public_or_system) {
                    .public => .MissingWhitespaceAfterDOCTYPEPublicKeyword,
                    .system => .MissingWhitespaceAfterDOCTYPESystemKeyword,
                };
                try parser.parseError(err);
                return doctypePublicOrSystemIdentifier(parser, tokenizer, doctype_data, public_or_system, quote);
            },
            '>' => {
                const err: ParseError = switch (public_or_system) {
                    .public => .MissingDOCTYPEPublicIdentifier,
                    .system => .MissingDOCTYPESystemIdentifier,
                };
                try parser.parseError(err);
                doctype_data.force_quirks = true;
                return;
            },
            else => {
                const err: ParseError = switch (public_or_system) {
                    .public => .MissingQuoteBeforeDOCTYPEPublicIdentifier,
                    .system => .MissingQuoteBeforeDOCTYPESystemIdentifier,
                };
                try parser.parseError(err);
                doctype_data.force_quirks = true;
                undo(parser);
                return bogusDOCTYPE(parser, tokenizer);
            },
        }
    } else {
        return try eofInDoctype(parser, tokenizer, doctype_data);
    }

    // BeforeDOCTYPEPublicIdentifier
    // BeforeDOCTYPESystemIdentifier
    while (nextNoErrorCheck(parser)) |current_input_char| {
        switch (current_input_char) {
            '\t', '\n', 0x0C, ' ' => {},
            '"', '\'' => |quote| return doctypePublicOrSystemIdentifier(parser, tokenizer, doctype_data, public_or_system, quote),
            '>' => {
                const err: ParseError = switch (public_or_system) {
                    .public => .MissingDOCTYPEPublicIdentifier,
                    .system => .MissingDOCTYPESystemIdentifier,
                };
                try parser.parseError(err);
                doctype_data.force_quirks = true;
                return;
            },
            else => {
                const err: ParseError = switch (public_or_system) {
                    .public => .MissingQuoteBeforeDOCTYPEPublicIdentifier,
                    .system => .MissingQuoteBeforeDOCTYPESystemIdentifier,
                };
                try parser.parseError(err);
                doctype_data.force_quirks = true;
                undo(parser);
                return bogusDOCTYPE(parser, tokenizer);
            },
        }
    } else {
        return try eofInDoctype(parser, tokenizer, doctype_data);
    }
}

fn doctypePublicOrSystemIdentifier(parser: *Parser, tokenizer: *Tokenizer, doctype_data: *DoctypeData, public_or_system: PublicOrSystem, quote: u21) Error!void {
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

    while (try next(parser)) |current_input_char| {
        if (current_input_char == quote) {
            const afterIdentifier = switch (public_or_system) {
                .public => afterDOCTYPEPublicIdentifier,
                .system => afterDOCTYPESystemIdentifier,
            };
            return afterIdentifier(parser, tokenizer, doctype_data);
        } else if (current_input_char == 0x00) {
            try parser.parseError(.UnexpectedNullCharacter);
            try appendChar(identifier_data, tokenizer.allocator, REPLACEMENT_CHARACTER);
        } else if (current_input_char == '>') {
            const err: ParseError = switch (public_or_system) {
                .public => .AbruptDOCTYPEPublicIdentifier,
                .system => .AbruptDOCTYPESystemIdentifier,
            };
            try parser.parseError(err);
            doctype_data.force_quirks = true;
            return;
        } else {
            try appendChar(identifier_data, tokenizer.allocator, current_input_char);
        }
    } else {
        return try eofInDoctype(parser, tokenizer, doctype_data);
    }
}

fn afterDOCTYPEPublicIdentifier(parser: *Parser, tokenizer: *Tokenizer, doctype_data: *DoctypeData) !void {
    if (nextNoErrorCheck(parser)) |current_input_char| {
        switch (current_input_char) {
            '\t', '\n', 0x0C, ' ' => {},
            '>' => return,
            '"', '\'' => |quote| {
                try parser.parseError(.MissingWhitespaceBetweenDOCTYPEPublicAndSystemIdentifiers);
                return doctypePublicOrSystemIdentifier(parser, tokenizer, doctype_data, .system, quote);
            },
            else => {
                try parser.parseError(.MissingQuoteBeforeDOCTYPESystemIdentifier);
                doctype_data.force_quirks = true;
                undo(parser);
                return bogusDOCTYPE(parser, tokenizer);
            },
        }
    } else {
        return try eofInDoctype(parser, tokenizer, doctype_data);
    }

    // BetweenDOCTYPEPublicAndSystemIdentifiers
    while (nextNoErrorCheck(parser)) |current_input_char| {
        switch (current_input_char) {
            '\t', '\n', 0x0C, ' ' => {},
            '>' => return,
            '"', '\'' => |quote| {
                return doctypePublicOrSystemIdentifier(parser, tokenizer, doctype_data, .system, quote);
            },
            else => {
                try parser.parseError(.MissingQuoteBeforeDOCTYPESystemIdentifier);
                doctype_data.force_quirks = true;
                undo(parser);
                return bogusDOCTYPE(parser, tokenizer);
            },
        }
    } else {
        return try eofInDoctype(parser, tokenizer, doctype_data);
    }
}

fn afterDOCTYPESystemIdentifier(parser: *Parser, tokenizer: *Tokenizer, doctype_data: *DoctypeData) !void {
    while (nextNoErrorCheck(parser)) |current_input_char| {
        switch (current_input_char) {
            '\t', '\n', 0x0C, ' ' => {},
            '>' => return,
            else => {
                try parser.parseError(.UnexpectedCharacterAfterDOCTYPESystemIdentifier);
                undo(parser);
                return bogusDOCTYPE(parser, tokenizer);
            },
        }
    } else {
        return try eofInDoctype(parser, tokenizer, doctype_data);
    }
}

fn eofInDoctype(parser: *Parser, tokenizer: *Tokenizer, doctype_data: *DoctypeData) !void {
    try parser.parseError(.EOFInDOCTYPE);
    doctype_data.force_quirks = true;
    return tokenizer.setNewState(.Eof);
}

fn bogusDOCTYPE(parser: *Parser, tokenizer: *Tokenizer) !void {
    while (try next(parser)) |current_input_char| switch (current_input_char) {
        '>' => return,
        0x00 => try parser.parseError(.UnexpectedNullCharacter),
        else => {},
    } else {
        return tokenizer.setNewState(.Eof);
    }
}

const ScriptState = enum {
    Normal,
    Escaped,
    DoubleEscaped,
};

fn scriptData(parser: *Parser, tokenizer: *Tokenizer) !void {
    var next_state: ?ScriptState = .Normal;
    while (next_state) |state| {
        next_state = switch (state) {
            .Normal => try scriptDataNormal(parser, tokenizer),
            .Escaped => try scriptDataEscaped(parser, tokenizer),
            .DoubleEscaped => try scriptDataDoubleEscaped(parser, tokenizer),
        };
    }
}

fn scriptDataNormal(parser: *Parser, tokenizer: *Tokenizer) !?ScriptState {
    while (try next(parser)) |char| switch (char) {
        0x00 => {
            try parser.parseError(.UnexpectedNullCharacter);
            try tokenizer.emitCharacter(REPLACEMENT_CHARACTER);
        },
        else => try tokenizer.emitCharacter(char),
        '<' => {
            // ScriptDataLessThanSign
            switch (nextIgnoreEofNoErrorCheck(parser)) {
                else => {
                    try tokenizer.emitCharacter('<');
                    undo(parser);
                    continue;
                },
                // ScriptDataEndTagOpen
                '/' => {
                    try nonDataEndTagOpen(parser, tokenizer);
                    if (tokenizer.state != .ScriptData) return null;
                },
                '!' => {
                    try tokenizer.emitString("<!");

                    // ScriptDataEscapeStart
                    if (nextIgnoreEofNoErrorCheck(parser) != '-') {
                        undo(parser);
                        continue;
                    }
                    try tokenizer.emitCharacter('-');

                    // ScriptDataEscapeStartDash
                    if (nextIgnoreEofNoErrorCheck(parser) != '-') {
                        undo(parser);
                        continue;
                    }
                    try tokenizer.emitCharacter('-');

                    // ScriptDataEscapedDashDash
                    return try scriptDataEscapedOrDoubleEscapedDashDash(parser, tokenizer, .Normal);
                },
            }
        },
    } else {
        tokenizer.setNewState(.Eof);
        return null;
    }
}

fn scriptDataEscaped(parser: *Parser, tokenizer: *Tokenizer) !?ScriptState {
    while (try next(parser)) |current_input_char| {
        switch (current_input_char) {
            '-' => {
                try tokenizer.emitCharacter('-');

                // ScriptDataEscapedDash
                if (nextIgnoreEofNoErrorCheck(parser) != '-') {
                    undo(parser);
                    continue;
                }
                try tokenizer.emitCharacter('-');

                // ScriptDataEscapedDashDash
                return try scriptDataEscapedOrDoubleEscapedDashDash(parser, tokenizer, .Escaped);
            },
            // ScriptDataEscapedLessThanSign
            '<' => switch (nextIgnoreEofNoErrorCheck(parser)) {
                '/' => {
                    try nonDataEndTagOpen(parser, tokenizer);
                    if (tokenizer.state != .ScriptData) return null;
                },
                'A'...'Z', 'a'...'z' => {
                    try tokenizer.emitCharacter('<');
                    undo(parser);

                    // ScriptDataDoubleEscapeStart
                    return try scriptDataDoubleEscapeStartOrEnd(parser, tokenizer, .Escaped);
                },
                else => {
                    try tokenizer.emitCharacter('<');
                    undo(parser);
                },
            },
            0x00 => {
                try parser.parseError(.UnexpectedNullCharacter);
                try tokenizer.emitCharacter(REPLACEMENT_CHARACTER);
            },
            else => |c| try tokenizer.emitCharacter(c),
        }
    } else {
        try parser.parseError(.EOFInScriptHtmlCommentLikeText);
        tokenizer.setNewState(.Eof);
        return null;
    }
}

fn scriptDataDoubleEscaped(parser: *Parser, tokenizer: *Tokenizer) !?ScriptState {
    while (try next(parser)) |current_input_char| {
        switch (current_input_char) {
            '-' => {
                try tokenizer.emitCharacter('-');

                // ScriptDataDoubleEscapedDash
                if (nextIgnoreEofNoErrorCheck(parser) != '-') {
                    undo(parser);
                    continue;
                }
                try tokenizer.emitCharacter('-');

                // ScriptDataDoubleEscapedDashDash
                return try scriptDataEscapedOrDoubleEscapedDashDash(parser, tokenizer, .DoubleEscaped);
            },
            '<' => {
                try tokenizer.emitCharacter('<');

                // ScriptDataDoubleEscapedLessThanSign
                if (nextIgnoreEofNoErrorCheck(parser) != '/') {
                    undo(parser);
                    continue;
                }

                try tokenizer.emitCharacter('/');

                // ScriptDataDoubleEscapeEnd
                return try scriptDataDoubleEscapeStartOrEnd(parser, tokenizer, .DoubleEscaped);
            },
            0x00 => {
                try parser.parseError(.UnexpectedNullCharacter);
                try tokenizer.emitCharacter(REPLACEMENT_CHARACTER);
            },
            else => |c| try tokenizer.emitCharacter(c),
        }
    } else {
        try parser.parseError(.EOFInScriptHtmlCommentLikeText);
        tokenizer.setNewState(.Eof);
        return null;
    }
}

fn scriptDataDoubleEscapeStartOrEnd(parser: *Parser, tokenizer: *Tokenizer, script_state: ScriptState) !ScriptState {
    const script = "script";
    var num_matching_chars: u3 = 0;
    var matches: ?bool = null;
    while (true) switch (nextIgnoreEofNoErrorCheck(parser)) {
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
            undo(parser);
            return script_state;
        },
    };
}

fn scriptDataEscapedOrDoubleEscapedDashDash(parser: *Parser, tokenizer: *Tokenizer, script_state: ScriptState) !?ScriptState {
    while (true) switch (nextIgnoreEofNoErrorCheck(parser)) {
        '-' => try tokenizer.emitCharacter('-'),
        '>' => {
            try tokenizer.emitCharacter('>');
            return .Normal;
        },
        else => {
            undo(parser);
            const next_state: ScriptState = switch (script_state) {
                .Normal, .Escaped => .Escaped,
                .DoubleEscaped => .DoubleEscaped,
            };
            return next_state;
        },
    };
}

fn rawText(parser: *Parser, tokenizer: *Tokenizer) !void {
    while (try next(parser)) |char| switch (char) {
        0x00 => {
            try parser.parseError(.UnexpectedNullCharacter);
            try tokenizer.emitCharacter(REPLACEMENT_CHARACTER);
        },
        else => |c| try tokenizer.emitCharacter(c),
        '<' => {
            // RAWTEXTLessThanSign
            if (nextIgnoreEofNoErrorCheck(parser) != '/') {
                try tokenizer.emitCharacter('<');
                undo(parser);
                continue;
            }

            return nonDataEndTagOpen(parser, tokenizer);
        },
    } else {
        return tokenizer.setNewState(.Eof);
    }
}

fn plainText(parser: *Parser, tokenizer: *Tokenizer) !void {
    while (true) {
        if (try next(parser)) |char| switch (char) {
            0x00 => {
                try parser.parseError(.UnexpectedNullCharacter);
                try tokenizer.emitCharacter(REPLACEMENT_CHARACTER);
            },
            else => |c| try tokenizer.emitCharacter(c),
        } else {
            return tokenizer.setNewState(.Eof);
        }
    }
}

fn rcData(parser: *Parser, tokenizer: *Tokenizer) !void {
    while (try next(parser)) |char| {
        switch (char) {
            '&' => try characterReference(parser, tokenizer, null),
            0x00 => {
                try parser.parseError(.UnexpectedNullCharacter);
                try tokenizer.emitCharacter(REPLACEMENT_CHARACTER);
            },
            else => |c| try tokenizer.emitCharacter(c),
            '<' => {
                // RCDATALessThanSign
                if (nextIgnoreEofNoErrorCheck(parser) != '/') {
                    try tokenizer.emitCharacter('<');
                    undo(parser);
                    continue;
                }

                return nonDataEndTagOpen(parser, tokenizer);
            },
        }
    } else {
        return tokenizer.setNewState(.Eof);
    }
}

fn cDataSection(parser: *Parser, tokenizer: *Tokenizer) !void {
    while (try next(parser)) |char| switch (char) {
        ']' => {
            if (consumeCharsIfEql(parser, "]>")) {
                return tokenizer.setNewState(.Data);
            } else {
                try tokenizer.emitCharacter(']');
            }
        },
        else => |c| try tokenizer.emitCharacter(c),
    } else {
        try parser.parseError(.EOFInCDATA);
        return tokenizer.setNewState(.Eof);
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
