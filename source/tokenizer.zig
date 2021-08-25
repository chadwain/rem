const std = @import("std");
const assert = std.debug.assert;
const ArrayListUnmanaged = std.ArrayListUnmanaged;
const AutoHashMapUnmanaged = std.AutoHashMapUnmanaged;
const Allocator = std.mem.Allocator;

const EOF = '\u{5FFFE}';
const REPLACEMENT_CHARACTER = '\u{FFFD}';

test "" {
    std.testing.refAllDecls(@This());
}

const TokenizerState = enum {
    Data,
    RCDATA,
    RAWTEXT,
    ScriptData,
    PLAINTEXT,
    TagOpen,
    EndTagOpen,
    TagName,
    RCDATALessThanSign,
    RCDATAEndTagOpen,
    RCDATAEndTagName,
    RAWTEXTLessThanSign,
    RAWTEXTEndTagOpen,
    RAWTEXTEndTagName,
    ScriptDataLessThanSign,
    ScriptDataEndTagOpen,
    ScriptDataEndTagName,
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
    AfterAttributeName,
    BeforeAttributeValue,
    AttributeValueDoubleQuoted,
    AttributeValueSingleQuoted,
    AttributeValueUnquoted,
    AfterAttributeValueQuoted,
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
    BeforeDOCTYPEPublicIdentifier,
    DOCTYPEPublicIdentifierDoubleQuoted,
    DOCTYPEPublicIdentifierSingleQuoted,
    AfterDOCTYPEPublicIdentifier,
    BetweenDOCTYPEPublicAndSystemIdentifiers,
    AfterDOCTYPESystemKeyword,
    BeforeDOCTYPESystemIdentifier,
    DOCTYPESystemIdentifierDoubleQuoted,
    DOCTYPESystemIdentifierSingleQuoted,
    AfterDOCTYPESystemIdentifier,
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

const ParseError = enum {
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
    UnexptecedCharacterAfterDOCTYPESystemIdentifier,
    EOFInCDATA,
    MissingSemicolonAfterCharacterReference,
    UnknownNamedCharacterReference,
    AbsenceOfDigitsInNumericCharacterReference,
    NullCharacterReference,
    CharacterReferenceOutsideUnicodeRange,
    SurrogateCharacterReference,
    NoncharacterCharacterReference,
    ControlCharacterReference,
};

const TokenDOCTYPE = struct {
    name: ?[]u21,
    public_identifier: ?[]u21,
    system_identifier: ?[]u21,
    force_quirks: bool,
};

pub const AttributeContext = struct {
    pub fn hash(self: @This(), s: []const u21) u64 {
        _ = self;
        return std.hash.Wyhash.hash(0, std.mem.sliceAsBytes(s));
    }
    pub fn eql(self: @This(), a: []const u21, b: []const u21) bool {
        _ = self;
        return std.mem.eql(u21, a, b);
    }
};

const AttributeSet = std.HashMapUnmanaged([]const u21, []const u21, AttributeContext, std.hash_map.default_max_load_percentage);
const TokenTag = struct {
    name: []u21,
    attributes: AttributeSet,
    self_closing: bool,
};
const TokenComment = struct {
    data: []u21,
};
const TokenCharacter = struct {
    data: u21,
};
const TokenEOF = struct {};
const Token = union(enum) {
    doctype: TokenDOCTYPE,
    start_tag: TokenTag,
    end_tag: TokenTag,
    comment: TokenComment,
    character: TokenCharacter,
    eof: TokenEOF,
};

const Tokenizer = struct {
    state: TokenizerState = .Data,
    return_state: TokenizerState = undefined,
    character_reference_code: u32 = 0,
    current_tag_name: ArrayListUnmanaged(u21) = .{},
    current_tag_attributes: AttributeSet = .{},
    current_tag_self_closing: bool = false,
    current_tag_type: enum { Start, End } = undefined,
    last_start_tag_name: ?[]u21 = null,
    current_attribute_name: ArrayListUnmanaged(u21) = .{},
    current_attribute_value: ArrayListUnmanaged(u21) = .{},
    current_attribute_value_result_loc: ?*[]const u21 = null,
    current_doctype_name: ArrayListUnmanaged(u21) = .{},
    current_doctype_public_identifier: ArrayListUnmanaged(u21) = .{},
    current_doctype_system_identifier: ArrayListUnmanaged(u21) = .{},
    current_doctype_force_quirks: bool = false,
    current_doctype_name_is_missing: bool = true,
    current_doctype_public_identifier_is_missing: bool = true,
    current_doctype_system_identifier_is_missing: bool = true,
    current_comment_data: ArrayListUnmanaged(u21) = .{},
    temp_buffer: ArrayListUnmanaged(u21) = .{},
    adjusted_current_node_is_in_html_namespace: bool = true,

    input: []const u21,
    position: usize,
    prev_position: usize,

    tokens: ArrayListUnmanaged(Token) = .{},
    parse_errors: ArrayListUnmanaged(ParseError) = .{},
    allocator: *Allocator,

    const Self = @This();

    fn nextInputChar(self: *Self) u21 {
        self.prev_position = self.position;
        if (self.position >= self.input.len) return EOF;
        defer self.position += 1;
        return self.input[self.position];
    }

    fn peekInputChar(self: *Self) u21 {
        // TODO Don't duplicate logic from nextInputChar.
        if (self.position >= self.input.len) return EOF;
        return self.input[self.position];
    }

    fn resetPosition(self: *Self, old_position: usize) void {
        self.position = old_position;
    }

    fn consumeN(self: *Self, count: usize) void {
        var i = count;
        while (i > 0) : (i -= 1) {
            _ = self.nextInputChar();
        }
    }

    fn nextFewCharsEql(self: *Self, comptime string: []const u8) bool {
        const saved_position = self.position;
        defer self.resetPosition(saved_position);
        for (decodeComptimeString(string)) |character| {
            const input_char = self.nextInputChar();
            if (input_char == EOF or input_char != character) return false;
        }
        return true;
    }

    fn nextFewCharsCaseInsensitiveEql(self: *Self, comptime string: []const u8) bool {
        const saved_position = self.position;
        defer self.resetPosition(saved_position);
        for (decodeComptimeString(string)) |character| {
            const input_char = self.nextInputChar();
            if (input_char == EOF or !caseInsensitiveEql(input_char, character)) return false;
        }
        return true;
    }

    fn changeTo(self: *Self, new_state: TokenizerState) void {
        self.state = new_state;
    }

    fn toCharacterReferenceState(self: *Self, return_state: TokenizerState) void {
        self.state = .CharacterReference;
        self.return_state = return_state;
    }

    fn partOfAnAttribute(self: *Self) bool {
        return switch (self.return_state) {
            .AttributeValueDoubleQuoted,
            .AttributeValueSingleQuoted,
            .AttributeValueUnquoted,
            => true,
            else => false,
        };
    }

    fn reconsume(self: *Self, new_state: TokenizerState) void {
        self.resetPosition(self.prev_position);
        self.state = new_state;
    }

    fn switchToReturnState(self: *Self) void {
        self.state = self.return_state;
        self.return_state = undefined;
    }

    fn reconsumeInReturnState(self: *Self) void {
        self.reconsume(self.return_state);
    }

    fn parseError(self: *Self, err: ParseError) !void {
        try self.parse_errors.append(self.allocator, err);
    }

    fn emitCharacter(self: *Self, character: u21) !void {
        try self.tokens.append(self.allocator, Token{ .character = .{ .data = character } });
    }

    fn emitString(self: *Self, comptime string: []const u8) !void {
        // TODO Maybe we can have a TokenString.
        for (decodeComptimeString(string)) |character| {
            try emitCharacter(self, character);
        }
    }

    fn emitTempBufferCharacters(self: *Self) !void {
        for (self.temp_buffer.items) |character| {
            try self.emitCharacter(character);
        }
    }

    fn emitDOCTYPE(self: *Self) !void {
        var name = self.current_doctype_name.toOwnedSlice(self.allocator);
        errdefer self.allocator.free(name);
        if (self.current_doctype_name_is_missing) assert(name.len == 0);

        const public_identifier = self.current_doctype_public_identifier.toOwnedSlice(self.allocator);
        errdefer self.allocator.free(public_identifier);
        if (self.current_doctype_public_identifier_is_missing) assert(public_identifier.len == 0);

        const system_identifier = self.current_doctype_system_identifier.toOwnedSlice(self.allocator);
        errdefer self.allocator.free(system_identifier);
        if (self.current_doctype_system_identifier_is_missing) assert(system_identifier.len == 0);

        const token = Token{ .doctype = .{
            .name = if (self.current_doctype_name_is_missing) null else name,
            .public_identifier = if (self.current_doctype_public_identifier_is_missing) null else public_identifier,
            .system_identifier = if (self.current_doctype_system_identifier_is_missing) null else system_identifier,
            .force_quirks = self.current_doctype_force_quirks,
        } };
        try self.tokens.append(self.allocator, token);
    }

    fn emitComment(self: *Self) !void {
        const data = self.current_comment_data.toOwnedSlice(self.allocator);
        errdefer self.allocator.free(data);
        try self.tokens.append(self.allocator, Token{ .comment = .{ .data = data } });
    }

    fn emitEOF(self: *Self) !void {
        try self.tokens.append(self.allocator, Token{ .eof = .{} });
    }

    fn emitCurrentTag(self: *Self) !void {
        const name = self.current_tag_name.toOwnedSlice(self.allocator);
        errdefer self.allocator.free(name);
        switch (self.current_tag_type) {
            .Start => {
                self.last_start_tag_name = try std.mem.dupe(self.allocator, u21, name);
                try self.tokens.append(self.allocator, Token{ .start_tag = .{
                    .name = name,
                    .attributes = self.current_tag_attributes,
                    .self_closing = self.current_tag_self_closing,
                } });
            },
            .End => {
                try self.tokens.append(self.allocator, Token{ .end_tag = .{
                    .name = name,
                    .attributes = self.current_tag_attributes,
                    .self_closing = self.current_tag_self_closing,
                } });
            },
        }
        self.current_tag_type = undefined;
    }

    fn isAppropriateEndTag(self: *Self) bool {
        return if (self.last_start_tag_name) |last_name|
            std.mem.eql(u21, last_name, self.current_tag_name.items)
        else
            false;
    }

    fn createStartTagToken(self: *Self) void {
        self.current_tag_type = .Start;
    }

    fn createEndTagToken(self: *Self) void {
        self.current_tag_type = .End;
    }

    fn makeCurrentTagSelfClosing(self: *Self) void {
        self.current_tag_self_closing = true;
    }

    fn createAttribute(self: *Self) void {
        // Nothing to do.
    }

    fn createDOCTYPEToken(self: *Self) void {
        // Nothing to do.
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

    fn createCommentToken(self: *Self) void {
        // Nothing to do.
    }

    fn appendCurrentTagName(self: *Self, character: u21) !void {
        try self.current_tag_name.append(self.allocator, character);
    }

    fn appendCurrentAttributeName(self: *Self, character: u21) !void {
        try self.current_attribute_name.append(self.allocator, character);
    }

    fn appendCurrentAttributeValue(self: *Self, character: u21) !void {
        try self.current_attribute_value.append(self.allocator, character);
    }

    fn finishAttributeName(self: *Self) !void {
        const name = self.current_attribute_name.toOwnedSlice(self.allocator);
        errdefer self.allocator.free(name);
        const get_result = try self.current_tag_attributes.getOrPut(self.allocator, name);
        if (get_result.found_existing) {
            self.allocator.free(name);
            self.current_attribute_value_result_loc = null;
        } else {
            self.current_attribute_value_result_loc = get_result.value_ptr;
        }
    }

    fn finishAttributeValue(self: *Self) void {
        const value = self.current_attribute_value.toOwnedSlice(self.allocator);
        errdefer self.allocator.free(value);
        if (self.current_attribute_value_result_loc) |ptr| {
            ptr.* = value;
        } else {
            self.allocator.free(value);
        }
    }

    fn appendDOCTYPEName(self: *Self, character: u21) !void {
        try self.current_doctype_name.append(self.allocator, character);
    }

    fn appendDOCTYPEPublicIdentifier(self: *Self, character: u21) !void {
        try self.current_doctype_public_identifier.append(self.allocator, character);
    }

    fn appendDOCTYPESystemIdentifier(self: *Self, character: u21) !void {
        try self.current_doctype_system_identifier.append(self.allocator, character);
    }

    fn appendComment(self: *Self, character: u21) !void {
        try self.current_comment_data.append(self.allocator, character);
    }

    fn appendCommentString(self: *Self, comptime string: []const u8) !void {
        try self.current_comment_data.appendSlice(self.allocator, &decodeComptimeString(string));
    }

    fn appendTempBuffer(self: *Self, character: u21) !void {
        try self.temp_buffer.append(self.allocator, character);
    }

    fn clearTempBuffer(self: *Self) void {
        self.temp_buffer.shrinkRetainingCapacity(0);
    }

    fn tempBufferEql(self: *Self, comptime string: []const u8) bool {
        return std.mem.eql(u21, self.temp_buffer.items, &decodeComptimeString(string));
    }

    fn tempBufferLast(self: *Self) u21 {
        return self.temp_buffer.items[self.temp_buffer.items.len - 1];
    }

    fn tempBufferDropLast(self: *Self) void {
        _ = self.temp_buffer.pop();
    }

    fn flushCharacterReference(self: *Self) !void {
        if (self.partOfAnAttribute()) {
            for (self.temp_buffer.items) |character| {
                try self.current_attribute_value.append(self.allocator, character);
            }
        } else {
            for (self.temp_buffer.items) |character| {
                try self.emitCharacter(character);
            }
        }
    }

    // TODO Have a third state for when there is no match.
    const NamedCharacterMatch = enum { Prefix, Exact };

    fn tempBufferMatchesNamedCharacterPrefix(self: *Self) ?NamedCharacterMatch {
        // TODO Do real named character matching.
        return null;
    }

    fn translateNamedCharacterReference(self: *Self) struct { first: u21, second: ?u21 } {
        // TODO Do real named character translation.
        unreachable;
    }

    fn adjustedCurrentNodeNotInHtmlNamepsace(self: *Self) bool {
        return !self.adjusted_current_node_is_in_html_namespace;
    }
};

pub fn tokenize(t: *Tokenizer) !void {
    switch (t.state) {
        .Data => {
            switch (t.nextInputChar()) {
                '&' => t.toCharacterReferenceState(.Data),
                '<' => t.changeTo(.TagOpen),
                0x00 => {
                    try t.parseError(.UnexpectedNullCharacter);
                    try t.emitCharacter(0x00);
                },
                EOF => try t.emitEOF(),
                else => |c| try t.emitCharacter(c),
            }
        },
        .RCDATA => {
            switch (t.nextInputChar()) {
                '&' => t.toCharacterReferenceState(.RCDATA),
                '<' => t.changeTo(.RCDATALessThanSign),
                0x00 => {
                    try t.parseError(.UnexpectedNullCharacter);
                    try t.emitCharacter(REPLACEMENT_CHARACTER);
                },
                EOF => try t.emitEOF(),
                else => |c| try t.emitCharacter(c),
            }
        },
        .RAWTEXT => {
            switch (t.nextInputChar()) {
                '<' => t.changeTo(.RAWTEXTLessThanSign),
                0x00 => {
                    try t.parseError(.UnexpectedNullCharacter);
                    try t.emitCharacter(REPLACEMENT_CHARACTER);
                },
                EOF => try t.emitEOF(),
                else => |c| try t.emitCharacter(c),
            }
        },
        .ScriptData => {
            switch (t.nextInputChar()) {
                '<' => t.changeTo(.ScriptDataLessThanSign),
                0x00 => {
                    try t.parseError(.UnexpectedNullCharacter);
                    try t.emitCharacter(REPLACEMENT_CHARACTER);
                },
                EOF => try t.emitEOF(),
                else => |c| try t.emitCharacter(c),
            }
        },
        .PLAINTEXT => {
            switch (t.nextInputChar()) {
                0x00 => {
                    try t.parseError(.UnexpectedNullCharacter);
                    try t.emitCharacter(REPLACEMENT_CHARACTER);
                },
                EOF => try t.emitEOF(),
                else => |c| try t.emitCharacter(c),
            }
        },
        .TagOpen => {
            switch (t.nextInputChar()) {
                '!' => t.changeTo(.MarkupDeclarationOpen),
                '/' => t.changeTo(.EndTagOpen),
                'A'...'Z', 'a'...'z' => {
                    t.createStartTagToken();
                    t.reconsume(.TagName);
                },
                '?' => {
                    try t.parseError(.UnexpectedQuestionMarkInsteadOfTagName);
                    t.createCommentToken();
                    t.reconsume(.BogusComment);
                },
                EOF => {
                    try t.parseError(.EOFBeforeTagName);
                    try t.emitCharacter('<');
                    try t.emitEOF();
                },
                else => {
                    try t.parseError(.InvalidFirstCharacterOfTagName);
                    try t.emitCharacter('<');
                    t.reconsume(.Data);
                },
            }
        },
        .EndTagOpen => {
            switch (t.nextInputChar()) {
                'A'...'Z', 'a'...'z' => {
                    t.createEndTagToken();
                    t.reconsume(.TagName);
                },
                '>' => {
                    try t.parseError(.MissingEndTagName);
                    t.changeTo(.Data);
                },
                EOF => {
                    try t.parseError(.EOFBeforeTagName);
                    try t.emitString("</");
                    try t.emitEOF();
                },
                else => {
                    try t.parseError(.InvalidFirstCharacterOfTagName);
                    t.createCommentToken();
                    t.reconsume(.BogusComment);
                },
            }
        },
        .TagName => {
            switch (t.nextInputChar()) {
                '\t', '\n', 0x0C, ' ' => t.changeTo(.BeforeAttributeName),
                '/' => t.changeTo(.SelfClosingStartTag),
                '>' => {
                    t.changeTo(.Data);
                    try t.emitCurrentTag();
                },
                'A'...'Z' => |c| try t.appendCurrentTagName(toLowercase(c)),
                0x00 => {
                    try t.parseError(.UnexpectedNullCharacter);
                    try t.appendCurrentTagName(REPLACEMENT_CHARACTER);
                },
                EOF => {
                    try t.parseError(.EOFInTag);
                    try t.emitEOF();
                },
                else => |c| try t.appendCurrentTagName(c),
            }
        },
        .RCDATALessThanSign => {
            switch (t.nextInputChar()) {
                '/' => {
                    t.clearTempBuffer();
                    t.changeTo(.RCDATAEndTagOpen);
                },
                else => {
                    try t.emitCharacter('<');
                    t.reconsume(.RCDATA);
                },
            }
        },
        .RCDATAEndTagOpen => {
            switch (t.nextInputChar()) {
                'A'...'Z', 'a'...'z' => {
                    t.createEndTagToken();
                    t.reconsume(.RCDATAEndTagName);
                },
                else => {
                    try t.emitString("</");
                    t.reconsume(.RCDATA);
                },
            }
        },
        .RCDATAEndTagName => {
            const current_input_char = t.nextInputChar();
            try endTagName(t, current_input_char, .RCDATA);
        },
        .RAWTEXTLessThanSign => {
            switch (t.nextInputChar()) {
                '/' => {
                    t.clearTempBuffer();
                    t.changeTo(.RAWTEXTEndTagOpen);
                },
                else => {
                    try t.emitCharacter('<');
                    t.reconsume(.RAWTEXT);
                },
            }
        },
        .RAWTEXTEndTagOpen => {
            switch (t.nextInputChar()) {
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
        .RAWTEXTEndTagName => {
            const current_input_char = t.nextInputChar();
            try endTagName(t, current_input_char, .RAWTEXT);
        },
        .ScriptDataLessThanSign => {
            switch (t.nextInputChar()) {
                '/' => {
                    t.clearTempBuffer();
                    t.changeTo(.ScriptDataEndTagOpen);
                },
                '!' => {
                    t.changeTo(.ScriptDataEscapeStart);
                    try t.emitString("<!");
                },
                else => {
                    try t.emitCharacter('<');
                    t.reconsume(.ScriptData);
                },
            }
        },
        .ScriptDataEndTagOpen => {
            switch (t.nextInputChar()) {
                'A'...'Z', 'a'...'z' => {
                    t.createEndTagToken();
                    t.reconsume(.ScriptDataEndTagName);
                },
                else => {
                    try t.emitString("</");
                    t.reconsume(.ScriptData);
                },
            }
        },
        .ScriptDataEndTagName => {
            const current_input_char = t.nextInputChar();
            try endTagName(t, current_input_char, .ScriptData);
        },
        .ScriptDataEscapeStart => {
            switch (t.nextInputChar()) {
                '-' => {
                    t.changeTo(.ScriptDataEscapeStartDash);
                    try t.emitCharacter('-');
                },
                else => t.reconsume(.ScriptData),
            }
        },
        .ScriptDataEscapeStartDash => {
            switch (t.nextInputChar()) {
                '-' => {
                    t.changeTo(.ScriptDataEscapedDashDash);
                    try t.emitCharacter('-');
                },
                else => t.reconsume(.ScriptData),
            }
        },
        .ScriptDataEscaped => {
            switch (t.nextInputChar()) {
                '-' => {
                    t.changeTo(.ScriptDataEscapedDash);
                    try t.emitCharacter('-');
                },
                '<' => t.changeTo(.ScriptDataEscapedLessThanSign),
                0x00 => {
                    try t.parseError(.UnexpectedNullCharacter);
                    try t.emitCharacter(REPLACEMENT_CHARACTER);
                },
                EOF => {
                    try t.parseError(.EOFInScriptHtmlCommentLikeText);
                    try t.emitEOF();
                },
                else => |c| try t.emitCharacter(c),
            }
        },
        .ScriptDataEscapedDash => {
            switch (t.nextInputChar()) {
                '-' => {
                    t.changeTo(.ScriptDataEscapedDashDash);
                    try t.emitCharacter('-');
                },
                '<' => t.changeTo(.ScriptDataEscapedLessThanSign),
                0x00 => {
                    try t.parseError(.UnexpectedNullCharacter);
                    t.changeTo(.ScriptDataEscaped);
                    try t.emitCharacter(REPLACEMENT_CHARACTER);
                },
                EOF => {
                    try t.parseError(.EOFInScriptHtmlCommentLikeText);
                    try t.emitEOF();
                },
                else => |c| {
                    t.changeTo(.ScriptDataEscaped);
                    try t.emitCharacter(c);
                },
            }
        },
        .ScriptDataEscapedDashDash => {
            switch (t.nextInputChar()) {
                '-' => try t.emitCharacter('-'),
                '<' => t.changeTo(.ScriptDataEscapedLessThanSign),
                '>' => {
                    t.changeTo(.ScriptData);
                    try t.emitCharacter('>');
                },
                0x00 => {
                    try t.parseError(.UnexpectedNullCharacter);
                    t.changeTo(.ScriptDataEscaped);
                    try t.emitCharacter(REPLACEMENT_CHARACTER);
                },
                EOF => {
                    try t.parseError(.EOFInScriptHtmlCommentLikeText);
                    try t.emitEOF();
                },
                else => |c| {
                    t.changeTo(.ScriptDataEscaped);
                    try t.emitCharacter(c);
                },
            }
        },
        .ScriptDataEscapedLessThanSign => {
            switch (t.nextInputChar()) {
                '/' => {
                    t.clearTempBuffer();
                    t.changeTo(.ScriptDataEscapedEndTagOpen);
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
            switch (t.nextInputChar()) {
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
        .ScriptDataEscapedEndTagName => {
            const current_input_char = t.nextInputChar();
            try endTagName(t, current_input_char, .ScriptDataEscaped);
        },
        .ScriptDataDoubleEscapeStart => {
            switch (t.nextInputChar()) {
                '\t', '\n', 0x0C, ' ', '/', '>' => |c| {
                    t.state = if (t.tempBufferEql("script")) .ScriptDataDoubleEscaped else .ScriptDataEscaped;
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
            switch (t.nextInputChar()) {
                '-' => {
                    t.changeTo(.ScriptDataDoubleEscapedDash);
                    try t.emitCharacter('-');
                },
                '<' => {
                    t.changeTo(.ScriptDataDoubleEscapedLessThanSign);
                    try t.emitCharacter('<');
                },
                0x00 => {
                    try t.parseError(.UnexpectedNullCharacter);
                    try t.emitCharacter(REPLACEMENT_CHARACTER);
                },
                EOF => {
                    try t.parseError(.EOFInScriptHtmlCommentLikeText);
                    try t.emitEOF();
                },
                else => |c| try t.emitCharacter(c),
            }
        },
        .ScriptDataDoubleEscapedDash => {
            switch (t.nextInputChar()) {
                '-' => {
                    t.changeTo(.ScriptDataDoubleEscapedDashDash);
                    try t.emitCharacter('-');
                },
                '<' => {
                    t.changeTo(.ScriptDataDoubleEscapedLessThanSign);
                    try t.emitCharacter('<');
                },
                0x00 => {
                    try t.parseError(.UnexpectedNullCharacter);
                    t.changeTo(.ScriptDataDoubleEscaped);
                    try t.emitCharacter(REPLACEMENT_CHARACTER);
                },
                EOF => {
                    try t.parseError(.EOFInScriptHtmlCommentLikeText);
                    try t.emitEOF();
                },
                else => |c| {
                    t.changeTo(.ScriptDataDoubleEscaped);
                    try t.emitCharacter(c);
                },
            }
        },
        .ScriptDataDoubleEscapedDashDash => {
            switch (t.nextInputChar()) {
                '-' => try t.emitCharacter('-'),
                '<' => {
                    t.changeTo(.ScriptDataDoubleEscapedLessThanSign);
                    try t.emitCharacter('<');
                },
                '>' => {
                    t.changeTo(.ScriptData);
                    try t.emitCharacter('>');
                },
                0x00 => {
                    try t.parseError(.UnexpectedNullCharacter);
                    t.changeTo(.ScriptDataDoubleEscaped);
                    try t.emitCharacter(REPLACEMENT_CHARACTER);
                },
                EOF => {
                    try t.parseError(.EOFInScriptHtmlCommentLikeText);
                    try t.emitEOF();
                },
                else => |c| {
                    t.changeTo(.ScriptDataDoubleEscaped);
                    try t.emitCharacter(c);
                },
            }
        },
        .ScriptDataDoubleEscapedLessThanSign => {
            switch (t.nextInputChar()) {
                '/' => {
                    t.clearTempBuffer();
                    t.changeTo(.ScriptDataDoubleEscapeEnd);
                    try t.emitCharacter('/');
                },
                else => t.reconsume(.ScriptDataDoubleEscaped),
            }
        },
        // Nearly identical to ScriptDataDoubleEscapeStart.
        .ScriptDataDoubleEscapeEnd => {
            switch (t.nextInputChar()) {
                '\t', '\n', 0x0C, ' ', '/', '>' => |c| {
                    t.state = if (t.tempBufferEql("script")) .ScriptDataEscaped else .ScriptDataDoubleEscaped;
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
            switch (t.nextInputChar()) {
                '\t', '\n', 0x0C, ' ' => {},
                '/', '>', EOF => t.reconsume(.AfterAttributeName),
                '=' => {
                    try t.parseError(.UnexpectedEqualsSignBeforeAttributeName);
                    t.createAttribute();
                    try t.appendCurrentAttributeName('=');
                    t.changeTo(.AttributeName);
                },
                else => {
                    t.createAttribute();
                    t.reconsume(.AttributeName);
                },
            }
        },
        .AttributeName => {
            switch (t.nextInputChar()) {
                '\t', '\n', 0x0C, ' ', '/', '>', EOF => {
                    try t.finishAttributeName();
                    t.reconsume(.AfterAttributeName);
                },
                '=' => {
                    try t.finishAttributeName();
                    t.changeTo(.BeforeAttributeValue);
                },
                'A'...'Z' => |c| try t.appendCurrentAttributeName(toLowercase(c)),
                0x00 => {
                    try t.parseError(.UnexpectedNullCharacter);
                    try t.appendCurrentAttributeName(REPLACEMENT_CHARACTER);
                },
                else => |c| {
                    switch (c) {
                        '"', '\'', '<' => try t.parseError(.UnexpectedCharacterInAttributeName),
                        else => {},
                    }
                    try t.appendCurrentAttributeName(c);
                },
            }
        },
        .AfterAttributeName => {
            switch (t.nextInputChar()) {
                '\t', '\n', 0x0C, ' ' => {},
                '/' => t.changeTo(.SelfClosingStartTag),
                '=' => t.changeTo(.BeforeAttributeValue),
                '>' => {
                    t.changeTo(.Data);
                    try t.emitCurrentTag();
                },
                EOF => {
                    try t.parseError(.EOFInTag);
                    try t.emitEOF();
                },
                else => {
                    t.createAttribute();
                    t.reconsume(.AttributeName);
                },
            }
        },
        .BeforeAttributeValue => {
            switch (t.nextInputChar()) {
                '\t', '\n', 0x0C, ' ' => {},
                '"' => t.changeTo(.AttributeValueDoubleQuoted),
                '\'' => t.changeTo(.AttributeValueSingleQuoted),
                '>' => {
                    try t.parseError(.MissingAttributeValue);
                    t.changeTo(.Data);
                    try t.emitCurrentTag();
                },
                else => t.reconsume(.AttributeValueUnquoted),
            }
        },
        .AttributeValueDoubleQuoted => {
            switch (t.nextInputChar()) {
                '"' => {
                    t.finishAttributeValue();
                    t.changeTo(.AfterAttributeValueQuoted);
                },
                '&' => t.toCharacterReferenceState(.AttributeValueDoubleQuoted),
                0x00 => {
                    try t.parseError(.UnexpectedNullCharacter);
                    try t.appendCurrentAttributeValue(REPLACEMENT_CHARACTER);
                },
                EOF => {
                    try t.parseError(.EOFInTag);
                    try t.emitEOF();
                },
                else => |c| try t.appendCurrentAttributeValue(c),
            }
        },
        // Nearly identical to AttributeValueDoubleQuoted.
        .AttributeValueSingleQuoted => {
            switch (t.nextInputChar()) {
                '\'' => {
                    t.finishAttributeValue();
                    t.changeTo(.AfterAttributeValueQuoted);
                },
                '&' => t.toCharacterReferenceState(.AttributeValueSingleQuoted),
                0x00 => {
                    try t.parseError(.UnexpectedNullCharacter);
                    try t.appendCurrentAttributeValue(REPLACEMENT_CHARACTER);
                },
                EOF => {
                    try t.parseError(.EOFInTag);
                    try t.emitEOF();
                },
                else => |c| try t.appendCurrentAttributeValue(c),
            }
        },
        .AttributeValueUnquoted => {
            switch (t.nextInputChar()) {
                '\t', '\n', 0x0C, ' ' => {
                    t.finishAttributeValue();
                    t.changeTo(.BeforeAttributeName);
                },
                '&' => t.toCharacterReferenceState(.AttributeValueUnquoted),
                '>' => {
                    t.finishAttributeValue();
                    t.changeTo(.Data);
                    try t.emitCurrentTag();
                },
                0x00 => {
                    try t.parseError(.UnexpectedNullCharacter);
                    try t.appendCurrentAttributeValue(REPLACEMENT_CHARACTER);
                },
                EOF => {
                    try t.parseError(.EOFInTag);
                    try t.emitEOF();
                },
                else => |c| {
                    switch (c) {
                        '"', '\'', '<', '=', '`' => try t.parseError(.UnexpectedCharacterInUnquotedAttributeValue),
                        else => {},
                    }
                    try t.appendCurrentAttributeValue(c);
                },
            }
        },
        .AfterAttributeValueQuoted => {
            switch (t.nextInputChar()) {
                '\t', '\n', 0x0C, ' ' => t.changeTo(.BeforeAttributeName),
                '/' => t.changeTo(.SelfClosingStartTag),
                '>' => {
                    t.changeTo(.Data);
                    try t.emitCurrentTag();
                },
                EOF => {
                    try t.parseError(.EOFInTag);
                    try t.emitEOF();
                },
                else => {
                    try t.parseError(.MissingWhitespaceBetweenAttributes);
                    t.reconsume(.BeforeAttributeName);
                },
            }
        },
        .SelfClosingStartTag => {
            switch (t.nextInputChar()) {
                '>' => {
                    t.makeCurrentTagSelfClosing();
                    t.changeTo(.Data);
                    try t.emitCurrentTag();
                },
                EOF => {
                    try t.parseError(.EOFInTag);
                    try t.emitEOF();
                },
                else => {
                    try t.parseError(.UnexpectedSolidusInTag);
                    t.reconsume(.BeforeAttributeName);
                },
            }
        },
        .BogusComment => {
            switch (t.nextInputChar()) {
                '>' => {
                    t.changeTo(.Data);
                    try t.emitComment();
                },
                EOF => {
                    try t.emitComment();
                    try t.emitEOF();
                },
                0x00 => {
                    try t.parseError(.UnexpectedNullCharacter);
                    try t.appendComment(REPLACEMENT_CHARACTER);
                },
                else => |c| try t.appendComment(c),
            }
        },
        .MarkupDeclarationOpen => {
            if (t.nextFewCharsEql("--")) {
                t.consumeN(2);
                t.createCommentToken();
                t.changeTo(.CommentStart);
            } else if (t.nextFewCharsCaseInsensitiveEql("DOCTYPE")) {
                t.consumeN(7);
                t.changeTo(.DOCTYPE);
            } else if (t.nextFewCharsEql("[CDATA[")) {
                t.consumeN(7);
                if (t.adjustedCurrentNodeNotInHtmlNamepsace()) {
                    t.changeTo(.CDATASection);
                } else {
                    try t.parseError(.CDATAInHtmlContent);
                    t.createCommentToken();
                    try t.appendCommentString("[CDATA[");
                    t.changeTo(.BogusComment);
                }
            } else {
                try t.parseError(.IncorrectlyOpenedComment);
                t.createCommentToken();
                t.changeTo(.BogusComment);
            }
        },
        .CommentStart => {
            switch (t.nextInputChar()) {
                '-' => t.changeTo(.CommentStartDash),
                '>' => {
                    try t.parseError(.AbruptClosingOfEmptyComment);
                    t.changeTo(.Data);
                    try t.emitComment();
                },
                else => t.reconsume(.Comment),
            }
        },
        .CommentStartDash => {
            switch (t.nextInputChar()) {
                '-' => t.changeTo(.CommentEnd),
                '>' => {
                    try t.parseError(.AbruptClosingOfEmptyComment);
                    t.changeTo(.Data);
                    try t.emitComment();
                },
                EOF => {
                    try t.parseError(.EOFInComment);
                    try t.emitComment();
                    try t.emitEOF();
                },
                else => {
                    try t.appendComment('-');
                    t.reconsume(.Comment);
                },
            }
        },
        .Comment => {
            switch (t.nextInputChar()) {
                '<' => {
                    try t.appendComment('<');
                    t.changeTo(.CommentLessThanSign);
                },
                '-' => t.changeTo(.CommentEndDash),
                0x00 => {
                    try t.parseError(.UnexpectedNullCharacter);
                    try t.appendComment(REPLACEMENT_CHARACTER);
                },
                EOF => {
                    try t.parseError(.EOFInComment);
                    try t.emitComment();
                    try t.emitEOF();
                },
                else => |c| try t.appendComment(c),
            }
        },
        .CommentLessThanSign => {
            switch (t.nextInputChar()) {
                '!' => {
                    try t.appendComment('!');
                    t.changeTo(.CommentLessThanSignBang);
                },
                '<' => try t.appendComment('<'),
                else => t.reconsume(.Comment),
            }
        },
        .CommentLessThanSignBang => {
            switch (t.nextInputChar()) {
                '-' => t.changeTo(.CommentLessThanSignBangDash),
                else => t.reconsume(.Comment),
            }
        },
        .CommentLessThanSignBangDash => {
            switch (t.nextInputChar()) {
                '-' => t.changeTo(.CommentLessThanSignBangDashDash),
                else => t.reconsume(.CommentEndDash),
            }
        },
        .CommentLessThanSignBangDashDash => {
            switch (t.nextInputChar()) {
                '>', EOF => t.reconsume(.CommentEnd),
                else => {
                    try t.parseError(.NestedComment);
                    t.reconsume(.CommentEnd);
                },
            }
        },
        .CommentEndDash => {
            switch (t.nextInputChar()) {
                '-' => t.changeTo(.CommentEnd),
                EOF => {
                    try t.parseError(.EOFInComment);
                    try t.emitComment();
                    try t.emitEOF();
                },
                else => {
                    try t.appendComment('-');
                    t.reconsume(.Comment);
                },
            }
        },
        .CommentEnd => {
            switch (t.nextInputChar()) {
                '>' => {
                    t.changeTo(.Data);
                    try t.emitComment();
                },
                '!' => t.changeTo(.CommentEndBang),
                '-' => try t.appendComment('-'),
                EOF => {
                    try t.parseError(.EOFInComment);
                    try t.emitComment();
                    try t.emitEOF();
                },
                else => {
                    try t.appendComment('-');
                    try t.appendComment('-');
                    t.reconsume(.Comment);
                },
            }
        },
        .CommentEndBang => {
            switch (t.nextInputChar()) {
                '-' => {
                    try t.appendComment('-');
                    try t.appendComment('-');
                    try t.appendComment('!');
                    t.changeTo(.CommentEndDash);
                },
                '>' => {
                    try t.parseError(.IncorrectlyClosedComment);
                    t.changeTo(.Data);
                    try t.emitComment();
                },
                EOF => {
                    try t.parseError(.EOFInComment);
                    try t.emitComment();
                    try t.emitEOF();
                },
                else => {
                    try t.appendComment('-');
                    try t.appendComment('-');
                    try t.appendComment('!');
                    t.reconsume(.Comment);
                },
            }
        },
        .DOCTYPE => {
            switch (t.nextInputChar()) {
                '\t', '\n', 0x0C, ' ' => t.changeTo(.BeforeDOCTYPEName),
                '>' => t.reconsume(.BeforeDOCTYPEName),
                EOF => {
                    try t.parseError(.EOFInDOCTYPE);
                    t.createDOCTYPEToken();
                    t.currentDOCTYPETokenForceQuirks();
                    try t.emitDOCTYPE();
                    try t.emitEOF();
                },
                else => {
                    try t.parseError(.MissingWhitespaceBeforeDOCTYPEName);
                    t.reconsume(.BeforeDOCTYPEName);
                },
            }
        },
        .BeforeDOCTYPEName => {
            switch (t.nextInputChar()) {
                '\t', '\n', 0x0C, ' ' => {},
                'A'...'Z' => |c| {
                    t.createDOCTYPEToken();
                    t.markCurrentDOCTYPENameNotMissing();
                    try t.appendDOCTYPEName(toLowercase(c));
                    t.changeTo(.DOCTYPEName);
                },
                '>' => {
                    try t.parseError(.MissingDOCTYPEName);
                    t.createDOCTYPEToken();
                    t.currentDOCTYPETokenForceQuirks();
                    t.changeTo(.Data);
                    try t.emitDOCTYPE();
                },
                EOF => {
                    try t.parseError(.EOFInDOCTYPE);
                    t.createDOCTYPEToken();
                    t.currentDOCTYPETokenForceQuirks();
                    try t.emitDOCTYPE();
                    try t.emitEOF();
                },
                else => |c| {
                    t.createDOCTYPEToken();
                    t.markCurrentDOCTYPENameNotMissing();
                    try t.appendDOCTYPEName(c);
                    t.changeTo(.DOCTYPEName);
                },
            }
        },
        .DOCTYPEName => {
            switch (t.nextInputChar()) {
                '\t', '\n', 0x0C, ' ' => t.changeTo(.AfterDOCTYPEName),
                '>' => {
                    t.changeTo(.Data);
                    try t.emitDOCTYPE();
                },
                'A'...'Z' => |c| try t.appendDOCTYPEName(c),
                0x00 => {
                    try t.parseError(.UnexpectedNullCharacter);
                    try t.appendDOCTYPEName(REPLACEMENT_CHARACTER);
                },
                EOF => {
                    try t.parseError(.EOFInDOCTYPE);
                    t.currentDOCTYPETokenForceQuirks();
                    try t.emitDOCTYPE();
                    try t.emitEOF();
                },
                else => |c| try t.appendDOCTYPEName(c),
            }
        },
        .AfterDOCTYPEName => {
            switch (t.nextInputChar()) {
                '\t', '\n', 0x0C, ' ' => {},
                '>' => {
                    t.changeTo(.Data);
                    try t.emitDOCTYPE();
                },
                EOF => {
                    try t.parseError(.EOFInDOCTYPE);
                    t.currentDOCTYPETokenForceQuirks();
                    try t.emitDOCTYPE();
                    try t.emitEOF();
                },
                else => |c| {
                    if (caseInsensitiveEql(c, 'P') and t.nextFewCharsCaseInsensitiveEql("UBLIC")) {
                        t.consumeN(5);
                        t.changeTo(.AfterDOCTYPEPublicKeyword);
                    } else if (caseInsensitiveEql(c, 'S') and t.nextFewCharsCaseInsensitiveEql("YSTEM")) {
                        t.consumeN(5);
                        t.changeTo(.AfterDOCTYPESystemKeyword);
                    } else {
                        try t.parseError(.InvalidCharacterSequenceAfterDOCTYPEName);
                        t.currentDOCTYPETokenForceQuirks();
                        t.reconsume(.BogusDOCTYPE);
                    }
                },
            }
        },
        .AfterDOCTYPEPublicKeyword => {
            switch (t.nextInputChar()) {
                '\t', '\n', 0x0C, ' ' => t.changeTo(.BeforeDOCTYPEPublicIdentifier),
                '"' => {
                    try t.parseError(.MissingWhitespaceAfterDOCTYPEPublicKeyword);
                    t.markCurrentDOCTYPEPublicIdentifierNotMissing();
                    t.changeTo(.DOCTYPEPublicIdentifierDoubleQuoted);
                },
                '\'' => {
                    try t.parseError(.MissingWhitespaceAfterDOCTYPEPublicKeyword);
                    t.markCurrentDOCTYPEPublicIdentifierNotMissing();
                    t.changeTo(.DOCTYPEPublicIdentifierSingleQuoted);
                },
                '>' => {
                    try t.parseError(.MissingDOCTYPEPublicIdentifier);
                    t.currentDOCTYPETokenForceQuirks();
                    t.changeTo(.Data);
                    try t.emitDOCTYPE();
                },
                EOF => {
                    try t.parseError(.EOFInDOCTYPE);
                    t.currentDOCTYPETokenForceQuirks();
                    try t.emitDOCTYPE();
                    try t.emitEOF();
                },
                else => {
                    try t.parseError(.MissingQuoteBeforeDOCTYPEPublicIdentifier);
                    t.currentDOCTYPETokenForceQuirks();
                    t.reconsume(.BogusDOCTYPE);
                },
            }
        },
        .BeforeDOCTYPEPublicIdentifier => {
            switch (t.nextInputChar()) {
                '\t', '\n', 0x0C, ' ' => {},
                '"' => {
                    t.markCurrentDOCTYPEPublicIdentifierNotMissing();
                    t.changeTo(.DOCTYPEPublicIdentifierDoubleQuoted);
                },
                '\'' => {
                    t.markCurrentDOCTYPEPublicIdentifierNotMissing();
                    t.changeTo(.DOCTYPEPublicIdentifierSingleQuoted);
                },
                '>' => {
                    try t.parseError(.MissingDOCTYPEPublicIdentifier);
                    t.currentDOCTYPETokenForceQuirks();
                    t.changeTo(.Data);
                    try t.emitDOCTYPE();
                },
                EOF => {
                    try t.parseError(.EOFInDOCTYPE);
                    t.currentDOCTYPETokenForceQuirks();
                    try t.emitDOCTYPE();
                    try t.emitEOF();
                },
                else => {
                    try t.parseError(.MissingQuoteBeforeDOCTYPEPublicIdentifier);
                    t.currentDOCTYPETokenForceQuirks();
                    t.reconsume(.BogusDOCTYPE);
                },
            }
        },
        .DOCTYPEPublicIdentifierDoubleQuoted => {
            switch (t.nextInputChar()) {
                '"' => t.changeTo(.AfterDOCTYPEPublicIdentifier),
                0x00 => {
                    try t.parseError(.UnexpectedNullCharacter);
                    try t.appendDOCTYPEPublicIdentifier(REPLACEMENT_CHARACTER);
                },
                '>' => {
                    try t.parseError(.AbruptDOCTYPEPublicIdentifier);
                    t.currentDOCTYPETokenForceQuirks();
                    t.changeTo(.Data);
                    try t.emitDOCTYPE();
                },
                EOF => {
                    try t.parseError(.EOFInDOCTYPE);
                    t.currentDOCTYPETokenForceQuirks();
                    try t.emitDOCTYPE();
                    try t.emitEOF();
                },
                else => |c| try t.appendDOCTYPEPublicIdentifier(c),
            }
        },
        // Nearly identical to DOCTYPEPublicIdentifierDoubleQuoted.
        .DOCTYPEPublicIdentifierSingleQuoted => {
            switch (t.nextInputChar()) {
                '\'' => t.changeTo(.AfterDOCTYPEPublicIdentifier),
                0x00 => {
                    try t.parseError(.UnexpectedNullCharacter);
                    try t.appendDOCTYPEPublicIdentifier(REPLACEMENT_CHARACTER);
                },
                '>' => {
                    try t.parseError(.AbruptDOCTYPEPublicIdentifier);
                    t.currentDOCTYPETokenForceQuirks();
                    t.changeTo(.Data);
                    try t.emitDOCTYPE();
                },
                EOF => {
                    try t.parseError(.EOFInDOCTYPE);
                    t.currentDOCTYPETokenForceQuirks();
                    try t.emitDOCTYPE();
                    try t.emitEOF();
                },
                else => |c| try t.appendDOCTYPEPublicIdentifier(c),
            }
        },
        .AfterDOCTYPEPublicIdentifier => {
            switch (t.nextInputChar()) {
                '\t', '\n', 0x0C, ' ' => t.changeTo(.BetweenDOCTYPEPublicAndSystemIdentifiers),
                '>' => {
                    t.changeTo(.Data);
                    try t.emitDOCTYPE();
                },
                '"' => {
                    try t.parseError(.MissingWhitespaceBetweenDOCTYPEPublicAndSystemIdentifiers);
                    t.markCurrentDOCTYPESystemIdentifierNotMissing();
                    t.changeTo(.DOCTYPESystemIdentifierDoubleQuoted);
                },
                '\'' => {
                    try t.parseError(.MissingWhitespaceBetweenDOCTYPEPublicAndSystemIdentifiers);
                    t.markCurrentDOCTYPESystemIdentifierNotMissing();
                    t.changeTo(.DOCTYPESystemIdentifierSingleQuoted);
                },
                EOF => {
                    try t.parseError(.EOFInDOCTYPE);
                    t.currentDOCTYPETokenForceQuirks();
                    try t.emitDOCTYPE();
                    try t.emitEOF();
                },
                else => {
                    try t.parseError(.MissingQuoteBeforeDOCTYPESystemIdentifier);
                    t.currentDOCTYPETokenForceQuirks();
                    t.reconsume(.BogusDOCTYPE);
                },
            }
        },
        .BetweenDOCTYPEPublicAndSystemIdentifiers => {
            switch (t.nextInputChar()) {
                '\t', '\n', 0x0C, ' ' => {},
                '>' => {
                    t.changeTo(.Data);
                    try t.emitDOCTYPE();
                },
                '"' => {
                    t.markCurrentDOCTYPESystemIdentifierNotMissing();
                    t.changeTo(.DOCTYPESystemIdentifierDoubleQuoted);
                },
                '\'' => {
                    t.markCurrentDOCTYPESystemIdentifierNotMissing();
                    t.changeTo(.DOCTYPESystemIdentifierSingleQuoted);
                },
                EOF => {
                    try t.parseError(.EOFInDOCTYPE);
                    t.currentDOCTYPETokenForceQuirks();
                    try t.emitDOCTYPE();
                },
                else => {
                    try t.parseError(.MissingQuoteBeforeDOCTYPESystemIdentifier);
                    t.currentDOCTYPETokenForceQuirks();
                    t.reconsume(.BogusDOCTYPE);
                },
            }
        },
        .AfterDOCTYPESystemKeyword => {
            switch (t.nextInputChar()) {
                '\t', '\n', 0x0C, ' ' => t.changeTo(.BeforeDOCTYPESystemIdentifier),
                '"' => {
                    try t.parseError(.MissingWhitespaceAfterDOCTYPESystemKeyword);
                    t.markCurrentDOCTYPESystemIdentifierNotMissing();
                    t.changeTo(.DOCTYPESystemIdentifierDoubleQuoted);
                },
                '\'' => {
                    try t.parseError(.MissingWhitespaceAfterDOCTYPESystemKeyword);
                    t.markCurrentDOCTYPESystemIdentifierNotMissing();
                    t.changeTo(.DOCTYPESystemIdentifierSingleQuoted);
                },
                '>' => {
                    try t.parseError(.MissingDOCTYPESystemIdentifier);
                    t.currentDOCTYPETokenForceQuirks();
                    t.changeTo(.Data);
                    try t.emitDOCTYPE();
                },
                EOF => {
                    try t.parseError(.EOFInDOCTYPE);
                    t.currentDOCTYPETokenForceQuirks();
                    try t.emitDOCTYPE();
                    try t.emitEOF();
                },
                else => {
                    try t.parseError(.MissingQuoteBeforeDOCTYPESystemIdentifier);
                    t.currentDOCTYPETokenForceQuirks();
                    t.reconsume(.BogusDOCTYPE);
                },
            }
        },
        .BeforeDOCTYPESystemIdentifier => {
            switch (t.nextInputChar()) {
                '\t', '\n', 0x0C, ' ' => {},
                '"' => {
                    t.markCurrentDOCTYPESystemIdentifierNotMissing();
                    t.changeTo(.DOCTYPESystemIdentifierDoubleQuoted);
                },
                '\'' => {
                    t.markCurrentDOCTYPESystemIdentifierNotMissing();
                    t.changeTo(.DOCTYPESystemIdentifierSingleQuoted);
                },
                '>' => {
                    try t.parseError(.MissingDOCTYPESystemIdentifier);
                    t.currentDOCTYPETokenForceQuirks();
                    t.changeTo(.Data);
                    try t.emitDOCTYPE();
                },
                EOF => {
                    try t.parseError(.EOFInDOCTYPE);
                    t.currentDOCTYPETokenForceQuirks();
                    try t.emitDOCTYPE();
                    try t.emitEOF();
                },
                else => {
                    try t.parseError(.MissingQuoteBeforeDOCTYPESystemIdentifier);
                    t.currentDOCTYPETokenForceQuirks();
                    t.reconsume(.BogusDOCTYPE);
                },
            }
        },
        .DOCTYPESystemIdentifierDoubleQuoted => {
            switch (t.nextInputChar()) {
                '"' => t.changeTo(.AfterDOCTYPESystemIdentifier),
                0x00 => {
                    try t.parseError(.UnexpectedNullCharacter);
                    try t.appendDOCTYPESystemIdentifier(REPLACEMENT_CHARACTER);
                },
                '>' => {
                    try t.parseError(.AbruptDOCTYPESystemIdentifier);
                    t.currentDOCTYPETokenForceQuirks();
                    t.changeTo(.Data);
                    try t.emitDOCTYPE();
                },
                EOF => {
                    try t.parseError(.EOFInDOCTYPE);
                    t.currentDOCTYPETokenForceQuirks();
                    try t.emitDOCTYPE();
                    try t.emitEOF();
                },
                else => |c| try t.appendDOCTYPESystemIdentifier(c),
            }
        },
        // Nearly identical to DOCTYPESystemIdentifierDoubleQuoted
        .DOCTYPESystemIdentifierSingleQuoted => {
            switch (t.nextInputChar()) {
                '\'' => t.changeTo(.AfterDOCTYPESystemIdentifier),
                0x00 => {
                    try t.parseError(.UnexpectedNullCharacter);
                    try t.appendDOCTYPESystemIdentifier(REPLACEMENT_CHARACTER);
                },
                '>' => {
                    try t.parseError(.AbruptDOCTYPESystemIdentifier);
                    t.currentDOCTYPETokenForceQuirks();
                    t.changeTo(.Data);
                    try t.emitDOCTYPE();
                },
                EOF => {
                    try t.parseError(.EOFInDOCTYPE);
                    t.currentDOCTYPETokenForceQuirks();
                    try t.emitDOCTYPE();
                    try t.emitEOF();
                },
                else => |c| try t.appendDOCTYPESystemIdentifier(c),
            }
        },
        .AfterDOCTYPESystemIdentifier => {
            switch (t.nextInputChar()) {
                '\t', '\n', 0x0C, ' ' => {},
                '>' => {
                    t.changeTo(.Data);
                    try t.emitDOCTYPE();
                },
                EOF => {
                    try t.parseError(.EOFInDOCTYPE);
                    t.currentDOCTYPETokenForceQuirks();
                    try t.emitDOCTYPE();
                    try t.emitEOF();
                },
                else => {
                    try t.parseError(.UnexptecedCharacterAfterDOCTYPESystemIdentifier);
                    t.reconsume(.BogusDOCTYPE);
                },
            }
        },
        .BogusDOCTYPE => {
            switch (t.nextInputChar()) {
                '>' => {
                    t.changeTo(.Data);
                    try t.emitDOCTYPE();
                },
                0x00 => try t.parseError(.UnexpectedNullCharacter),
                EOF => {
                    try t.emitDOCTYPE();
                    try t.emitEOF();
                },
                else => {},
            }
        },
        .CDATASection => {
            switch (t.nextInputChar()) {
                ']' => t.changeTo(.CDATASectionBracket),
                EOF => {
                    try t.parseError(.EOFInCDATA);
                    try t.emitEOF();
                },
                else => |c| try t.emitCharacter(c),
            }
        },
        .CDATASectionBracket => {
            switch (t.nextInputChar()) {
                ']' => t.changeTo(.CDATASectionEnd),
                else => {
                    try t.emitCharacter(']');
                    t.reconsume(.CDATASection);
                },
            }
        },
        .CDATASectionEnd => {
            switch (t.nextInputChar()) {
                ']' => try t.emitCharacter(']'),
                '>' => t.changeTo(.Data),
                else => {
                    try t.emitString("]]");
                    t.reconsume(.CDATASection);
                },
            }
        },
        .CharacterReference => {
            t.clearTempBuffer();
            try t.appendTempBuffer('&');
            switch (t.nextInputChar()) {
                '0'...'9', 'A'...'Z', 'a'...'z' => {
                    t.reconsume(.NamedCharacterReference);
                },
                '#' => {
                    try t.appendTempBuffer('#');
                    t.changeTo(.NumericCharacterReference);
                },
                else => {
                    try t.flushCharacterReference();
                    t.reconsumeInReturnState();
                },
            }
        },
        .NamedCharacterReference => {
            try t.appendTempBuffer(t.peekInputChar());
            // TODO Rewrite this loop.
            while (t.tempBufferMatchesNamedCharacterPrefix()) |match_type| {
                switch (match_type) {
                    .Prefix => {
                        _ = t.nextInputChar();
                        try t.appendTempBuffer(t.peekInputChar());
                        continue;
                    },
                    .Exact => {
                        _ = t.nextInputChar();
                        const c = t.peekInputChar();
                        if (t.partOfAnAttribute() and t.tempBufferLast() != ';' and (c == '=' or (c >= '0' and c <= '9') or (c >= 'A' and c <= 'Z') or (c >= 'a' and c <= 'z'))) {
                            // Legacy reasons.
                            try t.flushCharacterReference();
                            t.switchToReturnState();
                        } else {
                            if (t.tempBufferLast() != ';') {
                                try t.parseError(.MissingSemicolonAfterCharacterReference);
                            }
                            // NOTE: This is slightly out of order from what the spec says. Will this cause problems?
                            const chars = t.translateNamedCharacterReference();
                            try t.flushCharacterReference();
                            t.clearTempBuffer();
                            try t.appendTempBuffer(chars.first);
                            if (chars.second) |s| try t.appendTempBuffer(s);
                            t.switchToReturnState();
                        }
                    },
                }
            } else {
                t.tempBufferDropLast();
                try t.flushCharacterReference();
                t.changeTo(.AmbiguousAmpersand);
            }
        },
        .AmbiguousAmpersand => {
            switch (t.nextInputChar()) {
                '0'...'9', 'A'...'Z', 'a'...'z' => |c| if (t.partOfAnAttribute()) try t.appendCurrentAttributeValue(c) else try t.emitCharacter(c),
                ';' => {
                    try t.parseError(.UnknownNamedCharacterReference);
                    t.reconsumeInReturnState();
                },
                else => t.reconsumeInReturnState(),
            }
        },
        .NumericCharacterReference => {
            t.character_reference_code = 0;
            switch (t.nextInputChar()) {
                'x', 'X' => |c| {
                    try t.appendTempBuffer(c);
                    t.changeTo(.HexadecimalCharacterReferenceStart);
                },
                else => t.reconsume(.DecimalCharacterReferenceStart),
            }
        },
        .HexadecimalCharacterReferenceStart => {
            switch (t.nextInputChar()) {
                '0'...'9', 'A'...'F', 'a'...'f' => t.reconsume(.HexadecimalCharacterReference),
                else => {
                    try t.parseError(.AbsenceOfDigitsInNumericCharacterReference);
                    try t.flushCharacterReference();
                    t.reconsume(t.return_state);
                },
            }
        },
        .DecimalCharacterReferenceStart => {
            switch (t.nextInputChar()) {
                '0'...'9' => t.reconsume(.DecimalCharacterReference),
                else => {
                    try t.parseError(.AbsenceOfDigitsInNumericCharacterReference);
                    try t.flushCharacterReference();
                    t.reconsumeInReturnState();
                },
            }
        },
        .HexadecimalCharacterReference => {
            switch (t.nextInputChar()) {
                // Use saturating arithmetic here?
                '0'...'9' => |c| t.character_reference_code = t.character_reference_code * 16 + decimalCharToNumber(c),
                'A'...'F' => |c| t.character_reference_code = t.character_reference_code * 16 + upperHexCharToNumber(c),
                'a'...'f' => |c| t.character_reference_code = t.character_reference_code * 16 + lowerHexCharToNumber(c),
                ';' => t.changeTo(.NumericCharacterReferenceEnd),
                else => {
                    try t.parseError(.MissingSemicolonAfterCharacterReference);
                    t.reconsume(.NumericCharacterReferenceEnd);
                },
            }
        },
        .DecimalCharacterReference => {
            switch (t.nextInputChar()) {
                // Use saturating arithmetic here?
                '0'...'9' => |c| t.character_reference_code = t.character_reference_code * 10 + decimalCharToNumber(c),
                ';' => t.changeTo(.NumericCharacterReferenceEnd),
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
                    try t.parseError(.ControlCharacterReference);
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
            // NOTE: This is slightly out of order from what the spec says. Will this cause problems?
            const char = codepointFromCharacterReferenceCode(t.character_reference_code);
            try t.flushCharacterReference();
            t.clearTempBuffer();
            try t.appendTempBuffer(char);
            t.switchToReturnState();
        },
    }
}

fn toLowercase(character: u21) u21 {
    return switch (character) {
        'A'...'Z' => character + 0x20,
        else => unreachable,
    };
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

fn decodeComptimeStringLen(comptime string: []const u8) usize {
    var i: usize = 0;
    var decoded_len: usize = 0;
    while (i < string.len) {
        i += std.unicode.utf8ByteSequenceLength(string[i]) catch unreachable;
        decoded_len += 1;
    }
    return decoded_len;
}

fn decodeComptimeString(comptime string: []const u8) [decodeComptimeStringLen(string)]u21 {
    var result: [decodeComptimeStringLen(string)]u21 = undefined;
    var decoded_it = std.unicode.Utf8View.initComptime(string).iterator();
    var i: usize = 0;
    while (decoded_it.nextCodepoint()) |codepoint| {
        result[i] = codepoint;
        i += 1;
    }
    return result;
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

fn codepointFromCharacterReferenceCode(character_reference_code: u32) u21 {
    return @intCast(u21, character_reference_code);
}

fn endTagName(t: *Tokenizer, current_input_char: u21, next_state: TokenizerState) !void {
    switch (current_input_char) {
        '\t', '\n', 0x0C, ' ' => {
            if (t.isAppropriateEndTag()) {
                t.changeTo(.BeforeAttributeName);
                return;
            }
        },
        '/' => {
            if (t.isAppropriateEndTag()) {
                t.changeTo(.SelfClosingStartTag);
                return;
            }
        },
        '>' => {
            if (t.isAppropriateEndTag()) {
                t.changeTo(.Data);
                try t.emitCurrentTag();
                return;
            }
        },
        // These 2 prongs don't switch state (this could be in a loop)
        'A'...'Z' => |c| {
            try t.appendCurrentTagName(toLowercase(c));
            try t.appendTempBuffer(c);
            return;
        },
        'a'...'z' => |c| {
            try t.appendCurrentTagName(c);
            try t.appendTempBuffer(c);
            return;
        },
        else => {},
    }

    try t.emitString("</");
    try t.emitTempBufferCharacters();
    t.reconsume(next_state);
}
