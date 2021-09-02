// Copyright (C) 2021 Chadwain Holness
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

const named_characters = @import("named-character-references");

const std = @import("std");
const assert = std.debug.assert;
const ArrayListUnmanaged = std.ArrayListUnmanaged;
const Allocator = std.mem.Allocator;

const EOF = '\u{5FFFE}';
const REPLACEMENT_CHARACTER = '\u{FFFD}';

pub const TokenizerState = enum {
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

    // TODO
    NonVoidHtmlElementStartTagWithTrailingSolidus,
};

pub const TokenDOCTYPE = struct {
    name: ?[]const u8,
    public_identifier: ?[]const u8,
    system_identifier: ?[]const u8,
    force_quirks: bool,
};

pub const AttributeSet = std.StringHashMapUnmanaged([]const u8);

pub const TokenStartTag = struct {
    name: []const u8,
    attributes: AttributeSet,
    self_closing: bool,
};

pub const TokenEndTag = struct {
    name: []const u8,
};

pub const TokenComment = struct {
    data: []const u8,
};

pub const TokenCharacter = struct {
    data: u21,
};

pub const TokenEOF = void;

pub const Token = union(enum) {
    doctype: TokenDOCTYPE,
    start_tag: TokenStartTag,
    end_tag: TokenEndTag,
    comment: TokenComment,
    character: TokenCharacter,
    eof: TokenEOF,

    fn deinit(self: *@This(), allocator: *Allocator) void {
        switch (self.*) {
            .doctype => |d| {
                if (d.name) |name| allocator.free(name);
                if (d.public_identifier) |public_identifier| allocator.free(public_identifier);
                if (d.system_identifier) |system_identifier| allocator.free(system_identifier);
            },
            .start_tag => |*t| {
                allocator.free(t.name);
                var attr_it = t.attributes.iterator();
                while (attr_it.next()) |entry| {
                    allocator.free(entry.key_ptr.*);
                    allocator.free(entry.value_ptr.*);
                }
                t.attributes.deinit(allocator);
            },
            .end_tag => |t| {
                allocator.free(t.name);
            },
            .comment => |c| {
                allocator.free(c.data);
            },
            .character => {},
            .eof => {},
        }
    }

    pub fn format(value: @This(), comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = fmt;
        _ = options;

        switch (value) {
            .doctype => |d| {
                try writer.writeAll("DOCTYPE (");
                if (d.name) |name| try writer.writeAll(name);
                if (d.public_identifier) |pi| try writer.writeAll(pi);
                if (d.system_identifier) |si| try writer.writeAll(si);
                try writer.writeAll(")");
            },
            .start_tag => |t| {
                try writer.writeAll("Start tag ");
                if (t.self_closing) try writer.writeAll("(self closing) ");
                try writer.writeAll("\"");
                try writer.writeAll(t.name);
                try writer.writeAll("\" [");
                var it = t.attributes.iterator();
                while (it.next()) |entry| {
                    try writer.writeAll("\"");
                    try writer.writeAll(entry.key_ptr.*);
                    try writer.writeAll("\": \"");
                    try writer.writeAll(entry.value_ptr.*);
                    try writer.writeAll("\"");
                }
                try writer.writeAll("]");
            },
            .end_tag => |t| {
                try writer.writeAll("End tag \"");
                try writer.writeAll(t.name);
                try writer.writeAll("\"");
            },
            .comment => |c| {
                try writer.writeAll("Comment (");
                try writer.writeAll(c.data);
                try writer.writeAll(")");
            },
            .character => |c| {
                try writer.writeAll("Character (");
                switch (c.data) {
                    '\n' => try writer.writeAll("<newline>"),
                    '\t' => try writer.writeAll("<tab>"),
                    else => {
                        var code_units: [4]u8 = undefined;
                        const len = std.unicode.utf8Encode(c.data, &code_units) catch unreachable;
                        try writer.writeAll(code_units[0..len]);
                    },
                }
                try writer.writeAll(")");
            },
            .eof => {
                try writer.writeAll("End of file");
            },
        }
    }
};

pub const Tokenizer = struct {
    state: TokenizerState = .Data,
    return_state: TokenizerState = undefined,
    character_reference_code: u32 = 0,
    current_tag_name: ArrayListUnmanaged(u8) = .{},
    current_tag_attributes: AttributeSet = .{},
    current_tag_self_closing: bool = false,
    current_tag_type: enum { Start, End } = undefined,
    last_start_tag_name: []u8 = &[_]u8{},
    current_attribute_name: ArrayListUnmanaged(u8) = .{},
    current_attribute_value: ArrayListUnmanaged(u8) = .{},
    current_attribute_value_result_loc: ?*[]const u8 = null,
    current_doctype_name: ArrayListUnmanaged(u8) = .{},
    current_doctype_public_identifier: ArrayListUnmanaged(u8) = .{},
    current_doctype_system_identifier: ArrayListUnmanaged(u8) = .{},
    current_doctype_force_quirks: bool = false,
    current_doctype_name_is_missing: bool = true,
    current_doctype_public_identifier_is_missing: bool = true,
    current_doctype_system_identifier_is_missing: bool = true,
    current_comment_data: ArrayListUnmanaged(u8) = .{},
    temp_buffer: ArrayListUnmanaged(u21) = .{},
    adjusted_current_node_is_in_html_namespace: bool = true,

    input: []const u21,
    position: usize = 0,
    reconsumed_input_char: u21 = undefined,
    should_reconsume: bool = false,
    reached_eof: bool = false,

    tokens: ArrayListUnmanaged(Token) = .{},
    parse_errors: ArrayListUnmanaged(ParseError) = .{},
    allocator: *Allocator,

    const Self = @This();

    pub fn deinit(self: *Self) void {
        self.current_tag_name.deinit(self.allocator);
        var attr_it = self.current_tag_attributes.iterator();
        while (attr_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.current_tag_attributes.deinit(self.allocator);
        self.allocator.free(self.last_start_tag_name);
        self.current_attribute_name.deinit(self.allocator);
        self.current_attribute_value.deinit(self.allocator);
        self.current_doctype_name.deinit(self.allocator);
        self.current_doctype_public_identifier.deinit(self.allocator);
        self.current_doctype_system_identifier.deinit(self.allocator);
        self.current_comment_data.deinit(self.allocator);
        self.temp_buffer.deinit(self.allocator);

        for (self.tokens.items) |*token| token.deinit(self.allocator);
        self.tokens.deinit(self.allocator);
        self.parse_errors.deinit(self.allocator);
    }

    /// Gets the next character from the input stream, given a position.
    /// It implements the "Preprocessing the input stream" step.
    fn advancePosition(input: []const u21, old_position: usize) struct { character: u21, new_position: usize } {
        if (old_position >= input.len) return .{ .character = EOF, .new_position = old_position };
        var character = input[old_position];
        var new_position = old_position + 1;
        if (character == '\r') {
            character = '\n';
            if (new_position < input.len and input[new_position] == '\n') {
                new_position += 1;
            }
        } else if (character == EOF) {
            character = REPLACEMENT_CHARACTER;
        }
        return .{ .character = character, .new_position = new_position };
    }

    fn nextInputChar(self: *Self) !u21 {
        if (self.should_reconsume) {
            self.should_reconsume = false;
            return self.reconsumed_input_char;
        } else {
            const next_char_info = advancePosition(self.input, self.position);
            self.reconsumed_input_char = next_char_info.character;
            self.position = next_char_info.new_position;
            if (next_char_info.character != EOF) {
                try self.checkInputCharacterForErrors(next_char_info.character);
            }
            return next_char_info.character;
        }
    }

    fn peekInputChar(self: *Self) u21 {
        if (self.should_reconsume) {
            return self.reconsumed_input_char;
        } else {
            return advancePosition(self.input, self.position).character;
        }
    }

    fn consumeN(self: *Self, count: usize) !void {
        var new_position = self.position;
        var i = count;
        while (i > 0) : (i -= 1) {
            const next_char_info = advancePosition(self.input, new_position);
            new_position = next_char_info.new_position;
            try self.checkInputCharacterForErrors(next_char_info.character);
        }
        self.position = new_position;
    }

    fn nextFewCharsEql(self: *Self, comptime string: []const u8) bool {
        var position = self.position;
        for (decodeComptimeString(string)) |character| {
            const next_char_info = advancePosition(self.input, position);
            if (next_char_info.character == EOF or next_char_info.character != character) return false;
            position = next_char_info.new_position;
        }
        return true;
    }

    fn nextFewCharsCaseInsensitiveEql(self: *Self, comptime string: []const u8) bool {
        var position = self.position;
        for (decodeComptimeString(string)) |character| {
            const next_char_info = advancePosition(self.input, position);
            if (next_char_info.character == EOF or !caseInsensitiveEql(next_char_info.character, character)) return false;
            position = next_char_info.new_position;
        }
        return true;
    }

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
            0x01...0x08, 0x0B, 0x0D...0x1F, 0x7F...0x9F => try self.parseError(.ControlCharacterInInputStream),
            else => {},
        }
    }

    pub fn changeTo(self: *Self, new_state: TokenizerState) void {
        self.state = new_state;
    }

    fn toCharacterReferenceState(self: *Self, return_state: TokenizerState) void {
        self.state = .CharacterReference;
        self.return_state = return_state;
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

    fn reconsume(self: *Self, new_state: TokenizerState) void {
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

        self.current_doctype_name_is_missing = true;
        self.current_doctype_public_identifier_is_missing = true;
        self.current_doctype_system_identifier_is_missing = true;
        self.current_doctype_force_quirks = false;
    }

    fn emitComment(self: *Self) !void {
        const data = self.current_comment_data.toOwnedSlice(self.allocator);
        errdefer self.allocator.free(data);
        try self.tokens.append(self.allocator, Token{ .comment = .{ .data = data } });
    }

    fn emitEOF(self: *Self) !void {
        self.reached_eof = true;
        try self.tokens.append(self.allocator, Token{ .eof = .{} });
    }

    fn emitCurrentTag(self: *Self) !void {
        const name = self.current_tag_name.toOwnedSlice(self.allocator);
        errdefer self.allocator.free(name);
        switch (self.current_tag_type) {
            .Start => {
                self.last_start_tag_name = try self.allocator.realloc(self.last_start_tag_name, name.len);
                std.mem.copy(u8, self.last_start_tag_name, name);
                try self.tokens.append(self.allocator, Token{ .start_tag = .{
                    .name = name,
                    .attributes = self.current_tag_attributes,
                    .self_closing = self.current_tag_self_closing,
                } });
            },
            .End => {
                if (self.current_tag_attributes.count() > 0) {
                    self.current_tag_attributes.deinit(self.allocator);
                    try self.parseError(.EndTagWithAttributes);
                }
                if (self.current_tag_self_closing) {
                    try self.parseError(.EndTagWithTrailingSolidus);
                }
                try self.tokens.append(self.allocator, Token{ .end_tag = .{
                    .name = name,
                } });
            },
        }

        self.current_tag_self_closing = false;
        self.current_tag_attributes = .{};
        self.current_tag_type = undefined;
    }

    fn finishAttributeName(self: *Self) !void {
        const name = self.current_attribute_name.toOwnedSlice(self.allocator);
        errdefer self.allocator.free(name);
        const get_result = try self.current_tag_attributes.getOrPut(self.allocator, name);
        if (get_result.found_existing) {
            self.allocator.free(name);
            self.current_attribute_value_result_loc = null;
            try self.parseError(.DuplicateAttribute);
        } else {
            get_result.value_ptr.* = "";
            self.current_attribute_value_result_loc = get_result.value_ptr;
        }
    }

    fn finishAttributeValue(self: *Self) void {
        const value = self.current_attribute_value.toOwnedSlice(self.allocator);
        errdefer self.allocator.free(value);
        if (self.current_attribute_value_result_loc) |ptr| {
            ptr.* = value;
            self.current_attribute_value_result_loc = null;
        } else {
            self.allocator.free(value);
        }
    }

    fn isAppropriateEndTag(self: *Self) bool {
        // Looking at the tokenizer logic, it seems that is no way to reach this function without current_tag_name
        // having at least 1 ASCII character in it. So we don't have to worry about making sure it has non-zero length.
        //
        // Notice that this gets called from the states that end in "TagName", and that those states
        // can only be reached by reconsuming an ASCII character from an associated "TagOpen" state.
        return std.mem.eql(u8, self.last_start_tag_name, self.current_tag_name.items);
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
        _ = self;
        // Nothing to do.
    }

    fn createDOCTYPEToken(self: *Self) void {
        _ = self;
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
        _ = self;
        // Nothing to do.
    }

    fn appendCurrentTagName(self: *Self, character: u21) !void {
        var code_units: [4]u8 = undefined;
        const len = try std.unicode.utf8Encode(character, &code_units);
        try self.current_tag_name.appendSlice(self.allocator, code_units[0..len]);
    }

    fn resetCurrentTagName(self: *Self) void {
        self.current_tag_name.deinit(self.allocator);
        self.current_tag_name = .{};
    }

    fn appendCurrentAttributeName(self: *Self, character: u21) !void {
        var code_units: [4]u8 = undefined;
        const len = try std.unicode.utf8Encode(character, &code_units);
        try self.current_attribute_name.appendSlice(self.allocator, code_units[0..len]);
    }

    fn appendCurrentAttributeValue(self: *Self, character: u21) !void {
        var code_units: [4]u8 = undefined;
        const len = try std.unicode.utf8Encode(character, &code_units);
        try self.current_attribute_value.appendSlice(self.allocator, code_units[0..len]);
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
        self.temp_buffer.shrinkRetainingCapacity(0);
    }

    fn tempBufferEql(self: *Self, comptime string: []const u8) bool {
        return std.mem.eql(u21, self.temp_buffer.items, &decodeComptimeString(string));
    }

    fn tempBufferLast(self: *Self) u21 {
        return self.temp_buffer.items[self.temp_buffer.items.len - 1];
    }

    fn flushCharacterReference(self: *Self) !void {
        if (self.isPartOfAnAttribute()) {
            for (self.temp_buffer.items) |character| {
                var code_units: [4]u8 = undefined;
                const len = try std.unicode.utf8Encode(character, &code_units);
                try self.current_attribute_value.appendSlice(self.allocator, code_units[0..len]);
            }
        } else {
            for (self.temp_buffer.items) |character| {
                try self.emitCharacter(character);
            }
        }
    }

    fn findNamedCharacterReference(self: *Self) !named_characters.Value {
        var node = named_characters.root;
        var next_character = self.peekInputChar();
        var next_position = advancePosition(self.input, self.position).new_position;
        var character_reference_saved_position = self.position;
        var character_reference_consumed_codepoints_count: usize = 1;
        var last_matched_named_character_value = named_characters.Value{};
        while (true) {
            const key_index = node.find(next_character) orelse break;
            try self.appendTempBuffer(next_character);

            if (node.child(key_index)) |c_node| {
                const new_value = node.value(key_index);
                if (new_value[0] != null) {
                    // Partial match found.
                    character_reference_saved_position = next_position;
                    character_reference_consumed_codepoints_count = self.temp_buffer.items.len;
                    last_matched_named_character_value = new_value;
                }
                node = c_node;
            } else {
                // Complete match found.
                character_reference_saved_position = next_position;
                character_reference_consumed_codepoints_count = self.temp_buffer.items.len;
                last_matched_named_character_value = node.value(key_index);
                break;
            }

            const next_char_info = advancePosition(self.input, next_position);
            next_character = next_char_info.character;
            next_position = next_char_info.new_position;
        }

        self.position = character_reference_saved_position;
        self.temp_buffer.shrinkRetainingCapacity(character_reference_consumed_codepoints_count);
        for (self.temp_buffer.items[1..]) |c| {
            // The 0th character is an ampersand '&'.
            try self.checkInputCharacterForErrors(c);
        }
        return last_matched_named_character_value;
    }

    fn adjustedCurrentNodeNotInHtmlNamepsace(self: *Self) bool {
        // TODO
        return !self.adjusted_current_node_is_in_html_namespace;
    }

    pub fn run(t: *Self) !void {
        switch (t.state) {
            .Data => {
                switch (try t.nextInputChar()) {
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
                switch (try t.nextInputChar()) {
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
                switch (try t.nextInputChar()) {
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
                switch (try t.nextInputChar()) {
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
                switch (try t.nextInputChar()) {
                    0x00 => {
                        try t.parseError(.UnexpectedNullCharacter);
                        try t.emitCharacter(REPLACEMENT_CHARACTER);
                    },
                    EOF => try t.emitEOF(),
                    else => |c| try t.emitCharacter(c),
                }
            },
            .TagOpen => {
                switch (try t.nextInputChar()) {
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
                switch (try t.nextInputChar()) {
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
                switch (try t.nextInputChar()) {
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
                switch (try t.nextInputChar()) {
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
                switch (try t.nextInputChar()) {
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
                const current_input_char = try t.nextInputChar();
                try endTagName(t, current_input_char, .RCDATA);
            },
            .RAWTEXTLessThanSign => {
                switch (try t.nextInputChar()) {
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
                switch (try t.nextInputChar()) {
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
                const current_input_char = try t.nextInputChar();
                try endTagName(t, current_input_char, .RAWTEXT);
            },
            .ScriptDataLessThanSign => {
                switch (try t.nextInputChar()) {
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
                switch (try t.nextInputChar()) {
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
                const current_input_char = try t.nextInputChar();
                try endTagName(t, current_input_char, .ScriptData);
            },
            .ScriptDataEscapeStart => {
                switch (try t.nextInputChar()) {
                    '-' => {
                        t.changeTo(.ScriptDataEscapeStartDash);
                        try t.emitCharacter('-');
                    },
                    else => t.reconsume(.ScriptData),
                }
            },
            .ScriptDataEscapeStartDash => {
                switch (try t.nextInputChar()) {
                    '-' => {
                        t.changeTo(.ScriptDataEscapedDashDash);
                        try t.emitCharacter('-');
                    },
                    else => t.reconsume(.ScriptData),
                }
            },
            .ScriptDataEscaped => {
                switch (try t.nextInputChar()) {
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
                switch (try t.nextInputChar()) {
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
                switch (try t.nextInputChar()) {
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
                switch (try t.nextInputChar()) {
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
                switch (try t.nextInputChar()) {
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
                const current_input_char = try t.nextInputChar();
                try endTagName(t, current_input_char, .ScriptDataEscaped);
            },
            .ScriptDataDoubleEscapeStart => {
                switch (try t.nextInputChar()) {
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
                switch (try t.nextInputChar()) {
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
                switch (try t.nextInputChar()) {
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
                switch (try t.nextInputChar()) {
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
                switch (try t.nextInputChar()) {
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
                switch (try t.nextInputChar()) {
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
                switch (try t.nextInputChar()) {
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
                switch (try t.nextInputChar()) {
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
                switch (try t.nextInputChar()) {
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
                switch (try t.nextInputChar()) {
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
                switch (try t.nextInputChar()) {
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
                switch (try t.nextInputChar()) {
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
                switch (try t.nextInputChar()) {
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
                switch (try t.nextInputChar()) {
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
                switch (try t.nextInputChar()) {
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
                switch (try t.nextInputChar()) {
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
                    try t.consumeN(2);
                    t.createCommentToken();
                    t.changeTo(.CommentStart);
                } else if (t.nextFewCharsCaseInsensitiveEql("DOCTYPE")) {
                    try t.consumeN(7);
                    t.changeTo(.DOCTYPE);
                } else if (t.nextFewCharsEql("[CDATA[")) {
                    try t.consumeN(7);
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
                switch (try t.nextInputChar()) {
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
                switch (try t.nextInputChar()) {
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
                switch (try t.nextInputChar()) {
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
                switch (try t.nextInputChar()) {
                    '!' => {
                        try t.appendComment('!');
                        t.changeTo(.CommentLessThanSignBang);
                    },
                    '<' => try t.appendComment('<'),
                    else => t.reconsume(.Comment),
                }
            },
            .CommentLessThanSignBang => {
                switch (try t.nextInputChar()) {
                    '-' => t.changeTo(.CommentLessThanSignBangDash),
                    else => t.reconsume(.Comment),
                }
            },
            .CommentLessThanSignBangDash => {
                switch (try t.nextInputChar()) {
                    '-' => t.changeTo(.CommentLessThanSignBangDashDash),
                    else => t.reconsume(.CommentEndDash),
                }
            },
            .CommentLessThanSignBangDashDash => {
                switch (try t.nextInputChar()) {
                    '>', EOF => t.reconsume(.CommentEnd),
                    else => {
                        try t.parseError(.NestedComment);
                        t.reconsume(.CommentEnd);
                    },
                }
            },
            .CommentEndDash => {
                switch (try t.nextInputChar()) {
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
                switch (try t.nextInputChar()) {
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
                switch (try t.nextInputChar()) {
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
                switch (try t.nextInputChar()) {
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
                switch (try t.nextInputChar()) {
                    '\t', '\n', 0x0C, ' ' => {},
                    'A'...'Z' => |c| {
                        t.createDOCTYPEToken();
                        t.markCurrentDOCTYPENameNotMissing();
                        try t.appendDOCTYPEName(toLowercase(c));
                        t.changeTo(.DOCTYPEName);
                    },
                    0x00 => {
                        try t.parseError(.UnexpectedNullCharacter);
                        t.createDOCTYPEToken();
                        t.markCurrentDOCTYPENameNotMissing();
                        try t.appendDOCTYPEName(REPLACEMENT_CHARACTER);
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
                switch (try t.nextInputChar()) {
                    '\t', '\n', 0x0C, ' ' => t.changeTo(.AfterDOCTYPEName),
                    '>' => {
                        t.changeTo(.Data);
                        try t.emitDOCTYPE();
                    },
                    'A'...'Z' => |c| try t.appendDOCTYPEName(toLowercase(c)),
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
                switch (try t.nextInputChar()) {
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
                            try t.consumeN(5);
                            t.changeTo(.AfterDOCTYPEPublicKeyword);
                        } else if (caseInsensitiveEql(c, 'S') and t.nextFewCharsCaseInsensitiveEql("YSTEM")) {
                            try t.consumeN(5);
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
                switch (try t.nextInputChar()) {
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
                switch (try t.nextInputChar()) {
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
                switch (try t.nextInputChar()) {
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
                switch (try t.nextInputChar()) {
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
                switch (try t.nextInputChar()) {
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
                switch (try t.nextInputChar()) {
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
                        try t.emitEOF();
                    },
                    else => {
                        try t.parseError(.MissingQuoteBeforeDOCTYPESystemIdentifier);
                        t.currentDOCTYPETokenForceQuirks();
                        t.reconsume(.BogusDOCTYPE);
                    },
                }
            },
            .AfterDOCTYPESystemKeyword => {
                switch (try t.nextInputChar()) {
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
                switch (try t.nextInputChar()) {
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
                switch (try t.nextInputChar()) {
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
                switch (try t.nextInputChar()) {
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
                switch (try t.nextInputChar()) {
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
                        try t.parseError(.UnexpectedCharacterAfterDOCTYPESystemIdentifier);
                        t.reconsume(.BogusDOCTYPE);
                    },
                }
            },
            .BogusDOCTYPE => {
                switch (try t.nextInputChar()) {
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
                switch (try t.nextInputChar()) {
                    ']' => t.changeTo(.CDATASectionBracket),
                    EOF => {
                        try t.parseError(.EOFInCDATA);
                        try t.emitEOF();
                    },
                    else => |c| try t.emitCharacter(c),
                }
            },
            .CDATASectionBracket => {
                switch (try t.nextInputChar()) {
                    ']' => t.changeTo(.CDATASectionEnd),
                    else => {
                        try t.emitCharacter(']');
                        t.reconsume(.CDATASection);
                    },
                }
            },
            .CDATASectionEnd => {
                switch (try t.nextInputChar()) {
                    ']' => try t.emitCharacter(']'),
                    '>' => t.changeTo(.Data),
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
                switch (t.peekInputChar()) {
                    '0'...'9', 'A'...'Z', 'a'...'z' => {
                        t.changeTo(.NamedCharacterReference);
                    },
                    '#' => {
                        _ = try t.nextInputChar();
                        try t.appendTempBuffer('#');
                        t.changeTo(.NumericCharacterReference);
                    },
                    else => {
                        _ = try t.nextInputChar();
                        try t.flushCharacterReference();
                        t.reconsumeInReturnState();
                    },
                }
            },
            .NamedCharacterReference => {
                const chars = try t.findNamedCharacterReference();
                const match_found = chars[0] != null;
                if (match_found) {
                    const historical_reasons = t.isPartOfAnAttribute() and t.tempBufferLast() != ';' and switch (t.peekInputChar()) {
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
                    t.changeTo(.AmbiguousAmpersand);
                }
            },
            .AmbiguousAmpersand => {
                switch (try t.nextInputChar()) {
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
                switch (try t.nextInputChar()) {
                    'x', 'X' => |c| {
                        try t.appendTempBuffer(c);
                        t.changeTo(.HexadecimalCharacterReferenceStart);
                    },
                    else => t.reconsume(.DecimalCharacterReferenceStart),
                }
            },
            .HexadecimalCharacterReferenceStart => {
                switch (try t.nextInputChar()) {
                    '0'...'9', 'A'...'F', 'a'...'f' => t.reconsume(.HexadecimalCharacterReference),
                    else => {
                        try t.parseError(.AbsenceOfDigitsInNumericCharacterReference);
                        try t.flushCharacterReference();
                        t.reconsume(t.return_state);
                    },
                }
            },
            .DecimalCharacterReferenceStart => {
                switch (try t.nextInputChar()) {
                    '0'...'9' => t.reconsume(.DecimalCharacterReference),
                    else => {
                        try t.parseError(.AbsenceOfDigitsInNumericCharacterReference);
                        try t.flushCharacterReference();
                        t.reconsumeInReturnState();
                    },
                }
            },
            .HexadecimalCharacterReference => {
                switch (try t.nextInputChar()) {
                    '0'...'9' => |c| t.character_reference_code = characterReferenceCodeSaturatedMultiplyAdd(t.character_reference_code, 16, decimalCharToNumber(c)),
                    'A'...'F' => |c| t.character_reference_code = characterReferenceCodeSaturatedMultiplyAdd(t.character_reference_code, 16, upperHexCharToNumber(c)),
                    'a'...'f' => |c| t.character_reference_code = characterReferenceCodeSaturatedMultiplyAdd(t.character_reference_code, 16, lowerHexCharToNumber(c)),
                    ';' => t.changeTo(.NumericCharacterReferenceEnd),
                    else => {
                        try t.parseError(.MissingSemicolonAfterCharacterReference);
                        t.reconsume(.NumericCharacterReferenceEnd);
                    },
                }
            },
            .DecimalCharacterReference => {
                switch (try t.nextInputChar()) {
                    '0'...'9' => |c| t.character_reference_code = characterReferenceCodeSaturatedMultiplyAdd(t.character_reference_code, 10, decimalCharToNumber(c)),
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
                const char = codepointFromCharacterReferenceCode(t.character_reference_code);
                t.clearTempBuffer();
                try t.appendTempBuffer(char);
                try t.flushCharacterReference();
                t.switchToReturnState();
            },
        }
    }
};

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
    if (result.len == 0) return result;
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

fn characterReferenceCodeSaturatedMultiplyAdd(character_reference_code: u32, mul: u32, add: u32) u32 {
    var overflow = false;
    var result: u32 = undefined;
    overflow = overflow or @mulWithOverflow(u32, character_reference_code, mul, &result);
    overflow = overflow or @addWithOverflow(u32, result, add, &result);
    if (overflow) result = std.math.maxInt(u32);
    return result;
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

    t.resetCurrentTagName();
    try t.emitString("</");
    try t.emitTempBufferCharacters();
    t.reconsume(next_state);
}
