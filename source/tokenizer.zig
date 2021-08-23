const std = @import("std");
const ArrayListUnmanaged = std.ArrayListUnmanaged;

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

const ParserError = enum {
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

const Tokenizer = struct {
    input: []const u8,
    position: usize,
    prev_position: usize,
    token_tags: ArrayListUnmanaged(TokenTag),
    token_data: ArrayListUnmanaged(u8),
    parser_errors: ArrayListUnmanaged(std.meta.Tuple(ParserError, usize)),
    allocator: *Allocator,

    fn nextInputChar(self: *Self) ?u8 {
        self.prev_position = self.position;
        if (self.position >= self.input.len) return null;
        defer self.position += 1;
        return self.input[self.position];
    }

    fn parseError(self: *Self, tag: ParserError) !void {
        try self.parser_errors.append(self.allocator, .{ tag, self.prev_position });
    }
};

pub fn tokenize(t: *Tokenizer) !void {
    var state: TokenizerState = .Data;
    var return_state: TokenizerState = undefined;
    switch (state) {
        .Data => {
            switch (t.nextInputChar()) {
                '&' => {
                    return_state = .Data;
                    state = .CharacterReference;
                },
                '<' => state = .TagOpen,
                '\x00' => |c| {
                    try t.parseError(.UnexpectedNullCharacter);
                    emitToken(.Character, &.{c});
                },
                null => emitToken(.EOF, ""),
                else => |c| emitToken(.Character, &.{c}),
            }
        },
        .RCDATA => {
            switch (t.nextInputChar()) {
                '&' => {
                    return_state = .RCDATA;
                    state = .CharacterReference;
                },
                '<' => state = .RCDATALessThanSign,
                '\x00' => {
                    try t.parser_errors.append(.UnexpectedNullCharacter);
                    emitToken(.Character, &.{'\u{FFFD}'});
                },
                null => emitToken(.EOF, ""),
                else => |c| emitToken(.Character, &.{c}),
            }
        },
        .RAWTEXT => {
            switch (t.nextInputChar()) {
                '<' => state = .RAWTEXTLessThanSign,
                '\x00' => {
                    try t.parseError(.UnexpectedNullCharacter);
                    emitToken(.Character, &.{'\u{FFFD}'});
                },
                null => emitToken(.EOF, ""),
                else => |c| emitToken(.Character, &.{c}),
            }
        },
        .ScriptData => {
            switch (t.nextInputChar()) {
                '<' => state = .ScriptDataLessThanSign,
                '\x00' => {
                    try t.parseError(.UnexpectedNullCharacter);
                    emitToken(.Character, &.{'\u{FFFD}'});
                },
                null => emitToken(.EOF, ""),
                else => |c| emitToken(.Character, &.{c}),
            }
        },
        .PLAINTEXT => {
            switch (t.nextInputChar()) {
                '\x00' => {
                    try t.parseError(.UnexpectedNullCharacter);
                    emitToken(.Character, &.{'\u{FFFD}'});
                },
                null => emitToken(.EOF, ""),
                else => |c| emitToken(.Character, &.{c}),
            }
        },
        .TagOpen => {
            switch (t.nextInputChar()) {
                '!' => state = .MarkupDeclarationOpen,
                '/' => state = .EndTagOpen,
                'A'...'Z', 'a'...'z' => {
                    var token = createStartTagToken();
                    token.name = "";
                    t.reconsume();
                    state = .TagName;
                },
                '?' => {
                    try t.parseError(.UnexpectedQuestionMarkInsteadOfTagName);
                    var token = createCommentToken();
                    token.data = "";
                    t.reconsume();
                    state = .BogusComment;
                },
                null => {
                    try t.parseError(.EOFBeforeTagName);
                    emitToken(.Character, &.{'<'});
                    emitToken(.EOF, "");
                },
                else => {
                    try t.parseError(.InvalidFirstCharacterOfTagName);
                    emitToken(.Character, &.{'<'});
                    t.reconsume();
                    state = .Data;
                },
            }
        },
        .EndTagOpen => {
            switch (t.nextInputChar()) {
                'A'...'Z', 'a'...'z' => {
                    var token = createEndTagToken();
                    token.name = "";
                    t.reconsume();
                    state = .TagName;
                },
                '>' => {
                    try t.parseError(.MissingEndTagName);
                    state = .Data;
                },
                null => {
                    try t.parseError(.EOFBeforeTagName);
                    emitToken(.Character, &.{'<'});
                    emitToken(.Character, &.{'/'});
                    emitToken(.EOF, "");
                },
                else => {
                    try t.parseError(.InvalidFirstCharacterOfTagName);
                    var token = createCommentToken();
                    token.data = "";
                    t.reconsume();
                    state = .BogusComment;
                },
            }
        },
        .TagName => {
            switch (t.nextInputChar()) {
                '\t', '\n', '\u{000C}', ' ' => state = .BeforeAttributeName,
                '/' => state = .SelfClosingStartTag,
                '>' => {
                    state = .Data;
                    emitCurrentTagToken();
                },
                'A'...'Z' => |c| appendTagName(toLowercase(c)),
                '\x00' => {
                    try t.parseError(.UnexpectedNullCharacter);
                    appendTagName('\u{FFFD}');
                },
                null => {
                    try t.parseError(.EOFInTag);
                    emitToken(.EOF, "");
                },
                else => |c| appendTagName(c),
            }
        },
        .RCDATALessThanSign => {
            switch (t.nextInputChar()) {
                '/' => {
                    clearTempBuffer();
                    state = .RCDATAEndTagOpen;
                },
                else => {
                    emitToken(.Character, &.{'<'});
                    t.reconsume();
                    state = .RCDATA;
                },
            }
        },
        .RCDATAEndTagOpen => {
            switch (t.nextInputChar()) {
                'A'...'Z', 'a'...'z' => {
                    var token = createEndTagToken();
                    token.name = "";
                    t.reconsume();
                    state = .RCDATAEndTagName;
                },
                else => {
                    emitToken(.Character, &.{'<'});
                    emitToken(.Character, &.{'/'});
                    t.reconsume();
                    state = .RCDATA;
                },
            }
        },
        .RCDATAEndTagName => {
            const current_input_char = t.nextInputChar();
            endTagName(t, current_input_char, .RCDATA);
        },
        .RAWTEXTLessThanSign => {
            switch (t.nextInputChar()) {
                '/' => {
                    t.clearTempBuffer();
                    state = .RAWTEXTEndTagOpen;
                },
                else => {
                    emitToken(.Character, "<");
                    t.reconsume();
                    state = .RAWTEXT;
                },
            }
        },
        .RAWTEXTEndTagOpen => {
            switch (t.nextInputChar()) {
                'A'...'Z', 'a'...'z' => {
                    var token = createEndTagToken();
                    token.name = "";
                    t.reconsume();
                    state = .RAWTEXTEndTagName;
                },
                else => {
                    emitToken(.Character, "<");
                    emitToken(.Character, "/");
                    t.reconsume();
                    state = .RAWTEXT;
                },
            }
        },
        .RAWTEXTEndTagName => {
            const current_input_char = t.nextInputChar();
            endTagName(t, current_input_char, .RAWTEXT);
        },
        .ScriptDataLessThanSign => {
            switch (t.nextInputChar()) {
                '/' => {
                    t.clearTempBuffer();
                    state = .ScriptDataEndTagOpen;
                },
                '!' => {
                    state = .ScriptDataEscapeStart;
                    emitToken(.Character, "<");
                    emitToken(.Character, "!");
                },
                else => {
                    emitToken(.Character, "<");
                    t.reconsume();
                    state = .ScriptData;
                },
            }
        },
        .ScriptDataEndTagOpen => {
            switch (t.nextInputChar()) {
                'A'...'Z', 'a'...'z' => {
                    var token = createEndTagToken();
                    token.name = "";
                    t.reconsume();
                    state = .ScriptDataEndTagName;
                },
                else => {
                    emitToken(.Character, "<");
                    emitToken(.Character, "/");
                    t.reconsume();
                    state = .ScriptData;
                },
            }
        },
        .ScriptDataEndTagName => {
            const current_input_char = t.nextInputChar();
            endTagName(t, current_input_char, .ScriptData);
        },
        .ScriptDataEscapeStart => {
            switch (t.nextInputChar()) {
                '-' => {
                    state = .ScriptDataEscapeStartDash;
                    emitToken(.Character, "-");
                },
                else => {
                    t.reconsume();
                    state = .ScriptData;
                },
            }
        },
        .ScriptDataEscapeStartDash => {
            switch (t.nextInputChar()) {
                '-' => {
                    state = .ScriptDataEscapedDashDash;
                    emitToken(.Character, "-");
                },
                else => {
                    t.reconsume();
                    state = .ScriptData;
                },
            }
        },
        .ScriptDataEscaped => {
            switch (t.nextInputChar()) {
                '-' => {
                    state = .ScriptDataEscapedDash;
                    emitToken(.Character, "-");
                },
                '<' => state = .ScriptDataEscapedLessThanSign,
                '\x00' => {
                    try t.parseError(.UnexpectedNullCharacter);
                    emitToken(.Character, "\u{FFFD}");
                },
                null => {
                    try t.parseError(.EOFInScriptHtmlCommentLikeText);
                    emitToken(.EOF, "");
                },
                else => |c| emitToken(.Character, &.{c}),
            }
        },
        .ScriptDataEscapedDash => {
            switch (t.nextInputChar()) {
                '-' => {
                    state = .ScriptDataEscapedDashDash;
                    emitCharacter('-');
                },
                '<' => t.state = .ScriptDataEscapedLessThanSign,
                '\x00' => {
                    try t.parseError(.UnexpectedNullCharacter);
                    state = .ScriptDataEscaped;
                    emitReplacementCharacter();
                },
                null => {
                    try t.parseError(.EOFInScriptHtmlCommentLikeText);
                    emitEOF();
                },
                else => |c| {
                    state = .ScriptDataEscaped;
                    emitCharacter(c);
                },
            }
        },
        .ScriptDataEscapedDashDash => {
            switch (t.nextInputChar()) {
                '-' => emitCharacter('-'),
                '<' => t.state = .ScriptDataEscapedLessThanSign,
                '>' => {
                    t.state = .ScriptData;
                    emitCharacter('>');
                },
                '\x00' => {
                    try t.parseError(.UnexpectedNullCharacter);
                    t.state = .ScriptDataEscaped;
                    emitCharacter(REPLACEMENT_CHARACTER);
                },
                null => {
                    try t.parseError(.EOFInScriptHtmlCommentLikeText);
                    emitEOF();
                },
                else => |c| {
                    t.state = .ScriptDataEscaped;
                    emitCharacter(c);
                },
            }
        },
        .ScriptDataEscapedLessThanSign => {
            switch (t.nextInputChar()) {
                '/' => {
                    t.clearTempBuffer();
                    t.state = .ScriptDataEscapedEndTagOpen;
                },
                'A'...'Z', 'a'...'z' => {
                    t.clearTempBuffer();
                    emitCharacter('<');
                    t.reconsume();
                    t.state = .ScriptDataDoubleEscapeStart;
                },
                else => {
                    emitCharacter('<');
                    t.reconsume();
                    t.state = .ScriptDataEscaped;
                },
            }
        },
        .ScriptDataEscapedEndTagOpen => {
            switch (t.nextInputChar()) {
                'A'...'Z', 'a'...'z' => {
                    var token = createEndTagToken();
                    token.name = "";
                    t.reconsume();
                    t.state = .ScriptDataEscapedEndTagName;
                },
                else => {
                    emitCharacter('<');
                    emitCharacter('/');
                    t.reconsume();
                    t.state = .ScriptDataEscaped;
                },
            }
        },
        .ScriptDataEscapedEndTagName => {
            const current_input_char = t.nextInputChar();
            endTagName(t, current_input_char, .ScriptDataEscaped);
        },
        .ScriptDataDoubleEscapeStart => {
            switch (t.nextInputChar()) {
                '\t', '\n', 0x0C, ' ', '/', '>' => |c| {
                    t.state = if (t.tempBuffer.eql("script")) .ScriptDataDoubleEscaped else .ScriptDataEscaped;
                    emitCharacter(c);
                },
                'A'...'Z' => |c| {
                    t.tempBuffer.append(toLowercase(c));
                    emitCharacter(c);
                },
                'a'...'z' => |c| {
                    t.tempBuffer.append(c);
                    emitCharacter(c);
                },
                else => {
                    t.reconsume();
                    t.state = .ScriptDataEscaped;
                },
            }
        },
        .ScriptDataDoubleEscaped => {
            switch (t.nextInputChar()) {
                '-' => {
                    t.state = .ScriptDataDoubleEscapedDash;
                    emitCharacter('-');
                },
                '<' => {
                    t.state = .ScriptDataDoubleEscapedLessThanSign;
                    emitCharacter('<');
                },
                0x00 => {
                    try t.parseError(.UnexpectedNullCharacter);
                    emitCharacter(REPLACEMENT_CHARACTER);
                },
                null => {
                    try t.parseError(.EOFInScriptHtmlCommentLikeText);
                    emitEOF();
                },
                else => |c| emitCharacter(c),
            }
        },
        .ScriptDataDoubleEscapedDash => {
            switch (t.nextInputChar()) {
                '-' => {
                    t.state = .ScriptDataDoubleEscapedDashDash;
                    emitCharacter('-');
                },
                '<' => {
                    t.state = .ScriptDataDoubleEscapedLessThanSign;
                    emitCharacter('<');
                },
                0x00 => {
                    try t.parseError(.UnexpectedNullCharacter);
                    t.state = .ScriptDataDoubleEscaped;
                    emitCharacter(REPLACEMENT_CHARACTER);
                },
                null => {
                    try t.parseError(.EOFInScriptHtmlCommentLikeText);
                    emitEOF();
                },
                else => |c| {
                    t.state = .ScriptDataDoubleEscaped;
                    emitCharacter(c);
                },
            }
        },
        .ScriptDataDoubleEscapedDashDash => {
            switch (t.nextInputChar()) {
                '-' => emitCharacter('-'),
                '<' => {
                    t.state = .ScriptDataDoubleEscapedLessThanSign;
                    emitCharacter('<');
                },
                '>' => {
                    t.state = .ScriptData;
                    emitCharacter('>');
                },
                0x00 => {
                    try t.parseError(.UnexpectedNullCharacter);
                    state = .ScriptDataDoubleEscaped;
                    emitCharacter(REPLACEMENT_CHARACTER);
                },
                null => {
                    try t.parseError(.EOFInScriptHtmlCommentLikeText);
                    emitEOF();
                },
                else => |c| {
                    t.state = .ScriptDataDoubleEscaped;
                    emitCharacter(c);
                },
            }
        },
        .ScriptDataDoubleEscapedLessThanSign => {
            switch (t.nextInputChar()) {
                '/' => {
                    t.clearTempBuffer();
                    t.state = .ScriptDataDoubleEscapeEnd;
                    emitCharacter('/');
                },
                else => {
                    t.reconsume();
                    t.state = .ScriptDataDoubleEscaped;
                },
            }
        },
        // Nearly identical to ScriptDataDoubleEscapeStart.
        .ScriptDataDoubleEscapeEnd => {
            switch (t.nextInputChar()) {
                '\t', '\n', 0x0C, ' ', '/', '>' => |c| {
                    t.state = if (t.tempBuffer.eql("script")) .ScriptDataEscaped else .ScriptDataDoubleEscaped;
                    emitCharacter(c);
                },
                'A'...'Z' => |c| {
                    t.tempBuffer.append(toLowercase(c));
                    emitCharacter(c);
                },
                'a'...'z' => |c| {
                    t.tempBuffer.append(c);
                    emitCharacter(c);
                },
                else => {
                    t.reconsume();
                    t.state = .ScriptDataDoubleEscaped;
                },
            }
        },
        .BeforeAttributeName => {
            switch (t.nextInputChar()) {
                '\t', '\n', 0x0C, ' ' => {},
                '/', '>', null => {
                    t.reconsume();
                    t.state = .AfterAttributeName;
                },
                '=' => |c| {
                    try t.parseError(.UnexpectedEqualsSignBeforeAttributeName);
                    var attr = createAttribute(t.currentTagToken);
                    attr.name = &.{c};
                    attr.value = "";
                    t.state = .AttributeName;
                },
                else => {
                    var attr = createAttribute(t.currentTagToken);
                    attr.name = "";
                    attr.value = "";
                    t.reconsume();
                    t.state = .AttributeName;
                },
            }
        },
        .AttributeName => {
            // TODO The final attribute name must be compared to all other attribute names for duplicates.
            switch (t.nextInputChar()) {
                '\t', '\n', 0x0C, ' ', '/', '>', null => {
                    t.reconsume();
                    t.state = .AfterAttributeName;
                },
                '=' => t.state = .BeforeAttributeValue,
                'A'...'Z' => |c| t.currentAttribute.name.append(toLowercase(c)),
                null => {
                    try t.parseError(.UnexpectedNullCharacter);
                    t.currentAttribute.name.append(REPLACEMENT_CHARACTER);
                },
                else => |c| {
                    switch (c) {
                        '"', '\'', '<' => try t.parseError(.UnexpectedCharacterInAttributeName),
                        else => {},
                    }
                    t.currentAttribute.name.append(c);
                },
            }
        },
        .AfterAttributeName => {
            switch (t.nextInputChar()) {
                '\t', '\n', 0x0C, ' ' => {},
                '/' => t.state = .SelfClosingStartTag,
                '=' => t.state = .BeforeAttributeValue,
                '>' => {
                    t.state = .Data;
                    emitCurrentTagToken();
                },
                null => {
                    try t.parseError(.EOFInTag);
                    emitEOF();
                },
                else => {
                    var attr = createAttribute(t.currentTagToken);
                    attr.name = "";
                    attr.value = "";
                    t.reconsume();
                    t.state = .AttributeName;
                },
            }
        },
        BeforeAttributeValue => {
            switch (t.nextInputChar()) {
                '\t', '\n', 0x0C, ' ' => {},
                '"' => t.state = .AttributeValueDoubleQuoted,
                '\'' => t.state = .AttributeValueSingleQuoted,
                '>' => {
                    try t.parseError(.MissingAttributeValue);
                    t.state = .Data;
                    emitCurrentTagToken();
                },
                else => {
                    t.reconsume();
                    t.state = .AttributeValueUnquoted;
                },
            }
        },
        .AttributeValueDoubleQuoted => {
            switch (t.nextInputChar()) {
                '"' => t.state = .AfterAttributeValueQuoted,
                '&' => t.toCharacterReferenceState(.AttributeValueDoubleQuoted),
                0x00 => {
                    try t.parseError(.UnexpectedNullCharacter);
                    t.currentAttribute.value.append(REPLACEMENT_CHARACTER);
                },
                null => {
                    try t.parseError(.EOFInTag);
                    emitEOF();
                },
                else => |c| t.currentAttribute.value.append(c),
            }
        },
        // Nearly identical to AttributeValueDoubleQuoted.
        .AttributeValueSingleQuoted => {
            switch (t.nextInputChar()) {
                '\'' => t.state = .AfterAttributeValueQuoted,
                '&' => t.toCharacterReferenceState(.AttributeValueSingleQuoted),
                0x00 => {
                    try t.parseError(.UnexpectedNullCharacter);
                    t.currentAttribute.value.append(REPLACEMENT_CHARACTER);
                },
                null => {
                    try t.parseError(.EOFInTag);
                    emitEOF();
                },
                else => |c| t.currentAttribute.value.append(c),
            }
        },
        .AttributeValueUnquoted => {
            switch (t.nextInputChar()) {
                '\t', '\n', 0x0C, ' ' => t.state = .BeforeAttributeName,
                '&' => t.toCharacterReferenceState(.AttributeValueUnquoted),
                '>' => {
                    t.state = .Data;
                    emitCurrentTagToken();
                },
                0x00 => {
                    try t.parseError(.UnexpectedNullCharacter);
                    t.currentAttribute.value.append(REPLACEMENT_CHARACTER);
                },
                null => {
                    try t.parseError(.EOFInTag);
                    emitEOF();
                },
                else => |c| {
                    switch (c) {
                        '"', '\'', '<', '=', '`' => try t.parseError(.UnexpectedCharacterInUnquotedAttributeValue),
                        else => {},
                    }
                    t.currentAttribute.value.append(c);
                },
            }
        },
        .AfterAttributeValueQuoted => {
            switch (t.nextInputChar()) {
                '\t', '\n', 0x0C, ' ' => t.state = .BeforeAttributeName,
                '/' => t.state = .SelfClosingStartTag,
                '>' => {
                    t.state = .Data;
                    emitCurrentTagToken();
                },
                null => {
                    try t.parseError(.EOFInTag);
                    emitEOF();
                },
                else => {
                    try t.parseError(.MissingWhitespaceBetweenAttributes);
                    t.reconsume();
                    t.state = .BeforeAttributeName;
                },
            }
        },
        .SelfClosingStartTag => {
            switch (t.nextInputChar()) {
                '>' => {
                    t.currentTagToken.self_closing = true;
                    t.state = .Data;
                    emitCurrentTagToken();
                },
                null => {
                    try t.parseError(.EOFInTag);
                    emitEOF();
                },
                else => {
                    try t.parseError(.UnexpectedSolidusInTag);
                    t.reconsume();
                    t.state = .BeforeAttributeName;
                },
            }
        },
        .BogusComment => {
            switch (t.nextInputChar()) {
                '>' => {
                    t.state = .Data;
                    emitComment();
                },
                null => {
                    emitComment();
                    emitEOF();
                },
                0x00 => {
                    try t.parseError(.UnexpectedNullCharacter);
                    t.currentComment.append(REPLACEMENT_CHARACTER);
                },
                else => |c| t.currentComment.append(c),
            }
        },
        .MarkupDeclarationOpen => {
            if (t.nextFewCharsEql("--")) {
                t.consumeN(2);
                var token = createCommentToken();
                token.data = "";
                t.state = .CommentStart;
            } else if (t.nextFewCharsCaseInsensitiveEql("DOCTYPE")) {
                t.consumeN(7);
                t.state = .DOCTYPE;
            } else if (t.nextFewCharsEql("[CDATA[")) {
                t.consumeN(7);
                if (t.adjusted_current_node != null and t.adjusted_current_node.namespace != .html) {
                    t.state = .CDATASection;
                } else {
                    try t.parseError(.CDATAInHtmlContent);
                    var token = createCommentToken();
                    token.data = "[CDATA[";
                    t.state = .BogusComment;
                }
            } else {
                try t.parseError(.IncorrectlyOpenedComment);
                var token = createCommentToken();
                token.data = "";
                t.state = .BogusComment;
            }
        },
        .CommentStart => {
            switch (t.nextInputChar()) {
                '-' => t.state = .CommendStartDash,
                '>' => {
                    try t.parseError(.AbruptClosingOfEmptyComment);
                    t.state = .Data;
                    emitComment();
                },
                else => {
                    t.reconsume();
                    t.state = .Comment;
                },
            }
        },
        .CommentStartDash => {
            switch (t.nextInputChar()) {
                '-' => t.state = .CommentEnd,
                '>' => {
                    try t.parseError(.AbruptClosingOfEmptyComment);
                    t.state = .Data;
                    emitComment();
                },
                null => {
                    try t.parseError(.EOFInComment);
                    emitComment();
                    emitEOF();
                },
                else => {
                    t.currentComment.data.append('-');
                    t.reconsume();
                    t.state = .Comment;
                },
            }
        },
        .Comment => {
            switch (t.nextInputChar()) {
                '<' => |c| {
                    t.currentComment.data.append(c);
                    t.state = .CommentLessThanSign;
                },
                '-' => t.state = .CommentEndDash,
                0x00 => {
                    try t.parseError(.UnexpectedNullCharacter);
                    t.currentComment.data.append(REPLACEMENT_CHARACTER);
                },
                null => {
                    try t.parseError(.EOFInComment);
                    emitComment();
                    emitEOF();
                },
                else => |c| t.currentComment.data.append(c),
            }
        },
        .CommentLessThanSign => {
            switch (t.nextInputChar()) {
                '!' => |c| {
                    t.currentComment.data.append(c);
                    t.state = .CommentLessThanSignBang;
                },
                '<' => |c| t.currentComment.data.append(c),
                else => {
                    t.reconsume();
                    t.state = .Comment;
                },
            }
        },
        .CommentLessThanSignBang => {
            switch (t.nextInputChar()) {
                '-' => t.state = .CommentLessThanSignBangDash,
                else => {
                    t.reconsume();
                    t.state = .Comment;
                },
            }
        },
        .CommentLessThanSignBangDash => {
            switch (t.nextInputChar()) {
                '-' => t.state = .CommentLessThanSignBangDashDash,
                else => {
                    t.reconsume();
                    t.state = .CommentEndDash;
                },
            }
        },
        .CommentLessThanSignBangDashDash => {
            switch (t.nextInputChar()) {
                '>', null => {
                    t.reconsume();
                    t.state = .CommentEnd;
                },
                else => {
                    t.parseError(.NestedComment);
                    t.reconsume();
                    t.state = .CommentEnd;
                },
            }
        },
        .CommentEndDash => {
            switch (t.nextInputChar()) {
                '-' => t.state = .CommentEnd,
                null => {
                    try t.parseError(.EOFInComment);
                    emitComment();
                    emitEOF();
                },
                else => {
                    t.currentComment.data.append('-');
                    t.reconsume();
                    t.state = .Comment;
                },
            }
        },
        .CommentEnd => {
            switch (t.nextInputChar()) {
                '>' => {
                    t.state = .Data;
                    emitComment();
                },
                '!' => t.state = .CommentEndBang,
                '-' => t.currentComment.data.append('-'),
                null => {
                    try t.parseError(.EOFInComment);
                    emitComment();
                    emitEOF();
                },
                else => {
                    t.currentComment.data.append('-');
                    t.currentComment.data.append('-');
                    t.reconsume();
                    t.state = .Comment;
                },
            }
        },
        .CommentEndBang => {
            switch (t.nextInputChar()) {
                '-' => {
                    t.currentComment.data.append('-');
                    t.currentComment.data.append('-');
                    t.currentComment.data.append('!');
                    t.state = .CommentEndDash;
                },
                '>' => {
                    try t.parseError(.IncorrectlyClosedComment);
                    t.state = .Data;
                    emitComment();
                },
                null => {
                    try t.parseError(.EOFInComment);
                    emitComment();
                    emitEOF();
                },
                else => {
                    t.currentComment.data.append('-');
                    t.currentComment.data.append('-');
                    t.currentComment.data.append('!');
                    t.reconsume();
                    t.state = .Comment;
                },
            }
        },
        .DOCTYPE => {
            switch (t.nextInputChar()) {
                '\t', '\n', 0x0C, ' ' => t.state = .BeforeDOCTYPEName,
                '>' => {
                    t.reconsume();
                    t.state = .BeforeDOCTYPEName;
                },
                null => {
                    try t.parseError(.EOFInDOCTYPE);
                    var token = createDOCTYPEToken();
                    token.force_quirks = true;
                    emitToken(token);
                    emitEOF();
                },
                else => {
                    try t.parseError(.MissingWhitespaceBeforeDOCTYPEName);
                    t.reconsume();
                    t.state = .BeforeDOCTYPEName;
                },
            }
        },
        .BeforeDOCTYPEName => {
            switch (t.nextInputChar()) {
                '\t', '\n', 0x0C, ' ' => {},
                'A'...'Z' => |c| {
                    var token = createDOCTYPEToken();
                    token.name = &.{toLowercase(c)};
                    t.state = .DOCTYPEName;
                },
                '>' => {
                    try t.parseError(.MissingDOCTYPEName);
                    var token = createDOCTYPEToken();
                    token.force_quirks = true;
                    t.state = .Data;
                    emitToken(token);
                },
                null => {
                    try t.parseError(.EOFInDOCTYPE);
                    var token = createDOCTYPEToken();
                    token.force_quirks = true;
                    emitToken(token);
                    emitEOF();
                },
                else => |c| {
                    var token = createDOCTYPEToken();
                    token.name = &.{c};
                    t.state = .DOCTYPEName;
                },
            }
        },
        .DOCTYPEName => {
            switch (t.nextInputChar()) {
                '\t', '\n', 0x0C, ' ' => t.state = .AfterDOCTYPEName,
                '>' => {
                    t.state = .Data;
                    emitDOCTYPE();
                },
                'A'...'Z' => |c| t.currentDOCTYPE.name.append(c),
                0x00 => {
                    t.parseError(.UnexpectedNullCharacter);
                    t.currentDOCTYPE.name.append(REPLACEMENT_CHARACTER);
                },
                null => {
                    t.parseError(.EOFInDOCTYPE);
                    t.currentDOCTYPE.force_quirks = true;
                    emitDOCTYPE();
                    emitEOF();
                },
                else => |c| t.currentDOCTYPE.name.append(c),
            }
        },
        .AfterDOCTYPEName => {
            switch (t.nextInputChar()) {
                '\t', '\n', 0x0C, ' ' => {},
                '>' => {
                    t.state = .Data;
                    emitDOCTYPE();
                },
                null => {
                    t.parseError(.EOFInDOCTYPE);
                    t.currentDOCTYPE.force_quirks = true;
                    emitDOCTYPE();
                    emitEOF();
                },
                else => |c| {
                    if (eqlIgnoreCase(c, 'P') and t.nextFewCharsCaseInsensitiveEql("UBLIC")) {
                        t.consumeN(5);
                        t.state = .AfterDOCTYPEPublicKeyword;
                    } else if (eqlIgnoreCase(c, 'S') and t.nextFewCharsCaseInsensitiveEql("YSTEM")) {
                        t.consumeN(5);
                        t.state = .AfterDOCTYPESystemKeyword;
                    } else {
                        t.parseError(.InvalidCharacterSequenceAfterDOCTYPEName);
                        t.currentDOCTYPE.force_quirks = true;
                        t.reconsume();
                        t.state = BogusDOCTYPE;
                    }
                },
            }
        },
        .AfterDOCTYPEPublicKeyword => {
            switch (t.nextInputChar()) {
                '\t', '\n', 0x0C, ' ' => t.state = .BeforeDOCTYPEPublicIdentifier,
                '"' => {
                    t.parseError(.MissingWhitespaceAfterDOCTYPEPublicKeyword);
                    t.currentDOCTYPE.public_identifier = "";
                    t.state = .DOCTYPEPublicIdentifierDoubleQuoted;
                },
                '\'' => {
                    t.parseError(.MissingWhitespaceAfterDOCTYPEPublicKeyword);
                    t.currentDOCTYPE.public_identifier = "";
                    t.state = .DOCTYPEPublicIdentifierSingleQuoted;
                },
            }
        },
        .BeforeDOCTYPEPublicIdentifier => {
            switch (t.nextInputChar()) {
                '\t', '\n', 0x0C, ' ' => {},
                '"' => {
                    t.currentDOCTYPE.public_identifier = "";
                    t.state = .DOCTYPEPublicIdentifierDoubleQuoted;
                },
                '\'' => {
                    t.currentDOCTYPE.public_identifier = "";
                    t.state = .DOCTYPEPublicIdentifierSingleQuoted;
                },
                '>' => {
                    t.parseError(.MissingDOCTYPEPublicIdentifier);
                    t.currentDOCTYPE.force_quirks = true;
                    t.state = .Data;
                    emitDOCTYPE();
                },
                null => {
                    t.parseError(.EOFInDOCTYPE);
                    t.currentDOCTYPE.force_quirks = true;
                    emitDOCTYPE();
                    emitEOF();
                },
                else => {
                    t.parseError(.MissingQuoteBeforeDOCTYPEPublicIdentifier);
                    t.currentDOCTYPE.force_quirks = true;
                    t.reconsume();
                    t.state = .BogusDOCTYPE;
                },
            }
        },
        .DOCTYPEPublicIdentifierDoubleQuoted => {
            switch (t.nextInputChar()) {
                '"' => t.state = .AfterDOCTYPEPublicIdentifier,
                0x00 => {
                    t.parseError(.UnexpectedNullCharacter);
                    t.currentDOCTYPE.public_identifier.append(REPLACEMENT_CHARACTER);
                },
                '>' => {
                    t.parseError(.AbruptDOCTYPEPublicIdentifier);
                    t.currentDOCTYPE.force_quirks = true;
                    t.state = .Data;
                    emitDOCTYPE();
                },
                null => {
                    t.parseError(.EOFInDOCTYPE);
                    t.currentDOCTYPE.force_quirks = true;
                    emitDOCTYPE();
                    emitEOF();
                },
                else => |c| t.currentDOCTYPE.public_identifier.append(c),
            }
        },
        .DOCTYPEPublicIdentifierSingleQuoted => {
            switch (t.nextInputChar()) {
                '\'' => t.state = .AfterDOCTYPEPublicIdentifier,
                0x00 => {
                    t.parseError(.UnexpectedNullCharacter);
                    t.currentDOCTYPE.public_identifier.append(REPLACEMENT_CHARACTER);
                },
                '>' => {
                    t.parseError(.AbruptDOCTYPEPublicIdentifier);
                    t.currentDOCTYPE.force_quirks = true;
                    t.state = .Data;
                    emitDOCTYPE();
                },
                null => {
                    t.parseError(.EOFInDOCTYPE);
                    t.currentDOCTYPE.force_quirks = true;
                    emitDOCTYPE();
                    emitEOF();
                },
                else => |c| t.currentDOCTYPE.public_identifier.append(c),
            }
        },
        .AfterDOCTYPEPublicIdentifier => {
            switch (t.nextInputChar()) {
                '\t', '\n', 0x0C, ' ' => t.state = .BetweenDOCTYPEPublicAndSystemIdentifiers,
                '>' => {
                    t.state = .Data;
                    emitDOCTYPE();
                },
                '"' => {
                    t.parseError(.MissingWhitespaceBetweenDOCTYPEPublicAndSystemIdentifiers);
                    t.currentDOCTYPE.system_identifier = "";
                    t.state = .DOCTYPESystemIdentifierDoubleQuoted;
                },
                '\'' => {
                    t.parseError(.MissingWhitespaceBetweenDOCTYPEPublicAndSystemIdentifiers);
                    t.currentDOCTYPE.system_identifier = "";
                    t.state = .DOCTYPESystemIdentifierSingleQuoted;
                },
                null => {
                    t.parseError(.EOFInDOCTYPE);
                    t.currentDOCTYPE.force_quirks = true;
                    emitDOCTYPE();
                    emitEOF();
                },
                else => {
                    t.parseError(.MissingQuoteBeforeDOCTYPESystemIdentifier);
                    t.currentDOCTYPE.force_quirks = true;
                    t.reconsume();
                    t.state = .BogusDOCTYPE;
                },
            }
        },
        .BetweenDOCTYPEPublicAndSystemIdentifiers => {
            switch (t.nextInputChar()) {
                '\t', '\n', 0x0C, ' ' => {},
                '>' => {
                    t.state = .Data;
                    emitDOCTYPE();
                },
                '"' => {
                    t.currentDOCTYPE.system_identifier = "";
                    t.state = .DOCTYPESystemIdentifierDoubleQuoted;
                },
                '\'' => {
                    t.currentDOCTYPE.system_identifier = "";
                    t.state = .DOCTYPESystemIdentifierSingleQuoted;
                },
                null => {
                    t.parseError(.EOFInDOCTYPE);
                    t.currentDOCTYPE.force_quirks = true;
                    emitDOCTYPE();
                    emitDOCTYPE();
                },
                else => {
                    t.parseError(.MissingQuoteBeforeDOCTYPESystemIdentifier);
                    t.currentDOCTYPE.force_quirks = true;
                    t.reconsume();
                    t.state = .BogusDOCTYPE;
                },
            }
        },
        .AfterDOCTYPESystemKeyword => {
            switch (t.nextInputChar()) {
                '\t', '\n', 0x0C, ' ' => t.state = .BeforeDOCTYPESystemIdentifier,
                '"' => {
                    t.parseError(.MissingWhitespaceAfterDOCTYPESystemKeyword);
                    t.currentDOCTYPE.system_identifier = "";
                    t.state = .DOCTYPESystemIdentifierDoubleQuoted;
                },
                '\'' => {
                    t.parseError(.MissingWhitespaceAfterDOCTYPESystemKeyword);
                    t.currentDOCTYPE.system_identifier = "";
                    t.state = .DOCTYPESystemIdentifierSingleQuoted;
                },
                '>' => {
                    t.parseError(.MissingDOCTYPESystemIdentifier);
                    t.currentDOCTYPE.force_quirks = true;
                    t.state = .Data;
                    emitDOCTYPE();
                },
                null => {
                    t.parseError(.EOFInDOCTYPE);
                    t.currentDOCTYPE.force_quirks = true;
                    emitDOCTYPE();
                    emitEOF();
                },
                else => {
                    t.parseError(.MissingQuoteBeforeDOCTYPESystemIdentifier);
                    t.currentDOCTYPE.force_quirks = true;
                    t.reconsume();
                    t.state = .BogusDOCTYPE;
                },
            }
        },
        .BeforeDOCTYPESystemIdentifier => {
            switch (t.nextInputChar()) {
                '\t', '\n', 0x0C, ' ' => {},
                '"' => {
                    t.currentDOCTYPE.system_identifier = "";
                    t.state = .DOCTYPESystemIdentifierDoubleQuoted;
                },
                '\'' => {
                    t.currentDOCTYPE.system_identifier = "";
                    t.state = .DOCTYPESystemIdentifierSingleQuoted;
                },
                '>' => {
                    t.parseError(.MissingDOCTYPESystemIdentifier);
                    t.currentDOCTYPE.force_quirks = true;
                    t.state = .Data;
                    emitDOCTYPE();
                },
                null => {
                    t.parseError(.EOFInDOCTYPE);
                    t.currentDOCTYPE.force_quirks = true;
                    emitDOCTYPE();
                    emitEOF();
                },
                else => {
                    t.parseError(.MissingQuoteBeforeDOCTYPESystemIdentifier);
                    t.currentDOCTYPE.force_quirks = true;
                    t.reconsume();
                    t.state = .BogusDOCTYPE;
                },
            }
        },
        .DOCTYPESystemIdentifierDoubleQuoted => {
            switch (t.nextInputChar()) {
                '"' => t.state = .AfterDOCTYPESystemIdentifier,
                0x00 => {
                    t.parseError(.UnexpectedNullCharacter);
                    t.currentDOCTYPE.system_identifier.append(REPLACEMENT_CHARACTER);
                },
                '>' => {
                    t.parseError(.AbruptDOCTYPESystemIdentifier);
                    t.currentDOCTYPE.force_quirks = true;
                    t.state = .Data;
                    emitDOCTYPE();
                },
                null => {
                    t.parseError(.EOFInDOCTYPE);
                    t.currentDOCTYPE.force_quirks = true;
                    emitDOCTYPE();
                    emitEOF();
                },
                else => |c| t.currentDOCTYPE.system_identifier.append(c),
            }
        },
        .DOCTYPESystemIdentifierSingleQuoted => {
            switch (t.nextInputChar()) {
                '\'' => t.state = .AfterDOCTYPESystemIdentifier,
                0x00 => {
                    t.parseError(.UnexpectedNullCharacter);
                    t.currentDOCTYPE.system_identifier.append(REPLACEMENT_CHARACTER);
                },
                '>' => {
                    t.parseError(.AbruptDOCTYPESystemIdentifier);
                    t.currentDOCTYPE.force_quirks = true;
                    t.state = .Data;
                    emitDOCTYPE();
                },
                null => {
                    t.parseError(.EOFInDOCTYPE);
                    t.currentDOCTYPE.force_quirks = true;
                    emitDOCTYPE();
                    emitEOF();
                },
                else => |c| t.currentDOCTYPE.system_identifier.append(c),
            }
        },
        .AfterDOCTYPESystemIdentifier => {
            switch (t.nextInputChar()) {
                '\t', '\n', 0x0C, ' ' => {},
                '>' => {
                    t.state = .Data;
                    emitDOCTYPE();
                },
                null => {
                    t.parseError(.EOFInDOCTYPE);
                    t.currentDOCTYPE.force_quirks = true;
                    emitDOCTYPE();
                    emitEOF();
                },
                else => {
                    t.parseError(.UnexptecedCharacterAfterDOCTYPESystemIdentifier);
                    t.reconsume();
                    t.state = .BogusDOCTYPE;
                },
            }
        },
        .BogusDOCTYPE => {
            switch (t.nextInputChar()) {
                '>' => {
                    t.state = .Data;
                    emitDOCTYPE();
                },
                0x00 => t.parseError(.UnexpectedNullCharacter),
                null => {
                    emitDOCTYPE();
                    emitEOF();
                },
                else => {},
            }
        },
        .CDATASection => {
            switch (t.nextInputChar()) {
                ']' => t.state = .CDATASectionBracket,
                null => {
                    t.parseError(.EOFInCDATA);
                    emitEOF();
                },
                else => |c| emitCharacter(c),
            }
        },
        .CDATASectionBracket => {
            switch (t.nextInputChar()) {
                ']' => t.state = .CDATASectionEnd,
                else => {
                    emitCharacter(']');
                    t.reconsume();
                    t.state = .CDATASection;
                },
            }
        },
        .CDATASectionEnd => {
            switch (t.nextInputChar()) {
                ']' => emitCharacter(']'),
                '>' => t.state = .Data,
                else => {
                    emitCharacters("]]");
                    t.reconsume();
                    t.state = .CDATASection;
                },
            }
        },
        .CharacterReference => {
            t.clearTempBuffer();
            t.tempBuffer.append('&');
            switch (t.nextInputChar()) {
                '0'...'9', 'A'...'Z', 'a'...'z' => {
                    t.reconsume();
                    t.state = .NamedCharacterReference;
                },
                '#' => |c| {
                    t.tempBuffer.append(c);
                    t.state = .NumericCharacterReference;
                },
                else => {
                    t.flushCharacterReference();
                    t.reconsume();
                    t.switchToReturnState();
                },
            }
        },
        .NamedCharacterReference => {
            t.tempBuffer.append(t.peekInputChar());
            while (t.tempBufferMatchesNamedCharacterPrefix()) |match_type| {
                switch (match_type) {
                    .Prefix => {
                        _ = t.nextInputChar();
                        t.tempBuffer.append(t.peekInputChar());
                        continue;
                    },
                    .Exact => {
                        _ = t.nextInputChar();
                        const c = t.peekInputChar();
                        if (t.isInAttribute() and t.tempBuffer.last() != ';' and (c == '=' or (c >= '0' and c <= '9') or (c >= 'A' and c <= 'Z') or (c >= 'a' and c <= 'z'))) {
                            // Legacy reasons.
                            t.flushCharacterReference();
                            t.switchToReturnState();
                        } else {
                            if (t.tempBuffer.last() != ';') {
                                t.parseError(.MissingSemicolonAfterCharacterReference);
                            }
                            // NOTE: This is slightly out of order from what the spec says. Will this cause problems?
                            const chars = t.translateNamedCharacterReference();
                            t.flushCharacterReference();
                            t.clearTempBuffer();
                            t.tempBuffer.append(chars.first);
                            if (chars.second) |c| t.tempBuffer.append(c);
                            t.switchToReturnState();
                        }
                    },
                }
            } else {
                t.tempBuffer.dropOne();
                t.flushCharacterReference();
                t.state = .AmbiguousAmpersand;
            }
        },
        .AmbiguousAmpersand => {
            switch (t.nextInputChar()) {
                '0'...'9', 'A'...'Z', 'a'...'z' => |c| if (t.isInAttribute()) t.currentAttribute.value.append(c) else emitCharacter(c),
                ';' => {
                    t.parseError(.UnknownNamedCharacterReference);
                    t.reconsume();
                    t.switchToReturnState();
                },
                else => {
                    t.reconsume();
                    t.switchToReturnState();
                },
            }
        },
        .NumericCharacterReference => {
            t.character_reference_code = 0;
            switch (t.nextInputChar()) {
                'x', 'X' => |c| {
                    t.tempBuffer.append(c);
                    t.state = .HexadecimalCharacterReferenceStart;
                },
                else => {
                    t.reconsume();
                    t.state = .DecimalCharacterReferenceStart;
                },
            }
        },
        .HexadecimalCharacterReferenceStart => {
            switch (t.nextInputChar()) {
                '0'...'9', 'A'...'F', 'a'...'f' => {
                    t.reconsume();
                    t.state = .HexadecimalCharacterReference;
                },
                else => {
                    t.parseError(.AbsenceOfDigitsInNumericCharacterReference);
                    t.flushCharacterReference();
                    t.reconsume();
                    t.switchToReturnState();
                },
            }
        },
        .DecimalCharacterReferenceStart => {
            switch (t.nextInputChar()) {
                '0'...'9' => {
                    t.reconsume();
                    t.state = .DecimalCharacterReference;
                },
                else => {
                    t.parseError(AbsenceOfDigitsInNumericCharacterReference);
                    t.flushCharacterReference();
                    t.reconsume();
                    t.switchToReturnState();
                },
            }
        },
        .HexadecimalCharacterReference => {
            switch (t.nextInputChar()) {
                // Use saturating arithmetic here?
                '0'...'9' => |c| t.character_reference_code = t.character_reference_code * 16 + decimalCharToNumber(c),
                'A'...'F' => |c| t.character_reference_code = t.character_reference_code * 16 + upperHexCharToNumber(c),
                'a'...'f' => |c| t.character_reference_code = t.character_reference_code * 16 + lowerHexCharToNumber(c),
                ';' => t.state = .NumericCharacterReferenceEnd,
                else => {
                    t.parseError(.MissingSemicolonAfterCharacterReference);
                    t.reconsume();
                    t.state = .NumericCharacterReferenceEnd;
                },
            }
        },
        .DecimalCharacterReference => {
            switch (t.nextInputChar()) {
                // Use saturating arithmetic here?
                '0'...'9' => |c| t.character_reference_code = t.character_reference_code * 10 + decimalCharToNumber(c),
                ';' => t.state = .NumericCharacterReferenceEnd,
                else => {
                    t.parseError(.MissingSemicolonAfterCharacterReference);
                    t.reconsume();
                    t.state = .NumericCharacterReferenceEnd;
                },
            }
        },
        .NumericCharacterReferenceEnd => {
            switch (t.character_reference_code) {
                0x00 => {
                    t.parseError(.NullCharacterReference);
                    t.character_reference_code = REPLACEMENT_CHARACTER;
                },
                0x10FFFF...std.math.maxInt(@TypeOf(t.character_reference_code)) => {
                    t.parseError(.CharacterReferenceOutsideUnicodeRange);
                    t.character_reference_code = REPLACEMENT_CHARACTER;
                },
                0xD800...0xDFFF => {
                    t.parseError(.SurrogateCharacterReference);
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
                => t.parseError(.NoncharacterCharacterReference),
                0x00...0x08, 0x0B, 0x0D...0x1F => t.parseError(.ControlCharacterReference),
                0x7F...0x9F => |c| {
                    t.parseError(.ControlCharacterReference);
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
            }
            // NOTE: This is slightly out of order from what the spec says. Will this cause problems?
            const char = codepointFromCharacterReferenceCode(t.character_reference_code);
            t.flushCharacterReference();
            t.clearTempBuffer();
            t.tempBuffer.append(char);
            t.switchToReturnState();
        },
    }
}

fn endTagName(t: *Tokenizer, current_input_char: ?u8, next_state: TokenizerState) void {
    switch (current_input_char) {
        '\t', '\n', '\u{000C}', ' ' => {
            if (t.isAppropriateEndTag(t.currentToken)) {
                state = .BeforeAttributeName;
                return;
            }
        },
        '/' => {
            if (t.isAppropriateEndTag(t.currentToken)) {
                state = .SelfClosingStartTag;
                return;
            }
        },
        '>' => {
            if (t.isAppropriateEndTag(t.currentToken)) {
                state = .Data;
                emitCurrentTagToken();
                return;
            }
        },
        // These 2 prongs don't switch state (this could be in a loop)
        'A'...'Z' => |c| {
            t.currentToken.name.append(toLowercase(c));
            t.appendTempBuffer(c);
            return;
        },
        'a'...'z' => |c| {
            t.currentToken.name.append(c);
            t.appendTempBuffer(c);
            return;
        },
        else => {},
    }

    emitToken(.Character, "<");
    emitToken(.Character, "/");
    for (t.tempBuffer) |c| emitToken(.Character, &.{c});
    t.reconsume();
    state = next_state;
}
