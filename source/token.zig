// Copyright (C) 2021-2023 Chadwain Holness
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

const rem = @import("../rem.zig");

const std = @import("std");
const Allocator = std.mem.Allocator;
const StringHashMapUnmanaged = std.StringHashMapUnmanaged;

pub const TokenDoctype = struct {
    name: ?[]const u8,
    public_identifier: ?[]const u8,
    system_identifier: ?[]const u8,
    force_quirks: bool,
};

pub const TokenStartTag = struct {
    name: []const u8,
    attributes: Attributes,
    self_closing: bool,

    pub const Attributes = StringHashMapUnmanaged([]const u8);
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

pub const TokenEof = void;

pub const Token = union(enum) {
    doctype: Doctype,
    start_tag: StartTag,
    end_tag: EndTag,
    comment: Comment,
    character: Character,
    eof: Eof,

    pub const Doctype = TokenDoctype;
    pub const StartTag = TokenStartTag;
    pub const EndTag = TokenEndTag;
    pub const Comment = TokenComment;
    pub const Character = TokenCharacter;
    pub const Eof = TokenEof;

    pub fn deinit(token: *Token, allocator: Allocator) void {
        switch (token.*) {
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
            .character, .eof => {},
        }
    }

    pub fn eql(lhs: Token, rhs: Token) bool {
        const eqlNullSlices = rem.util.eqlNullSlices;
        if (std.meta.activeTag(lhs) != std.meta.activeTag(rhs)) return false;
        switch (lhs) {
            .doctype => return lhs.doctype.force_quirks == rhs.doctype.force_quirks and
                eqlNullSlices(u8, lhs.doctype.name, rhs.doctype.name) and
                eqlNullSlices(u8, lhs.doctype.public_identifier, rhs.doctype.public_identifier) and
                eqlNullSlices(u8, lhs.doctype.system_identifier, rhs.doctype.system_identifier),
            .start_tag => {
                if (!(lhs.start_tag.self_closing == rhs.start_tag.self_closing and
                    eqlNullSlices(u8, lhs.start_tag.name, rhs.start_tag.name) and
                    lhs.start_tag.attributes.count() == rhs.start_tag.attributes.count())) return false;
                var iterator = lhs.start_tag.attributes.iterator();
                while (iterator.next()) |attr| {
                    const rhs_value = rhs.start_tag.attributes.get(attr.key_ptr.*) orelse return false;
                    if (!std.mem.eql(u8, attr.value_ptr.*, rhs_value)) return false;
                }
                return true;
            },
            .end_tag => return eqlNullSlices(u8, lhs.end_tag.name, rhs.end_tag.name),
            .comment => return eqlNullSlices(u8, lhs.comment.data, rhs.comment.data),
            .character => return lhs.character.data == rhs.character.data,
            .eof => return true,
        }
    }

    pub fn format(value: Token, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = fmt;
        _ = options;

        switch (value) {
            .doctype => |d| {
                try writer.writeAll("DOCTYPE (");
                if (d.name) |name| try writer.writeAll(name);
                if (d.public_identifier) |pi| {
                    try writer.writeAll(" PUBLIC:");
                    try writer.writeAll(pi);
                }
                if (d.system_identifier) |si| {
                    try writer.writeAll(" SYSTEM:");
                    try writer.writeAll(si);
                }
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
                    try writer.writeAll("\", ");
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
                    0x00...0x08, 0x0B...0x7F => {
                        const as_u7: u7 = @intCast(c.data);
                        if (std.ascii.isControl(as_u7) or std.ascii.isWhitespace(as_u7)) {
                            try writer.print("U+{X}", .{as_u7});
                        } else {
                            try writer.writeByte(as_u7);
                        }
                    },
                    '\n' => try writer.writeAll("<newline>"),
                    '\t' => try writer.writeAll("<tab>"),
                    else => try writer.print("U+{X}", .{c.data}),
                }
                try writer.writeAll(")");
            },
            .eof => {
                try writer.writeAll("End of file");
            },
        }
    }
};
