// Copyright (C) 2021-2023 Chadwain Holness
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

const rem = @import("../rem.zig");
const std = @import("std");
const Allocator = std.mem.Allocator;
const StringHashMapUnmanaged = std.StringHashMapUnmanaged;

pub const TokenDOCTYPE = struct {
    name: ?[]const u8,
    public_identifier: ?[]const u8,
    system_identifier: ?[]const u8,
    force_quirks: bool,
};

pub const TokenStartTag = struct {
    name: []const u8,
    attributes: TokenStartTag.Attributes,
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

pub const TokenEOF = void;

pub const Token = union(enum) {
    doctype: TokenDOCTYPE,
    start_tag: TokenStartTag,
    end_tag: TokenEndTag,
    comment: TokenComment,
    character: TokenCharacter,
    eof: TokenEOF,

    pub fn deinit(self: *Token, allocator: Allocator) void {
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

    pub fn copy(self: Token, allocator: Allocator) !Token {
        switch (self) {
            .doctype => |d| {
                const name = if (d.name) |s| try allocator.dupe(u8, s) else null;
                errdefer if (name) |s| allocator.free(s);
                const public_identifier = if (d.public_identifier) |s| try allocator.dupe(u8, s) else null;
                errdefer if (public_identifier) |s| allocator.free(s);
                const system_identifier = if (d.system_identifier) |s| try allocator.dupe(u8, s) else null;
                errdefer if (system_identifier) |s| allocator.free(s);
                return Token{ .doctype = .{
                    .name = name,
                    .public_identifier = public_identifier,
                    .system_identifier = system_identifier,
                    .force_quirks = d.force_quirks,
                } };
            },
            .start_tag => |st| {
                const name = try allocator.dupe(u8, st.name);
                errdefer allocator.free(name);

                var attributes = TokenStartTag.Attributes{};
                errdefer {
                    var iterator = attributes.iterator();
                    while (iterator.next()) |attr| {
                        allocator.free(attr.key_ptr.*);
                        allocator.free(attr.value_ptr.*);
                    }
                    attributes.deinit(allocator);
                }

                var iterator = st.attributes.iterator();
                while (iterator.next()) |attr| {
                    const key = try allocator.dupe(u8, attr.key_ptr.*);
                    errdefer allocator.free(key);
                    const value = try allocator.dupe(u8, attr.value_ptr.*);
                    errdefer allocator.free(value);
                    try attributes.putNoClobber(allocator, key, value);
                }

                return Token{ .start_tag = .{ .name = name, .attributes = attributes, .self_closing = st.self_closing } };
            },
            .end_tag => |et| {
                const name = try allocator.dupe(u8, et.name);
                return Token{ .end_tag = .{ .name = name } };
            },
            .comment => |c| {
                const data = try allocator.dupe(u8, c.data);
                return Token{ .comment = .{ .data = data } };
            },
            .character, .eof => return self,
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
