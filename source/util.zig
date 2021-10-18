// Copyright (C) 2021 Chadwain Holness
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

const std = @import("std");
const Allocator = std.mem.Allocator;
const StringHashMapUnmanaged = std.StringHashMapUnmanaged;

pub fn freeStringHashMap(map: *StringHashMapUnmanaged([]u8), allocator: *Allocator) void {
    var iterator = map.iterator();
    while (iterator.next()) |attr| {
        allocator.free(attr.key_ptr.*);
        allocator.free(attr.value_ptr.*);
    }
    map.deinit(allocator);
}

pub fn eqlNullSlices(comptime T: type, slice1: ?[]const T, slice2: ?[]const T) bool {
    if (slice1) |a| {
        const b = slice2 orelse return false;
        return std.mem.eql(T, a, b);
    } else {
        return slice2 == null;
    }
}

pub fn utf8DecodeComptimeLen(comptime string: []const u8) usize {
    var i: usize = 0;
    var decoded_len: usize = 0;
    while (i < string.len) {
        i += std.unicode.utf8ByteSequenceLength(string[i]) catch unreachable;
        decoded_len += 1;
    }
    return decoded_len;
}

pub fn utf8DecodeComptime(comptime string: []const u8) [utf8DecodeComptimeLen(string)]u21 {
    var result: [utf8DecodeComptimeLen(string)]u21 = undefined;
    if (result.len == 0) return result;
    var decoded_it = std.unicode.Utf8View.initComptime(string).iterator();
    var i: usize = 0;
    while (decoded_it.nextCodepoint()) |codepoint| {
        result[i] = codepoint;
        i += 1;
    }
    return result;
}
