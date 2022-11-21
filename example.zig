// Copyright (C) 2021 Chadwain Holness
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

const std = @import("std");
const rem = @import("rem");

pub fn main() !u8 {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const stdin = std.io.getStdIn();
    const stdout = std.io.getStdOut().writer();
    const stderr = std.io.getStdErr().writer();

    var byte_buffer: [1024]u8 = undefined;
    var byte_buffer_len: usize = 0;
    var decoded = std.ArrayListUnmanaged(u21){};
    defer decoded.deinit(allocator);
    while (b: {
        byte_buffer_len += try stdin.read(byte_buffer[byte_buffer_len..]);
        break :b byte_buffer_len != 0;
    }) {
        var byte_buffer_index: usize = 0;
        while (byte_buffer_index < byte_buffer_len) {
            const seq_len = std.unicode.utf8ByteSequenceLength(byte_buffer[byte_buffer_index]) catch |err| {
                stderr.print("{s}\n", .{@errorName(err)}) catch {};
                return 1;
            };
            if (byte_buffer_index + seq_len > byte_buffer_len) break;
            const codepoint = std.unicode.utf8Decode(byte_buffer[byte_buffer_index..][0..seq_len]) catch |err| {
                stderr.print("{s}\n", .{@errorName(err)}) catch {};
                return 1;
            };
            byte_buffer_index += seq_len;
            try decoded.append(allocator, codepoint);
        }
        const leftover = byte_buffer[byte_buffer_index..byte_buffer_len];
        std.mem.copy(u8, byte_buffer[0..leftover.len], leftover);
        byte_buffer_len = leftover.len;
    }

    // Create the DOM in which the parsed Document will be created.
    var dom = rem.dom.Dom{ .allocator = allocator };
    defer dom.deinit();

    var parser = try rem.Parser.init(&dom, decoded.items, allocator, .report, false);
    defer parser.deinit();
    try parser.run();

    const errors = parser.errors();
    for (errors) |e| {
        try stderr.print("Parse error: {s}\n", .{@tagName(e)});
    }

    const document = parser.getDocument();
    try rem.util.printDocument(stdout, document, &dom, allocator);
    return 0;
}
