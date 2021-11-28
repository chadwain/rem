// Copyright (C) 2021 Chadwain Holness
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

const std = @import("std");
const rem = @import("rem");
const allocator = std.testing.allocator;

pub fn main() !u8 {
    const string = "<!doctype html><html><body>Click here to download more RAM!";
    // The string must be decoded before it can be passed to the parser.
    const input = &rem.util.utf8DecodeStringComptime(string);

    // Create the DOM in which the parsed Document will be created.
    var dom = rem.dom.Dom{ .allocator = allocator };
    defer dom.deinit();

    var parser = try rem.Parser.init(&dom, input, allocator, .abort, false);
    defer parser.deinit();
    try parser.run();

    const errors = parser.errors();
    if (errors.len > 0) {
        std.log.err("A parsing error occured!\n{s}\n", .{@tagName(errors[0])});
        return 1;
    }

    const writer = std.io.getStdOut().writer();
    const document = parser.getDocument();
    try rem.util.printDocument(writer, document, &dom, allocator);
    return 0;
}
