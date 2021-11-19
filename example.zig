const std = @import("std");
const html5 = @import("html5");
const allocator = std.testing.allocator;

pub fn main() !void {
    const string = "<!doctype html><html><body>Click here to download more RAM!";
    // The string must be decoded before it can be passed to the parser.
    const input = &html5.util.utf8DecodeStringComptime(string);

    // Create the DOM in which the parsed Document will be created.
    var dom = html5.dom.DomTree{ .allocator = allocator };
    defer dom.deinit();

    var parser = try html5.Parser.init(&dom, input, allocator, false);
    defer parser.deinit();
    try parser.run();

    const writer = std.io.getStdOut().writer();
    try html5.util.printDocument(writer, parser.getDocument(), &dom, allocator);
}
