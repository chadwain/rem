# html5-parser
rem is an HTML5 parser written in [Zig](https://ziglang.org).

## Get the code
Clone the repository like this:
```
git clone --recursive --config core.autocrlf=false https://github.com/chwayne/rem.git
```
There are no dependencies other than a Zig compiler. You should use the latest version of Zig that is available.

## Use the code
Before doing anything, you should run `zig build gen-named-characters`. This creates `tools/named_character_references.zig`, which contains some data that is required for the parser to work. This only needs to be done once.

Here's an example of using the parser (you can also see the output of this program by running `zig build example`).

```zig
const std = @import("std");
const rem = @import("rem");
const allocator = std.testing.allocator;

pub fn main() !void {
    const string = "<!doctype html><html><body>Click here to download more RAM!";
    // The string must be decoded before it can be passed to the parser.
    const input = &rem.util.utf8DecodeStringComptime(string);

    // Create the DOM in which the parsed Document will be created.
    var dom = rem.dom.DomTree{ .allocator = allocator };
    defer dom.deinit();

    var parser = try rem.Parser.init(&dom, input, allocator, false);
    defer parser.deinit();
    try parser.run();

    const writer = std.io.getStdOut().writer();
    try rem.util.printDocument(writer, parser.getDocument(), &dom, allocator);
}
```

## Test the code
Note: Before running any tests, be sure that you have already done `zig build gen-named-characters`.

rem uses (a fork of) [html5lib-tests](https://github.com/html5lib/html5lib-tests) as a test suite. Specifically, it tests against the 'tokenizer' and 'tree-construction' tests from that suite. 

`zig build test-tokenizer` will run the 'tokenizer' tests.
`zig build test-tree-constructor` will run the 'tree-construction' tests in 2 ways: with scripting off, then with scripting on.
The expected results are as follows:
- tokenizer: All tests pass.
- tree-construction with scripting off: Some tests are skipped because they rely on HTML features that aren't yet implemented in this library (namely templates and namespaced element attributes). All other tests pass.
- tree-construction with scripting on: Similar to testing with scripting off, but in addition, some entire test files are skipped because they would cause a crash.

## License
### GPL-3.0-only
Copyright (C) 2021 Chadwain Holness

rem is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3.

This library is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this library.  If not, see <https://www.gnu.org/licenses/>.

## References
[HTML Parsing Specification](https://html.spec.whatwg.org/multipage/parsing.html)

[DOM Specification](https://dom.spec.whatwg.org/)

