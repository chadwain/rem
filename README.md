# rem
rem is an HTML5 parser written in [Zig](https://ziglang.org).

## About
### Features
- [x] An HTML5 parser consisting of a tokenizer (complete) and a tree constructor (works "well enough")
- [x] A minimal DOM implementation
- [x] HTML fragment parsing
- [x] Tested by [html5lib-tests](https://github.com/html5lib/html5lib-tests)

### Things to be improved
- [ ] Better DOM functionality
- [ ] Support for more character encodings
- [ ] Support for Javascript

### Why create this?
* To understand what it takes "implement" HTML, even if just a small portion of it. As I discovered, even just trying to parse an HTML file _correctly_ can be quite challenging.
* To learn more about web standards in general. Reading the HTML spec naturally causes (or rather, forces) one to learn about DOM (especially), SVG, CSS, and many others.
* For use in other projects, and to be useful to others.

### Lastly...
rem is still a work in progress. Not all the features of a fully-capable HTML5 parser are implemented.

## Get the code
Clone the repository like this:
```
git clone --recursive --config core.autocrlf=false https://github.com/chwayne/rem.git
```
There is also a [GitLab mirror](https://gitlab.com/chwayne/rem).

There are no dependencies other than a Zig compiler. You should use the latest version of Zig that is available.

## Use the code
Before using rem, you must run `zig build gen-named-characters-trie`. This creates `tools/named_characters_trie.zig`, which has some data that is required for the parser to work. This only needs to be done once.

Here's an example of using the parser (you can also see the output of this program by running `zig build example`).

```zig
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
```

## Test the code
Note: Before running any tests, be sure that you have already done `zig build gen-named-characters-trie`.

rem uses (a fork of) [html5lib-tests](https://github.com/html5lib/html5lib-tests) as a test suite. Specifically, it tests against the 'tokenizer' and 'tree-construction' tests from that suite. 

`zig build test-tokenizer` will run the 'tokenizer' tests.
`zig build test-tree-construction` will run the 'tree-construction' tests in 2 ways: with scripting off, then with scripting on.
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
