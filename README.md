# rem
rem is an HTML5 parser written in [Zig](https://ziglang.org).

## About
### Features
- [x] An HTML5 parser consisting of a tokenizer (complete) and a tree constructor (works "well enough")
- [x] A minimal DOM implementation
- [x] HTML fragment parsing
- [x] Tested by [html5lib-tests](https://github.com/chadwain/html5lib-tests)

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
git clone --recursive --config core.autocrlf=false https://github.com/chadwain/rem.git
```

**Using the Zig Package Manager**
```
zig fetch --save https://github.com/chadwain/rem/archive/refs/heads/master.tar.gz
```

There are no dependencies other than a Zig compiler. Note that this library is only compatible with Zig version 0.11.0 or newer.

## Use the code
Here's an example of using the parser. You can see the output of this program by running `zig build example`.

```zig
const std = @import("std");
const rem = @import("rem");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer std.debug.assert(gpa.deinit() == .ok);
    const allocator = gpa.allocator();

    // This is the text that will be read by the parser.
    // Since the parser accepts Unicode codepoints, the text must be decoded before it can be used.
    const input = "<!doctype html><html><h1 style=bold>Your text goes here!</h1>";
    const decoded_input = &rem.util.utf8DecodeStringComptime(input);

    // Create the DOM in which the parsed Document will be created.
    var dom = rem.Dom{ .allocator = allocator };
    defer dom.deinit();

    // Create the HTML parser.
    var parser = try rem.Parser.init(&dom, decoded_input, allocator, .report, false);
    defer parser.deinit();

    // This causes the parser to read the input and produce a Document.
    try parser.run();

    // `errors` returns the list of parse errors that were encountered while parsing.
    // Since we know that our input was well-formed HTML, we expect there to be 0 parse errors.
    const errors = parser.errors();
    std.debug.assert(errors.len == 0);

    // We can now print the resulting Document to the console.
    const stdout = std.io.getStdOut().writer();
    const document = parser.getDocument();
    try rem.util.printDocument(stdout, document, &dom, allocator);
}
```

## Test the code
rem uses [html5lib-tests](https://github.com/html5lib/html5lib-tests) as a test suite. Specifically, it tests against the 'tokenizer' and 'tree-construction' tests from that suite. 

`zig build test-tokenizer` will run the 'tokenizer' tests.
`zig build test-tree-construction` will run the 'tree-construction' tests in 2 ways: with scripting disabled, then with scripting enabled.
The expected results are as follows:
- tokenizer: All tests pass.
- tree-construction (scripting disabled): Some tests are skipped because they rely on HTML features that aren't yet implemented in this library (specifically, templates). All other tests pass.
- tree-construction (scripting enabled): Similar to testing with scripting off, but in addition, some entire test files are skipped because they would cause panics.

## License
### GPL-3.0-only
Copyright (C) 2021-2023 Chadwain Holness

rem is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3.

This library is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this library.  If not, see <https://www.gnu.org/licenses/>.

## References
[HTML Parsing Specification](https://html.spec.whatwg.org/multipage/parsing.html)

[DOM Specification](https://dom.spec.whatwg.org/)
