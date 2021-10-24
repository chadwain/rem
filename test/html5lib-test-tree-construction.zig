const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;

const expect = std.testing.expect;
const expectEqual = std.testing.expectEqual;
const expectEqualStrings = std.testing.expectEqualStrings;

const html5 = @import("html5");
const Dom = html5.dom;
const Tokenizer = html5.Tokenizer;
const TreeConstructor = html5.tree_construction.TreeConstructor;
const Parser = html5.Parser;
const FragmentParser = html5.FragmentParser;

fn eql(str1: []const u8, str2: []const u8) bool {
    return std.mem.eql(u8, str1, str2);
}

fn startsWith(str1: []const u8, str2: []const u8) bool {
    return std.mem.startsWith(u8, str1, str2);
}

fn endsWith(str1: []const u8, str2: []const u8) bool {
    return std.mem.endsWith(u8, str1, str2);
}

test {
    try runTestFile("test/html5lib-tests/tree-construction/tests1.dat");
}

fn runTestFile(file_path: []const u8) !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    //defer assert(!gpa.deinit());
    const allocator = &gpa.allocator;

    const contents = try std.fs.cwd().readFileAlloc(allocator, file_path, std.math.maxInt(usize));
    defer allocator.free(contents);

    var tests = std.mem.split(u8, contents[0 .. contents.len - 1], "\n\n");
    var count: usize = 1;
    while (tests.next()) |t| {
        defer count += 1;
        const the_test = createTest(t, allocator) catch |err| switch (err) {
            error.SkipTest => {
                std.debug.print("Test {} skipped.\n\n", .{count});
                continue;
            },
            else => return err,
        };
        switch (the_test.script) {
            .on => {
                std.debug.print("\n\nTest {} scripting: on\n", .{count});
                try runTest(the_test, allocator, true);
            },
            .off => {
                std.debug.print("\n\nTest {} scripting: off\n", .{count});
                try runTest(the_test, allocator, false);
            },
            .both => {
                std.debug.print("\n\nTest {} scripting: off\n", .{count});
                try runTest(the_test, allocator, false);
                std.debug.print("\n\nTest {} scripting: on\n", .{count});
                try runTest(the_test, allocator, true);
            },
        }
        std.debug.print("\n\n", .{});
    }
}

const Expected = union(enum) {
    dom: Dom.Dom,
    fragment: Dom.Element,
};

const Test = struct {
    input: []const u8,
    errors: usize,
    new_errors: usize,
    script: ScriptOption,
    expected: Expected,

    const ScriptOption = enum { on, off, both };
};

fn createTest(test_string: []const u8, allocator: *Allocator) error{ OutOfMemory, SkipTest }!Test {
    var lines = std.mem.split(u8, test_string, "\n");
    var section = lines.next().?;

    assert(eql(section, "#data"));
    var data: []const u8 = lines.rest()[0..0];
    while (!startsWith(lines.rest(), "#errors")) {
        data.len += lines.next().?.len + 1;
    }
    if (data.len > 0) data.len -= 1;
    section = lines.next().?;
    //std.debug.print("#data\n{s}\n", .{data});

    assert(eql(section, "#errors"));
    var errors: []const u8 = lines.rest()[0..0];
    while (!startsWith(lines.rest(), "#")) {
        errors.len += lines.next().?.len + 1;
    }
    section = lines.next().?;
    //std.debug.print("#errors\n{s}", .{errors});

    var new_errors: []const u8 = lines.rest()[0..0];
    if (startsWith(section, "#new-errors")) {
        while (!startsWith(lines.rest(), "#")) {
            new_errors.len += lines.next().?.len + 1;
        }
        section = lines.next().?;
        //std.debug.print("#new-errors\n{s}", .{new_errors});
    }

    var document_fragment: []const u8 = lines.rest()[0..0];
    var context_element_type: ?Dom.ElementType = null;
    if (startsWith(section, "#document-fragment")) {
        document_fragment = lines.next().?;
        if (startsWith(document_fragment, "svg ") or startsWith(document_fragment, "math ")) {
            std.debug.print("TODO: Document fragment in non-html namespace: {s}\n", .{document_fragment});
            return error.SkipTest;
        }
        context_element_type = Dom.ElementType.fromStringHtml(document_fragment) orelse .custom_html;
        section = lines.next().?;
        //std.debug.print("#document-fragment\n{s}\n", .{document_fragment});
    }

    var script: Test.ScriptOption = .both;
    if (startsWith(section, "#script")) {
        if (eql(section, "#script-off")) {
            script = .off;
        } else if (eql(section, "#script-on")) {
            script = .on;
        } else {
            unreachable;
        }
        section = lines.next().?;
    }
    //std.debug.print("#script-{s}\n", .{@tagName(script)});

    assert(eql(section, "#document"));
    var document: []const u8 = lines.rest();
    //std.debug.print("#document\n{s}\n", .{document});

    var expected = try parseDomTree(document, context_element_type, allocator);
    //var stderr = std.io.getStdErr().writer();
    //try Dom.printDom(dom, stderr, allocator);

    return Test{
        .input = data,
        .errors = std.mem.count(u8, errors, "\n"),
        .new_errors = std.mem.count(u8, new_errors, "\n"),
        .script = script,
        .expected = expected,
    };
}

fn parseDomTree(string: []const u8, fragment: ?Dom.ElementType, allocator: *Allocator) !Expected {
    var stack = ArrayList(*Dom.Element).init(allocator);
    defer stack.deinit();

    var result = if (fragment) |f|
        Expected{ .fragment = Dom.Element{
            .element_type = f,
            .parent = null,
            .attributes = .{},
            .children = .{},
        } }
    else
        Expected{
            .dom = Dom.Dom{ .allocator = allocator },
        };

    var lines = std.mem.split(u8, string, "\n");
    while (lines.next()) |line| {
        assert(startsWith(line, "| "));
        var first_char: usize = 2;
        while (line[first_char] == ' ') {
            first_char += 1;
        }
        const depth = @divExact(first_char, 2) - 1;
        assert(depth <= stack.items.len);
        if (depth < stack.items.len) {
            stack.shrinkRetainingCapacity(depth);
        }
        const data = line[first_char..];

        if (startsWith(data, "<!DOCTYPE ")) {
            // doctype
            assert(stack.items.len == 0);
            const name_start = "<!DOCTYPE ".len;
            const name_end = std.mem.indexOfAnyPos(u8, data, name_start, " >").?;
            const name = data[name_start..name_end];
            if (data[name_end] == ' ') {
                assert(data[name_end + 1] == '"');
                const public_id_endquote = std.mem.indexOfScalarPos(u8, data, name_end + 2, '"').?;
                const public_id = data[name_end + 2 .. public_id_endquote];
                assert(data[public_id_endquote + 1] == ' ');
                assert(data[public_id_endquote + 2] == '"');
                const system_id_endquote = std.mem.indexOfScalarPos(u8, data, public_id_endquote + 3, '"').?;
                const system_id = data[public_id_endquote + 3 .. system_id_endquote];
                _ = try result.dom.document.insertDocumentType(allocator, name, public_id, system_id);
            } else {
                _ = try result.dom.document.insertDocumentType(allocator, name, null, null);
            }
        } else if (startsWith(data, "<!-- ")) {
            // comment
            assert(endsWith(data, " -->"));
            const comment = data["<!-- ".len .. data.len - " -->".len];
            if (depth == 0) {
                switch (result) {
                    .dom => |*dom| try dom.document.insertCharacterData(allocator, comment, .comment),
                    .fragment => |*e| {
                        const cdata = try allocator.create(Dom.CharacterData);
                        errdefer allocator.destroy(cdata);
                        cdata.* = .{ .interface = .comment };
                        errdefer cdata.deinit(allocator);
                        try cdata.append(allocator, comment);
                        try Dom.mutation.elementAppend(dom, e, .{ .cdata = cdata }, .Suppress);
                    },
                }
            } else {
                try stack.items[depth - 1].insertCharacterData(allocator, comment, .comment);
            }
        } else if (startsWith(data, "<?")) {
            // processing instruction
            @panic("TODO Parse processing instructions");
        } else if (data[0] == '<') {
            // element
            assert(data[data.len - 1] == '>');
            const tag_name = data[1 .. data.len - 1];

            var element_type: Dom.ElementType = undefined;
            if (startsWith(tag_name, "svg ")) {
                @panic("Element in the SVG namespace");
            } else if (startsWith(tag_name, "math ")) {
                @panic("Element in the MathML namespace");
            } else {
                element_type = Dom.ElementType.fromStringHtml(tag_name) orelse @panic("Unknown HTML element or custom element");
            }

            const element = try allocator.create(Dom.Element);
            errdefer allocator.destroy(element);
            element.* = Dom.Element{
                .element_type = element_type,
                .parent = null,
                .attributes = .{},
                .children = .{},
            };
            errdefer element.deinit(allocator);
            try stack.append(if (depth == 0)
                switch (result) {
                    .dom => |*dom| dom.document.insertElement(element),
                    .fragment => |*e| try Dom.mutation.elementAppend(dom, e, .{ .element = element }, .Suppress),
                }
            else
                try stack.items[stack.items.len - 1].insertElement(allocator, element));
        } else if (data[0] == '"') {
            // text
            var text: []const u8 = undefined;
            var rest = lines.rest();
            if (startsWith(rest, "| ")) {
                assert(data[data.len - 1] == '"');
                text = data[1 .. data.len - 1];
            } else {
                text = data.ptr[1 .. 1 + data.len];
                while (rest.len > 0 and !startsWith(rest, "| ")) {
                    text.len += lines.next().?.len + 1;
                    rest = lines.rest();
                } else {
                    assert(endsWith(text, "\"\n"));
                    text.len -= 2;
                }
            }
            if (depth == 0) {
                switch (result) {
                    .dom => unreachable,
                    .fragment => |*e| try e.insertCharacterData(allocator, text, .text),
                }
            } else {
                try stack.items[stack.items.len - 1].insertCharacterData(allocator, text, .text);
            }
        } else if (eql(data, "content")) {
            // template contents
            @panic("TODO Template contents");
        } else {
            // attribute
            assert(depth == stack.items.len);
            const eql_sign = std.mem.indexOfScalar(u8, data, '=').?;
            assert(data[eql_sign + 1] == '"');
            assert(data[data.len - 1] == '"');
            const attribute_name = data[0..eql_sign];
            const value = data[eql_sign + 2 .. data.len - 1];

            if (startsWith(attribute_name, "xlink ")) {
                @panic("TODO Attribute namespaces: xlink");
            } else if (startsWith(attribute_name, "xml ")) {
                @panic("TODO Attribute namespaces: xml");
            } else if (startsWith(attribute_name, "xmlns ")) {
                @panic("TODO Attribute namespaces: xmlns");
            } else {
                try stack.items[stack.items.len - 1].addAttribute(allocator, attribute_name, value);
            }
        }
    }

    return result;
}

fn runTest(t: Test, allocator: *Allocator, scripting: bool) !void {
    const input = input: {
        var list = ArrayList(u21).init(allocator);
        errdefer list.deinit();
        var i: usize = 0;
        while (i < t.input.len) {
            const len = std.unicode.utf8ByteSequenceLength(t.input[i]) catch unreachable;
            const value = std.unicode.utf8Decode(t.input[i .. i + len]) catch unreachable;
            try list.append(value);
            i += len;
        }
        break :input list.toOwnedSlice();
    };
    defer allocator.free(input);

    switch (t.expected) {
        .dom => {
            var result_dom = Dom.Dom{ .allocator = allocator };
            var parser = Parser.init(&result_dom, input, allocator);
            try parser.run();
        },
        .fragment => |e| {
            var context_element = Dom.Element{
                .element_type = e.element_type,
                .parent = null,
                .attributes = .{},
                .children = .{},
            };
            // TODO Set the scripting flag.
            var parser = try FragmentParser.init(&context_element, input, allocator, scripting, .no_quirks);
            try parser.run();

            const html = parser.inner.constructor.open_elements.items[0];
            assert(html.element_type == .html_html);
            try expectEqual(e.children.items.len, html.children.items.len);
            for (e.children.items) |e_child, i| {
                const html_child = html.children.items[i];
                switch (e_child) {
                    .element => {
                        try expect(html_child == .element);
                        try deeplyCompareElements(allocator, e_child.element, html_child.element);
                    },
                    .cdata => {
                        try expect(html_child == .cdata);
                        try expectEqualCdatas(e_child.cdata, html_child.cdata);
                    },
                }
            }
        },
    }
}

fn deeplyCompareElements(allocator: *Allocator, element1: *const Dom.Element, element2: *const Dom.Element) !void {
    const ElementPair = struct {
        e1: *const Dom.Element,
        e2: *const Dom.Element,
    };

    var stack = ArrayList(ElementPair).init(allocator);
    defer stack.deinit();
    try stack.append(.{ .e1 = element1, .e2 = element2 });

    while (stack.items.len > 0) {
        const pair = stack.pop();

        try expectEqualElements(pair.e1, pair.e2);
        try expectEqual(pair.e1.children.items.len, pair.e2.children.items.len);
        var i = pair.e1.children.items.len;
        while (i > 0) : (i -= 1) {
            const e1_child = pair.e1.children.items[i - 1];
            const e2_child = pair.e2.children.items[i - 1];
            switch (e1_child) {
                .element => {
                    try expect(e2_child == .element);
                    try stack.append(.{ .e1 = e1_child.element, .e2 = e2_child.element });
                },
                .cdata => {
                    try expect(e2_child == .cdata);
                    try expectEqualCdatas(e1_child.cdata, e2_child.cdata);
                },
            }
        }
    }
}

fn expectEqualElements(e1: *const Dom.Element, e2: *const Dom.Element) !void {
    // TODO: If the element type has an interface associated with it, check that for equality too.
    try expectEqual(e1.element_type, e2.element_type);
    try expect(html5.util.eqlStringHashMaps(e1.attributes, e2.attributes));
}

fn expectEqualCdatas(c1: *const Dom.CharacterData, c2: *const Dom.CharacterData) !void {
    try expectEqual(c1.interface, c2.interface);
    try expectEqualStrings(c1.data.items, c2.data.items);
}
