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

//test {
//    try runTestFile("test/html5lib-tests/tree-construction/tests2.dat");
//}

test {
    try runTestFile("test/html5lib-tests/tree-construction/tests3.dat");
}

test {
    try runTestFile("test/html5lib-tests/tree-construction/tests4.dat");
}

test {
    try runTestFile("test/html5lib-tests/tree-construction/tests5.dat");
}

test {
    try runTestFile("test/html5lib-tests/tree-construction/tests6.dat");
}

test {
    try runTestFile("test/html5lib-tests/tree-construction/tests7.dat");
}

//test {
//    try runTestFile("test/html5lib-tests/tree-construction/tests8.dat");
//}

//test {
//    try runTestFile("test/html5lib-tests/tree-construction/tests9.dat");
//}

//test {
//    try runTestFile("test/html5lib-tests/tree-construction/tests10.dat");
//}

//test {
//    try runTestFile("test/html5lib-tests/tree-construction/tests11.dat");
//}

//test {
//    try runTestFile("test/html5lib-tests/tree-construction/tests12.dat");
//}

//test {
//    try runTestFile("test/html5lib-tests/tree-construction/tests14.dat");
//}

test {
    try runTestFile("test/html5lib-tests/tree-construction/tests15.dat");
}

//test {
//    try runTestFile("test/html5lib-tests/tree-construction/tests16.dat");
//}

test {
    try runTestFile("test/html5lib-tests/tree-construction/tests17.dat");
}

//test {
//    try runTestFile("test/html5lib-tests/tree-construction/tests18.dat");
//}

//test {
//    try runTestFile("test/html5lib-tests/tree-construction/tests19.dat");
//}

//test {
//    try runTestFile("test/html5lib-tests/tree-construction/tests20.dat");
//}

//test {
//    try runTestFile("test/html5lib-tests/tree-construction/tests21.dat");
//}

test {
    try runTestFile("test/html5lib-tests/tree-construction/tests22.dat");
}

test {
    try runTestFile("test/html5lib-tests/tree-construction/tests23.dat");
}

test {
    try runTestFile("test/html5lib-tests/tree-construction/tests24.dat");
}

test {
    try runTestFile("test/html5lib-tests/tree-construction/tests25.dat");
}

//test {
//    try runTestFile("test/html5lib-tests/tree-construction/tests26.dat");
//}

fn runTestFile(file_path: []const u8) !void {
    const allocator = std.testing.allocator;

    const contents = try std.fs.cwd().readFileAlloc(allocator, file_path, std.math.maxInt(usize));
    defer allocator.free(contents);

    var tests = contents;
    var count: usize = 1;
    while (tests.len > 0) {
        defer count += 1;
        var the_test = createTest(&tests, allocator) catch |err| switch (err) {
            error.SkipTest => {
                std.debug.print("Test {} skipped.\n", .{count});
                continue;
            },
            else => return err,
        };
        defer the_test.expected.deinit();

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
        std.debug.print("\n", .{});
    }
}

const Expected = struct {
    dom: Dom.Dom,
    fragment_context: ?*Dom.Element,

    fn deinit(self: *@This()) void {
        self.dom.deinit();
    }
};

const Test = struct {
    input: []const u8,
    errors: usize,
    new_errors: usize,
    script: ScriptOption,
    expected: Expected,

    const ScriptOption = enum { on, off, both };
};

fn createTest(test_string: *[]const u8, allocator: *Allocator) error{ OutOfMemory, SkipTest }!Test {
    var lines = std.mem.split(u8, test_string.*, "\n");
    defer test_string.* = lines.rest();
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
    //var document: []const u8 = lines.rest();
    //std.debug.print("#document\n{s}\n", .{document});

    var expected = parseDomTree(&lines, context_element_type, allocator) catch |err| switch (err) {
        error.DomException => unreachable,
        else => |e| return e,
    };
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

fn parseDomTree(lines: *std.mem.SplitIterator(u8), context_element_type: ?Dom.ElementType, allocator: *Allocator) !Expected {
    var stack = ArrayList(*Dom.Element).init(allocator);
    defer stack.deinit();

    var dom = Dom.Dom{ .allocator = allocator };
    errdefer dom.deinit();
    const fragment_context = if (context_element_type) |ty| try dom.makeElement(ty) else null;

    while (lines.next()) |line| {
        if (line.len == 0) {
            break;
        }
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

            const doctype = if (data[name_end] == ' ') blk: {
                assert(data[name_end + 1] == '"');
                const public_id_endquote = std.mem.indexOfScalarPos(u8, data, name_end + 2, '"').?;
                const public_id = data[name_end + 2 .. public_id_endquote];
                assert(data[public_id_endquote + 1] == ' ');
                assert(data[public_id_endquote + 2] == '"');
                const system_id_endquote = std.mem.indexOfScalarPos(u8, data, public_id_endquote + 3, '"').?;
                const system_id = data[public_id_endquote + 3 .. system_id_endquote];

                break :blk try dom.makeDoctype(name, public_id, system_id);
            } else try dom.makeDoctype(name, null, null);
            try Dom.mutation.documentAppendDocumentType(&dom, &dom.document, doctype, .Suppress);
        } else if (startsWith(data, "<!-- ")) {
            // comment
            assert(endsWith(data, " -->"));
            const comment = data["<!-- ".len .. data.len - " -->".len];
            const cdata = try dom.makeCdata(comment, .comment);
            if (depth == 0) {
                if (fragment_context) |e| {
                    try Dom.mutation.elementAppend(&dom, e, .{ .cdata = cdata }, .Suppress);
                } else {
                    try Dom.mutation.documentAppendCdata(&dom, &dom.document, cdata, .Suppress);
                }
            } else {
                try Dom.mutation.elementAppend(&dom, stack.items[depth - 1], .{ .cdata = cdata }, .Suppress);
            }
        } else if (startsWith(data, "<?")) {
            // processing instruction
            @panic("TODO Parse processing instructions");
        } else if (data[0] == '<') {
            // element
            assert(data[data.len - 1] == '>');
            const tag_name = data[1 .. data.len - 1];

            var element: *Dom.Element = undefined;
            if (startsWith(tag_name, "svg ")) {
                element = try dom.makeElement(.custom_svg);
                // TODO Try to find an element type from the tag name.
                try dom.registerLocalName(element, tag_name[4..]);
            } else if (startsWith(tag_name, "math ")) {
                element = try dom.makeElement(.custom_mathml);
                // TODO Try to find an element type from the tag name.
                try dom.registerLocalName(element, tag_name[5..]);
            } else {
                const maybe_element_type = Dom.ElementType.fromStringHtml(tag_name);
                if (maybe_element_type) |t| {
                    element = try dom.makeElement(t);
                } else {
                    element = try dom.makeElement(.custom_html);
                    try dom.registerLocalName(element, tag_name);
                }
            }

            if (depth == 0) {
                if (fragment_context) |e| {
                    try Dom.mutation.elementAppend(&dom, e, .{ .element = element }, .Suppress);
                } else {
                    try Dom.mutation.documentAppendElement(&dom, &dom.document, element, .Suppress);
                }
            } else {
                try Dom.mutation.elementAppend(&dom, stack.items[stack.items.len - 1], .{ .element = element }, .Suppress);
            }
            try stack.append(element);
        } else if (data[0] == '"') {
            // text
            var text: []const u8 = data[0..0];
            var my_line = data;
            while (true) {
                text.len += my_line.len + 1;
                if (text.len > 2 and endsWith(my_line, "\"")) {
                    text = text[1 .. text.len - 2];
                    break;
                }
                my_line = lines.next().?;
            }

            const cdata = try dom.makeCdata(text, .text);
            if (depth == 0) {
                try Dom.mutation.elementAppend(&dom, fragment_context.?, .{ .cdata = cdata }, .Suppress);
            } else {
                try Dom.mutation.elementAppend(&dom, stack.items[stack.items.len - 1], .{ .cdata = cdata }, .Suppress);
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

    return Expected{ .dom = dom, .fragment_context = fragment_context };
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

    if (t.expected.fragment_context) |e| {
        var context_element = Dom.Element{
            .element_type = e.element_type,
            .parent = null,
            .attributes = .{},
            .children = .{},
        };
        // TODO Set the scripting flag.
        var parser = try FragmentParser.init(&context_element, input, allocator, scripting, .no_quirks);
        defer parser.deinit();
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
    } else {
        var result_dom = Dom.Dom{ .allocator = allocator };
        defer result_dom.deinit();

        var parser = Parser.init(&result_dom, input, allocator);
        defer parser.deinit();
        try parser.run();
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
