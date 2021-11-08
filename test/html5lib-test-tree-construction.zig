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

fn eql(str1: []const u8, str2: []const u8) bool {
    return std.mem.eql(u8, str1, str2);
}

fn startsWith(str1: []const u8, str2: []const u8) bool {
    return std.mem.startsWith(u8, str1, str2);
}

fn endsWith(str1: []const u8, str2: []const u8) bool {
    return std.mem.endsWith(u8, str1, str2);
}

test "html5lib-tests tree construction without scripting" {
    try runTestFile("test/html5lib-tests/tree-construction/adoption01.dat", false);
    try runTestFile("test/html5lib-tests/tree-construction/adoption02.dat", false);
    try runTestFile("test/html5lib-tests/tree-construction/blocks.dat", false);
    try runTestFile("test/html5lib-tests/tree-construction/comments01.dat", false);
    try runTestFile("test/html5lib-tests/tree-construction/doctype01.dat", false);
    try runTestFile("test/html5lib-tests/tree-construction/domjs-unsafe.dat", false);
    try runTestFile("test/html5lib-tests/tree-construction/entities01.dat", false);
    try runTestFile("test/html5lib-tests/tree-construction/entities02.dat", false);
    try runTestFile("test/html5lib-tests/tree-construction/foreign-fragment.dat", false);
    try runTestFile("test/html5lib-tests/tree-construction/html5test-com.dat", false);
    try runTestFile("test/html5lib-tests/tree-construction/inbody01.dat", false);
    try runTestFile("test/html5lib-tests/tree-construction/isindex.dat", false);
    try runTestFile("test/html5lib-tests/tree-construction/main-element.dat", false);
    try runTestFile("test/html5lib-tests/tree-construction/math.dat", false);
    try runTestFile("test/html5lib-tests/tree-construction/menuitem-element.dat", false);
    try runTestFile("test/html5lib-tests/tree-construction/namespace-sensitivity.dat", false);
    try runTestFile("test/html5lib-tests/tree-construction/noscript01.dat", false);
    try runTestFile("test/html5lib-tests/tree-construction/pending-spec-changes-plain-text-unsafe.dat", false);
    try runTestFile("test/html5lib-tests/tree-construction/pending-spec-changes.dat", false);
    try runTestFile("test/html5lib-tests/tree-construction/plain-text-unsafe.dat", false);
    try runTestFile("test/html5lib-tests/tree-construction/ruby.dat", false);
    try runTestFile("test/html5lib-tests/tree-construction/scriptdata01.dat", false);
    try runTestFile("test/html5lib-tests/tree-construction/svg.dat", false);
    try runTestFile("test/html5lib-tests/tree-construction/tables01.dat", false);
    try runTestFile("test/html5lib-tests/tree-construction/template.dat", false);
    try runTestFile("test/html5lib-tests/tree-construction/tests1.dat", false);
    try runTestFile("test/html5lib-tests/tree-construction/tests2.dat", false);
    try runTestFile("test/html5lib-tests/tree-construction/tests3.dat", false);
    try runTestFile("test/html5lib-tests/tree-construction/tests4.dat", false);
    try runTestFile("test/html5lib-tests/tree-construction/tests5.dat", false);
    try runTestFile("test/html5lib-tests/tree-construction/tests6.dat", false);
    try runTestFile("test/html5lib-tests/tree-construction/tests7.dat", false);
    try runTestFile("test/html5lib-tests/tree-construction/tests8.dat", false);
    try runTestFile("test/html5lib-tests/tree-construction/tests9.dat", false);
    try runTestFile("test/html5lib-tests/tree-construction/tests10.dat", false);
    try runTestFile("test/html5lib-tests/tree-construction/tests11.dat", false);
    try runTestFile("test/html5lib-tests/tree-construction/tests12.dat", false);
    try runTestFile("test/html5lib-tests/tree-construction/tests14.dat", false);
    try runTestFile("test/html5lib-tests/tree-construction/tests15.dat", false);
    try runTestFile("test/html5lib-tests/tree-construction/tests16.dat", false);
    try runTestFile("test/html5lib-tests/tree-construction/tests17.dat", false);
    try runTestFile("test/html5lib-tests/tree-construction/tests18.dat", false);
    try runTestFile("test/html5lib-tests/tree-construction/tests19.dat", false);
    try runTestFile("test/html5lib-tests/tree-construction/tests20.dat", false);
    try runTestFile("test/html5lib-tests/tree-construction/tests21.dat", false);
    try runTestFile("test/html5lib-tests/tree-construction/tests22.dat", false);
    try runTestFile("test/html5lib-tests/tree-construction/tests23.dat", false);
    try runTestFile("test/html5lib-tests/tree-construction/tests24.dat", false);
    try runTestFile("test/html5lib-tests/tree-construction/tests25.dat", false);
    try runTestFile("test/html5lib-tests/tree-construction/tests26.dat", false);
    try runTestFile("test/html5lib-tests/tree-construction/tests_innerHTML_1.dat", false);
    try runTestFile("test/html5lib-tests/tree-construction/tricky01.dat", false);
    try runTestFile("test/html5lib-tests/tree-construction/webkit01.dat", false);
    try runTestFile("test/html5lib-tests/tree-construction/webkit02.dat", false);
    try runTestFile("test/html5lib-tests/tree-construction/scripted/adoption01.dat", false);
    try runTestFile("test/html5lib-tests/tree-construction/scripted/ark.dat", false);
    try runTestFile("test/html5lib-tests/tree-construction/scripted/webkit01.dat", false);
}

test "html5lib-tests tree construction with scripting" {
    // Tests that are commented out are not passing.
    // The goal of course is to have none of them commented out.

    // NOTE: All of failing tests fail because of:
    //     1. Finding a "script" end tag token in the "text" insertion mode
    //     2. Finding an eof token while the current node is a script in the "text" insertion mode
    //     3. Finding a "script" end tag token in foreign content, while the current node is an SVG script

    try runTestFile("test/html5lib-tests/tree-construction/adoption01.dat", true);
    try runTestFile("test/html5lib-tests/tree-construction/adoption02.dat", true);
    try runTestFile("test/html5lib-tests/tree-construction/blocks.dat", true);
    try runTestFile("test/html5lib-tests/tree-construction/comments01.dat", true);
    try runTestFile("test/html5lib-tests/tree-construction/doctype01.dat", true);
    // try runTestFile("test/html5lib-tests/tree-construction/domjs-unsafe.dat", true);
    try runTestFile("test/html5lib-tests/tree-construction/entities01.dat", true);
    try runTestFile("test/html5lib-tests/tree-construction/entities02.dat", true);
    try runTestFile("test/html5lib-tests/tree-construction/foreign-fragment.dat", true);
    try runTestFile("test/html5lib-tests/tree-construction/html5test-com.dat", true);
    try runTestFile("test/html5lib-tests/tree-construction/inbody01.dat", true);
    try runTestFile("test/html5lib-tests/tree-construction/isindex.dat", true);
    try runTestFile("test/html5lib-tests/tree-construction/main-element.dat", true);
    try runTestFile("test/html5lib-tests/tree-construction/math.dat", true);
    try runTestFile("test/html5lib-tests/tree-construction/menuitem-element.dat", true);
    try runTestFile("test/html5lib-tests/tree-construction/namespace-sensitivity.dat", true);
    try runTestFile("test/html5lib-tests/tree-construction/noscript01.dat", true);
    try runTestFile("test/html5lib-tests/tree-construction/pending-spec-changes-plain-text-unsafe.dat", true);
    try runTestFile("test/html5lib-tests/tree-construction/pending-spec-changes.dat", true);
    try runTestFile("test/html5lib-tests/tree-construction/plain-text-unsafe.dat", true);
    try runTestFile("test/html5lib-tests/tree-construction/ruby.dat", true);
    // try runTestFile("test/html5lib-tests/tree-construction/scriptdata01.dat", true);
    try runTestFile("test/html5lib-tests/tree-construction/svg.dat", true);
    try runTestFile("test/html5lib-tests/tree-construction/tables01.dat", true);
    try runTestFile("test/html5lib-tests/tree-construction/template.dat", true);
    // try runTestFile("test/html5lib-tests/tree-construction/tests1.dat", true);
    // try runTestFile("test/html5lib-tests/tree-construction/tests2.dat", true);
    // try runTestFile("test/html5lib-tests/tree-construction/tests3.dat", true);
    try runTestFile("test/html5lib-tests/tree-construction/tests4.dat", true);
    // try runTestFile("test/html5lib-tests/tree-construction/tests5.dat", true);
    try runTestFile("test/html5lib-tests/tree-construction/tests6.dat", true);
    // try runTestFile("test/html5lib-tests/tree-construction/tests7.dat", true);
    try runTestFile("test/html5lib-tests/tree-construction/tests8.dat", true);
    try runTestFile("test/html5lib-tests/tree-construction/tests9.dat", true);
    // try runTestFile("test/html5lib-tests/tree-construction/tests10.dat", true);
    try runTestFile("test/html5lib-tests/tree-construction/tests11.dat", true);
    try runTestFile("test/html5lib-tests/tree-construction/tests12.dat", true);
    try runTestFile("test/html5lib-tests/tree-construction/tests14.dat", true);
    try runTestFile("test/html5lib-tests/tree-construction/tests15.dat", true);
    // try runTestFile("test/html5lib-tests/tree-construction/tests16.dat", true);
    try runTestFile("test/html5lib-tests/tree-construction/tests17.dat", true);
    // try runTestFile("test/html5lib-tests/tree-construction/tests18.dat", true);
    try runTestFile("test/html5lib-tests/tree-construction/tests19.dat", true);
    try runTestFile("test/html5lib-tests/tree-construction/tests20.dat", true);
    try runTestFile("test/html5lib-tests/tree-construction/tests21.dat", true);
    try runTestFile("test/html5lib-tests/tree-construction/tests22.dat", true);
    try runTestFile("test/html5lib-tests/tree-construction/tests23.dat", true);
    try runTestFile("test/html5lib-tests/tree-construction/tests24.dat", true);
    try runTestFile("test/html5lib-tests/tree-construction/tests25.dat", true);
    try runTestFile("test/html5lib-tests/tree-construction/tests26.dat", true);
    try runTestFile("test/html5lib-tests/tree-construction/tests_innerHTML_1.dat", true);
    try runTestFile("test/html5lib-tests/tree-construction/tricky01.dat", true);
    // try runTestFile("test/html5lib-tests/tree-construction/webkit01.dat", true);
    try runTestFile("test/html5lib-tests/tree-construction/webkit02.dat", true);
    // try runTestFile("test/html5lib-tests/tree-construction/scripted/adoption01.dat", true);
    // try runTestFile("test/html5lib-tests/tree-construction/scripted/ark.dat", true);
    // try runTestFile("test/html5lib-tests/tree-construction/scripted/webkit01.dat", true);
}

fn runTestFile(file_path: []const u8, scripting: bool) !void {
    std.debug.print(
        \\
        \\Running the tests in file {s}
        \\=======================================================================
        \\
    ,
        .{file_path},
    );

    const allocator = std.testing.allocator;

    const contents = try std.fs.cwd().readFileAlloc(allocator, file_path, 1 << 24);
    defer allocator.free(contents);

    var tests = contents;
    var count: usize = 1;
    var passed: usize = 0;
    while (tests.len > 0) {
        defer count += 1;
        var the_test = createTest(&tests, allocator) catch |err| switch (err) {
            // TODO: Don't skip any tests.
            error.AttributeNamespaces => {
                std.debug.print("Test #{} (Skipped: Exptected DOM tree contains namespaced attributes)\n", .{count});
                continue;
            },
            error.TemplateContents => {
                std.debug.print("Test #{} (Skipped: Exptected DOM tree contains templates)\n", .{count});
                continue;
            },
            error.OutOfMemory => |e| return e,
        };
        defer the_test.expected.deinit();

        if (scripting) {
            if (the_test.script == .off) {
                std.debug.print("Test #{} (Skipped: Scripting must be off for this test)\n", .{count});
                continue;
            }
        } else {
            if (the_test.script == .on) {
                std.debug.print("Test #{} (Skipped: Scripting must be on for this test)\n", .{count});
                continue;
            }
        }

        try runTest(the_test, allocator, scripting);
        passed += 1;
    }
    std.debug.print("{} total, {} passed, {} skipped\n", .{ count - 1, passed, count - 1 - passed });
}

const Expected = struct {
    dom: Dom.Dom,
    document: *Dom.Document,
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

fn createTest(test_string: *[]const u8, allocator: *Allocator) !Test {
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
        if (startsWith(document_fragment, "svg ")) {
            context_element_type = Dom.ElementType.fromStringSvg(document_fragment[4..]) orelse .some_other_svg;
        } else if (startsWith(document_fragment, "math ")) {
            context_element_type = Dom.ElementType.fromStringMathMl(document_fragment[5..]) orelse .some_other_mathml;
        } else {
            context_element_type = Dom.ElementType.fromStringHtml(document_fragment) orelse .custom_html;
        }
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
    const document = try dom.makeDocument();
    const fragment_context = if (context_element_type) |ty| try dom.makeElement(ty) else null;
    var possible_error: ?error{ AttributeNamespaces, TemplateContents } = null;

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
            try Dom.mutation.documentAppendDocumentType(&dom, document, doctype, .Suppress);
        } else if (startsWith(data, "<!-- ")) {
            // comment
            var comment: []const u8 = data[0..0];
            var my_line = data;
            while (true) {
                comment.len += my_line.len + 1;
                if (endsWith(my_line, " -->")) {
                    comment = comment[5 .. comment.len - 5];
                    break;
                }
                my_line = lines.next().?;
            }

            const cdata = try dom.makeCdata(comment, .comment);
            if (depth == 0) {
                if (fragment_context) |e| {
                    try Dom.mutation.elementAppend(&dom, e, .{ .cdata = cdata }, .Suppress);
                } else {
                    try Dom.mutation.documentAppendCdata(&dom, document, cdata, .Suppress);
                }
            } else {
                try Dom.mutation.elementAppend(&dom, stack.items[depth - 1], .{ .cdata = cdata }, .Suppress);
            }
        } else if (startsWith(data, "<?")) {
            // processing instruction
            @panic("TODO Parse processing instructions");
        } else if (data[0] == '<') {
            // element
            if (data[data.len - 1] != '>') {
                // nope, actually an attribute
                parseAttribute(&dom, &stack, data, depth) catch |err| switch (err) {
                    error.AttributeNamespaces => if (possible_error == null) {
                        possible_error = error.AttributeNamespaces;
                    },
                    else => return err,
                };
                continue;
            }
            const tag_name = data[1 .. data.len - 1];

            var element: *Dom.Element = undefined;
            if (startsWith(tag_name, "svg ")) {
                element = try dom.makeElement(.some_other_svg);
                // TODO Try to find an element type from the tag name.
                try dom.registerLocalName(element, tag_name[4..]);
            } else if (startsWith(tag_name, "math ")) {
                element = try dom.makeElement(.some_other_mathml);
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
                    try Dom.mutation.documentAppendElement(&dom, document, element, .Suppress);
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

            // Our DOM tree does not yet support HTML templates.
            // Create a new element and add it to the stack.
            // This is done just so we can continue reading the rest of the tree.
            if (possible_error == null) possible_error = error.TemplateContents;
            const dummy_element = try dom.makeElement(.html_template);
            try stack.append(dummy_element);
        } else {
            // attribute
            parseAttribute(&dom, &stack, data, depth) catch |err| switch (err) {
                error.AttributeNamespaces => if (possible_error == null) {
                    possible_error = error.AttributeNamespaces;
                },
                else => return err,
            };
        }
    }

    if (possible_error) |err| return err;
    return Expected{ .dom = dom, .document = document, .fragment_context = fragment_context };
}

fn parseAttribute(dom: *Dom.Dom, stack: *ArrayList(*Dom.Element), data: []const u8, depth: usize) !void {
    assert(depth == stack.items.len);
    const eql_sign = std.mem.indexOfScalar(u8, data, '=').?;
    assert(data[eql_sign + 1] == '"');
    assert(data[data.len - 1] == '"');
    const attribute_name = data[0..eql_sign];
    const value = data[eql_sign + 2 .. data.len - 1];

    if (startsWith(attribute_name, "xlink ")) {
        return error.AttributeNamespaces;
    } else if (startsWith(attribute_name, "xml ")) {
        return error.AttributeNamespaces;
    } else if (startsWith(attribute_name, "xmlns ")) {
        return error.AttributeNamespaces;
    } else {
        try stack.items[stack.items.len - 1].addAttribute(dom.allocator, attribute_name, value);
    }
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

    var result_dom = Dom.Dom{ .allocator = allocator };
    defer result_dom.deinit();

    if (t.expected.fragment_context) |e| {
        var context_element = Dom.Element{
            .element_type = e.element_type,
            .parent = null,
            .attributes = .{},
            .children = .{},
        };
        var parser = try Parser.initFragment(&result_dom, &context_element, input, allocator, scripting, .no_quirks);
        defer parser.deinit();
        try parser.run();

        try deeplyCompareDocuments(allocator, t.expected.document, parser.getDocument());
    } else {
        var parser = try Parser.init(&result_dom, input, allocator, scripting);
        defer parser.deinit();
        try parser.run();

        try deeplyCompareDocuments(allocator, t.expected.document, parser.getDocument());
    }
}

fn deeplyCompareDocuments(allocator: *Allocator, doc1: *const Dom.Document, doc2: *const Dom.Document) !void {
    //try expectEqual(doc1.quirks_mode, doc2.quirks_mode);
    comptime var i = 0;
    inline while (i < doc1.cdata_slices.len) : (i += 1) {
        try expectEqual(doc1.cdata_slices[i], doc2.cdata_slices[i]);
    }
    for (doc1.cdata.items) |c1, j| {
        try expectEqualCdatas(c1, doc2.cdata.items[j]);
    }

    if (doc1.doctype) |d1| {
        try expect(doc2.doctype != null);
        try expectEqualDoctypes(d1, doc2.doctype.?);
    }

    if (doc2.element) |e1| {
        try expect(doc2.element != null);
        try deeplyCompareElements(allocator, e1, doc2.element.?);
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

fn expectEqualDoctypes(d1: *const Dom.DocumentType, d2: *const Dom.DocumentType) !void {
    try expectEqualStrings(d1.name, d2.name);
    try expectEqualStrings(d1.publicId, d2.publicId);
    try expectEqualStrings(d1.systemId, d2.systemId);
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
