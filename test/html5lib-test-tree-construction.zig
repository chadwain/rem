const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;

const html5 = @import("html5");
const Dom = html5.dom;
const Tokenizer = html5.Tokenizer;
const TreeConstructor = html5.tree_construction.TreeConstructor;

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
    try runTestFile("test/html5lib-tests/tree-construction/tests3.dat");
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
        std.debug.print("Test {}\n", .{count});
        defer count += 1;
        const the_test = createTest(t, allocator) catch |err| switch (err) {
            error.SkipTest => {
                std.debug.print("Test {} skipped.\n\n", .{count});
                continue;
            },
            else => return err,
        };
        try runTest(the_test, allocator);
        std.debug.print("\n\n", .{});
    }
}

const Test = struct {
    input: []const u8,
    errors: usize,
    new_errors: usize,
    fragment: ?[]const u8,
    script: ScriptOption,
    expected_dom: Dom.Dom,

    const ScriptOption = enum { on, off, both };
};

fn createTest(test_string: []const u8, allocator: *Allocator) !Test {
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
    if (startsWith(section, "#document-fragment")) {
        return error.SkipTest;
        //document_fragment = lines.next().?;
        //section = lines.next().?;
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

    var dom = try parseDomTree(document, allocator);
    //var stderr = std.io.getStdErr().writer();
    //try Dom.printDom(dom, stderr, allocator);

    return Test{
        .input = data,
        .errors = std.mem.count(u8, errors, "\n"),
        .new_errors = std.mem.count(u8, new_errors, "\n"),
        .fragment = if (document_fragment.len > 0) document_fragment else null,
        .script = script,
        .expected_dom = dom,
    };
}

fn parseDomTree(string: []const u8, allocator: *Allocator) !Dom.Dom {
    var dom = Dom.Dom{};

    var stack = ArrayList(*Dom.Element).init(allocator);
    defer stack.deinit();

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
                _ = try dom.document.insertDocumentType(allocator, name, public_id, system_id);
            } else {
                _ = try dom.document.insertDocumentType(allocator, name, null, null);
            }
        } else if (startsWith(data, "<!-- ")) {
            assert(endsWith(data, " -->"));
            const comment = data["<!-- ".len .. data.len - " -->".len];
            if (depth == 0) {
                try dom.document.insertCharacterData(allocator, comment, .comment);
            } else {
                try stack.items[depth - 1].insertCharacterData(allocator, comment, .comment);
            }
        } else if (startsWith(data, "<?")) {
            @panic("TODO Parse processing instructions");
        } else if (data[0] == '<') {
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

            const element = Dom.Element{
                .element_type = element_type,
                .attributes = .{},
                .is = null,
                .children = .{},
            };
            try stack.append(if (depth == 0)
                dom.document.insertElement(element)
            else
                try stack.items[stack.items.len - 1].insertElement(allocator, element));
        } else if (data[0] == '"') {
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
            if (depth == 0)
                try dom.document.insertCharacterData(allocator, text, .text)
            else
                try stack.items[stack.items.len - 1].insertCharacterData(allocator, text, .text);
        } else if (eql(data, "content")) {
            @panic("TODO Template contents");
        } else {
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

    return dom;
}

fn runTest(t: Test, allocator: *Allocator) !void {
    // TODO: Fragment tests
    if (t.fragment != null) return;

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

    var tokens = ArrayList(Tokenizer.Token).init(allocator);
    defer tokens.deinit();

    var parse_errors = ArrayList(Tokenizer.ParseError).init(allocator);
    defer parse_errors.deinit();

    var tokenizer = Tokenizer.init(input, allocator, &tokens, &parse_errors);
    defer tokenizer.deinit();

    var result_dom = Dom.Dom{};
    var constructor = TreeConstructor.init(&result_dom, allocator);

    while (try tokenizer.run()) {
        if (tokens.items.len == 0) continue;
        for (tokens.items) |token, i| {
            const result = try constructor.run(token);
            if (result.new_tokenizer_state) |state| {
                assert(i == tokens.items.len - 1);
                tokenizer.setState(state);
            }
            tokenizer.setAdjustedCurrentNodeIsNotInHtmlNamespace(result.adjusted_current_node_is_not_in_html_namespace);
        }
        tokens.clearRetainingCapacity();
        parse_errors.clearRetainingCapacity();
    }
}
