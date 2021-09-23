const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;

const html5 = @import("html5");
const Dom = html5.dom;

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
    try runTestFile("test/html5lib-tests/tree-construction/tests5.dat");
}

fn runTestFile(file_path: []const u8) !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    //defer assert(!gpa.deinit());
    const allocator = &gpa.allocator;

    const contents = try std.fs.cwd().readFileAlloc(allocator, file_path, std.math.maxInt(usize));
    defer allocator.free(contents);

    var tests = std.mem.split(u8, contents[0 .. contents.len - 1], "\n\n");
    while (tests.next()) |t| {
        try printTest(t, allocator);
        std.debug.print("\n", .{});
    }
}

fn printTest(test_string: []const u8, allocator: *Allocator) !void {
    var lines = std.mem.split(u8, test_string, "\n");
    var section = lines.next().?;

    assert(eql(section, "#data"));
    var data: []const u8 = lines.rest()[0..0];
    while (!startsWith(lines.rest(), "#errors")) {
        data.len += lines.next().?.len + 1;
    }
    if (data.len > 0) data.len -= 1;
    section = lines.next().?;
    std.debug.print("#data\n{s}\n", .{data});

    assert(eql(section, "#errors"));
    var errors: []const u8 = lines.rest()[0..0];
    while (!startsWith(lines.rest(), "#")) {
        errors.len += lines.next().?.len + 1;
    }
    section = lines.next().?;
    std.debug.print("#errors\n{s}", .{errors});

    var new_errors: []const u8 = lines.rest()[0..0];
    if (startsWith(section, "#new-errors")) {
        _ = lines.next();
        while (!startsWith(lines.rest(), "#")) {
            new_errors.len += lines.next().?.len + 1;
        }
        section = lines.next().?;
        std.debug.print("#new-errors\n{s}", .{new_errors});
    }

    var document_fragment: []const u8 = lines.rest()[0..0];
    if (startsWith(section, "#document-fragment")) {
        _ = lines.next();
        document_fragment = lines.next().?;
        section = lines.next().?;
        std.debug.print("#document-fragment\n{s}\n", .{document_fragment});
    }

    var script: enum { on, off, both } = .both;
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
    std.debug.print("#script-{s}\n", .{@tagName(script)});

    assert(eql(section, "#document"));
    var document: []const u8 = lines.rest();
    std.debug.print("#document\n{s}\n", .{document});

    var dom = try parseDomTree(document, allocator);
    var stdout = std.io.getStdOut().writer();
    try Dom.printDom(dom, stdout, allocator);
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

            var namespace: Dom.WhatWgNamespace = undefined;
            var namespace_prefix: ?[]u8 = undefined;
            var local_name: []u8 = undefined;
            var element_type: Dom.ElementType = undefined;
            if (startsWith(tag_name, "svg ")) {
                namespace = .svg;
                namespace_prefix = try allocator.dupe(u8, "svg");
                errdefer allocator.free(namespace_prefix.?);
                local_name = try allocator.dupe(u8, tag_name[4..]);
                element_type = unreachable;
            } else if (startsWith(tag_name, "math ")) {
                namespace = .mathml;
                namespace_prefix = try allocator.dupe(u8, "math");
                errdefer allocator.free(namespace_prefix.?);
                local_name = try allocator.dupe(u8, tag_name[5..]);
                element_type = unreachable;
            } else {
                namespace = .html;
                namespace_prefix = null;
                local_name = try allocator.dupe(u8, tag_name);
                element_type = Dom.ElementType.fromStringHtml(local_name).?;
            }
            errdefer {
                if (namespace_prefix) |ns| allocator.free(ns);
                allocator.free(local_name);
            }

            const element = Dom.Element{
                .namespace = namespace,
                .namespace_prefix = namespace_prefix,
                .local_name = local_name,
                .is = null,
                .element_type = element_type,
                .attributes = .{},
                .children = .{},
            };
            try stack.append(if (depth == 0)
                dom.document.insertElement(element)
            else
                try stack.items[stack.items.len - 1].insertElement(allocator, element));
        } else if (data[0] == '"') {
            assert(depth > 0);
            assert(data[data.len - 1] == '"');
            const text = data[1 .. data.len - 1];
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
