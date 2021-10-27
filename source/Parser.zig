// Copyright (C) 2021 Chadwain Holness
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

const html5 = @import("../html5.zig");
const Dom = html5.dom;
const Tokenizer = html5.Tokenizer;
const tree_construction = html5.tree_construction;
const TreeConstructor = tree_construction.TreeConstructor;

const std = @import("std");
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;

pub const Parser = struct {
    tokenizer: Tokenizer,
    constructor: TreeConstructor,
    input: []const u21,
    allocator: *Allocator,

    const Self = @This();

    pub fn init(dom: *Dom.Dom, input: []const u21, allocator: *Allocator) Self {
        return Self{
            .tokenizer = Tokenizer.init(allocator, undefined, undefined),
            .constructor = TreeConstructor.init(dom, allocator, .{}),
            .input = input,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.tokenizer.deinit();
        self.constructor.deinit();
    }

    pub fn run(self: *Self) !void {
        var tokens = std.ArrayList(Tokenizer.Token).init(self.allocator);
        defer {
            for (tokens.items) |*t| t.deinit(self.allocator);
            tokens.deinit();
        }

        var parse_errors = std.ArrayList(Tokenizer.ParseError).init(self.allocator);
        defer parse_errors.deinit();

        self.tokenizer.tokens = &tokens;
        self.tokenizer.parse_errors = &parse_errors;
        defer {
            self.tokenizer.tokens = undefined;
            self.tokenizer.parse_errors = undefined;
        }

        while (try self.tokenizer.run(&self.input)) {
            if (tokens.items.len > 0) {
                var constructor_result: tree_construction.RunResult = undefined;
                for (tokens.items) |*token| {
                    constructor_result = try self.constructor.run(token.*);
                    token.deinit(self.allocator);
                }
                tokens.clearRetainingCapacity();

                if (constructor_result.new_tokenizer_state) |state| self.tokenizer.setState(state);
                self.tokenizer.setAdjustedCurrentNodeIsNotInHtmlNamespace(constructor_result.adjusted_current_node_is_not_in_html_namespace);
            }
        }
    }
};

test "Parser" {
    const allocator = std.testing.allocator;
    var dom = Dom.Dom{ .allocator = allocator };
    defer dom.deinit();
    const string = "<!doctype><html>asdf</body hello=world>";
    const input: []const u21 = &html5.util.utf8DecodeComptime(string);

    var parser = Parser.init(&dom, input, allocator);
    defer parser.deinit();
    try parser.run();
}

pub const FragmentParser = struct {
    context: *Dom.Element,
    inner: Parser,
    dom: *Dom.Dom,
    allocator: *Allocator,

    const Self = @This();

    // Follows https://html.spec.whatwg.org/multipage/parsing.html#parsing-html-fragments
    pub fn init(
        context: *Dom.Element,
        input: []const u21,
        allocator: *Allocator,
        scripting: bool,
        // Must be the same "quirks mode" as the node document of the context.
        quirks_mode: Dom.Document.QuirksMode,
    ) !Self {
        // NOTE: The DOM is heap allocator to avoid keeping an internal pointer in TreeConstructor.
        // If the API of TreeConstructor is changed, maybe this won't be necessary.
        // TODO: We only need to create a new Document node, not a new DOM tree.
        const dom = try allocator.create(Dom.Dom);
        errdefer allocator.destroy(dom);
        dom.* = .{ .allocator = allocator };

        var result = Self{
            // NOTE: Make a duplicate of the context element?
            .context = context,
            .inner = undefined,
            .dom = dom,
            .allocator = allocator,
        };
        // Step 2
        result.dom.document.quirks_mode = quirks_mode;

        // Step 4
        const initial_state: Tokenizer.State = switch (context.element_type) {
            .html_title, .html_textarea => .RCDATA,
            .html_style, .html_xmp, .html_iframe, .html_noembed, .html_noframes => .RAWTEXT,
            .html_script => .ScriptData,
            .html_noscript => if (scripting) Tokenizer.State.RAWTEXT else Tokenizer.State.Data,
            .html_plaintext => .PLAINTEXT,
            else => .Data,
        };
        result.inner = .{
            .tokenizer = Tokenizer.initState(allocator, initial_state, undefined, undefined),
            .constructor = TreeConstructor.init(result.dom, allocator, .{
                .fragment_context = context,
                .scripting = scripting,
            }),
            // Step 12
            .input = input,
            .allocator = allocator,
        };

        // Steps 5-7
        const html = try result.dom.makeElement(.html_html);
        errdefer result.dom.freeElement(html);
        try Dom.mutation.documentAppendElement(result.dom, &result.dom.document, html, .Suppress);
        try result.inner.constructor.open_elements.append(result.inner.constructor.allocator, html);

        // Step 8
        if (context.element_type == .html_template) {
            try result.inner.constructor.template_insertion_modes.append(result.inner.constructor.allocator, .InTemplate);
        }

        // Step 9
        // TODO: Determine if this is an HTML integration point.

        // Step 10
        tree_construction.resetInsertionModeAppropriately(&result.inner.constructor);

        // Step 11
        var form: ?*Dom.Element = context;
        while (form) |f| {
            if (f.element_type == .html_form) break;
            switch (f.parent orelse break) {
                .document => break,
                .element => |e| form = e,
            }
        }
        result.inner.constructor.form_element_pointer = form;

        // Step 12
        // TODO: Set the encoding confidence.

        return result;
    }

    pub fn deinit(self: *Self) void {
        self.inner.deinit();
        self.dom.deinit();
        self.allocator.destroy(self.dom);
    }

    pub fn run(self: *Self) !void {
        try self.inner.run();
    }
};

test "FragmentParser" {
    const allocator = std.testing.allocator;

    var context = Dom.Element{
        .element_type = .html_div,
        .attributes = .{},
        .parent = null,
        .children = .{},
    };
    const string = "<!doctype><html>asdf</body hello=world>";
    const input: []const u21 = &html5.util.utf8DecodeComptime(string);

    var parser = try FragmentParser.init(&context, input, allocator, false, .no_quirks);
    defer parser.deinit();
    try parser.run();
}
