// Copyright (C) 2021 Chadwain Holness
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

const std = @import("std");

pub fn build(b: *std.build.Builder) void {
    const named_character_references_pkg = std.build.Pkg{
        .name = "named-character-references",
        .path = .{ .path = "tools/named_character_references.zig" },
    };
    const tokenizer_pkg = std.build.Pkg{
        .name = "Tokenizer",
        .path = .{ .path = "source/Tokenizer.zig" },
        .dependencies = &.{named_character_references_pkg},
    };

    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const mode = b.standardReleaseOptions();

    const lib = b.addStaticLibrary("html-parser", "source/Tokenizer.zig");
    lib.setBuildMode(mode);
    lib.install();
    lib.addPackage(named_character_references_pkg);

    const gen_named_refs = b.addExecutable("gen_named_refs", "tools/gen_named_character_references.zig");
    gen_named_refs.setBuildMode(.Debug);
    const run_gen_named_refs = gen_named_refs.run();
    const gen_named_refs_step = b.step("gen-named-characters", "Generate the named character references data");
    gen_named_refs_step.dependOn(&run_gen_named_refs.step);

    var html5lib_tokenizer_tests = b.addTest("test/html5lib-test-tokenizer.zig");
    html5lib_tokenizer_tests.setBuildMode(mode);
    html5lib_tokenizer_tests.addPackage(tokenizer_pkg);
    const html5lib_tokenizer_tests_step = b.step("test-tokenizer", "Run tokenizer tests from html5lib-tests");
    html5lib_tokenizer_tests_step.dependOn(&html5lib_tokenizer_tests.step);

    var tree_construction_tests = b.addTest("source/tree_construction.zig");
    tree_construction_tests.setBuildMode(mode);
    const tree_construction_tests_step = b.step("test-tree-construction", "Run tree construction tests");
    tree_construction_tests_step.dependOn(&tree_construction_tests.step);
}
