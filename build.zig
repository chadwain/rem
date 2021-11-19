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
    const html5_pkg = std.build.Pkg{
        .name = "html5",
        .path = .{ .path = "html5.zig" },
        .dependencies = &.{named_character_references_pkg},
    };

    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const mode = b.standardReleaseOptions();

    const lib = b.addStaticLibrary("html5", "html5.zig");
    lib.setBuildMode(mode);
    lib.install();
    lib.addPackage(named_character_references_pkg);

    const lib_tests = b.addTest("html5.zig");
    lib_tests.setBuildMode(mode);
    lib_tests.addPackage(named_character_references_pkg);
    const lib_tests_step = b.step("test", "Run library tests");
    lib_tests_step.dependOn(&lib_tests.step);

    const gen_named_refs = b.addExecutable("gen_named_refs", "tools/gen_named_character_references.zig");
    gen_named_refs.setBuildMode(.Debug);
    const run_gen_named_refs = gen_named_refs.run();
    const gen_named_refs_step = b.step("gen-named-characters", "Generate the named character references data");
    gen_named_refs_step.dependOn(&run_gen_named_refs.step);

    const html5lib_tokenizer_tests = b.addTest("test/html5lib-test-tokenizer.zig");
    html5lib_tokenizer_tests.setBuildMode(mode);
    html5lib_tokenizer_tests.addPackage(html5_pkg);
    const html5lib_tokenizer_tests_step = b.step("test-tokenizer", "Run tokenizer tests from html5lib-tests");
    html5lib_tokenizer_tests_step.dependOn(&html5lib_tokenizer_tests.step);

    const html5lib_tree_construction_tests = b.addTest("test/html5lib-test-tree-construction.zig");
    html5lib_tree_construction_tests.setBuildMode(mode);
    html5lib_tree_construction_tests.addPackage(html5_pkg);
    const html5lib_tree_construction_tests_step = b.step("test-tree-constructor", "Run tree construction tests from html5lib-tests");
    html5lib_tree_construction_tests_step.dependOn(&html5lib_tree_construction_tests.step);

    const example = b.addExecutable("example", "./example.zig");
    example.setBuildMode(mode);
    example.addPackage(html5_pkg);
    const example_run = example.run();
    const example_step = b.step("example", "Run an example program");
    example_step.dependOn(&example_run.step);
}
