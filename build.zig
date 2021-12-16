// Copyright (C) 2021 Chadwain Holness
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

const std = @import("std");

pub fn build(b: *std.build.Builder) void {
    const named_characters_data_pkg = std.build.Pkg{
        .name = "named-characters-data",
        .path = .{ .path = "tools/named_characters_data.zig" },
    };
    const rem_pkg = std.build.Pkg{
        .name = "rem",
        .path = .{ .path = "rem.zig" },
        .dependencies = &.{named_characters_data_pkg},
    };

    const mode = b.standardReleaseOptions();
    const target = b.standardTargetOptions(.{});

    const do_gen_char_data = if (std.fs.cwd().access("tools/named_characters_data.zig", .{})) false else |_| true;
    const gen_char_data = b.addExecutable("gen_char_data", "tools/gen_named_characters_data.zig");
    gen_char_data.setBuildMode(.Debug);
    gen_char_data.setTarget(target);
    const run_gen_char_data = gen_char_data.run();

    const lib = b.addStaticLibrary("rem", "rem.zig");
    lib.setBuildMode(mode);
    lib.setTarget(target);
    lib.install();
    lib.addPackage(named_characters_data_pkg);
    if (do_gen_char_data) b.default_step.dependOn(&run_gen_char_data.step);

    const lib_tests = b.addTest("rem.zig");
    lib_tests.setBuildMode(mode);
    lib_tests.setTarget(target);
    lib_tests.addPackage(named_characters_data_pkg);
    if (do_gen_char_data) lib_tests.step.dependOn(&run_gen_char_data.step);
    const lib_tests_step = b.step("test", "Run library tests");
    lib_tests_step.dependOn(&lib_tests.step);

    const gen_char_data_step = b.step("gen-named-characters-data", "Generate the named character reference data");
    gen_char_data_step.dependOn(&run_gen_char_data.step);

    const html5lib_tokenizer_tests = b.addTest("test/html5lib-test-tokenizer.zig");
    html5lib_tokenizer_tests.setBuildMode(mode);
    html5lib_tokenizer_tests.setTarget(target);
    html5lib_tokenizer_tests.addPackage(rem_pkg);
    if (do_gen_char_data) html5lib_tokenizer_tests.step.dependOn(&run_gen_char_data.step);
    const html5lib_tokenizer_tests_step = b.step("test-tokenizer", "Run tokenizer tests from html5lib-tests");
    html5lib_tokenizer_tests_step.dependOn(&html5lib_tokenizer_tests.step);

    const html5lib_tree_construction_tests = b.addTest("test/html5lib-test-tree-construction.zig");
    html5lib_tree_construction_tests.setBuildMode(mode);
    html5lib_tree_construction_tests.setTarget(target);
    html5lib_tree_construction_tests.addPackage(rem_pkg);
    if (do_gen_char_data) html5lib_tree_construction_tests.step.dependOn(&run_gen_char_data.step);
    const html5lib_tree_construction_tests_step = b.step("test-tree-construction", "Run tree construction tests from html5lib-tests");
    html5lib_tree_construction_tests_step.dependOn(&html5lib_tree_construction_tests.step);

    const example = b.addExecutable("example", "./example.zig");
    example.setBuildMode(mode);
    example.setTarget(target);
    example.addPackage(rem_pkg);
    example.install();
    if (do_gen_char_data) example.step.dependOn(&run_gen_char_data.step);
    const example_run = example.run();
    const example_step = b.step("example", "Run an example program");
    example_step.dependOn(&example_run.step);
}
