// Copyright (C) 2021-2023 Chadwain Holness
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

const std = @import("std");

pub fn build(builder: *std.build.Builder) void {
    const rem_pkg = std.build.Pkg{
        .name = "rem",
        .source = .{ .path = "rem.zig" },
    };

    const mode = builder.standardReleaseOptions();
    const target = builder.standardTargetOptions(.{});

    const lib = builder.addStaticLibrary("rem", "rem.zig");
    lib.setBuildMode(mode);
    lib.setTarget(target);
    lib.use_stage1 = true;
    lib.install();

    const lib_tests = builder.addTest("rem.zig");
    lib_tests.setBuildMode(mode);
    lib_tests.setTarget(target);
    lib_tests.use_stage1 = true;
    const lib_tests_step = builder.step("test", "Run library tests");
    lib_tests_step.dependOn(&lib_tests.step);

    const html5lib_tokenizer_tests = builder.addTest("test/html5lib-test-tokenizer.zig");
    html5lib_tokenizer_tests.setBuildMode(mode);
    html5lib_tokenizer_tests.setTarget(target);
    html5lib_tokenizer_tests.addPackage(rem_pkg);
    html5lib_tokenizer_tests.use_stage1 = true;
    const html5lib_tokenizer_tests_step = builder.step("test-tokenizer", "Run tokenizer tests from html5lib-tests");
    html5lib_tokenizer_tests_step.dependOn(&html5lib_tokenizer_tests.step);

    const html5lib_tree_construction_tests = builder.addTest("test/html5lib-test-tree-construction.zig");
    html5lib_tree_construction_tests.setBuildMode(mode);
    html5lib_tree_construction_tests.setTarget(target);
    html5lib_tree_construction_tests.addPackage(rem_pkg);
    html5lib_tree_construction_tests.use_stage1 = true;
    const html5lib_tree_construction_tests_step = builder.step("test-tree-construction", "Run tree construction tests from html5lib-tests");
    html5lib_tree_construction_tests_step.dependOn(&html5lib_tree_construction_tests.step);

    const example = builder.addExecutable("example", "./example.zig");
    example.setBuildMode(mode);
    example.setTarget(target);
    example.addPackage(rem_pkg);
    example.use_stage1 = true;
    example.install();
    const example_run = example.run();
    const example_step = builder.step("example", "Run an example program");
    example_step.dependOn(&example_run.step);

    const run_generate_named_characters = genNamedCharactersRunStep(builder);
    const generate_named_characters_step = builder.step("generate-named-characters", "Generate the named character reference data");
    generate_named_characters_step.dependOn(&run_generate_named_characters.step);
}

fn genNamedCharactersRunStep(builder: *std.build.Builder) *std.build.RunStep {
    const json_data = builder.pathFromRoot("tools/character_reference_data.json");
    const path = builder.pathFromRoot("source/named_characters.zig");
    const generate_named_characters = builder.addExecutable(
        "generate_named_characters",
        "tools/generate_named_characters.zig",
    );
    generate_named_characters.setBuildMode(.Debug);
    const run_generate_named_characters = generate_named_characters.run();
    run_generate_named_characters.addArgs(&.{ json_data, path });
    return run_generate_named_characters;
}
