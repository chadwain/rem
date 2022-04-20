// Copyright (C) 2021 Chadwain Holness
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

const std = @import("std");

pub fn build(builder: *std.build.Builder) void {
    const character_reference_data_generated_file = characterReferenceDataGeneratedFile(builder);
    const named_characters_data_pkg = std.build.Pkg{
        .name = "named-characters-data",
        .path = .{ .generated = character_reference_data_generated_file },
    };
    const rem_pkg = std.build.Pkg{
        .name = "rem",
        .path = .{ .path = "rem.zig" },
        .dependencies = &.{named_characters_data_pkg},
    };

    const mode = builder.standardReleaseOptions();
    const target = builder.standardTargetOptions(.{});

    const lib = builder.addStaticLibrary("rem", "rem.zig");
    lib.setBuildMode(mode);
    lib.setTarget(target);
    lib.install();
    lib.addPackage(named_characters_data_pkg);

    const lib_tests = builder.addTest("rem.zig");
    lib_tests.setBuildMode(mode);
    lib_tests.setTarget(target);
    lib_tests.addPackage(named_characters_data_pkg);
    const lib_tests_step = builder.step("test", "Run library tests");
    lib_tests_step.dependOn(&lib_tests.step);

    const html5lib_tokenizer_tests = builder.addTest("test/html5lib-test-tokenizer.zig");
    html5lib_tokenizer_tests.setBuildMode(mode);
    html5lib_tokenizer_tests.setTarget(target);
    html5lib_tokenizer_tests.addPackage(rem_pkg);
    const html5lib_tokenizer_tests_step = builder.step("test-tokenizer", "Run tokenizer tests from html5lib-tests");
    html5lib_tokenizer_tests_step.dependOn(&html5lib_tokenizer_tests.step);

    const html5lib_tree_construction_tests = builder.addTest("test/html5lib-test-tree-construction.zig");
    html5lib_tree_construction_tests.setBuildMode(mode);
    html5lib_tree_construction_tests.setTarget(target);
    html5lib_tree_construction_tests.addPackage(rem_pkg);
    const html5lib_tree_construction_tests_step = builder.step("test-tree-construction", "Run tree construction tests from html5lib-tests");
    html5lib_tree_construction_tests_step.dependOn(&html5lib_tree_construction_tests.step);

    const example = builder.addExecutable("example", "./example.zig");
    example.setBuildMode(mode);
    example.setTarget(target);
    example.addPackage(rem_pkg);
    example.install();
    const example_run = example.run();
    const example_step = builder.step("example", "Run an example program");
    example_step.dependOn(&example_run.step);

    const generate_character_reference_data_step = builder.step("generate-character-reference-data", "Generate the named character reference data");
    generate_character_reference_data_step.dependOn(character_reference_data_generated_file.step);
}

fn characterReferenceDataGeneratedFile(builder: *std.build.Builder) *std.build.GeneratedFile {
    const json_data = builder.pathFromRoot("tools/character_reference_data.json");
    const path = builder.pathFromRoot("tools/character_reference_data.zig");
    const generate_character_reference_data = builder.addExecutable("generate_character_reference_data", "tools/generate_character_reference_data.zig");
    generate_character_reference_data.setBuildMode(.Debug);
    const run_generate_character_reference_data = generate_character_reference_data.run();
    run_generate_character_reference_data.addArgs(&.{ json_data, path });

    const generated_file = builder.allocator.create(std.build.GeneratedFile) catch unreachable;
    generated_file.* = .{ .step = &run_generate_character_reference_data.step, .path = path };
    return generated_file;
}
