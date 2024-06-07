// Copyright (C) 2021-2024 Chadwain Holness
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

const std = @import("std");
const Build = std.Build;

pub fn build(b: *Build) void {
    const optimize = b.standardOptimizeOption(.{});
    const target = b.standardTargetOptions(.{});

    const rem_lib = b.addStaticLibrary(.{
        .name = "rem",
        .root_source_file = b.path("rem.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.installArtifact(rem_lib);

    {
        const rem_unit_tests = b.addTest(.{
            .name = "rem-unit-tests",
            .root_source_file = b.path("rem.zig"),
            .target = target,
            .optimize = optimize,
        });
        b.installArtifact(rem_unit_tests);

        const rem_unit_tests_run = b.addRunArtifact(rem_unit_tests);
        rem_unit_tests_run.step.dependOn(&rem_unit_tests.step);

        const rem_unit_tests_run_step = b.step("test", "Run unit tests");
        rem_unit_tests_run_step.dependOn(&rem_unit_tests_run.step);
    }

    const rem_module = b.addModule("rem", .{ .root_source_file = b.path("rem.zig") });

    {
        const html5lib_tokenizer_tests = b.addTest(.{
            .name = "html5lib-tokenizer-tests",
            .root_source_file = b.path("test/html5lib-test-tokenizer.zig"),
            .target = target,
            .optimize = optimize,
        });
        html5lib_tokenizer_tests.root_module.addImport("rem", rem_module);
        b.installArtifact(html5lib_tokenizer_tests);

        const html5lib_tokenizer_tests_run = b.addRunArtifact(html5lib_tokenizer_tests);
        html5lib_tokenizer_tests_run.step.dependOn(&html5lib_tokenizer_tests.step);

        const html5lib_tokenizer_tests_run_step = b.step(
            "test-tokenizer",
            "Run tokenizer tests from html5lib-tests (requires 0.12.0-dev.91+a155e3585 or newer)",
        );
        html5lib_tokenizer_tests_run_step.dependOn(&html5lib_tokenizer_tests_run.step);
    }

    {
        const html5lib_tree_construction_tests = b.addTest(.{
            .name = "html5lib-tree-construction-tests",
            .root_source_file = b.path("test/html5lib-test-tree-construction.zig"),
            .target = target,
            .optimize = optimize,
        });
        html5lib_tree_construction_tests.root_module.addImport("rem", rem_module);
        b.installArtifact(html5lib_tree_construction_tests);

        const html5lib_tree_construction_tests_run = b.addRunArtifact(html5lib_tree_construction_tests);
        html5lib_tree_construction_tests_run.step.dependOn(&html5lib_tree_construction_tests.step);

        const html5lib_tree_construction_tests_run_step = b.step("test-tree-construction", "Run tree construction tests from html5lib-tests");
        html5lib_tree_construction_tests_run_step.dependOn(&html5lib_tree_construction_tests_run.step);
    }

    {
        const example = b.addExecutable(.{
            .name = "example",
            .root_source_file = b.path("./example.zig"),
            .target = target,
            .optimize = optimize,
        });
        example.root_module.addImport("rem", rem_module);
        b.installArtifact(example);

        const example_run = b.addRunArtifact(example);
        const example_run_step = b.step("example", "Run an example program");
        example_run_step.dependOn(&example_run.step);
    }

    {
        const json_data = b.pathFromRoot("tools/character_reference_data.json");
        const output_path = b.pathFromRoot("source/named_characters.zig");
        const generate_named_characters = b.addExecutable(.{
            .name = "generate-named-characters",
            .root_source_file = b.path("tools/generate_named_characters.zig"),
            .target = target,
            .optimize = .Debug,
        });

        const generate_named_characters_run = b.addRunArtifact(generate_named_characters);
        generate_named_characters_run.addArgs(&.{ json_data, output_path });

        const generate_named_characters_run_step = b.step("generate-named-characters", "Generate the named character reference data");
        generate_named_characters_run_step.dependOn(&generate_named_characters_run.step);
    }
}
