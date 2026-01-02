// Copyright (C) 2021-2024 Chadwain Holness
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

const std = @import("std");
const Build = std.Build;
const Module = Build.Module;

const Config = struct {
    optimize: std.builtin.OptimizeMode,
    target: Build.ResolvedTarget,
};

pub fn build(b: *Build) void {
    const config = Config{
        .optimize = b.standardOptimizeOption(.{}),
        .target = b.standardTargetOptions(.{}),
    };

    const deps = .{
        .named_character_references = b.dependency("named_character_references", .{
            .target = config.target,
            .optimize = config.optimize,
        }),
    };

    const rem = b.addModule("rem", .{
        .root_source_file = b.path("rem.zig"),
        .target = config.target,
        .optimize = config.optimize,
        .imports = &.{
            .{ .name = "named_character_references", .module = deps.named_character_references.module("named_character_references") },
        },
    });

    addUnitTests(b, rem);
    addHtml5LibTokenizerTests(b, config, rem);
    addHtml5LibTreeConstructionTests(b, config, rem);
    addExample(b, config, rem);
}

fn addUnitTests(b: *Build, rem: *Module) void {
    const rem_unit_tests = b.addTest(.{
        .name = "rem-unit-tests",
        .root_module = rem,
    });
    b.installArtifact(rem_unit_tests);

    const step = b.step("test", "Run unit tests");
    step.dependOn(&b.addRunArtifact(rem_unit_tests).step);
}

fn addHtml5LibTokenizerTests(b: *Build, config: Config, rem: *Module) void {
    const html5lib_tokenizer_tests = b.addTest(.{
        .name = "html5lib-tokenizer-tests",
        .root_module = b.createModule(.{
            .root_source_file = b.path("test/html5lib-test-tokenizer.zig"),
            .target = config.target,
            .optimize = config.optimize,
            .imports = &.{
                .{ .name = "rem", .module = rem },
            },
        }),
    });
    b.installArtifact(html5lib_tokenizer_tests);

    const step = b.step("test-tokenizer", "Run tokenizer tests from html5lib-tests");
    step.dependOn(&b.addRunArtifact(html5lib_tokenizer_tests).step);
}

fn addHtml5LibTreeConstructionTests(b: *Build, config: Config, rem: *Module) void {
    const html5lib_tree_construction_tests = b.addTest(.{
        .name = "html5lib-tree-construction-tests",
        .root_module = b.createModule(.{
            .root_source_file = b.path("test/html5lib-test-tree-construction.zig"),
            .target = config.target,
            .optimize = config.optimize,
            .imports = &.{
                .{ .name = "rem", .module = rem },
            },
        }),
    });
    b.installArtifact(html5lib_tree_construction_tests);

    const step = b.step("test-tree-construction", "Run tree construction tests from html5lib-tests");
    step.dependOn(&b.addRunArtifact(html5lib_tree_construction_tests).step);
}

fn addExample(b: *Build, config: Config, rem: *Module) void {
    const example = b.addExecutable(.{
        .name = "example",
        .root_module = b.createModule(.{
            .root_source_file = b.path("./example.zig"),
            .target = config.target,
            .optimize = config.optimize,
            .imports = &.{
                .{ .name = "rem", .module = rem },
            },
        }),
    });
    b.installArtifact(example);

    const step = b.step("example", "Run an example program");
    step.dependOn(&b.addRunArtifact(example).step);
}
