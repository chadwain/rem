const std = @import("std");

pub fn build(b: *std.build.Builder) void {
    const named_character_references_pkg = std.build.Pkg{
        .name = "named-character-references",
        .path = .{ .path = "tools/named_character_references.zig" },
    };

    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const mode = b.standardReleaseOptions();

    const lib = b.addStaticLibrary("dom", "source/tokenizer.zig");
    lib.setBuildMode(mode);
    lib.install();
    lib.addPackage(named_character_references_pkg);

    var main_tests = b.addTest("source/tokenizer.zig");
    main_tests.setBuildMode(mode);
    main_tests.addPackage(named_character_references_pkg);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&main_tests.step);

    genNamedCharRefs(b);
}

fn genNamedCharRefs(b: *std.build.Builder) void {
    const gen_named_refs = b.addExecutable("gen_named_refs", "tools/gen_named_character_references.zig");
    gen_named_refs.setBuildMode(.Debug);
    const run_gen_named_refs = gen_named_refs.run();

    const gen_named_refs_step = b.step("gen-named-characters", "Generate the named character references data");
    gen_named_refs_step.dependOn(&run_gen_named_refs.step);
}
