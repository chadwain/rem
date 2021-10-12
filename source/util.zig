const std = @import("std");
const Allocator = std.mem.Allocator;
const StringHashMapUnmanaged = std.StringHashMapUnmanaged;

pub fn freeStringHashMap(map: *StringHashMapUnmanaged([]u8), allocator: *Allocator) void {
    var iterator = map.iterator();
    while (iterator.next()) |attr| {
        allocator.free(attr.key_ptr.*);
        allocator.free(attr.value_ptr.*);
    }
    map.deinit(allocator);
}
