const std = @import("std");
const Allocator = std.mem.Allocator;

pub const LENSIZE = 5;

pub fn serialize(data: anytype, out_stream: anytype) !void {
    try std.json.stringify(data, .{}, out_stream);
}

pub fn deserialize(comptime T: type, data_serialized: []const u8, allocator: Allocator) !std.json.Parsed(T) {
    return try std.json.parseFromSlice(T, allocator, data_serialized, .{});
}

pub fn encodeMessageSize(size: usize) [LENSIZE]u8 {
    var size_inner = size;
    var encoded_size: [LENSIZE]u8 = undefined;

    for (0..LENSIZE) |i| {
        encoded_size[LENSIZE - i - 1] = @as(u8, @truncate(size_inner));
        size_inner >>= 8;
    }

    return encoded_size;
}

pub fn decodeMessageSize(encoded_size: [LENSIZE]u8) usize {
    var size: usize = 0;

    for (encoded_size) |x| {
        size = (size << 8) + x;
    }

    return size;
}
