const std = @import("std");

const client = @import("client.zig");
const server = @import("server.zig");
const crypto = @import("crypto.zig");
const util = @import("util.zig");

pub const Client = client.Client;
pub const Server = server.Server;

const testing = std.testing;

test "serialize and deserialize" {
    const Foo = struct {
        id: usize,
        bar: []const u8,
    };

    const value = Foo{
        .id = 1,
        .bar = "baz",
    };

    var value_serialized = std.ArrayList(u8).init(testing.allocator);
    defer value_serialized.deinit();

    try util.serialize(value, value_serialized.writer());
    try testing.expectEqualStrings(value_serialized.items, "{\"id\":1,\"bar\":\"baz\"}");

    const value_deserialized = try util.deserialize(Foo, value_serialized.items, testing.allocator);
    defer value_deserialized.deinit();
    try testing.expectEqualDeep(value_deserialized.value, value);
}

test "encode message size" {
    try testing.expectEqualSlices(u8, &util.encodeMessageSize(0), &[_]u8{ 0, 0, 0, 0, 0 });
    try testing.expectEqualSlices(u8, &util.encodeMessageSize(1), &[_]u8{ 0, 0, 0, 0, 1 });
    try testing.expectEqualSlices(u8, &util.encodeMessageSize(255), &[_]u8{ 0, 0, 0, 0, 255 });
    try testing.expectEqualSlices(u8, &util.encodeMessageSize(256), &[_]u8{ 0, 0, 0, 1, 0 });
    try testing.expectEqualSlices(u8, &util.encodeMessageSize(257), &[_]u8{ 0, 0, 0, 1, 1 });
    try testing.expectEqualSlices(u8, &util.encodeMessageSize(4311810305), &[_]u8{ 1, 1, 1, 1, 1 });
    try testing.expectEqualSlices(u8, &util.encodeMessageSize(4328719365), &[_]u8{ 1, 2, 3, 4, 5 });
    try testing.expectEqualSlices(u8, &util.encodeMessageSize(47362409218), &[_]u8{ 11, 7, 5, 3, 2 });
    try testing.expectEqualSlices(u8, &util.encodeMessageSize(1099511627775), &[_]u8{ 255, 255, 255, 255, 255 });
}

test "decode message size" {
    try testing.expectEqual(util.decodeMessageSize([_]u8{ 0, 0, 0, 0, 0 }), 0);
    try testing.expectEqual(util.decodeMessageSize([_]u8{ 0, 0, 0, 0, 1 }), 1);
    try testing.expectEqual(util.decodeMessageSize([_]u8{ 0, 0, 0, 0, 255 }), 255);
    try testing.expectEqual(util.decodeMessageSize([_]u8{ 0, 0, 0, 1, 0 }), 256);
    try testing.expectEqual(util.decodeMessageSize([_]u8{ 0, 0, 0, 1, 1 }), 257);
    try testing.expectEqual(util.decodeMessageSize([_]u8{ 1, 1, 1, 1, 1 }), 4311810305);
    try testing.expectEqual(util.decodeMessageSize([_]u8{ 1, 2, 3, 4, 5 }), 4328719365);
    try testing.expectEqual(util.decodeMessageSize([_]u8{ 11, 7, 5, 3, 2 }), 47362409218);
    try testing.expectEqual(util.decodeMessageSize([_]u8{ 255, 255, 255, 255, 255 }), 1099511627775);
}

test "crypto" {
    // TODO
}

test "server serving" {
    // TODO
}

test "addresses" {
    // TODO
}

test "send" {
    // TODO
}

test "large send" {
    // TODO
}

test "sending numerous messages" {
    // TODO
}

test "sending custom types" {
    // TODO
}

test "multiple clients" {
    // TODO
}

test "remove client" {
    // TODO
}

test "stop server while client connected" {
    // TODO
}

test "example" {
    // TODO
}
