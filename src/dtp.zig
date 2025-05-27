const std = @import("std");

const client_impl = @import("client.zig");
const server_impl = @import("server.zig");
const crypto = @import("crypto.zig");
const util = @import("util.zig");
const err = @import("err.zig");

pub const Client = client_impl.Client;
pub const ClientOptions = client_impl.ClientOptions;
pub const Server = server_impl.Server;
pub const ServerOptions = server_impl.ServerOptions;
pub const Error = err.Error;

const testing = std.testing;
const Allocator = std.mem.Allocator;
const Thread = std.Thread;
const Mutex = Thread.Mutex;

const SERVER_HOST = "127.0.0.1";
const SERVER_PORT = 0;
const SLEEP_TIME = 100_000_000;

fn sleep() void {
    Thread.sleep(SLEEP_TIME);
}

const ExpectMap = struct {
    const Self = @This();

    pub const ExpectType = enum {
        server_receive,
        server_connect,
        server_disconnect,
        client_receive,
        client_disconnected,

        pub fn format(self: ExpectType, comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
            try writer.writeAll(switch (self) {
                .server_receive => ".server_receive",
                .server_connect => ".server_connect",
                .server_disconnect => ".server_disconnect",
                .client_receive => ".client_receive",
                .client_disconnected => ".client_disconnected",
            });
        }
    };

    expected: std.AutoHashMap(ExpectType, usize),
    observed: std.AutoHashMap(ExpectType, usize),
    mutex: Mutex,

    pub fn init(allocator: Allocator) Self {
        return Self{
            .expected = std.AutoHashMap(ExpectType, usize).init(allocator),
            .observed = std.AutoHashMap(ExpectType, usize).init(allocator),
            .mutex = Mutex{},
        };
    }

    pub fn deinit(self: *Self) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.expected.deinit();
        self.observed.deinit();
    }

    pub fn expect(self: *Self, kind: ExpectType, count: usize) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        try self.expected.put(kind, count);
        try self.observed.put(kind, 0);
    }

    pub fn received(self: *Self, kind: ExpectType) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.observed.getPtr(kind)) |count| {
            count.* += 1;
        } else {
            try self.observed.put(kind, 1);
        }
    }

    pub fn done(self: *Self) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        var iter = self.expected.keyIterator();

        while (iter.next()) |kind| {
            const expected = self.expected.get(kind.*).?;
            const observed = self.observed.get(kind.*).?;

            if (expected != observed) {
                std.debug.print("\"{s}\" expected {d}, got {d}\n", .{ kind, expected, observed });
            }

            try testing.expectEqual(expected, observed);
        }
    }
};

fn OnReceive(comptime S: type, comptime R: type) fn (*ExpectMap, *Server(S, R, *ExpectMap), usize, R) void {
    return struct {
        fn onReceive(expected: *ExpectMap, _: *Server(S, R, *ExpectMap), _: usize, _: R) void {
            expected.received(.server_receive) catch |e| {
                std.debug.panic("{any}\n", .{e});
            };
        }
    }.onReceive;
}

fn OnConnect(comptime S: type, comptime R: type) fn (*ExpectMap, *Server(S, R, *ExpectMap), usize) void {
    return struct {
        fn onConnect(expected: *ExpectMap, _: *Server(S, R, *ExpectMap), _: usize) void {
            expected.received(.server_connect) catch |e| {
                std.debug.panic("{any}\n", .{e});
            };
        }
    }.onConnect;
}

fn OnDisconnect(comptime S: type, comptime R: type) fn (*ExpectMap, *Server(S, R, *ExpectMap), usize) void {
    return struct {
        fn onDisonnect(expected: *ExpectMap, _: *Server(S, R, *ExpectMap), _: usize) void {
            expected.received(.server_disconnect) catch |e| {
                std.debug.panic("{any}\n", .{e});
            };
        }
    }.onDisonnect;
}

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
    const public_key = crypto.newKeyPair().public_key;
    const secret_key1 = crypto.newKeyPair().secret_key;
    const secret_key2 = crypto.newKeyPair().secret_key;
    const intermediate_shared_key1 = try crypto.dh1(public_key, secret_key2);
    const intermediate_shared_key2 = try crypto.dh1(public_key, secret_key1);
    const shared_key1 = try crypto.dh2(intermediate_shared_key1, secret_key1);
    const shared_key2 = try crypto.dh2(intermediate_shared_key2, secret_key2);
    std.debug.print("Public key:                      {s}\n", .{public_key});
    std.debug.print("Alice's secret key:              {s}\n", .{secret_key1});
    std.debug.print("Bob's secret key:                {s}\n", .{secret_key2});
    std.debug.print("Alice's intermediate shared key: {s}\n", .{intermediate_shared_key1});
    std.debug.print("Bob's intermediate shared key:   {s}\n", .{intermediate_shared_key2});
    std.debug.print("Alice's final shared key:        {s}\n", .{shared_key1});
    std.debug.print("Bob's final shared key:          {s}\n", .{shared_key2});
    try testing.expect(!std.meta.eql(secret_key1, secret_key2));
    try testing.expect(!std.meta.eql(intermediate_shared_key1, intermediate_shared_key2));
    try testing.expectEqual(shared_key1, shared_key2);

    const aes_message = "Hello, AES!";
    var aes_encrypted1 = std.ArrayList(u8).init(testing.allocator);
    defer aes_encrypted1.deinit();
    try crypto.aesEncrypt(shared_key1, aes_message, aes_encrypted1.writer());
    var aes_decrypted1 = std.ArrayList(u8).init(testing.allocator);
    defer aes_decrypted1.deinit();
    try crypto.aesDecrypt(shared_key1, aes_encrypted1.items, aes_decrypted1.writer());
    std.debug.print("Original string:          '{s}'\n", .{aes_message});
    std.debug.print("Alice's encrypted string: '{s}'\n", .{aes_encrypted1.items});
    std.debug.print("Alice's decrypted string: '{s}'\n", .{aes_decrypted1.items});
    try testing.expectEqualStrings(aes_decrypted1.items, aes_message);
    try testing.expect(!std.mem.eql(u8, aes_encrypted1.items, aes_message));
    var aes_encrypted2 = std.ArrayList(u8).init(testing.allocator);
    defer aes_encrypted2.deinit();
    try crypto.aesEncrypt(shared_key2, aes_message, aes_encrypted2.writer());
    var aes_decrypted2 = std.ArrayList(u8).init(testing.allocator);
    defer aes_decrypted2.deinit();
    try crypto.aesDecrypt(shared_key2, aes_encrypted2.items, aes_decrypted2.writer());
    std.debug.print("Original string:          '{s}'\n", .{aes_message});
    std.debug.print("Bob's encrypted string:   '{s}'\n", .{aes_encrypted2.items});
    std.debug.print("Bob's decrypted string:   '{s}'\n", .{aes_decrypted2.items});
    try testing.expectEqualStrings(aes_decrypted2.items, aes_message);
    try testing.expect(!std.mem.eql(u8, aes_encrypted2.items, aes_message));
    try testing.expectEqualStrings(aes_decrypted1.items, aes_decrypted2.items);
}

test "server serving" {
    var expected = ExpectMap.init(testing.allocator);
    defer expected.deinit();
    try expected.expect(.server_receive, 0);
    try expected.expect(.server_connect, 0);
    try expected.expect(.server_disconnect, 0);

    var server = Server(i32, []const u8, *ExpectMap).init(testing.allocator, &expected, .{
        .on_receive = OnReceive(i32, []const u8),
        .on_connect = OnConnect(i32, []const u8),
        .on_disconnect = OnDisconnect(i32, []const u8),
    });
    try testing.expect(!server.serving());
    try server.start(SERVER_HOST, SERVER_PORT);
    sleep();

    try testing.expect(server.serving());
    const addr = try server.getAddress();
    std.debug.print("Server address: {}\n", .{addr});

    try server.stop();
    sleep();

    try testing.expect(!server.serving());

    try expected.done();
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
