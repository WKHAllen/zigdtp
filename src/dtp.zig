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
const ArrayList = std.ArrayList;
const Allocator = std.mem.Allocator;
const ThreadSafeAllocator = std.heap.ThreadSafeAllocator;
const Thread = std.Thread;
const Mutex = Thread.Mutex;
const Parsed = std.json.Parsed;

const SERVER_HOST = "127.0.0.1";
const SERVER_PORT = 0;
const SLEEP_TIME = 100_000_000;

fn sleep() void {
    Thread.sleep(SLEEP_TIME);
}

fn threadSafeAllocator() ThreadSafeAllocator {
    return ThreadSafeAllocator{
        .child_allocator = testing.allocator,
    };
}

fn eqlInner(comptime T: type, a: T, b: T) bool {
    switch (@typeInfo(T)) {
        .noreturn,
        .@"opaque",
        .frame,
        .@"anyframe",
        => @compileError("unable to compare values of type " ++ @typeName(T)),

        .undefined,
        .null,
        .void,
        => return true,

        .bool,
        .int,
        .float,
        .comptime_int,
        .comptime_float,
        .enum_literal,
        .@"enum",
        .@"fn",
        .error_set,
        .type,
        => return a == b,

        .pointer => |ptr| {
            switch (ptr.size) {
                .c, .many => return a == b,
                .one => {
                    switch (@typeInfo(ptr.child)) {
                        .@"fn", .@"opaque" => return a == b,
                        else => return eql(a.*, b.*),
                    }
                },
                .slice => {
                    if (a.len != b.len) return false;

                    var i: usize = 0;
                    while (i < a.len) : (i += 1) {
                        if (!eql(a[i], b[i])) return false;
                    }

                    return true;
                },
            }
        },

        .array => |_| {
            if (a.len != b.len) return false;

            var i: usize = 0;
            while (i < a.len) : (i += 1) {
                if (!eql(a[i], b[i])) return false;
            }

            return true;
        },

        .vector => |vec| {
            if (vec.len != @typeInfo(T).vector.len) return false;

            var i: usize = 0;
            while (i < vec.len) : (i += 1) {
                if (!eql(a[i], b[i])) return false;
            }

            return true;
        },

        .@"struct" => |struct_info| {
            inline for (struct_info.fields) |field| {
                if (!eql(@field(a, field.name), @field(b, field.name))) return false;
            }

            return true;
        },

        .@"union" => |union_info| {
            if (union_info.tag_type == null) {
                @compileError("Unable to compare untagged union values for type " ++ @typeName(T));
            }

            const Tag = std.meta.Tag(T);
            const aTag = @as(Tag, a);
            const bTag = @as(Tag, b);

            if (!eql(aTag, bTag)) return false;

            switch (a) {
                inline else => |val, tag| {
                    return eql(val, @field(b, @tagName(tag)));
                },
            }
        },

        .optional => {
            return if (a) |a_inner|
                if (b) |b_inner|
                    eql(a_inner, b_inner)
                else
                    false
            else if (b) false else true;
        },

        .error_union => {
            return if (a) |a_ok_inner|
                if (b) |b_ok_inner|
                    eql(a_ok_inner, b_ok_inner)
                else
                    false
            else |a_err_inner| if (b) false else |b_err_inner| eql(a_err_inner, b_err_inner);
        },
    }
}

fn eql(a: anytype, b: @TypeOf(a)) bool {
    return eqlInner(@TypeOf(a), a, b);
}

fn indexOf(comptime T: type, slice: []const T, value: T) ?usize {
    for (slice, 0..) |current, i| {
        if (eql(current, value)) return i;
    }

    return null;
}

fn ExpectValue(comptime S: type, comptime C: type) type {
    return union(enum) {
        const Self = @This();

        server_receive: struct { usize, S },
        server_connect: usize,
        server_disconnect: usize,
        client_receive: C,
        client_disconnected,

        pub fn format(self: Self, comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
            try switch (self) {
                .server_receive => |inner| writer.print(".server_receive({d}, {any})", .{ inner.@"0", inner.@"1" }),
                .server_connect => |client_id| writer.print(".server_connect({d})", .{client_id}),
                .server_disconnect => |client_id| writer.print(".server_disconnect({d})", .{client_id}),
                .client_receive => |data| writer.print(".client_receive({any})", .{data}),
                .client_disconnected => writer.print(".client_disconnected", .{}),
            };
        }
    };
}

fn ExpectMap(comptime S: type, comptime C: type) type {
    return struct {
        const Self = @This();

        pub const Value = ExpectValue(S, C);

        expected: ArrayList(Value),
        mutex: Mutex,

        pub fn init(allocator: Allocator) Self {
            return Self{
                .expected = ArrayList(Value).init(allocator),
                .mutex = Mutex{},
            };
        }

        pub fn deinit(self: *Self) void {
            self.mutex.lock();
            defer self.mutex.unlock();

            self.expected.deinit();
        }

        pub fn expect(self: *Self, value: Value) !void {
            self.mutex.lock();
            defer self.mutex.unlock();

            try self.expected.append(value);
        }

        pub fn received(self: *Self, value: Value) !void {
            self.mutex.lock();
            defer self.mutex.unlock();

            if (indexOf(Value, self.expected.items, value)) |index| {
                _ = self.expected.swapRemove(index);
            } else {
                std.debug.panic("unexpected event received: {any}\n", .{value});
            }
        }

        pub fn done(self: *Self) !void {
            self.mutex.lock();
            defer self.mutex.unlock();

            if (self.expected.items.len > 0) {
                for (self.expected.items) |value| {
                    std.debug.print("expected event not received: {any}\n", .{value});
                }

                std.debug.panic("some expected events were never received\n", .{});
            }
        }

        pub fn ServerOnReceive() fn (*ExpectMap(S, C), *Server(C, S, *ExpectMap(S, C)), usize, Parsed(S)) void {
            return struct {
                fn serverOnReceive(expected: *ExpectMap(S, C), _: *Server(C, S, *ExpectMap(S, C)), client_id: usize, data: Parsed(S)) void {
                    defer data.deinit();

                    expected.received(.{ .server_receive = .{ client_id, data.value } }) catch |e| {
                        std.debug.panic("{any}\n", .{e});
                    };
                }
            }.serverOnReceive;
        }

        pub fn ServerOnConnect() fn (*ExpectMap(S, C), *Server(C, S, *ExpectMap(S, C)), usize) void {
            return struct {
                fn serverOnConnect(expected: *ExpectMap(S, C), _: *Server(C, S, *ExpectMap(S, C)), client_id: usize) void {
                    expected.received(.{ .server_connect = client_id }) catch |e| {
                        std.debug.panic("{any}\n", .{e});
                    };
                }
            }.serverOnConnect;
        }

        pub fn ServerOnDisconnect() fn (*ExpectMap(S, C), *Server(C, S, *ExpectMap(S, C)), usize) void {
            return struct {
                fn serverOnDisonnect(expected: *ExpectMap(S, C), _: *Server(C, S, *ExpectMap(S, C)), client_id: usize) void {
                    expected.received(.{ .server_disconnect = client_id }) catch |e| {
                        std.debug.panic("{any}\n", .{e});
                    };
                }
            }.serverOnDisonnect;
        }

        pub fn ClientOnReceive() fn (*ExpectMap(S, C), *Client(S, C, *ExpectMap(S, C)), Parsed(C)) void {
            return struct {
                fn clientOnReceive(expected: *ExpectMap(S, C), _: *Client(S, C, *ExpectMap(S, C)), data: Parsed(C)) void {
                    defer data.deinit();

                    expected.received(.{ .client_receive = data.value }) catch |e| {
                        std.debug.panic("{any}\n", .{e});
                    };
                }
            }.clientOnReceive;
        }

        pub fn ClientOnDisconnected() fn (*ExpectMap(S, C), *Client(S, C, *ExpectMap(S, C))) void {
            return struct {
                fn clientOnDisconnected(expected: *ExpectMap(S, C), _: *Client(S, C, *ExpectMap(S, C))) void {
                    expected.received(.client_disconnected) catch |e| {
                        std.debug.panic("{any}\n", .{e});
                    };
                }
            }.clientOnDisconnected;
        }
    };
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

    var value_serialized = ArrayList(u8).init(testing.allocator);
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
    var aes_encrypted1 = ArrayList(u8).init(testing.allocator);
    defer aes_encrypted1.deinit();
    try crypto.aesEncrypt(shared_key1, aes_message, aes_encrypted1.writer());
    var aes_decrypted1 = ArrayList(u8).init(testing.allocator);
    defer aes_decrypted1.deinit();
    try crypto.aesDecrypt(shared_key1, aes_encrypted1.items, aes_decrypted1.writer());
    std.debug.print("Original string:          '{s}'\n", .{aes_message});
    std.debug.print("Alice's encrypted string: '{s}'\n", .{aes_encrypted1.items});
    std.debug.print("Alice's decrypted string: '{s}'\n", .{aes_decrypted1.items});
    try testing.expectEqualStrings(aes_decrypted1.items, aes_message);
    try testing.expect(!std.mem.eql(u8, aes_encrypted1.items, aes_message));
    var aes_encrypted2 = ArrayList(u8).init(testing.allocator);
    defer aes_encrypted2.deinit();
    try crypto.aesEncrypt(shared_key2, aes_message, aes_encrypted2.writer());
    var aes_decrypted2 = ArrayList(u8).init(testing.allocator);
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
    var thread_safe_allocator = threadSafeAllocator();
    const allocator = thread_safe_allocator.allocator();

    const EM = ExpectMap([]const u8, i32);
    var expected = EM.init(allocator);
    defer expected.deinit();

    var server = Server(i32, []const u8, *EM).init(allocator, &expected, .{
        .on_receive = EM.ServerOnReceive(),
        .on_connect = EM.ServerOnConnect(),
        .on_disconnect = EM.ServerOnDisconnect(),
    });
    try testing.expect(!server.serving());
    try server.start(SERVER_HOST, SERVER_PORT);
    sleep();

    try testing.expect(server.serving());
    const server_addr = try server.getAddress();
    std.debug.print("Server address: {}\n", .{server_addr});

    try server.stop();
    sleep();

    try testing.expect(!server.serving());

    try expected.done();
}

test "addresses" {
    var thread_safe_allocator = threadSafeAllocator();
    const allocator = thread_safe_allocator.allocator();

    const EM = ExpectMap([]const u8, i32);
    var expected = EM.init(allocator);
    defer expected.deinit();
    try expected.expect(.{ .server_connect = 0 });
    try expected.expect(.{ .server_disconnect = 0 });

    var server = Server(i32, []const u8, *EM).init(allocator, &expected, .{
        .on_receive = EM.ServerOnReceive(),
        .on_connect = EM.ServerOnConnect(),
        .on_disconnect = EM.ServerOnDisconnect(),
    });
    try server.start(SERVER_HOST, SERVER_PORT);
    sleep();

    const server_addr = try server.getAddress();
    std.debug.print("Server address: {}\n", .{server_addr});

    var client = Client([]const u8, i32, *EM).init(allocator, &expected, .{
        .on_receive = EM.ClientOnReceive(),
        .on_disconnected = EM.ClientOnDisconnected(),
    });
    try client.connect(SERVER_HOST, server_addr.getPort());
    sleep();

    const client_addr = try server.getClientAddress(0);
    std.debug.print("Client address: {}\n", .{client_addr});

    try client.disconnect();
    sleep();

    try server.stop();
    sleep();

    try expected.done();
}

test "send" {
    const message_from_server = 29275;
    const message_from_client = "Hello, server!";

    var thread_safe_allocator = threadSafeAllocator();
    const allocator = thread_safe_allocator.allocator();

    const EM = ExpectMap([]const u8, i32);
    var expected = EM.init(allocator);
    defer expected.deinit();
    try expected.expect(.{ .server_connect = 0 });
    try expected.expect(.{ .client_receive = message_from_server });
    try expected.expect(.{ .server_receive = .{ 0, message_from_client } });
    try expected.expect(.{ .server_disconnect = 0 });

    var server = Server(i32, []const u8, *EM).init(allocator, &expected, .{
        .on_receive = EM.ServerOnReceive(),
        .on_connect = EM.ServerOnConnect(),
        .on_disconnect = EM.ServerOnDisconnect(),
    });
    try server.start(SERVER_HOST, SERVER_PORT);
    sleep();

    const server_addr = try server.getAddress();
    std.debug.print("Server address: {}\n", .{server_addr});

    var client = Client([]const u8, i32, *EM).init(allocator, &expected, .{
        .on_receive = EM.ClientOnReceive(),
        .on_disconnected = EM.ClientOnDisconnected(),
    });
    try client.connectViaAddress(server_addr);
    sleep();

    const client_addr = try server.getClientAddress(0);
    std.debug.print("Client address: {}\n", .{client_addr});

    try server.sendAll(message_from_server);
    try client.send(message_from_client);
    sleep();

    try client.disconnect();
    sleep();

    try server.stop();
    sleep();

    try expected.done();
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
