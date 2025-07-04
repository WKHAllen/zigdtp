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
/// A value received through a network socket. `deinit` must be called once the
/// memory is no longer needed.
pub const Received = util.Received;

const testing = std.testing;
const ArrayList = std.ArrayList;
const Allocator = std.mem.Allocator;
const ThreadSafeAllocator = std.heap.ThreadSafeAllocator;
const Thread = std.Thread;
const Mutex = Thread.Mutex;
const Random = std.Random;
const Xoshiro256 = Random.Xoshiro256;
const posix = std.posix;
const GetRandomError = posix.GetRandomError;

/// Default server host address.
const SERVER_HOST = "127.0.0.1";

/// Default server port.
const SERVER_PORT = 0;

/// Default amount of time to sleep, in nanoseconds.
const SLEEP_TIME = 100_000_000;

/// Sleep for the default duration.
fn sleep() void {
    Thread.sleep(SLEEP_TIME);
}

/// Sleep for a desired duration.
fn sleepFor(seconds: f64) void {
    Thread.sleep(@intFromFloat(seconds * 1_000_000_000.0));
}

/// Constructs a thread-safe allocator.
fn threadSafeAllocator() ThreadSafeAllocator {
    return ThreadSafeAllocator{
        .child_allocator = testing.allocator,
    };
}

/// Constructs a Xoshiro256 RNG instance.
fn rngInstance() GetRandomError!Xoshiro256 {
    return std.Random.DefaultPrng.init(blk: {
        var seed: u64 = undefined;
        try posix.getrandom(std.mem.asBytes(&seed));
        break :blk seed;
    });
}

/// Generates a random sequence of `n` bytes. The caller is responsible for
/// calling `deinit` on the returned value.
fn randomBytes(n: usize, rand: Random, allocator: Allocator) Allocator.Error!ArrayList(u8) {
    var bytes = try ArrayList(u8).initCapacity(allocator, n);
    bytes.expandToCapacity();
    rand.bytes(bytes.items);
    return bytes;
}

/// Generates a sequence of random `u16` values. The caller is responsible for
/// calling `deinit` on the returned value.
fn randomMessages(min: usize, max: usize, rand: Random, allocator: Allocator) Allocator.Error!ArrayList(u16) {
    const n = rand.intRangeLessThan(usize, min, max);
    var messages = try ArrayList(u16).initCapacity(allocator, n);
    messages.expandToCapacity();

    for (messages.items) |*message| message.* = rand.int(u16);
    return messages;
}

/// Compares two values of the same type using deep equality.
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

/// Compares two values of the same type using deep equality.
fn eql(a: anytype, b: @TypeOf(a)) bool {
    return eqlInner(@TypeOf(a), a, b);
}

/// Returns the index of a given value in a slice.
fn indexOf(comptime T: type, slice: []const T, value: T) ?usize {
    for (slice, 0..) |current, i| {
        if (eql(current, value)) return i;
    }

    return null;
}

/// A testing type. This represents a single expected event value.
fn ExpectValue(comptime S: type, comptime C: type) type {
    return union(enum) {
        const Self = @This();

        /// The server received data from a client.
        server_receive: struct { usize, S },
        /// A client connected to the server.
        server_connect: usize,
        /// A client disconnected from the server.
        server_disconnect: usize,
        /// The client received data from the server.
        client_receive: C,
        /// The client was disconnected from the server.
        client_disconnected,

        /// Display implementation.
        pub fn format(self: Self, comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) @TypeOf(writer).Error!void {
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

/// A testing type. This represents all expected events in a single testing
/// context. It is thread-safe and can be shared as the context value for any
/// number of servers and clients.
fn ExpectMap(comptime S: type, comptime C: type) type {
    return struct {
        const Self = @This();

        /// The event value type for this expect map.
        pub const Value = ExpectValue(S, C);

        /// The events expected to be encountered.
        expected: ArrayList(Value),
        /// The mutex for thread-safety.
        mutex: Mutex,

        /// Initializes a new expect map.
        pub fn init(allocator: Allocator) Self {
            return Self{
                .expected = ArrayList(Value).init(allocator),
                .mutex = Mutex{},
            };
        }

        /// Releases all allocated memory.
        pub fn deinit(self: *Self) void {
            self.mutex.lock();
            defer self.mutex.unlock();

            self.expected.deinit();
        }

        /// Notes that an event value is expected in this testing context.
        pub fn expect(self: *Self, value: Value) Allocator.Error!void {
            self.mutex.lock();
            defer self.mutex.unlock();

            try self.expected.append(value);
        }

        /// Notes that an event value has been received. This will panic if the
        /// received event was not expected.
        pub fn received(self: *Self, value: Value) void {
            self.mutex.lock();
            defer self.mutex.unlock();

            if (indexOf(Value, self.expected.items, value)) |index| {
                _ = self.expected.swapRemove(index);
            } else {
                std.debug.panic("unexpected event received: {any}\n", .{value});
            }
        }

        /// Checks that all expected events were received. This will panic if
        /// any events have yet to be encountered.
        pub fn done(self: *Self) void {
            self.mutex.lock();
            defer self.mutex.unlock();

            if (self.expected.items.len > 0) {
                for (self.expected.items) |value| {
                    std.debug.print("expected event not received: {any}\n", .{value});
                }

                std.debug.panic("some expected events were never received\n", .{});
            }
        }

        /// Returns a function that notes incoming server receive events.
        pub fn ServerOnReceive() fn (*ExpectMap(S, C), *Server(C, S, *ExpectMap(S, C)), usize, Received(S)) void {
            return struct {
                fn serverOnReceive(expected: *ExpectMap(S, C), _: *Server(C, S, *ExpectMap(S, C)), client_id: usize, data: Received(S)) void {
                    defer data.deinit();
                    expected.received(.{ .server_receive = .{ client_id, data.value } });
                }
            }.serverOnReceive;
        }

        /// Returns a function that notes incoming server connect events.
        pub fn ServerOnConnect() fn (*ExpectMap(S, C), *Server(C, S, *ExpectMap(S, C)), usize) void {
            return struct {
                fn serverOnConnect(expected: *ExpectMap(S, C), _: *Server(C, S, *ExpectMap(S, C)), client_id: usize) void {
                    expected.received(.{ .server_connect = client_id });
                }
            }.serverOnConnect;
        }

        /// Returns a function that notes incoming server disconnect events.
        pub fn ServerOnDisconnect() fn (*ExpectMap(S, C), *Server(C, S, *ExpectMap(S, C)), usize) void {
            return struct {
                fn serverOnDisonnect(expected: *ExpectMap(S, C), _: *Server(C, S, *ExpectMap(S, C)), client_id: usize) void {
                    expected.received(.{ .server_disconnect = client_id });
                }
            }.serverOnDisonnect;
        }

        /// Returns a function that notes incoming client receive events.
        pub fn ClientOnReceive() fn (*ExpectMap(S, C), *Client(S, C, *ExpectMap(S, C)), Received(C)) void {
            return struct {
                fn clientOnReceive(expected: *ExpectMap(S, C), _: *Client(S, C, *ExpectMap(S, C)), data: Received(C)) void {
                    defer data.deinit();
                    expected.received(.{ .client_receive = data.value });
                }
            }.clientOnReceive;
        }

        /// Returns a function that notes incoming client disconnected events.
        pub fn ClientOnDisconnected() fn (*ExpectMap(S, C), *Client(S, C, *ExpectMap(S, C))) void {
            return struct {
                fn clientOnDisconnected(expected: *ExpectMap(S, C), _: *Client(S, C, *ExpectMap(S, C))) void {
                    expected.received(.client_disconnected);
                }
            }.clientOnDisconnected;
        }
    };
}

/// An alternative to `ExpectMap(...).ServerOnReceive()`. This will do the same
/// but is typed to receive strings and will always send back the length of the
/// received string.
fn serverOnReceiveRespond(expected: *ExpectMap([]const u8, i32), server: *Server(i32, []const u8, *ExpectMap([]const u8, i32)), client_id: usize, data: Received([]const u8)) void {
    defer data.deinit();

    expected.received(.{ .server_receive = .{ client_id, data.value } });

    server.send(@intCast(data.value.len), client_id) catch |e| {
        std.debug.panic("{any}\n", .{e});
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
    defer server.deinit();
    try testing.expect(!server.serving());
    try server.start(SERVER_HOST, SERVER_PORT);
    sleep();

    try testing.expect(server.serving());
    const server_addr = try server.getAddress();
    std.debug.print("Server address: {}\n", .{server_addr});

    try server.stop();
    sleep();

    try testing.expect(!server.serving());

    expected.done();
}

test "addresses" {
    var thread_safe_allocator = threadSafeAllocator();
    const allocator = thread_safe_allocator.allocator();

    const EM = ExpectMap([]const u8, i32);
    var expected = EM.init(allocator);
    defer expected.deinit();
    try expected.expect(.{ .server_connect = 0 });
    try expected.expect(.{ .server_disconnect = 0 });

    const address = try util.resolveIp(SERVER_HOST, SERVER_PORT);

    var server = Server(i32, []const u8, *EM).init(allocator, &expected, .{
        .on_receive = EM.ServerOnReceive(),
        .on_connect = EM.ServerOnConnect(),
        .on_disconnect = EM.ServerOnDisconnect(),
    });
    defer server.deinit();
    try testing.expect(!server.serving());
    try server.startViaAddress(address);
    sleep();

    try testing.expect(server.serving());
    const server_addr = try server.getAddress();
    std.debug.print("Server address: {}\n", .{server_addr});

    var client = Client([]const u8, i32, *EM).init(allocator, &expected, .{
        .on_receive = EM.ClientOnReceive(),
        .on_disconnected = EM.ClientOnDisconnected(),
    });
    defer client.deinit();
    try testing.expect(!client.connected());
    try client.connect(SERVER_HOST, server_addr.getPort());
    sleep();

    try testing.expect(client.connected());
    const client_addr = try client.getAddress();
    std.debug.print("Client address: {}\n", .{client_addr});
    try testing.expect((try server.getAddress()).eql(try client.getServerAddress()));
    try testing.expect((try client.getAddress()).eql(try server.getClientAddress(0)));

    try client.disconnect();
    sleep();

    try testing.expect(!client.connected());

    try server.stop();
    sleep();

    try testing.expect(!server.serving());

    expected.done();
}

test "send" {
    var thread_safe_allocator = threadSafeAllocator();
    const allocator = thread_safe_allocator.allocator();

    const message_from_server = 29275;
    const message_from_client = "Hello, server!";

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
    defer server.deinit();
    try server.start(SERVER_HOST, SERVER_PORT);
    sleep();

    const server_addr = try server.getAddress();
    std.debug.print("Server address: {}\n", .{server_addr});

    var client = Client([]const u8, i32, *EM).init(allocator, &expected, .{
        .on_receive = EM.ClientOnReceive(),
        .on_disconnected = EM.ClientOnDisconnected(),
    });
    defer client.deinit();
    try client.connectViaAddress(server_addr);
    sleep();

    const client_addr = try client.getAddress();
    std.debug.print("Client address: {}\n", .{client_addr});

    try server.sendAll(message_from_server);
    try client.send(message_from_client);
    sleep();

    try client.disconnect();
    sleep();

    try server.stop();
    sleep();

    expected.done();
}

test "large send" {
    var thread_safe_allocator = threadSafeAllocator();
    const allocator = thread_safe_allocator.allocator();

    var prng = try rngInstance();
    const rand = prng.random();

    const message_from_server = try randomBytes(rand.intRangeLessThan(usize, 32768, 65536), rand, allocator);
    defer message_from_server.deinit();
    const message_from_client = try randomBytes(rand.intRangeLessThan(usize, 16384, 32768), rand, allocator);
    defer message_from_client.deinit();

    const EM = ExpectMap([]const u8, []const u8);
    var expected = EM.init(allocator);
    defer expected.deinit();
    try expected.expect(.{ .server_connect = 0 });
    try expected.expect(.{ .client_receive = message_from_server.items });
    try expected.expect(.{ .server_receive = .{ 0, message_from_client.items } });
    try expected.expect(.{ .server_disconnect = 0 });

    var server = Server([]const u8, []const u8, *EM).init(allocator, &expected, .{
        .on_receive = EM.ServerOnReceive(),
        .on_connect = EM.ServerOnConnect(),
        .on_disconnect = EM.ServerOnDisconnect(),
    });
    defer server.deinit();
    try server.start(SERVER_HOST, SERVER_PORT);
    sleep();

    const server_addr = try server.getAddress();
    std.debug.print("Server address: {}\n", .{server_addr});

    var client = Client([]const u8, []const u8, *EM).init(allocator, &expected, .{
        .on_receive = EM.ClientOnReceive(),
        .on_disconnected = EM.ClientOnDisconnected(),
    });
    defer client.deinit();
    try client.connectViaAddress(server_addr);
    sleep();

    const client_addr = try client.getAddress();
    std.debug.print("Client address: {}\n", .{client_addr});

    try server.sendAll(message_from_server.items);
    try client.send(message_from_client.items);
    sleepFor(1.0);

    try client.disconnect();
    sleep();

    try server.stop();
    sleep();

    expected.done();
}

test "sending numerous messages" {
    var thread_safe_allocator = threadSafeAllocator();
    const allocator = thread_safe_allocator.allocator();

    var prng = try rngInstance();
    const rand = prng.random();

    const messages_from_server = try randomMessages(64, 128, rand, allocator);
    defer messages_from_server.deinit();
    const messages_from_client = try randomMessages(128, 256, rand, allocator);
    defer messages_from_client.deinit();

    const EM = ExpectMap(u16, u16);
    var expected = EM.init(allocator);
    defer expected.deinit();
    try expected.expect(.{ .server_connect = 0 });
    for (messages_from_server.items) |message| try expected.expect(.{ .client_receive = message });
    for (messages_from_client.items) |message| try expected.expect(.{ .server_receive = .{ 0, message } });
    try expected.expect(.{ .server_disconnect = 0 });

    var server = Server(u16, u16, *EM).init(allocator, &expected, .{
        .on_receive = EM.ServerOnReceive(),
        .on_connect = EM.ServerOnConnect(),
        .on_disconnect = EM.ServerOnDisconnect(),
    });
    defer server.deinit();
    try server.start(SERVER_HOST, SERVER_PORT);
    sleep();

    const server_addr = try server.getAddress();
    std.debug.print("Server address: {}\n", .{server_addr});

    var client = Client(u16, u16, *EM).init(allocator, &expected, .{
        .on_receive = EM.ClientOnReceive(),
        .on_disconnected = EM.ClientOnDisconnected(),
    });
    defer client.deinit();
    try client.connectViaAddress(server_addr);
    sleep();

    const client_addr = try client.getAddress();
    std.debug.print("Client address: {}\n", .{client_addr});

    for (messages_from_server.items) |message| try server.sendAll(message);
    for (messages_from_client.items) |message| try client.send(message);
    sleepFor(1.0);

    try client.disconnect();
    sleep();

    try server.stop();
    sleep();

    expected.done();
}

test "sending custom types" {
    const Custom = struct {
        a: i32,
        b: []const u8,
        c: []const []const u8,
    };

    var thread_safe_allocator = threadSafeAllocator();
    const allocator = thread_safe_allocator.allocator();

    const message_from_server = Custom{
        .a = 123,
        .b = "Hello, custom server type!",
        .c = &[_][]const u8{ "first server item", "second server item" },
    };
    const message_from_client = Custom{
        .a = 456,
        .b = "Hello, custom client type!",
        .c = &[_][]const u8{ "#1 client item", "client item #2", "(3) client item" },
    };

    const EM = ExpectMap(Custom, Custom);
    var expected = EM.init(allocator);
    defer expected.deinit();
    try expected.expect(.{ .server_connect = 0 });
    try expected.expect(.{ .client_receive = message_from_server });
    try expected.expect(.{ .server_receive = .{ 0, message_from_client } });
    try expected.expect(.{ .server_disconnect = 0 });

    var server = Server(Custom, Custom, *EM).init(allocator, &expected, .{
        .on_receive = EM.ServerOnReceive(),
        .on_connect = EM.ServerOnConnect(),
        .on_disconnect = EM.ServerOnDisconnect(),
    });
    defer server.deinit();
    try server.start(SERVER_HOST, SERVER_PORT);
    sleep();

    const server_addr = try server.getAddress();
    std.debug.print("Server address: {}\n", .{server_addr});

    var client = Client(Custom, Custom, *EM).init(allocator, &expected, .{
        .on_receive = EM.ClientOnReceive(),
        .on_disconnected = EM.ClientOnDisconnected(),
    });
    defer client.deinit();
    try client.connectViaAddress(server_addr);
    sleep();

    const client_addr = try client.getAddress();
    std.debug.print("Client address: {}\n", .{client_addr});

    try server.sendAll(message_from_server);
    try client.send(message_from_client);
    sleep();

    try client.disconnect();
    sleep();

    try server.stop();
    sleep();

    expected.done();
}

test "multiple clients" {
    var thread_safe_allocator = threadSafeAllocator();
    const allocator = thread_safe_allocator.allocator();

    const message_from_server = 29275;
    const message_from_client1 = "Hello from client #1!";
    const message_from_client2 = "Goodbye from client #2!";

    const EM = ExpectMap([]const u8, i32);
    var expected = EM.init(allocator);
    defer expected.deinit();
    try expected.expect(.{ .server_connect = 0 });
    try expected.expect(.{ .server_connect = 1 });
    try expected.expect(.{ .client_receive = message_from_server });
    try expected.expect(.{ .client_receive = message_from_server });
    try expected.expect(.{ .server_receive = .{ 0, message_from_client1 } });
    try expected.expect(.{ .server_receive = .{ 1, message_from_client2 } });
    try expected.expect(.{ .client_receive = message_from_client1.len });
    try expected.expect(.{ .client_receive = message_from_client2.len });
    try expected.expect(.{ .server_disconnect = 0 });
    try expected.expect(.{ .server_disconnect = 1 });

    var server = Server(i32, []const u8, *EM).init(allocator, &expected, .{
        .on_receive = serverOnReceiveRespond,
        .on_connect = EM.ServerOnConnect(),
        .on_disconnect = EM.ServerOnDisconnect(),
    });
    defer server.deinit();
    try server.start(SERVER_HOST, SERVER_PORT);
    sleep();

    const server_addr = try server.getAddress();
    std.debug.print("Server address: {}\n", .{server_addr});

    var client1 = Client([]const u8, i32, *EM).init(allocator, &expected, .{
        .on_receive = EM.ClientOnReceive(),
        .on_disconnected = EM.ClientOnDisconnected(),
    });
    defer client1.deinit();
    try client1.connectViaAddress(server_addr);
    sleep();

    const client1_addr = try client1.getAddress();
    std.debug.print("Client 1 address: {}\n", .{client1_addr});
    try testing.expect((try server.getAddress()).eql(try client1.getServerAddress()));
    try testing.expect((try client1.getAddress()).eql(try server.getClientAddress(0)));

    var client2 = Client([]const u8, i32, *EM).init(allocator, &expected, .{
        .on_receive = EM.ClientOnReceive(),
        .on_disconnected = EM.ClientOnDisconnected(),
    });
    defer client2.deinit();
    try client2.connectViaAddress(server_addr);
    sleep();

    const client2_addr = try client2.getAddress();
    std.debug.print("Client 2 address: {}\n", .{client2_addr});
    try testing.expect((try server.getAddress()).eql(try client2.getServerAddress()));
    try testing.expect((try client2.getAddress()).eql(try server.getClientAddress(1)));

    try server.sendMultiple(message_from_server, &.{ 0, 1 });
    try client1.send(message_from_client1);
    try client2.send(message_from_client2);
    sleep();

    try client1.disconnect();
    sleep();

    try client2.disconnect();
    sleep();

    try server.stop();
    sleep();

    expected.done();
}

test "remove client" {
    var thread_safe_allocator = threadSafeAllocator();
    const allocator = thread_safe_allocator.allocator();

    const EM = ExpectMap([]const u8, i32);
    var expected = EM.init(allocator);
    defer expected.deinit();
    try expected.expect(.{ .server_connect = 0 });
    try expected.expect(.{ .server_disconnect = 0 });
    try expected.expect(.client_disconnected);

    var server = Server(i32, []const u8, *EM).init(allocator, &expected, .{
        .on_receive = EM.ServerOnReceive(),
        .on_connect = EM.ServerOnConnect(),
        .on_disconnect = EM.ServerOnDisconnect(),
    });
    defer server.deinit();
    try testing.expect(!server.serving());
    try server.start(SERVER_HOST, SERVER_PORT);
    sleep();

    try testing.expect(server.serving());
    const server_addr = try server.getAddress();
    std.debug.print("Server address: {}\n", .{server_addr});

    var client = Client([]const u8, i32, *EM).init(allocator, &expected, .{
        .on_receive = EM.ClientOnReceive(),
        .on_disconnected = EM.ClientOnDisconnected(),
    });
    defer client.deinit();
    try testing.expect(!client.connected());
    try client.connect(SERVER_HOST, server_addr.getPort());
    sleep();

    try testing.expect(client.connected());
    const client_addr = try client.getAddress();
    std.debug.print("Client address: {}\n", .{client_addr});

    try server.removeClient(0);
    sleep();

    try testing.expect(!client.connected());

    try server.stop();
    sleep();

    try testing.expect(!server.serving());

    expected.done();
}

test "stop server while client connected" {
    var thread_safe_allocator = threadSafeAllocator();
    const allocator = thread_safe_allocator.allocator();

    const EM = ExpectMap([]const u8, i32);
    var expected = EM.init(allocator);
    defer expected.deinit();
    try expected.expect(.{ .server_connect = 0 });
    try expected.expect(.{ .server_disconnect = 0 });
    try expected.expect(.client_disconnected);

    var server = Server(i32, []const u8, *EM).init(allocator, &expected, .{
        .on_receive = EM.ServerOnReceive(),
        .on_connect = EM.ServerOnConnect(),
        .on_disconnect = EM.ServerOnDisconnect(),
    });
    defer server.deinit();
    try testing.expect(!server.serving());
    try server.start(SERVER_HOST, SERVER_PORT);
    sleep();

    try testing.expect(server.serving());
    const server_addr = try server.getAddress();
    std.debug.print("Server address: {}\n", .{server_addr});

    var client = Client([]const u8, i32, *EM).init(allocator, &expected, .{
        .on_receive = EM.ClientOnReceive(),
        .on_disconnected = EM.ClientOnDisconnected(),
    });
    defer client.deinit();
    try testing.expect(!client.connected());
    try client.connect(SERVER_HOST, server_addr.getPort());
    sleep();

    try testing.expect(client.connected());
    const client_addr = try client.getAddress();
    std.debug.print("Client address: {}\n", .{client_addr});

    try server.stop();
    sleep();

    try testing.expect(!server.serving());
    try testing.expect(!client.connected());

    expected.done();
}

// Called when data is received from a client
fn exampleServerReceive(_: void, server: *Server(usize, []const u8, void), client_id: usize, data: Received([]const u8)) void {
    defer data.deinit();
    // Send back the length of the string
    server.send(data.value.len, client_id) catch unreachable;
}

// Called when a client connects
fn exampleServerConnect(_: void, _: *Server(usize, []const u8, void), client_id: usize) void {
    std.debug.print("Client with ID {d} connected\n", .{client_id});
}

// Called when a client disconnects
fn exampleServerDisconnect(_: void, server: *Server(usize, []const u8, void), client_id: usize) void {
    std.debug.print("Client with ID {d} disconnected\n", .{client_id});
    server.stop() catch unreachable;
}

const exampleMessage = "Hello, server!";

// Called when data is received from the server
fn exampleClientReceive(_: void, client: *Client([]const u8, usize, void), data: Received(usize)) void {
    defer data.deinit();
    // Validate the response
    std.debug.print("Received response from server: {d}\n", .{data.value});
    testing.expect(data.value == exampleMessage.len) catch unreachable;
    client.disconnect() catch unreachable;
}

// Called when the client is disconnected from the server
fn exampleClientDisconnected(_: void, _: *Client([]const u8, usize, void)) void {
    std.debug.print("Unexpectedly disconnected from server\n", .{});
}

test "example" {
    var thread_safe_allocator = threadSafeAllocator();
    const allocator = thread_safe_allocator.allocator();

    // Create a server that receives strings and returns the length of each string
    var server = Server(usize, []const u8, void).init(allocator, {}, .{
        .on_receive = exampleServerReceive,
        .on_connect = exampleServerConnect,
        .on_disconnect = exampleServerDisconnect,
    });
    defer server.deinit();
    try server.start("127.0.0.1", 29275);

    // Create a client that sends a message to the server and receives the length of the message
    var client = Client([]const u8, usize, void).init(allocator, {}, .{
        .on_receive = exampleClientReceive,
        .on_disconnected = exampleClientDisconnected,
    });
    defer client.deinit();
    try client.connect("127.0.0.1", 29275);
    try client.send(exampleMessage);

    while (client.connected()) sleep();
    while (server.serving()) sleep();

    std.debug.print("Example finished\n", .{});
}
