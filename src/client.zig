const std = @import("std");
const crypto = @import("crypto.zig");
const util = @import("util.zig");
const Error = @import("err.zig").Error;
const Allocator = std.mem.Allocator;
const net = std.net;
const Stream = net.Stream;
const Address = net.Address;
const Thread = std.Thread;
const Parsed = std.json.Parsed;

const ClientStateInner = struct {
    sock: Stream,
    key: [crypto.key_length]u8,
};

const ClientState = union(enum) {
    not_connected,
    connected: ClientStateInner,
};

pub fn ClientOptions(comptime S: type, comptime R: type, comptime C: type) type {
    return struct {
        on_receive: ?*const fn (C, *Client(S, R, C), R) void = null,
        on_disconnected: ?*const fn (C, *Client(S, R, C)) void = null,
    };
}

fn callOnReceiveInner(comptime S: type, comptime R: type, comptime C: type, on_receive: *const fn (C, *Client(S, R, C), R) void, ctx: C, client: *Client(S, R, C), data_parsed: Parsed(R)) void {
    on_receive(ctx, client, data_parsed.value);
    data_parsed.deinit();
}

fn callOnDisconnectedInner(comptime S: type, comptime R: type, comptime C: type, on_disconnected: *const fn (C, *Client(S, R, C)) void, ctx: C, client: *Client(S, R, C)) void {
    on_disconnected(ctx, client);
}

pub fn Client(comptime S: type, comptime R: type, comptime C: type) type {
    return struct {
        const Self = @This();

        state: ClientState,
        handle_thread: ?Thread,
        handle_error: ?Error,
        ctx: C,
        options: ClientOptions(S, R, C),
        allocator: Allocator,

        pub fn init(allocator: Allocator, ctx: C, options: ClientOptions(S, R, C)) Self {
            return Self{
                .state = .not_connected,
                .handle_error = null,
                .ctx = ctx,
                .options = options,
                .allocator = allocator,
            };
        }

        pub fn deinit(self: *Self) void {
            if (self.connected()) {
                self.disconnect() catch {};
            }
        }

        pub fn connect(self: *Self, host: []const u8, port: u16) Error!void {
            if (self.connected()) {
                return Error.AlreadyConnected;
            }

            const stream = try net.tcpConnectToHost(self.allocator, host, port);
            self.exchangeKeys(stream);
        }

        pub fn connectViaAddress(self: *Self, address: Address) Error!void {
            if (self.connected()) {
                return Error.AlreadyConnected;
            }

            const stream = try net.tcpConnectToAddress(self.allocator, address);
            self.exchangeKeys(stream);
        }

        pub fn disconnect(self: *Self) Error!void {
            switch (self.state) {
                .not_connected => return Error.NotConnected,
                .connected => |state| {
                    state.sock.close();
                    self.state = .not_connected;

                    if (self.handle_thread) |handle_thread| handle_thread.join();

                    if (self.handle_error) |err| return err;
                },
            }
        }

        pub fn send(self: *Self, data: S) Error!void {
            switch (self.state) {
                .not_connected => return Error.NotConnected,
                .connected => |state| {
                    var data_serialized = std.ArrayList(u8).init(self.allocator);
                    defer data_serialized.deinit();
                    try util.serialize(data, data_serialized.writer());

                    var data_encrypted = std.ArrayList(u8).init(self.allocator);
                    defer data_encrypted.deinit();
                    try crypto.aesEncrypt(state.key, data_serialized.items, data_encrypted.writer());

                    const encoded_size = util.encodeMessageSize(data_encrypted.items.len);
                    try state.sock.writeAll(&encoded_size);
                    try state.sock.writeAll(data_encrypted.items);
                },
            }
        }

        pub fn connected(self: *Self) bool {
            return switch (self.state) {
                .not_connected => false,
                .connected => |_| true,
            };
        }

        fn callOnReceive(self: *Self, data_parsed: Parsed(R)) Thread.SpawnError!void {
            if (self.options.on_receive) |on_receive| {
                const thread = try Thread.spawn(.{}, callOnReceiveInner, .{ S, R, C, on_receive, self.ctx, self, data_parsed });
                thread.detach();
            }
        }

        fn callOnDisconnected(self: *Self) Thread.SpawnError!void {
            if (self.options.on_disconnected) |on_disconnected| {
                const thread = try Thread.spawn(.{}, callOnDisconnectedInner, .{ S, R, C, on_disconnected, self.ctx, self });
                thread.detach();
            }
        }

        fn exchangeKeys(self: *Self, sock: Stream) Error!void {
            const secret_key = crypto.newKeyPair().secret_key;

            var public_key: [crypto.public_length]u8 = undefined;
            try sock.readAll(&public_key);

            const this_intermediate_shared_key = try crypto.dh1(public_key, secret_key);
            try sock.writeAll(&this_intermediate_shared_key);

            var other_intermediate_shared_key: [crypto.shared_length]u8 = undefined;
            try sock.readAll(&other_intermediate_shared_key);

            const shared_key = try crypto.dh2(other_intermediate_shared_key, secret_key);

            self.state = .{ .connected = .{ .key = shared_key, .sock = sock } };

            self.handle_thread = try Thread.spawn(.{}, self.runHandle, .{});
        }

        fn runHandle(self: *Self) void {
            self.handle() catch |err| {
                self.handle_error = err;
            };
        }

        fn handle(self: *Self) Error!void {
            while (true) {
                switch (self.state) {
                    .not_connected => break,
                    .connected => |state| {
                        const should_continue = try self.handleMessage(state);
                        if (!should_continue) break;
                    },
                }
            }

            switch (self.state) {
                .connected => |state| {
                    state.sock.close();
                    self.state = .not_connected;
                },
            }

            try self.callOnDisconnected();
        }

        fn handleMessage(self: *Self, state: ClientStateInner) Error!bool {
            var size_buffer: [util.LENSIZE]u8 = undefined;
            state.sock.readAll(&size_buffer) catch return false;
            const message_size = util.decodeMessageSize(size_buffer);

            var data_encrypted = try std.ArrayList(u8).initCapacity(self.allocator, message_size);
            defer data_encrypted.deinit();
            state.sock.readAll(data_encrypted.items) catch return false;

            var data_serialized = std.ArrayList(u8).init(self.allocator);
            defer data_serialized.deinit();
            crypto.aesDecrypt(state.key, data_encrypted.items, data_serialized.writer());

            const data_parsed = try util.deserialize(R, data_serialized, self.allocator);
            try self.callOnReceive(data_parsed);

            return true;
        }
    };
}
