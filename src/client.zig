const std = @import("std");
const crypto = @import("crypto.zig");
const util = @import("util.zig");
const Error = @import("err.zig").Error;
const Allocator = std.mem.Allocator;
const net = std.net;
const Stream = net.Stream;
const ReadError = std.posix.ReadError;
const Address = net.Address;
const Thread = std.Thread;
const Received = util.Received;

/// The inner client state when the client is connected to a server.
const ClientStateInner = struct {
    /// The client socket.
    sock: Stream,
    /// The client's crypto key.
    key: [crypto.key_length]u8,
};

/// The outer client state, modeling whether the client is connected to a
/// server.
const ClientState = union(enum) {
    /// The client is not connected to a server.
    not_connected,
    /// The client is connected to a server.
    connected: ClientStateInner,
};

/// Client configuration options. Each option is an event handler function that
/// is given the details of the vent, as well as the client instance and a
/// context value configured on the client.
///
/// - `S` is the type that the client will send to the server.
/// - `R` is the type that the client will receive from the server.
/// - `C` is the type of the context value that will be available in each event
/// handler.
pub fn ClientOptions(comptime S: type, comptime R: type, comptime C: type) type {
    return struct {
        on_receive: ?*const fn (C, *Client(S, R, C), Received(R)) void = null,
        on_disconnected: ?*const fn (C, *Client(S, R, C)) void = null,
    };
}

/// Calls the configured client receive handler.
fn callOnReceiveInner(comptime S: type, comptime R: type, comptime C: type, on_receive: *const fn (C, *Client(S, R, C), Received(R)) void, ctx: C, client: *Client(S, R, C), data: Received(R)) void {
    on_receive(ctx, client, data);
}

/// Calls the configured client disconnected handler.
fn callOnDisconnectedInner(comptime S: type, comptime R: type, comptime C: type, on_disconnected: *const fn (C, *Client(S, R, C)) void, ctx: C, client: *Client(S, R, C)) void {
    on_disconnected(ctx, client);
}

/// A network client.
///
/// - `S` is the type that the client will send to the server.
/// - `R` is the type that the client will receive from the server.
/// - `C` is the type of the context value that will be available in each event
/// handler.
pub fn Client(comptime S: type, comptime R: type, comptime C: type) type {
    return struct {
        const Self = @This();

        /// The current state of the client.
        state: ClientState,
        /// The thread currently handling the connection to the server.
        handle_thread: ?Thread,
        /// Any error that has occurred while connected to the server.
        handle_error: ?Error,
        /// The configured context to be provided in each event handler.
        ctx: C,
        /// The configured event handlers.
        options: ClientOptions(S, R, C),
        /// The client's allocator.
        allocator: Allocator,

        /// Initializes a new network client. Call `connect` to connect to a
        /// server.
        pub fn init(allocator: Allocator, ctx: C, options: ClientOptions(S, R, C)) Self {
            return Self{
                .state = .not_connected,
                .handle_thread = null,
                .handle_error = null,
                .ctx = ctx,
                .options = options,
                .allocator = allocator,
            };
        }

        /// Releases all client memory. This will attempt to disconnect the
        /// client from the server if it is still connected. Calling
        /// `disconnect` before this is recommended, as any errors encountered
        /// here when disconnecting from the server are discarded.
        pub fn deinit(self: *Self) void {
            if (self.connected()) {
                self.disconnect() catch {};
            }

            self.* = undefined;
        }

        /// Connects to a server at the given host and port.
        pub fn connect(self: *Self, host: []const u8, port: u16) Error!void {
            if (self.connected()) {
                return Error.AlreadyConnected;
            }

            const stream = try net.tcpConnectToHost(self.allocator, host, port);
            try self.exchangeKeys(stream);
        }

        /// Connects to a server at the given address.
        pub fn connectViaAddress(self: *Self, address: Address) Error!void {
            if (self.connected()) {
                return Error.AlreadyConnected;
            }

            const stream = try net.tcpConnectToAddress(address);
            try self.exchangeKeys(stream);
        }

        /// Disconnects from the server.
        pub fn disconnect(self: *Self) Error!void {
            switch (self.state) {
                .not_connected => return Error.NotConnected,
                .connected => |state| {
                    self.state = .not_connected;
                    util.tryClose(state.sock) catch {};

                    if (self.handle_thread) |handle_thread| handle_thread.join();

                    if (self.handle_error) |err| return err;
                },
            }
        }

        /// Sends data to the server.
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
                    var message = try std.ArrayList(u8).initCapacity(self.allocator, data_encrypted.items.len + util.LENSIZE);
                    defer message.deinit();
                    try message.appendSlice(&encoded_size);
                    try message.appendSlice(data_encrypted.items);
                    try state.sock.writeAll(message.items);
                },
            }
        }

        /// Is the client currently connected to a server?
        pub fn connected(self: *Self) bool {
            return switch (self.state) {
                .not_connected => false,
                .connected => |_| true,
            };
        }

        /// Calls the configured client receive handler.
        fn callOnReceive(self: *Self, data: Received(R)) Thread.SpawnError!void {
            if (self.options.on_receive) |on_receive| {
                const thread = try Thread.spawn(.{}, callOnReceiveInner, .{ S, R, C, on_receive, self.ctx, self, data });
                thread.detach();
            } else {
                data.deinit();
            }
        }

        /// Calls the configured client disconnected handler.
        fn callOnDisconnected(self: *Self) Thread.SpawnError!void {
            if (self.options.on_disconnected) |on_disconnected| {
                const thread = try Thread.spawn(.{}, callOnDisconnectedInner, .{ S, R, C, on_disconnected, self.ctx, self });
                thread.detach();
            }
        }

        /// Performs a cryptographic key exchange with the server.
        fn exchangeKeys(self: *Self, sock: Stream) Error!void {
            try util.setBlocking(sock, true);

            const secret_key = crypto.newKeyPair().secret_key;

            var public_key: [crypto.public_length]u8 = undefined;
            const n1 = try sock.readAll(&public_key);
            if (n1 != public_key.len) return Error.KeyExchangeFailed;

            const this_intermediate_shared_key = crypto.dh1(public_key, secret_key) catch return Error.KeyExchangeFailed;
            try sock.writeAll(&this_intermediate_shared_key);

            var other_intermediate_shared_key: [crypto.shared_length]u8 = undefined;
            const n2 = try sock.readAll(&other_intermediate_shared_key);
            if (n2 != other_intermediate_shared_key.len) return Error.KeyExchangeFailed;

            const shared_key = crypto.dh2(other_intermediate_shared_key, secret_key) catch return Error.KeyExchangeFailed;

            try util.setBlocking(sock, false);

            self.state = .{ .connected = .{ .key = shared_key, .sock = sock } };

            self.handle_thread = try Thread.spawn(.{}, runHandle, .{self});
        }

        /// A wrapper around `handle` that notes any error returned.
        fn runHandle(self: *Self) void {
            self.handle() catch |err| {
                self.handle_error = err;
            };
        }

        /// Event loop for the client.
        fn handle(self: *Self) Error!void {
            const disconnected = while (true) {
                switch (self.state) {
                    .not_connected => break false,
                    .connected => |state| {
                        const should_continue = try self.handleMessage(state);
                        if (!should_continue) break true;
                    },
                }

                Thread.sleep(util.SLEEP_TIME);
            };

            switch (self.state) {
                .not_connected => {},
                .connected => |state| {
                    util.tryClose(state.sock) catch {};
                    self.state = .not_connected;
                },
            }

            if (disconnected) try self.callOnDisconnected();
        }

        /// Handles a single message from the server.
        fn handleMessage(self: *Self, state: ClientStateInner) Error!bool {
            var size_buffer: [util.LENSIZE]u8 = undefined;
            const n1 = state.sock.readAll(&size_buffer) catch |err| {
                return switch (err) {
                    ReadError.WouldBlock => true,
                    else => false,
                };
            };
            if (n1 != size_buffer.len) return false;
            const message_size = util.decodeMessageSize(size_buffer);

            var data_encrypted = try std.ArrayList(u8).initCapacity(self.allocator, message_size);
            defer data_encrypted.deinit();
            data_encrypted.expandToCapacity();
            const n2 = state.sock.readAll(data_encrypted.items) catch return false;
            if (n2 != data_encrypted.items.len) return false;

            var data_serialized = std.ArrayList(u8).init(self.allocator);
            defer data_serialized.deinit();
            try crypto.aesDecrypt(state.key, data_encrypted.items, data_serialized.writer());

            const data = try util.deserialize(R, data_serialized.items, self.allocator);
            try self.callOnReceive(data);

            return true;
        }
    };
}
