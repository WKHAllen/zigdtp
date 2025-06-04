const std = @import("std");
const crypto = @import("crypto.zig");
const util = @import("util.zig");
const Error = @import("err.zig").Error;
const Allocator = std.mem.Allocator;
const net = std.net;
const Stream = net.Stream;
const Listener = net.Server;
const ReadError = std.posix.ReadError;
const AcceptError = Listener.AcceptError;
const Address = net.Address;
const Thread = std.Thread;
const Received = util.Received;

/// A representation of a single connected client.
const ClientRepr = struct {
    /// The client socket.
    sock: Stream,
    /// The client's address.
    address: Address,
    /// The crypto key unique to the client.
    key: [crypto.key_length]u8,
    /// A handle to the thread serving the client. Despite that this is typed as
    /// an optional, the value will always be non-null except for the moment
    /// when the thread is being spawned.
    serve_client_thread: ?Thread,
};

/// The inner server state when the server is running.
const ServerStateInner = struct {
    /// The listener socket.
    sock: Listener,
    /// A mapping of all connected clients.
    clients: std.AutoHashMap(usize, ClientRepr),
    /// The next available client ID.
    next_client_id: usize,
};

/// The outer server state, modeling whether the server is serving.
const ServerState = union(enum) {
    /// The server is not serving.
    not_serving,
    /// The server is serving.
    serving: ServerStateInner,
};

/// Server configuration options. Each option is an event handler function that
/// is given the details of the event, as well as the server instance and a
/// context value configured on the server.
///
/// - `S` is the type that the server will send to clients.
/// - `R` is the type that the server will receive from clients.
/// - `C` is the type of the context value that will be available in each event
/// handler.
pub fn ServerOptions(comptime S: type, comptime R: type, comptime C: type) type {
    return struct {
        on_receive: ?*const fn (C, *Server(S, R, C), usize, Received(R)) void = null,
        on_connect: ?*const fn (C, *Server(S, R, C), usize) void = null,
        on_disconnect: ?*const fn (C, *Server(S, R, C), usize) void = null,
    };
}

/// Calls the configured server receive handler.
fn callOnReceiveInner(comptime S: type, comptime R: type, comptime C: type, on_receive: *const fn (C, *Server(S, R, C), usize, Received(R)) void, ctx: C, server: *Server(S, R, C), client_id: usize, data: Received(R)) void {
    on_receive(ctx, server, client_id, data);
}

/// Calls the configured server connect handler.
fn callOnConnectInner(comptime S: type, comptime R: type, comptime C: type, on_connect: *const fn (C, *Server(S, R, C), usize) void, ctx: C, server: *Server(S, R, C), client_id: usize) void {
    on_connect(ctx, server, client_id);
}

/// Calls the configured server disconnect handler.
fn callOnDisconnectInner(comptime S: type, comptime R: type, comptime C: type, on_disconnect: *const fn (C, *Server(S, R, C), usize) void, ctx: C, server: *Server(S, R, C), client_id: usize) void {
    on_disconnect(ctx, server, client_id);
}

/// Resolves an IPv4 address.
///
/// TODO: remove this once [this PR](https://github.com/ziglang/zig/pull/22555)
/// is included in a major release.
fn resolveIp(name: []const u8, port: u16) !Address {
    if (Address.parseIp4(name, port)) |ip4| return ip4 else |err| switch (err) {
        error.Overflow,
        error.InvalidEnd,
        error.InvalidCharacter,
        error.Incomplete,
        error.NonCanonical,
        => {},
        else => return err,
    }

    return error.InvalidIPAddressFormat;
}

/// A network server.
///
/// - `S` is the type that the server will send to clients.
/// - `R` is the type that the server will receive from clients.
/// - `C` is the type of the context value that will be available in each event
/// handler.
pub fn Server(comptime S: type, comptime R: type, comptime C: type) type {
    return struct {
        const Self = @This();

        /// The current state of the server.
        state: ServerState,
        /// The thread currently accepting clients.
        serve_thread: ?Thread,
        /// Any error that has occurred while serving clients.
        serve_error: ?Error,
        /// The configured context to be provided in each event handler.
        ctx: C,
        /// The configured event handlers.
        options: ServerOptions(S, R, C),
        /// The server's allocator.
        allocator: Allocator,

        /// Initializes a new network server. Call `start` to start listening
        /// for clients.
        pub fn init(allocator: Allocator, ctx: C, options: ServerOptions(S, R, C)) Self {
            return Self{
                .state = .not_serving,
                .serve_thread = null,
                .serve_error = null,
                .ctx = ctx,
                .options = options,
                .allocator = allocator,
            };
        }

        /// Releases all server memory. This will attempt to stop the server if
        /// it is still serving. Calling `stop` before this is recommended, as
        /// any errors encountered here when stopping the server are discarded.
        pub fn deinit(self: *Self) void {
            if (self.serving()) {
                self.stop() catch {};
            }

            self.* = undefined;
        }

        /// Starts the server listening on the given host and port.
        pub fn start(self: *Self, host: []const u8, port: u16) Error!void {
            if (self.serving()) {
                return Error.AlreadyServing;
            }

            const address = try resolveIp(host, port);
            try self.startViaAddress(address);
        }

        /// Starts the server listening on the given address.
        pub fn startViaAddress(self: *Self, address: Address) Error!void {
            if (self.serving()) {
                return Error.AlreadyServing;
            }

            const listener = try address.listen(.{ .reuse_address = true, .force_nonblocking = true });

            self.state = .{ .serving = .{ .sock = listener, .clients = std.AutoHashMap(usize, ClientRepr).init(self.allocator), .next_client_id = 0 } };

            self.serve_thread = try Thread.spawn(.{}, runServe, .{self});
        }

        /// Stops the server, disconnecting all clients in the process.
        pub fn stop(self: *Self) Error!void {
            switch (self.state) {
                .not_serving => return Error.NotServing,
                .serving => |*state| {
                    var iter = state.clients.valueIterator();

                    while (iter.next()) |client| {
                        util.tryClose(client.sock) catch {};

                        if (client.serve_client_thread) |serve_client_thread| serve_client_thread.join();
                    }

                    state.clients.deinit();
                    state.sock.deinit();
                    self.state = .not_serving;

                    if (self.serve_thread) |serve_thread| serve_thread.join();

                    if (self.serve_error) |err| return err;
                },
            }
        }

        /// Sends data to a client.
        pub fn send(self: *Self, data: S, client_id: usize) Error!void {
            switch (self.state) {
                .not_serving => return Error.NotServing,
                .serving => |state| {
                    if (state.clients.get(client_id)) |client| {
                        var data_serialized = std.ArrayList(u8).init(self.allocator);
                        defer data_serialized.deinit();
                        try util.serialize(data, data_serialized.writer());

                        var data_encrypted = std.ArrayList(u8).init(self.allocator);
                        defer data_encrypted.deinit();
                        try crypto.aesEncrypt(client.key, data_serialized.items, data_encrypted.writer());

                        const encoded_size = util.encodeMessageSize(data_encrypted.items.len);
                        var message = try std.ArrayList(u8).initCapacity(self.allocator, data_encrypted.items.len + util.LENSIZE);
                        defer message.deinit();
                        try message.appendSlice(&encoded_size);
                        try message.appendSlice(data_encrypted.items);
                        try client.sock.writeAll(message.items);
                    } else {
                        return Error.ClientDoesNotExist;
                    }
                },
            }
        }

        /// Sends data to a given set of clients.
        pub fn sendMultiple(self: *Self, data: S, client_ids: []const usize) Error!void {
            switch (self.state) {
                .not_serving => return Error.NotServing,
                .serving => |_| {
                    for (client_ids) |client_id| try self.send(data, client_id);
                },
            }
        }

        /// Sends data to all clients.
        pub fn sendAll(self: *Self, data: S) Error!void {
            switch (self.state) {
                .not_serving => return Error.NotServing,
                .serving => |state| {
                    var iter = state.clients.keyIterator();

                    while (iter.next()) |client_id| {
                        try self.send(data, client_id.*);
                    }
                },
            }
        }

        /// Is the server currently serving?
        pub fn serving(self: *Self) bool {
            return switch (self.state) {
                .not_serving => false,
                .serving => |_| true,
            };
        }

        /// Returns the server's address.
        pub fn getAddress(self: *Self) Error!Address {
            return switch (self.state) {
                .not_serving => Error.NotServing,
                .serving => |state| state.sock.listen_address,
            };
        }

        /// Returns a client's address.
        pub fn getClientAddress(self: *Self, client_id: usize) Error!Address {
            return switch (self.state) {
                .not_serving => Error.NotServing,
                .serving => |state| if (state.clients.get(client_id)) |client|
                    client.address
                else
                    Error.ClientDoesNotExist,
            };
        }

        /// Disconnects a client from the server.
        pub fn removeClient(self: *Self, client_id: usize) Error!void {
            switch (self.state) {
                .not_serving => return Error.NotServing,
                .serving => |*state| {
                    if (state.clients.fetchRemove(client_id)) |client_entry| {
                        util.tryClose(client_entry.value.sock) catch {};

                        if (client_entry.value.serve_client_thread) |serve_client_thread| serve_client_thread.join();
                    } else {
                        return Error.ClientDoesNotExist;
                    }
                },
            }
        }

        /// Calls the configured server receive handler.
        fn callOnReceive(self: *Self, client_id: usize, data: Received(R)) Thread.SpawnError!void {
            if (self.options.on_receive) |on_receive| {
                const thread = try Thread.spawn(.{}, callOnReceiveInner, .{ S, R, C, on_receive, self.ctx, self, client_id, data });
                thread.detach();
            } else {
                data.deinit();
            }
        }

        /// Calls the configured server connect handler.
        fn callOnConnect(self: *Self, client_id: usize) Thread.SpawnError!void {
            if (self.options.on_connect) |on_connect| {
                const thread = try Thread.spawn(.{}, callOnConnectInner, .{ S, R, C, on_connect, self.ctx, self, client_id });
                thread.detach();
            }
        }

        /// Calls the configured server disconnect handler.
        fn callOnDisconnect(self: *Self, client_id: usize) Thread.SpawnError!void {
            if (self.options.on_disconnect) |on_disconnect| {
                const thread = try Thread.spawn(.{}, callOnDisconnectInner, .{ S, R, C, on_disconnect, self.ctx, self, client_id });
                thread.detach();
            }
        }

        /// Performs a cryptographic key exchange with a connecting client.
        fn exchangeKeys(self: *Self, sock: Stream, address: Address) Error!void {
            try util.setBlocking(sock, true);

            const public_key = crypto.newKeyPair().public_key;
            try sock.writeAll(&public_key);

            const secret_key = crypto.newKeyPair().secret_key;

            const this_intermediate_shared_key = try crypto.dh1(public_key, secret_key);
            try sock.writeAll(&this_intermediate_shared_key);

            var other_intermediate_shared_key: [crypto.shared_length]u8 = undefined;
            const n = try sock.readAll(&other_intermediate_shared_key);
            if (n != other_intermediate_shared_key.len) return Error.KeyExchangeFailed;

            const shared_key = try crypto.dh2(other_intermediate_shared_key, secret_key);

            try util.setBlocking(sock, false);

            switch (self.state) {
                .serving => |*state| {
                    const client_id = state.next_client_id;
                    state.next_client_id += 1;

                    try state.clients.put(client_id, ClientRepr{
                        .sock = sock,
                        .address = address,
                        .key = shared_key,
                        .serve_client_thread = null,
                    });

                    state.clients.getPtr(client_id).?.serve_client_thread = try Thread.spawn(.{}, serveClient, .{ self, client_id });
                },
                .not_serving => {},
            }
        }

        /// A wrapper around `serve` that notes any error returned.
        fn runServe(self: *Self) void {
            self.serve() catch |err| {
                self.serve_error = err;
            };
        }

        /// Event loop for the server listener.
        fn serve(self: *Self) Error!void {
            while (true) {
                switch (self.state) {
                    .not_serving => break,
                    .serving => |*state| {
                        const conn = state.sock.accept() catch |err| {
                            switch (err) {
                                AcceptError.WouldBlock => {
                                    Thread.sleep(util.SLEEP_TIME);
                                    continue;
                                },
                                else => break,
                            }
                        };

                        try self.exchangeKeys(conn.stream, conn.address);
                    },
                }

                Thread.sleep(util.SLEEP_TIME);
            }
        }

        /// Event loop for a single connected client.
        fn serveClient(self: *Self, client_id: usize) Error!void {
            try self.callOnConnect(client_id);

            while (true) {
                switch (self.state) {
                    .not_serving => break,
                    .serving => |*state| if (state.clients.get(client_id)) |client| {
                        const should_continue = try self.handleClientMessage(client_id, client);
                        if (!should_continue) {
                            util.tryClose(client.sock) catch {};
                            _ = state.clients.remove(client_id);
                        }
                    } else break,
                }

                Thread.sleep(util.SLEEP_TIME);
            }

            try self.callOnDisconnect(client_id);
        }

        /// Handles a single message from a client.
        fn handleClientMessage(self: *Self, client_id: usize, client: ClientRepr) Error!bool {
            var size_buffer: [util.LENSIZE]u8 = undefined;
            const n1 = client.sock.readAll(&size_buffer) catch |err| {
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
            const n2 = client.sock.readAll(data_encrypted.items) catch return false;
            if (n2 != data_encrypted.items.len) return false;

            var data_serialized = std.ArrayList(u8).init(self.allocator);
            defer data_serialized.deinit();
            try crypto.aesDecrypt(client.key, data_encrypted.items, data_serialized.writer());

            const data = try util.deserialize(R, data_serialized.items, self.allocator);
            try self.callOnReceive(client_id, data);

            return true;
        }
    };
}
