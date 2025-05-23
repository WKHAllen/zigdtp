const std = @import("std");
const crypto = @import("crypto.zig");
const util = @import("util.zig");
const Error = @import("err.zig").Error;
const Allocator = std.mem.Allocator;
const net = std.net;
const Stream = net.Stream;
const Listener = net.Server;
const Connection = Listener.Connection;
const Address = net.Address;
const Thread = std.Thread;
const Parsed = std.json.Parsed;

const ClientRepr = struct {
    sock: Stream,
    address: Address,
    key: [crypto.key_length]u8,
    serve_client_thread: ?Thread,
};

const ServerStateInner = struct {
    sock: Listener,
    clients: std.AutoHashMap(usize, ClientRepr),
    next_client_id: usize,
};

const ServerState = union(enum) {
    not_serving,
    serving: ServerStateInner,
};

pub fn ServerOptions(comptime S: type, comptime R: type, comptime C: type) type {
    return struct {
        on_receive: ?*const fn (C, *Server(S, R, C), usize, R) void = null,
        on_connect: ?*const fn (C, *Server(S, R, C), usize) void = null,
        on_disconnect: ?*const fn (C, *Server(S, R, C), usize) void = null,
    };
}

fn callOnReceiveInner(comptime S: type, comptime R: type, comptime C: type, on_receive: *const fn (C, *Server(S, R, C), usize, R) void, ctx: C, server: *Server(S, R, C), client_id: usize, data_parsed: Parsed(R)) void {
    on_receive(ctx, server, client_id, data_parsed.value);
    data_parsed.deinit();
}

fn callOnConnectInner(comptime S: type, comptime R: type, comptime C: type, on_connect: *const fn (C, *Server(S, R, C), usize) void, ctx: C, server: *Server(S, R, C), client_id: usize) void {
    on_connect(ctx, server, client_id);
}

fn callOnDisconnectInner(comptime S: type, comptime R: type, comptime C: type, on_disconnect: *const fn (C, *Server(S, R, C), usize) void, ctx: C, server: *Server(S, R, C), client_id: usize) void {
    on_disconnect(ctx, server, client_id);
}

pub fn Server(comptime S: type, comptime R: type, comptime C: type) type {
    return struct {
        const Self = @This();

        state: ServerState,
        serve_thread: ?Thread,
        serve_error: ?Error,
        ctx: C,
        options: ServerOptions(S, R, C),
        allocator: Allocator,

        pub fn init(allocator: Allocator, ctx: C, options: ServerOptions(S, R, C)) Self {
            return Self{
                .state = .not_serving,
                .serve_error = null,
                .ctx = ctx,
                .options = options,
                .allocator = allocator,
            };
        }

        pub fn deinit(self: *Self) void {
            if (self.serving()) {
                self.stop() catch {};
            }
        }

        pub fn start(self: *Self, host: []const u8, port: u16) Error!void {
            if (self.serving()) {
                return Error.AlreadyServing;
            }

            const address = try Address.resolveIp(host, port);
            try self.startViaAddress(address);
        }

        pub fn startViaAddress(self: *Self, address: Address) Error!void {
            if (self.serving()) {
                return Error.AlreadyServing;
            }

            const listener = try address.listen(.{ .reuse_address = true, .reuse_port = true });

            self.state = .{ .serving = .{ .sock = listener, .clients = std.AutoHashMap(usize, ClientRepr).init(self.allocator), .next_client_id = 0 } };

            self.serve_thread = try Thread.spawn(.{}, self.runServe, .{});
        }

        pub fn stop(self: *Self) Error!void {
            switch (self.state) {
                .not_serving => return Error.NotServing,
                .serving => |state| {
                    var iter = state.clients.valueIterator();

                    while (iter.next()) |client| {
                        client.sock.close();

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

        pub fn send(self: *Self, data: R, client_id: usize) Error!void {
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
                        try client.sock.writeAll(&encoded_size);
                        try client.sock.writeAll(data_encrypted.items);
                    } else {
                        return Error.ClientDoesNotExist;
                    }
                },
            }
        }

        pub fn sendMultiple(self: *Self, data: R, client_ids: []const usize) Error!void {
            switch (self.state) {
                .not_serving => return Error.NotServing,
                .serving => |_| {
                    for (client_ids) |client_id| try self.send(data, client_id);
                },
            }
        }

        pub fn sendAll(self: *Self, data: R) Error!void {
            switch (self.state) {
                .not_serving => return Error.NotServing,
                .serving => |state| {
                    for (state.clients.keys()) |client_id| try self.send(data, client_id);
                },
            }
        }

        pub fn serving(self: *Self) bool {
            return switch (self.state) {
                .not_serving => false,
                .serving => |_| true,
            };
        }

        pub fn getAddress(self: *Self) Error!Address {
            return switch (self.state) {
                .not_serving => Error.NotServing,
                .serving => |state| state.sock.listen_address,
            };
        }

        pub fn getClientAddress(self: *Self, client_id: usize) Error!Address {
            return switch (self.state) {
                .not_serving => Error.NotServing,
                .serving => |state| if (state.clients.get(client_id)) |client|
                    client.address
                else
                    Error.ClientDoesNotExist,
            };
        }

        pub fn removeClient(self: *Self, client_id: usize) Error!void {
            switch (self.state) {
                .not_serving => return Error.NotServing,
                .serving => |state| {
                    if (state.clients.fetchRemove(client_id)) |client_entry| {
                        client_entry.value.sock.close();

                        if (client_entry.value.serve_client_thread) |serve_client_thread| serve_client_thread.join();
                    } else {
                        return Error.ClientDoesNotExist;
                    }
                },
            }
        }

        fn callOnReceive(self: *Self, client_id: usize, data_parsed: Parsed(R)) Thread.SpawnError!void {
            if (self.options.on_receive) |on_receive| {
                const thread = try Thread.spawn(.{}, callOnReceiveInner, .{ S, R, C, on_receive, self.ctx, self, client_id, data_parsed });
                thread.detach();
            }
        }

        fn callOnConnect(self: *Self, client_id: usize) Thread.SpawnError!void {
            if (self.options.on_connect) |on_connect| {
                const thread = try Thread.spawn(.{}, callOnConnectInner, .{ S, R, C, on_connect, self.ctx, self, client_id });
                thread.detach();
            }
        }

        fn callOnDisconnect(self: *Self, client_id: usize) Thread.SpawnError!void {
            if (self.options.on_disconnect) |on_disconnect| {
                const thread = try Thread.spawn(.{}, callOnDisconnectInner, .{ S, R, C, on_disconnect, self.ctx, self, client_id });
                thread.detach();
            }
        }

        fn exchangeKeys(self: *Self, sock: Stream, address: Address) Error!void {
            const public_key = crypto.newKeyPair().public_key;
            try sock.writeAll(&public_key);

            const secret_key = crypto.newKeyPair().secret_key;

            const this_intermediate_shared_key = try crypto.dh1(public_key, secret_key);
            try sock.writeAll(&this_intermediate_shared_key);

            var other_intermediate_shared_key: [crypto.shared_length]u8 = undefined;
            try sock.readAll(&other_intermediate_shared_key);

            const shared_key = try crypto.dh2(other_intermediate_shared_key, secret_key);

            switch (self.state) {
                .serving => |state| {
                    const client_id = state.next_client_id;
                    state.next_client_id += 1;

                    try state.clients.put(client_id, ClientRepr{
                        .sock = sock,
                        .address = address,
                        .key = shared_key,
                        .serve_client_thread = null,
                    });

                    state.clients.getPtr(client_id).?.serve_client_thread = try Thread.spawn(.{}, self.serveClient, .{client_id});
                },
            }
        }

        fn runServe(self: *Self) void {
            self.serve() catch |err| {
                self.serve_error = err;
            };
        }

        fn serve(self: *Self) Error!void {
            while (true) {
                switch (self.state) {
                    .not_serving => break,
                    .serving => |state| {
                        const conn = state.sock.accept() catch break;
                        try self.exchangeKeys(conn.stream, conn.address);
                    },
                }
            }
        }

        fn serveClient(self: *Self, client_id: usize) Error!void {
            try self.callOnConnect(client_id);

            while (true) {
                switch (self.state) {
                    .not_serving => break,
                    .serving => |state| if (state.clients.get(client_id)) |client| {
                        const should_continue = try self.handleClientMessage(client);
                        if (!should_continue) break;
                    } else break,
                }
            }

            try self.callOnDisconnect(client_id);
        }

        fn handleClientMessage(self: *Self, client: ClientRepr) Error!bool {
            var size_buffer: [util.LENSIZE]u8 = undefined;
            client.sock.readAll(&size_buffer) catch return false;
            const message_size = util.decodeMessageSize(size_buffer);

            var data_encrypted = try std.ArrayList(u8).initCapacity(self.allocator, message_size);
            defer data_encrypted.deinit();
            client.sock.readAll(data_encrypted.items) catch return false;

            var data_serialized = std.ArrayList(u8).init(self.allocator);
            defer data_serialized.deinit();
            crypto.aesDecrypt(client.key, data_encrypted.items, data_serialized.writer());

            const data_parsed = try util.deserialize(R, data_serialized, self.allocator);
            try self.callOnReceive(data_parsed);

            return true;
        }
    };
}
