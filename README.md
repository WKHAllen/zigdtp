# Data Transfer Protocol for Zig

Ergonomic networking interfaces for Zig.

## Data Transfer Protocol

The Data Transfer Protocol (DTP) is a larger project to make ergonomic network programming available in any language. See the full project [here](https://wkhallen.com/dtp/).

## Installation

Add the package in `build.zig.zon`:

```sh
$ zig fetch --save git+https://github.com/WKHAllen/zigdtp.git
```

Add the module as a dependency to your program:

```zig
const zigdtp = b.dependency("zigdtp", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("zigdtp", zigdtp.module("zigdtp"));
```

## Creating a server

A server can be built using the `Server` implementation:

```zig
const std = @import("std");
const zigdtp = @import("zigdtp");
const Server = zigdtp.Server;
const Received = zigdtp.Received;

// Called when data is received from a client
fn receive(_: void, server: *Server(usize, []const u8, void), client_id: usize, data: Received([]const u8)) void {
    defer data.deinit();
    // Send back the length of the string
    server.send(data.value.len, client_id) catch {
        // Handle send error
    };
}

// Called when a client connects
fn connect(_: void, _: *Server(usize, []const u8, void), client_id: usize) void {
    std.debug.print("Client with ID {d} connected\n", .{client_id});
}

// Called when a client disconnects
fn disconnect(_: void, _: *Server(usize, []const u8, void), client_id: usize) void {
    std.debug.print("Client with ID {d} disconnected\n", .{client_id});
}

pub fn main() !void {
    const allocator = std.heap.page_allocator; // or some other thread-safe allocator

    // Create a server that receives strings and returns the length of each string
    var server = Server(usize, []const u8, void).init(allocator, {}, .{
        .on_receive = receive,
        .on_connect = connect,
        .on_disconnect = disconnect,
    });
    defer server.deinit();
    try server.start("127.0.0.1", 29275);
}
```

## Creating a client

A client can be built using the `Client` implementation:

```zig
const std = @import("std");
const zigdtp = @import("zigdtp");
const Client = zigdtp.Client;
const Received = zigdtp.Received;

const message = "Hello, server!";

// Called when data is received from the server
fn receive(_: void, _: *Client([]const u8, usize, void), data: Received(usize)) void {
    defer data.deinit();
    // Validate the response
    std.debug.print("Received response from server: {d}\n", .{data.value});
    std.debug.assert(data.value == message.len);
}

// Called when the client is disconnected from the server
fn disconnected(_: void, _: *Client([]const u8, usize, void)) void {
    std.debug.print("Unexpectedly disconnected from server\n", .{});
}

pub fn main() !void {
    const allocator = std.heap.page_allocator; // or some other thread-safe allocator

    // Create a client that sends a message to the server and receives the length of the message
    var client = Client([]const u8, usize, void).init(allocator, {}, .{
        .on_receive = receive,
        .on_disconnected = disconnected,
    });
    defer client.deinit();
    try client.connect("127.0.0.1", 29275);
    try client.send(message);
}
```

## Security

Information security comes included. Every message sent over a network interface is encrypted with AES-256. Diffie-Hellman key exchanges are performed via X25519.
