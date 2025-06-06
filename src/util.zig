const std = @import("std");
const builtin = @import("builtin");
const Error = @import("err.zig").Error;
const Allocator = std.mem.Allocator;
const Stream = std.net.Stream;
const ParseError = std.json.ParseError;
const Scanner = std.json.Scanner;
const FcntlError = std.posix.FcntlError;
const native_os = builtin.os.tag;
const windows = std.os.windows;
const posix = std.posix;
const FIONBIO = windows.ws2_32.FIONBIO;
const F_GETFL = 3;
const F_SETFL = 4;
const O_NONBLOCK: usize = 0o4000;

/// Returns the error type returned from a function.
fn ErrorReturnedFrom(comptime f: anytype) type {
    switch (@typeInfo(@TypeOf(f))) {
        .@"fn" => |fn_info| {
            if (fn_info.return_type) |fn_return| {
                switch (@typeInfo(fn_return)) {
                    .error_union => |fn_err_union| return fn_err_union.error_set,
                    else => @compileError(@typeName(@TypeOf(f)) ++ " is not typed to return an error"),
                }
            } else {
                @compileError(@typeName(@TypeOf(f)) ++ " is not typed to return an error");
            }
        },
        else => @compileError(@typeName(@TypeOf(f)) ++ " is not a function type"),
    }
}

/// Any error occurring when resolving an IP address. This is necessary because
/// `std.net` doesn't export enough of its concrete error types.
pub const AddressError = ErrorReturnedFrom(std.net.getAddressList);

/// A value received through a network socket. `deinit` must be called once the
/// memory is no longer needed.
pub const Received = std.json.Parsed;

/// The length of the size portion of a message.
pub const LENSIZE = 5;

/// The amount of time to wait between repeated network operations.
pub const SLEEP_TIME = 1_000_000;

/// Serializes a value to a byte stream.
pub fn serialize(data: anytype, out_stream: anytype) @TypeOf(out_stream).Error!void {
    try std.json.stringify(data, .{}, out_stream);
}

/// Deserializes a byte slice into a new value of a given type.
pub fn deserialize(comptime T: type, data_serialized: []const u8, allocator: Allocator) ParseError(Scanner)!Received(T) {
    return try std.json.parseFromSlice(T, allocator, data_serialized, .{ .allocate = .alloc_always });
}

/// Encodes the size portion of a message.
pub fn encodeMessageSize(size: usize) [LENSIZE]u8 {
    var size_inner = size;
    var encoded_size: [LENSIZE]u8 = undefined;

    for (0..LENSIZE) |i| {
        encoded_size[LENSIZE - i - 1] = @as(u8, @truncate(size_inner));
        size_inner >>= 8;
    }

    return encoded_size;
}

/// Decodes the sizes portion of a message.
pub fn decodeMessageSize(encoded_size: [LENSIZE]u8) usize {
    var size: usize = 0;

    for (encoded_size) |x| {
        size = (size << 8) + x;
    }

    return size;
}

/// Tries to close a socket, returning an error if the operation fails. This is
/// necessary because Zig's socket API has a lot of `unreachable`s. Panicking is
/// not a desirable side effect of simply trying to close a socket twice.
pub fn tryClose(sock: Stream) Error!void {
    switch (native_os) {
        .windows => windows.closesocket(sock.handle) catch return Error.SocketCloseFailed,
        else => {
            if (native_os == .wasi and !builtin.link_libc) {
                _ = std.os.wasi.fd_close(sock.handle);
                return;
            }
            switch (posix.errno(posix.system.close(sock.handle))) {
                .BADF => return Error.SocketCloseFailed,
                .INTR => return,
                else => return,
            }
        },
    }
}

/// Sets a socket's blocking mode. This is necessary because Zig's socket API
/// doesn't currently support this anywhere other than in server listeners.
/// Additionally, it doesn't seem to actually set the socket to non-blocking
/// mode on Windows.
pub fn setBlocking(sock: Stream, blocking: bool) FcntlError!void {
    // try posix.setsockopt(sock.handle, posix.SOL.SOCKET, posix.SO.NONBLOCK, &mem.toBytes(@as(c_int, 1)));

    if (native_os == .windows) {
        var mode: u32 = if (blocking) 0 else 1;
        const err_code = windows.ws2_32.ioctlsocket(sock.handle, FIONBIO, &mode);

        if (err_code != 0) {
            return windows.unexpectedWSAError(windows.ws2_32.WSAGetLastError());
        }
    } else {
        const getfl = try posix.fcntl(sock.handle, F_GETFL, 0);

        const arg = if (blocking)
            getfl & ~O_NONBLOCK
        else
            getfl | O_NONBLOCK;

        const err_code = try posix.fcntl(sock.handle, F_SETFL, arg);

        if (err_code == -1) {
            return posix.unexpectedErrno(posix.errno(err_code));
        }
    }
}
