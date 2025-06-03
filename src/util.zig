const std = @import("std");
const builtin = @import("builtin");
const Error = @import("err.zig").Error;
const Allocator = std.mem.Allocator;
const Stream = std.net.Stream;
const Parsed = std.json.Parsed;
const native_os = builtin.os.tag;
const windows = std.os.windows;
const posix = std.posix;
const FIONBIO = windows.ws2_32.FIONBIO;
const F_GETFL = 3;
const F_SETFL = 4;
const O_NONBLOCK: usize = 0o4000;

pub const LENSIZE = 5;

pub const SLEEP_TIME = 1_000_000;

pub fn serialize(data: anytype, out_stream: anytype) !void {
    try std.json.stringify(data, .{}, out_stream);
}

pub fn deserialize(comptime T: type, data_serialized: []const u8, allocator: Allocator) !Parsed(T) {
    return try std.json.parseFromSlice(T, allocator, data_serialized, .{ .allocate = .alloc_always });
}

pub fn encodeMessageSize(size: usize) [LENSIZE]u8 {
    var size_inner = size;
    var encoded_size: [LENSIZE]u8 = undefined;

    for (0..LENSIZE) |i| {
        encoded_size[LENSIZE - i - 1] = @as(u8, @truncate(size_inner));
        size_inner >>= 8;
    }

    return encoded_size;
}

pub fn decodeMessageSize(encoded_size: [LENSIZE]u8) usize {
    var size: usize = 0;

    for (encoded_size) |x| {
        size = (size << 8) + x;
    }

    return size;
}

pub fn tryClose(sock: Stream) !void {
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

pub fn setBlocking(sock: Stream, blocking: bool) !void {
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
