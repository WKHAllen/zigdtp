const std = @import("std");

pub const Error = error{
    NotConnected,
    AlreadyConnected,
    NotServing,
    AlreadyServing,
    ClientDoesNotExist,
    KeyExchangeFailed,
} || std.net.TcpConnectToHostError || std.Thread.SpawnError || std.io.AnyWriter.Error;
