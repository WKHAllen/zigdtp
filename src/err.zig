const std = @import("std");

pub const Error = error{
    NotConnected,
    AlreadyConnected,
    NotServing,
    AlreadyServing,
    ClientDoesNotExist,
} || std.net.TcpConnectToHostError || std.Thread.SpawnError;
