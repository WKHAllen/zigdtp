const std = @import("std");

/// General type encompassing all Data Transfer Protocol errors.
pub const Error = error{
    /// The client is not connected to a server.
    NotConnected,
    /// The client is already connected to a server.
    AlreadyConnected,
    /// The server is not serving.
    NotServing,
    /// The server is already serving.
    AlreadyServing,
    /// The specified client does not exist.
    ClientDoesNotExist,
    /// The cryptographic key exchange failed.
    KeyExchangeFailed,
    /// The socket failed to close.
    SocketCloseFailed,
} || std.net.TcpConnectToHostError || std.Thread.SpawnError || std.io.AnyWriter.Error;
