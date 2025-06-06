const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;
const X25519 = std.crypto.dh.X25519;
const Aes256 = std.crypto.core.aes.Aes256;
const KeyPair = X25519.KeyPair;
const IdentityElementError = std.crypto.errors.IdentityElementError;

pub const public_length = X25519.public_length;
pub const secret_length = X25519.secret_length;
pub const shared_length = X25519.shared_length;

/// Length (in bytes) of an AES-256 key.
pub const key_length = Aes256.key_bits / 8;

/// Performs a SHA-256 hash of a sequence of bytes.
fn sha256(bytes: []const u8) [Sha256.digest_length]u8 {
    var hasher = Sha256.init(.{});
    hasher.update(bytes);
    return hasher.finalResult();
}

/// Generates a new X25519 key pair.
pub fn newKeyPair() KeyPair {
    return KeyPair.generate();
}

/// Performs the math for the first half of a Diffie-Hellman key exchange.
pub fn dh1(public_key: [public_length]u8, secret_key: [secret_length]u8) IdentityElementError![shared_length]u8 {
    return try X25519.scalarmult(secret_key, public_key);
}

/// Performs the math for the second half of a Diffie-Hellman key exchange,
/// hashing the resulting shared key before returning it.
pub fn dh2(intermediate_shared_key: [shared_length]u8, secret_key: [secret_length]u8) IdentityElementError![shared_length]u8 {
    const shared_key = try X25519.scalarmult(secret_key, intermediate_shared_key);
    return sha256(&shared_key);
}

/// An iterator over a sequence of bytes, providing a chunk of bytes of a given
/// length with each call to `next`.
fn BlocksIterator(block_size: usize) type {
    return struct {
        const Self = @This();

        /// The bytes being iterated over.
        bytes: []const u8,
        /// The current offset.
        offset: usize,

        /// Constructs the iterator.
        pub fn of(bytes: []const u8) Self {
            return .{
                .bytes = bytes,
                .offset = 0,
            };
        }

        /// Returns the next block of the given length, or null if the end of
        /// the byte sequence has been reached. Note that the last block may be
        /// shorter than the configured block size.
        pub fn next(self: *Self) ?[]const u8 {
            if (self.offset >= self.bytes.len) return null;

            const end_offset = @min(self.offset + block_size, self.bytes.len);
            const block = self.bytes[self.offset..end_offset];
            self.offset = end_offset;
            return block;
        }

        /// Returns whether the iterator has reached the end of the byte
        /// sequence. Does not progress the state of the iterator.
        pub inline fn done(self: Self) bool {
            return self.offset >= self.bytes.len;
        }
    };
}

/// Performs an AES encryption. This handles cases where the data is not a
/// multiple of 16 bytes long.
pub fn aesEncrypt(key: [key_length]u8, data: []const u8, writer: anytype) @TypeOf(writer).Error!void {
    const last_block_len = if (data.len == 0) 0 else if (data.len % 16 == 0) 16 else @as(u8, @truncate(data.len % 16));
    try writer.writeByte(last_block_len);

    var ctx = Aes256.initEnc(key);
    var blocks = BlocksIterator(16).of(data);

    while (blocks.next()) |block| {
        var src: [16]u8 = undefined;
        std.mem.copyForwards(u8, &src, block);
        for (src[block.len..16]) |*byte| byte.* = 0;

        var dst: [16]u8 = undefined;
        ctx.encrypt(&dst, &src);
        try writer.writeAll(&dst);
    }
}

/// Performs an AES decryption. This handles cases where the data is not a
/// multiple of 16 bytes long.
pub fn aesDecrypt(key: [key_length]u8, data: []const u8, writer: anytype) @TypeOf(writer).Error!void {
    const last_block_len = @as(usize, data[0]);

    var ctx = Aes256.initDec(key);
    var blocks = BlocksIterator(16).of(data[1..]);

    while (blocks.next()) |block| {
        var src: [16]u8 = undefined;
        std.mem.copyForwards(u8, &src, block);

        var dst: [16]u8 = undefined;
        ctx.decrypt(&dst, &src);

        if (!blocks.done()) {
            try writer.writeAll(&dst);
        } else {
            try writer.writeAll(dst[0..last_block_len]);
        }
    }
}
