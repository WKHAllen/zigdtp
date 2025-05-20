const std = @import("std");

const Sha256 = std.crypto.hash.sha2.Sha256;

const X25519 = std.crypto.dh.X25519;
const KeyPair = X25519.KeyPair;
const public_length = X25519.public_length;
const secret_length = X25519.secret_length;
const shared_length = X25519.shared_length;

const Aes256 = std.crypto.core.aes.Aes256;
const key_length = Aes256.key_bits / 8;

fn sha256(bytes: []const u8) [Sha256.digest_length]u8 {
    var hasher = Sha256.init(.{});
    hasher.update(bytes);
    return hasher.finalResult();
}

pub fn newKeyPair() KeyPair {
    return KeyPair.generate();
}

pub fn dh1(public_key: [public_length]u8, secret_key: [secret_length]u8) ![shared_length]u8 {
    return try X25519.scalarmult(secret_key, public_key);
}

pub fn dh2(intermediate_shared_key: [shared_length]u8, secret_key: [shared_length]u8) ![shared_length]u8 {
    const shared_key = try X25519.scalarmult(secret_key, intermediate_shared_key);
    return sha256(&shared_key);
}

fn BlocksIterator(block_size: usize) type {
    return struct {
        const Self = @This();

        bytes: []const u8,
        offset: usize,

        pub fn of(bytes: []const u8) Self {
            return .{
                .bytes = bytes,
                .offset = 0,
            };
        }

        pub fn next(self: *Self) ?[]const u8 {
            if (self.offset >= self.bytes.len) return null;

            const end_offset = @min(self.offset + block_size, self.bytes.len);
            const block = self.bytes[self.offset..end_offset];
            self.offset = end_offset;
            return block;
        }

        pub inline fn done(self: Self) bool {
            return self.offset >= self.bytes.len;
        }
    };
}

pub fn aesEncrypt(key: [key_length]u8, data: []const u8, writer: anytype) !void {
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

pub fn aesDecrypt(key: [key_length]u8, data: []const u8, writer: anytype) !void {
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
