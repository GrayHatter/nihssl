// TODO refactor more
const std = @import("std");
const root = @import("root.zig");

const Cipher = root.Cipher;
const ConnectionEnd = root.ConnectionEnd;
const PRFAlgorithm = root.PRFAlgorithm;
const BulkCipherAlgorithm = root.BulkCipherAlgorithm;
const CipherType = root.CipherType;
const MACAlgorithm = root.MACAlgorithm;
const CompressionMethod = root.CompressionMethod;

pub const State = @This();

cipher: Cipher = .{},
entity: ConnectionEnd = .{},
prf_algorithm: PRFAlgorithm = .{},
bulk_cipher_algorithm: BulkCipherAlgorithm = .{},
cipher_type: ?CipherType = null,
enc_key_length: u8 = 0,
block_length: u8 = 0,
fixed_iv_length: u8 = 0,
record_iv_length: u8 = 0,
mac_algorithm: MACAlgorithm = .{},
mac_length: u8 = 0,
mac_key_length: u8 = 0,
/// Compressed encryption is a mistake...
compression_algorithm: CompressionMethod = null,
master_secret: [48]u8 = std.mem.zeroes([48]u8),
client_random: [32]u8 = std.mem.zeroes([32]u8),
server_random: [32]u8 = std.mem.zeroes([32]u8),
