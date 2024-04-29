// TODO refactor more
const std = @import("std");

const root = @import("root.zig");
const Cipher = @import("cipher.zig");

const ConnectionEnd = root.ConnectionEnd;
const PRFAlgorithm = root.PRFAlgorithm;
const BulkCipherAlgorithm = root.BulkCipherAlgorithm;
const MACAlgorithm = root.MACAlgorithm;
const CompressionMethod = root.CompressionMethod;
const SessionID = root.SessionID;

pub const ConnCtx = @This();

cipher: Cipher = .{},
our_random: [32]u8,
peer_random: ?[32]u8 = null,
session_id: ?SessionID = null,
entity: ConnectionEnd = .{},
prf_algorithm: PRFAlgorithm = .{},
mac_algorithm: MACAlgorithm = .{},
/// Compressed encryption is a mistake...
compression_algorithm: CompressionMethod = null,
// I hate this protocol
handshake_record: std.ArrayList(u8),

pub fn initClient(a: std.mem.Allocator) ConnCtx {
    var rand: [32]u8 = undefined;
    var csprng = std.Random.ChaCha.init([_]u8{0} ** 32);
    csprng.fill(&rand);

    return .{
        .our_random = rand,
        .handshake_record = std.ArrayList(u8).init(a),
    };
}

pub fn initServer() ConnCtx {
    return .{};
}
