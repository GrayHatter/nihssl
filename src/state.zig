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

pub const State = @This();

cipher: Cipher = .{},
session_id: ?SessionID = null,
entity: ConnectionEnd = .{},
prf_algorithm: PRFAlgorithm = .{},
mac_algorithm: MACAlgorithm = .{},
/// Compressed encryption is a mistake...
compression_algorithm: CompressionMethod = null,
