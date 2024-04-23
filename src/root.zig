const std = @import("std");
const net = std.net;
const testing = std.testing;
const print = std.debug.print;
const fixedBufferStream = std.io.fixedBufferStream;

const TESTING_IP = "127.0.0.1";
const TESTING_PORT = 4433;

const Alert = @import("alert.zig");
const Extensions = @import("extensions.zig");
const Extension = Extensions.Extension;

var csprng = std.Random.ChaCha.init([_]u8{0} ** 32);

pub const ProtocolVersion = extern struct {
    major: u8,
    minor: u8,
};

const TLSv1_2: ProtocolVersion = .{
    .major = 3,
    .minor = 3,
};

const TLSv1_3: ProtocolVersion = .{
    .major = 3,
    .minor = 4,
};

const ContentType = enum(u8) {
    change_cipher_spec = 20,
    alert = 21,
    handshake = 22,
    application_data = 23,

    pub fn fromByte(from: u8) !ContentType {
        return switch (from) {
            20 => .change_cipher_spec,
            21 => .alert,
            22 => .handshake,
            23 => .application_data,
            else => error.UnknownContentType,
        };
    }
};

const TLSRecord = struct {
    version: ProtocolVersion = TLSv1_2,
    length: u16 = 0,
    kind: union(ContentType) {
        change_cipher_spec: []const u8,
        alert: Alert,
        handshake: Handshake,
        application_data: []const u8,
    },

    pub fn packFragment(record: TLSRecord, buffer: []u8) !usize {
        var fba = fixedBufferStream(buffer);
        const len = switch (record.kind) {
            .handshake => |ch| try ch.pack(buffer[5..]),
            else => unreachable,
        };
        var w = fba.writer().any();
        try w.writeByte(@intFromEnum(record.kind));
        try w.writeByte(record.version.major);
        try w.writeByte(record.version.minor);
        try w.writeInt(u16, @truncate(len), std.builtin.Endian.big);
        return len + 5;
    }

    pub fn pack(record: TLSRecord, buffer: []u8) !usize {
        return record.packFragment(buffer);
    }

    pub fn unpackFragment(buffer: []const u8, sess: *SessionState) !TLSRecord {
        var fba = fixedBufferStream(buffer);
        var r = fba.reader().any();

        const fragtype = try ContentType.fromByte(try r.readByte());
        const version = ProtocolVersion{
            .major = try r.readByte(),
            .minor = try r.readByte(),
        };
        const length = try r.readInt(u16, std.builtin.Endian.big);

        if (length > buffer[5..].len) return error.IncompleteFragment;
        const fragbuff = buffer[5..][0..length];

        return .{
            .version = version,
            .length = length,
            .kind = switch (fragtype) {
                .change_cipher_spec => .{ .change_cipher_spec = unreachable },
                .alert => .{ .alert = try Alert.unpack(fragbuff) },
                .handshake => .{ .handshake = try Handshake.unpack(fragbuff, sess) },
                .application_data => .{ .application_data = unreachable },
            },
        };
    }
    pub fn unpack(buffer: []const u8, sess: *SessionState) !TLSRecord {
        return try unpackFragment(buffer, sess);
    }
};

pub const Random = extern struct {
    unix_time: u32,
    random_bytes: [28]u8,
};

comptime {
    std.debug.assert(@sizeOf(Random) == 32);
}

pub const SessionID = [32]u8;

pub const Compression = enum(u8) {
    null = 0,
};

pub const ClientHello = struct {
    version: ProtocolVersion,
    random: Random,
    session_id: SessionID,
    ciphers: []const CipherSuite = &[0]CipherSuite{},
    compression: Compression,
    extensions: []const Extension = &[0]Extension{},

    pub const SupportedExtensions = [_]type{
        Extensions.SupportedGroups,
        Extensions.SignatureAlgorithms,
    };

    pub const SupportedSuiteList = [_]CipherSuite{
        CipherSuites.TLS_DH_DSS_WITH_AES_128_CBC_SHA256,
        CipherSuites.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
        CipherSuites.TLS_DH_RSA_WITH_AES_256_CBC_SHA256,
        CipherSuites.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        CipherSuites.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        CipherSuites.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,

        CipherSuites.TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA,
        CipherSuites.TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA,
        CipherSuites.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
        CipherSuites.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
        CipherSuites.TLS_DH_DSS_WITH_AES_128_CBC_SHA,
        CipherSuites.TLS_DH_RSA_WITH_AES_128_CBC_SHA,
        CipherSuites.TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
        CipherSuites.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
        CipherSuites.TLS_DH_DSS_WITH_AES_256_CBC_SHA,
        CipherSuites.TLS_DH_RSA_WITH_AES_256_CBC_SHA,
        CipherSuites.TLS_DHE_DSS_WITH_AES_256_CBC_SHA,
        CipherSuites.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
        CipherSuites.TLS_DH_RSA_WITH_AES_128_CBC_SHA256,
        CipherSuites.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256,
        CipherSuites.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
        CipherSuites.TLS_DH_DSS_WITH_AES_256_CBC_SHA256,
        CipherSuites.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256,
    };
    pub const length = @sizeOf(ClientHello);

    pub fn init() ClientHello {
        var hello = ClientHello{
            .version = .{ .major = 3, .minor = 3 },
            .random = .{
                .unix_time = @truncate(@abs(std.time.timestamp())),
                .random_bytes = undefined,
            },
            .session_id = [_]u8{0} ** 32,
            .ciphers = &SupportedSuiteList,
            .compression = .null,
        };

        csprng.fill(&hello.random.random_bytes);
        csprng.fill(&hello.session_id);
        return hello;
    }

    pub fn pack(ch: ClientHello, buffer: []u8) !usize {
        var fba = fixedBufferStream(buffer);
        var w = fba.writer().any();
        try w.writeByte(ch.version.major);
        try w.writeByte(ch.version.minor);
        try w.writeStruct(ch.random);
        try w.writeByte(0);
        //try w.writeByte(ch.session_id.len);
        //try w.writeAll(&ch.session_id);

        const c_count: u16 = @truncate(ch.ciphers.len);
        try w.writeInt(u16, c_count * 2, std.builtin.Endian.big);
        for (ch.ciphers) |cipher| {
            try w.writeByte(cipher[0]);
            try w.writeByte(cipher[1]);
        }
        try w.writeByte(1);
        try w.writeByte(@intFromEnum(ch.compression));

        var e_count: u16 = 0;
        var extension_buffer: [0x1000]u8 = undefined;
        inline for (SupportedExtensions) |extension| {
            var extt = extension{};
            var ext = extt.extension();
            e_count += @truncate(ext.pack(extension_buffer[e_count..]));
        }
        try w.writeInt(u16, e_count, std.builtin.Endian.big);
        try w.writeAll(extension_buffer[0..e_count]);

        return fba.pos;
    }

    pub fn unpack(buffer: []const u8, _: *SessionState) !ClientHello {
        _ = buffer;
        unreachable;
    }
};

const RecordProto = struct {};
const ConnectionEnd = struct {};
const PRFAlgorithm = struct {};
const BulkCipherAlgorithm = struct {};
const MACAlgorithm = struct {};
const CompressionMethod = ?void;

const EllipticCurveCipher = struct {
    curve: union(CurveType) {
        invalid: void,
        explicit_prime: ExplicitPrime,
        explicit_char2: ExplicitChar2,
        named_curve: NamedCurve,
    } = .{ .invalid = {} },

    pub const CurveType = enum(u8) {
        invalid = 0,
        explicit_prime = 1,
        explicit_char2 = 2,
        named_curve = 3,

        pub fn fromByte(t: u8) !CurveType {
            return switch (t) {
                inline 0...3 => |i| @enumFromInt(i),
                else => return error.InvalidECCCurveType,
            };
        }
    };

    pub const ExplicitPrime = struct {};
    pub const ExplicitChar2 = struct {};
    pub const NamedCurve = struct {};

    pub fn unpackKeyExchange(buffer: []const u8) !EllipticCurveCipher {
        var fba = fixedBufferStream(buffer);
        const r = fba.reader().any();

        const curve_type = try CurveType.fromByte(try r.readByte());
        return .{
            .curve = switch (curve_type) {
                .named_curve => .{ .named_curve = .{} },
                else => return error.UnsupportedCurve,
            },
        };
    }
};

const Cipher = struct {
    suite: union(enum) {
        invalid: void,
        ecc: EllipticCurveCipher,
    } = .{ .invalid = {} },
};

const SessionState = struct {
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
};

//
//   Implementations MUST NOT send zero-length fragments of Handshake,
//   Alert, or ChangeCipherSpec content types.  Zero-length fragments of
//   Application data MAY be sent as they are potentially useful as a
//   traffic analysis countermeasure.
//
//   Note: Data of different TLS record layer content types MAY be
//   interleaved.  Application data is generally of lower precedence for
//   transmission than other content types.  However, records MUST be
//   delivered to the network in the same order as they are protected by
//   the record layer.  Recipients MUST receive and process interleaved
//   application layer traffic during handshakes subsequent to the first
//   one on a connection.

const CipherType = enum {
    stream,
    block,
    aead,
};

const GenericStreamCipher = struct {};
const GenericBlockCipher = struct {};
const GenericAEADCipher = struct {};

//fn TLSCiphertext(comptime frgmt: CipherType) type {
//    return struct {
//        type: ContentType,
//        version: ProtocolVersion,
//        length: u16,
//        fragment: switch (frgmt) {
//            .stream => GenericStreamCipher,
//            .block => GenericBlockCipher,
//            .aead => GenericAEADCipher,
//        },
//    };
//}

const HelloRequest = struct {};

const HandshakeType = enum(u8) {
    hello_request = 0,
    client_hello = 1,
    server_hello = 2,
    certificate = 11,
    server_key_exchange = 12,
    certificate_request = 13,
    server_hello_done = 14,
    certificate_verify = 15,
    client_key_exchange = 16,
    finished = 20,

    pub fn fromByte(kind: u8) !HandshakeType {
        return switch (kind) {
            0 => .hello_request,
            1 => .client_hello,
            2 => .server_hello,
            11 => .certificate,
            12 => .server_key_exchange,
            13 => .certificate_request,
            14 => .server_hello_done,
            15 => .certificate_verify,
            16 => .client_key_exchange,
            20 => .finished,
            else => unreachable,
        };
    }

    pub fn toType(kind: HandshakeType) type {
        return switch (kind) {
            inline .hello_request => unreachable,
            inline .client_hello => ClientHello,
            inline .server_hello => ServerHello,
            inline .certificate => Certificate,
            inline .server_key_exchange => ServerKeyExchange,
            inline .certificate_request => CertificateRequest,
            inline .server_hello_done => ServerHelloDone,

            .certificate_verify,
            .client_key_exchange,
            .finished,
            => unreachable,
            else => return error.UnknownHandshakeType,
        };
    }
};

const ServerHello = struct {
    version: ProtocolVersion,
    random: Random,
    session_id: SessionID,
    cipher: CipherSuite,
    compression: Compression,
    extensions: []const Extension,

    pub fn unpack(buffer: []const u8, _: *SessionState) !ServerHello {
        var fba = fixedBufferStream(buffer);
        const r = fba.reader().any();

        const version = ProtocolVersion{
            .major = try r.readByte(),
            .minor = try r.readByte(),
        };
        var random = Random{
            .unix_time = try r.readInt(u32, std.builtin.Endian.big),
            .random_bytes = undefined,
        };
        try r.readNoEof(&random.random_bytes);

        const session_size = try r.readByte();
        var session_id: [32]u8 = [_]u8{0} ** 32;
        try r.readNoEof(session_id[0..session_size]);

        // cipers
        //const cbytes: u16 = try r.readInt(u16, std.builtin.Endian.big);
        const cipher: [2]u8 = [2]u8{
            try r.readByte(),
            try r.readByte(),
        };
        print("requested cipher {any}\n", .{cipher});

        // compression
        if (try r.readByte() != 0) return error.InvalidCompression;

        // extensions
        if (r.readInt(u16, std.builtin.Endian.big)) |extbytes| {
            var extbuffer: [0x1000]u8 = undefined;
            try r.readNoEof(extbuffer[0..extbytes]);
        } else |err| switch (err) {
            error.EndOfStream => print("server hello readerror {}\n", .{err}),
            else => return err,
        }

        return .{
            .version = version,
            .random = random,
            .session_id = session_id,
            .cipher = cipher,
            .compression = .null,
            .extensions = &[0]Extension{},
        };
    }
};

const Certificate = struct {
    buffer: []const u8,
    session: *SessionState,

    pub fn unpack(buffer: []const u8, sess: *SessionState) !Certificate {
        return .{
            .buffer = buffer,
            .session = sess,
        };
    }
};

const ServerKeyExchange = struct {
    buffer: []const u8,
    cipher: *const Cipher,

    /// Will modify sess with supplied
    pub fn unpack(buffer: []const u8, sess: *SessionState) !ServerKeyExchange {
        switch (sess.cipher.suite) {
            .ecc => {
                sess.cipher.suite.ecc = try EllipticCurveCipher.unpackKeyExchange(buffer);
            },
            else => unreachable,
        }
        return .{
            .buffer = buffer,
            .cipher = &sess.cipher,
        };
    }
};

const CertificateRequest = struct {
    buffer: []const u8,
    session: *SessionState,

    pub fn unpack(buffer: []const u8, sess: *SessionState) !CertificateRequest {
        return .{
            .buffer = buffer,
            .session = sess,
        };
    }
};

const ServerHelloDone = struct {
    buffer: []const u8,
    session: *SessionState,

    pub fn unpack(buffer: []const u8, sess: *SessionState) !ServerHelloDone {
        return .{
            .buffer = buffer,
            .session = sess,
        };
    }
};

const CertificateVerify = struct {};

const ClientECDH = struct {
    _key_material: [255]u8 = [_]u8{8} ** 255,
    // 1..255
    point: []u8 = &[0]u8{},
};

const ClientKeyExchange = struct {
    /// RFC 4492
    pve: enum(u8) {
        /// Provided in the client cert
        implicit = 0,
        /// specified next
        explicit = 1,
    } = .explicit,
    key_exchange_algo: ClientECDH = .{},
    key_material: ?std.crypto.dh.X25519.KeyPair = null,

    pub fn init() !ClientKeyExchange {
        var cke = ClientKeyExchange{
            .key_exchange_algo = .{},
        };
        cke.key_material = try std.crypto.dh.X25519.KeyPair.create(null);
        cke.key_exchange_algo.point = &cke.key_material.?.public_key;
        return cke;
    }

    pub fn pack(cke: ClientKeyExchange, buffer: []u8) !usize {
        var fba = fixedBufferStream(buffer);
        var w = fba.writer().any();
        try w.writeByte(@intFromEnum(cke.pve));
        try w.writeByte(@truncate(cke.key_exchange_algo.point.len));
        try w.writeAll(cke.key_exchange_algo.point);
        return 1 + 1 + cke.key_exchange_algo.point.len;
    }
};

const Finished = struct {};

fn handshakeFromHeader(kind: HandshakeType) type {
    return Handshake(kind);
}

const Handshakes = union(HandshakeType) {
    hello_request: void,
    client_hello: ClientHello,
    server_hello: ServerHello,
    certificate: Certificate,
    server_key_exchange: ServerKeyExchange,
    certificate_request: CertificateRequest,
    server_hello_done: ServerHelloDone,
    certificate_verify: void,
    client_key_exchange: ClientKeyExchange,
    finished: void,
};

const Handshake = struct {
    msg_type: HandshakeType,
    _length: u24 = 0, // unused
    body: Handshakes,

    pub fn wrap(any: anytype) !Handshake {
        const kind = @TypeOf(any);
        return switch (kind) {
            ClientHello => .{
                .msg_type = .client_hello,
                .body = .{ .client_hello = any },
            },
            ClientKeyExchange => .{
                .msg_type = .client_key_exchange,
                .body = .{ .client_key_exchange = any },
            },
            else => comptime unreachable,
        };
    }

    pub fn pack(hs: Handshake, buffer: []u8) !usize {
        var fba = fixedBufferStream(buffer);
        var w = fba.writer().any();
        const len = switch (hs.body) {
            .client_hello => |ch| try ch.pack(buffer[4..]),
            .client_key_exchange => |cke| try cke.pack(buffer[4..]),
            else => unreachable,
        };
        std.debug.assert(len < std.math.maxInt(u24));

        try w.writeByte(@intFromEnum(hs.msg_type));
        try w.writeInt(u24, @truncate(len), std.builtin.Endian.big);
        return len + 4;
    }

    pub fn unpack(buffer: []const u8, sess: *SessionState) !Handshake {
        const hs_type = try HandshakeType.fromByte(buffer[0]);
        const hsbuf = buffer[4..];
        return .{
            .msg_type = hs_type,
            .body = switch (hs_type) {
                .client_hello => .{ .client_hello = try ClientHello.unpack(hsbuf, sess) },
                .server_hello => .{ .server_hello = try ServerHello.unpack(hsbuf, sess) },
                .certificate => .{ .certificate = try Certificate.unpack(hsbuf, sess) },
                .server_key_exchange => .{ .server_key_exchange = try ServerKeyExchange.unpack(hsbuf, sess) },
                .certificate_request => .{ .certificate_request = try CertificateRequest.unpack(hsbuf, sess) },
                .server_hello_done => .{ .server_hello_done = try ServerHelloDone.unpack(hsbuf, sess) },
                else => unreachable,
            },
        };
    }
};

const HashAlgorithm = enum(u8) {
    none = 0,
    md5 = 1,
    sha1 = 2,
    sha224 = 3,
    sha256 = 4,
    sha384 = 5,

    sha512 = 6,
};

const SignatureAlgorithm = enum(u8) {
    anonymous = 0,
    rsa = 1,
    dsa = 2,
    ecdsa = 3,
};

const SignatureAndHashAlgorithm = struct {
    hash: HashAlgorithm,
    signature: SignatureAlgorithm,
};

test "Handshake ClientHello" {
    var buffer = [_]u8{0} ** 0x400;
    const client_hello = ClientHello.init();
    const record = TLSRecord{
        .kind = .{
            .handshake = try Handshake.wrap(client_hello),
        },
    };

    const len = try record.pack(&buffer);
    _ = len;
}

test "tls" {
    const addr = net.Address.resolveIp(TESTING_IP, TESTING_PORT) catch |err| {
        print("unable to resolve address because {}\n", .{err});
        return err;
    };
    const conn = try net.tcpConnectToAddress(addr);

    var buffer = [_]u8{0} ** 0x1000;
    const client_handshake = ClientHello.init();
    const record = TLSRecord{
        .kind = .{
            .handshake = try Handshake.wrap(client_handshake),
        },
    };

    const len = try record.pack(&buffer);
    const dout = try conn.write(buffer[0..len]);
    _ = dout;

    //print("data count {}\n", .{dout});
    if (false) print("data out {any}\n", .{buffer[0..len]});
    var server_hello: [0x1000]u8 = undefined;
    const s_hello_read = try conn.read(&server_hello);
    if (s_hello_read == 0) return error.InvalidSHello;

    const server_msg = server_hello[0..s_hello_read];
    if (false) print("server data: {any}\n", .{server_msg});

    //const session: SessionState = undefined;

    //const tlsr = try TLSRecord.unpack(server_msg, session);

    //switch (tlsr.kind) {
    //    .alert => |a| {
    //        try std.testing.expect(a.description != .decode_error);
    //        print("ALERT {}\n", .{a});
    //    },
    //    else => |na| print("non alert message {}\n", .{na}),
    //}

    //if (false) print("server data: {any}\n", .{tlsr});

    //try conn.writeAll(&client_fin);
    try std.testing.expect(s_hello_read > 7);

    const cke = try ClientKeyExchange.init();
    const cke_record = TLSRecord{
        .kind = .{
            .handshake = try Handshake.wrap(cke),
        },
    };

    const cke_len = try cke_record.pack(&buffer);
    try std.testing.expectEqual(43, cke_len);
    print("CKE: {any}\n", .{buffer[0..43]});
    const ckeout = try conn.write(buffer[0..cke_len]);
    if (true) print("cke delivered, {}\n", .{ckeout});
}

test "mock server response" {
    // zig fmt: off
    const server_data = [_]u8{
        22, 3, 3, 0, 74,
        2, 0, 0, 70,
            3, 3, 75, 127, 236, 41, 6, 185, 127, 156, 38, 101, 41, 80, 93, 16, 140, 154, 60, 40, 250, 248, 115, 110, 115, 15, 68, 79, 87, 78, 71, 82, 68, 1, 32, 24, 187, 143, 225, 245, 127, 101, 130, 182, 200, 134, 201, 74, 38, 128, 15, 14, 35, 146, 216, 106, 109, 225, 72, 177, 41, 225, 227, 146, 101, 101, 10, 204, 169, 0,
        22, 3, 3, 2, 64,
        11, 0, 2, 60,
            0, 2, 57, 0, 2, 54, 48, 130, 2, 50, 48,
            130, 1, 184, 160, 3, 2, 1, 2, 2, 20, 104,
            254, 206, 87, 13, 243, 60, 147, 173, 38,
            100, 66, 220, 129, 46, 24, 54, 59, 37,
            114, 48, 10, 6, 8, 42, 134, 72, 206,
            61, 4, 3, 2, 48, 80, 49, 11, 48, 9, 6,
            3, 85, 4, 6, 19, 2, 85, 83, 49, 19, 48,
            17, 6, 3, 85, 4, 8, 12, 10, 83, 111, 109,
            101, 45, 83, 116, 97, 116, 101, 49, 13,
            48, 11, 6, 3, 85, 4, 10, 12, 4, 110, 117,
            108, 108, 49, 13, 48, 11, 6, 3, 85, 4,
            11, 12, 4, 110, 117, 108, 108, 49, 14, 48,
            12, 6, 3, 85, 4, 3, 12, 5, 116, 111, 119,
            101, 114, 48, 30, 23, 13, 50, 51, 49, 48,
            49, 48, 48, 49, 53, 53, 53, 55, 90, 23,
            13, 50, 54, 49, 48, 48, 57, 48, 49, 53,
            53, 53, 55, 90, 48, 80, 49, 11, 48, 9, 6,
            3, 85, 4, 6, 19, 2, 85, 83, 49, 19, 48, 17,
            6, 3, 85, 4, 8, 12, 10, 83, 111, 109, 101,
            45, 83, 116, 97, 116, 101, 49, 13, 48, 11,
            6, 3, 85, 4, 10, 12, 4, 110, 117, 108, 108,
            49, 13, 48, 11, 6, 3, 85, 4, 11, 12, 4, 110,
            117, 108, 108, 49, 14, 48, 12, 6, 3, 85, 4,
            3, 12, 5, 116, 111, 119, 101, 114, 48, 118,
            48, 16, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6,
            5, 43, 129, 4, 0, 34, 3, 98, 0, 4, 198, 26,
            57, 146, 22, 113, 142, 223, 208, 19, 112, 123,
            87, 194, 131, 225, 118, 55, 148, 113, 62, 196,
            158, 171, 34, 127, 140, 90, 235, 113, 221, 120,
            251, 141, 38, 234, 151, 224, 155, 183, 70, 192,
            129, 180, 116, 145, 238, 132, 71, 21, 10, 72,
            24, 104, 229, 26, 155, 129, 59, 117, 223, 165,
            200, 108, 233, 105, 103, 2, 98, 118, 249, 192,
            114, 123, 82, 234, 152, 130, 17, 91, 38, 234,
            87, 243, 52, 240, 72, 160, 35, 196, 25, 129, 201,
            97, 112, 57, 163, 83, 48, 81, 48, 29, 6, 3,
            85, 29, 14, 4, 22, 4, 20, 48, 133, 244, 80,
            200, 17, 185, 240, 93, 162, 90, 225, 53, 62,
            231, 234, 47, 38, 117, 207, 48, 31, 6, 3,
            85, 29, 35, 4, 24, 48, 22, 128, 20, 48, 133,
            244, 80, 200, 17, 185, 240, 93, 162, 90,
            225, 53, 62, 231, 234, 47, 38, 117, 207, 48,
            15, 6, 3, 85, 29, 19, 1, 1, 255, 4, 5, 48, 3,
            1, 1, 255, 48, 10, 6, 8, 42, 134, 72, 206, 61,
            4, 3, 2, 3, 104, 0, 48, 101, 2, 48, 9, 248,
            206, 200, 89, 165, 36, 63, 181, 5, 145, 31,
            138, 207, 12, 223, 57, 189, 65, 152, 99, 77,
            182, 90, 47, 152, 227, 196, 144, 166, 147, 97,
            44, 115, 138, 229, 212, 211, 251, 38, 221, 161,
            225, 1, 88, 215, 83, 179, 2, 49, 0, 130, 255,
            220, 17, 165, 227, 46, 238, 140, 122, 122, 18,
            139, 47, 181, 191, 223, 154, 13, 62, 100, 0,
            83, 84, 100, 92, 116, 99, 214, 144, 164, 102,
            191, 190, 74, 81, 133, 80, 68, 166, 135, 147,
            190, 189, 222, 192, 200, 113,
        22, 3, 3, 0, 146,
        12, 0, 0, 142,
            3, 0, 29, 32, 79, 189, 85, 166,
            190, 168, 238, 144, 215, 56, 187, 13, 64, 120,
            156, 134, 33, 146, 225, 213, 111, 241, 251, 212,
            105, 110, 68, 224, 176, 203, 101, 109, 4, 3, 0,
            102, 48, 100, 2, 48, 109, 172, 43, 76, 16, 12,
            149, 10, 199, 222, 137, 93, 199, 188, 15, 217,
            191, 67, 9, 108, 228, 27, 224, 5, 85, 161, 180,
            167, 89, 54, 134, 99, 44, 174, 71, 201, 99, 10,
            175, 46, 207, 252, 5, 47, 74, 248, 80, 185, 2,
            48, 25, 189, 150, 104, 207, 122, 9, 91, 186,
            103, 172, 61, 128, 204, 245, 193, 119, 30, 202,
            187, 75, 203, 45, 40, 49, 6, 51, 234, 98, 94,
            191, 167, 187, 71, 12, 181, 172, 187, 203, 71,
            91, 167, 76, 160, 224, 48, 135, 35,
        22, 3, 3, 0, 142,
        13, 0, 0, 138,
            3, 1, 2, 64, 0, 46, 4, 3, 5, 3, 6, 3, 8, 7, 8, 8,
            8, 26, 8, 27, 8, 28, 8, 9, 8, 10, 8, 11, 8, 4, 8,
            5, 8, 6, 4, 1, 5, 1, 6, 1, 3, 3, 3, 1, 3, 2, 4, 2,
            5, 2, 6, 2, 0, 84, 0, 82, 48, 80, 49, 11, 48, 9,
            6, 3, 85, 4, 6, 19, 2, 85, 83, 49, 19, 48, 17, 6,
            3, 85, 4, 8, 12, 10, 83, 111, 109, 101, 45, 83,
            116, 97, 116, 101, 49, 13, 48, 11, 6, 3, 85, 4,
            10, 12, 4, 110, 117, 108, 108, 49, 13, 48, 11, 6,
            3, 85, 4, 11, 12, 4, 110, 117, 108, 108, 49, 14,
            48, 12, 6, 3, 85, 4, 3, 12, 5, 116, 111, 119, 101, 114,
        22, 3, 3, 0, 4,
        14, 0, 0, 0


        };
    // zig fmt: on

    var session = SessionState{};
    var next_block: []const u8 = &server_data;

    while (next_block.len > 0) {
        const tlsr = try TLSRecord.unpack(next_block, &session);
        if (false) print("mock {}\n", .{tlsr.length});
        next_block = next_block[tlsr.length + 5 ..];

        switch (tlsr.kind) {
            .change_cipher_spec, .alert, .application_data => return error.UnexpectedResponse,
            .handshake => |hs| {
                switch (hs.body) {
                    .server_hello => |hello| {
                        print("server hello {}\n", .{@TypeOf(hello)});
                        if (std.mem.eql(
                            u8,
                            &hello.cipher,
                            &CipherSuites.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                        )) {
                            session.cipher.suite = .{ .ecc = .{} };
                        } else {
                            return error.UnexpectedCipherSuite;
                        }
                    },
                    .certificate => |cert| {
                        print("server cert {}\n", .{@TypeOf(cert)});
                    },
                    .server_key_exchange => |keyex| {
                        print("server keyex {}\n", .{@TypeOf(keyex)});
                    },
                    .certificate_request => |req| {
                        print("server req {}\n", .{@TypeOf(req)});
                    },
                    .server_hello_done => |done| {
                        print("server done {}\n", .{@TypeOf(done)});
                    },
                    else => return error.UnexpectedHandshake,
                }
            },
        }
    }

    const cke = try ClientKeyExchange.init();
    const record = TLSRecord{
        .kind = .{
            .handshake = try Handshake.wrap(cke),
        },
    };

    var buffer = [_]u8{0} ** 0x1000;
    const len = try record.pack(&buffer);
    try std.testing.expectEqual(43, len);
    print("CKE: {any}\n", .{buffer[0..43]});
}

const CipherSuite = [2]u8;

const CipherSuites = struct {
    pub const TLS_DHE_RSA_WITH_AES_256_CBC_SHA256: CipherSuite = .{ 0x00, 0x6B };
    pub const TLS_DH_RSA_WITH_AES_256_CBC_SHA256: CipherSuite = .{ 0x00, 0x69 };
    pub const TLS_DH_DSS_WITH_AES_128_CBC_SHA256: CipherSuite = .{ 0x00, 0x3E };

    pub const TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: CipherSuite = .{ 0xCC, 0xA8 };
    pub const TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: CipherSuite = .{ 0xCC, 0xA9 };
    pub const TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256: CipherSuite = .{ 0xCC, 0xAA };

    pub const TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA: CipherSuite = .{ 0x00, 0x0D };
    pub const TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA: CipherSuite = .{ 0x00, 0x10 };
    pub const TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA: CipherSuite = .{ 0x00, 0x13 };
    pub const TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA: CipherSuite = .{ 0x00, 0x16 };
    pub const TLS_DH_DSS_WITH_AES_128_CBC_SHA: CipherSuite = .{ 0x00, 0x30 };
    pub const TLS_DH_RSA_WITH_AES_128_CBC_SHA: CipherSuite = .{ 0x00, 0x31 };
    pub const TLS_DHE_DSS_WITH_AES_128_CBC_SHA: CipherSuite = .{ 0x00, 0x32 };
    pub const TLS_DHE_RSA_WITH_AES_128_CBC_SHA: CipherSuite = .{ 0x00, 0x33 };
    pub const TLS_DH_DSS_WITH_AES_256_CBC_SHA: CipherSuite = .{ 0x00, 0x36 };
    pub const TLS_DH_RSA_WITH_AES_256_CBC_SHA: CipherSuite = .{ 0x00, 0x37 };
    pub const TLS_DHE_DSS_WITH_AES_256_CBC_SHA: CipherSuite = .{ 0x00, 0x38 };
    pub const TLS_DHE_RSA_WITH_AES_256_CBC_SHA: CipherSuite = .{ 0x00, 0x39 };

    pub const TLS_DH_RSA_WITH_AES_128_CBC_SHA256: CipherSuite = .{ 0x00, 0x3F };
    pub const TLS_DHE_DSS_WITH_AES_128_CBC_SHA256: CipherSuite = .{ 0x00, 0x40 };
    pub const TLS_DHE_RSA_WITH_AES_128_CBC_SHA256: CipherSuite = .{ 0x00, 0x67 };
    pub const TLS_DH_DSS_WITH_AES_256_CBC_SHA256: CipherSuite = .{ 0x00, 0x68 };
    pub const TLS_DHE_DSS_WITH_AES_256_CBC_SHA256: CipherSuite = .{ 0x00, 0x6A };
    // RFC7905
    //TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: CipherSuite = .{ 0xCC, 0xA8 },
    //TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: CipherSuite = .{ 0xCC, 0xA9 },
    //TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256: CipherSuite = .{ 0xCC, 0xAA },

    // RFC5246
    TLS_PSK_WITH_CHACHA20_POLY1305_SHA256: CipherSuite = .{ 0xCC, 0xAB },
    TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256: CipherSuite = .{ 0xCC, 0xAC },
    TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256: CipherSuite = .{ 0xCC, 0xAD },
    TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256: CipherSuite = .{ 0xCC, 0xAE },
    //TLS_DHE_RSA_WITH_AES_256_CBC_SHA256: CipherSuite = .{ 0x00, 0x6B },

    // The following cipher suites are used for completely anonymous
    // Diffie-Hellman communications in which neither party is
    // authenticated.  Note that this mode is vulnerable to man-in-the-
    // middle attacks.  Using this mode therefore is of limited use: These
    // cipher suites MUST NOT be used by TLS 1.2 implementations unless the
    // application layer has specifically requested to allow anonymous key
    // exchange.  (Anonymous key exchange may sometimes be acceptable, for
    // example, to support opportunistic encryption when no set-up for
    // authentication is in place, or when TLS is used as part of more
    // complex security protocols that have other means to ensure
    // authentication.)

    TLS_DH_anon_WITH_RC4_128_MD5: CipherSuite = .{ 0x00, 0x18 },
    TLS_DH_anon_WITH_3DES_EDE_CBC_SHA: CipherSuite = .{ 0x00, 0x1B },
    TLS_DH_anon_WITH_AES_128_CBC_SHA: CipherSuite = .{ 0x00, 0x34 },
    TLS_DH_anon_WITH_AES_256_CBC_SHA: CipherSuite = .{ 0x00, 0x3A },
    TLS_DH_anon_WITH_AES_128_CBC_SHA256: CipherSuite = .{ 0x00, 0x6C },
    TLS_DH_anon_WITH_AES_256_CBC_SHA256: CipherSuite = .{ 0x00, 0x6D },

    // Note that using non-anonymous key exchange without actually verifying
    // the key exchange is essentially equivalent to anonymous key exchange,
    // and the same precautions apply.  While non-anonymous key exchange
    // will generally involve a higher computational and communicational
    // cost than anonymous key exchange, it may be in the interest of
    // interoperability not to disable non-anonymous key exchange when the
    // application layer is allowing anonymous key exchange.

    // New cipher suite values have been assigned by IANA as described in
    // Section 12.

    // Note: The cipher suite values { 0x00, 0x1C } and { 0x00, 0x1D } are
    // reserved to avoid collision with Fortezza-based cipher suites in
    // SSL 3.
};

// Cipher Suite                            Key Excg     Cipher         Mac
//
// TLS_NULL_WITH_NULL_NULL                 NULL         NULL         NULL
// TLS_RSA_WITH_NULL_MD5                   RSA          NULL         MD5
// TLS_RSA_WITH_NULL_SHA                   RSA          NULL         SHA
// TLS_RSA_WITH_NULL_SHA256                RSA          NULL         SHA256
// TLS_RSA_WITH_RC4_128_MD5                RSA          RC4_128      MD5
// TLS_RSA_WITH_RC4_128_SHA                RSA          RC4_128      SHA
// TLS_RSA_WITH_3DES_EDE_CBC_SHA           RSA          3DES_EDE_CBC SHA
// TLS_RSA_WITH_AES_128_CBC_SHA            RSA          AES_128_CBC  SHA
// TLS_RSA_WITH_AES_256_CBC_SHA            RSA          AES_256_CBC  SHA
// TLS_RSA_WITH_AES_128_CBC_SHA256         RSA          AES_128_CBC  SHA256
// TLS_RSA_WITH_AES_256_CBC_SHA256         RSA          AES_256_CBC  SHA256
// TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA        DH_DSS       3DES_EDE_CBC SHA
// TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA        DH_RSA       3DES_EDE_CBC SHA
// TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA       DHE_DSS      3DES_EDE_CBC SHA
// TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA       DHE_RSA      3DES_EDE_CBC SHA
// TLS_DH_anon_WITH_RC4_128_MD5            DH_anon      RC4_128      MD5
// TLS_DH_anon_WITH_3DES_EDE_CBC_SHA       DH_anon      3DES_EDE_CBC SHA
// TLS_DH_DSS_WITH_AES_128_CBC_SHA         DH_DSS       AES_128_CBC  SHA
// TLS_DH_RSA_WITH_AES_128_CBC_SHA         DH_RSA       AES_128_CBC  SHA
// TLS_DHE_DSS_WITH_AES_128_CBC_SHA        DHE_DSS      AES_128_CBC  SHA
// TLS_DHE_RSA_WITH_AES_128_CBC_SHA        DHE_RSA      AES_128_CBC  SHA
// TLS_DH_anon_WITH_AES_128_CBC_SHA        DH_anon      AES_128_CBC  SHA
// TLS_DH_DSS_WITH_AES_256_CBC_SHA         DH_DSS       AES_256_CBC  SHA
// TLS_DH_RSA_WITH_AES_256_CBC_SHA         DH_RSA       AES_256_CBC  SHA
// TLS_DHE_DSS_WITH_AES_256_CBC_SHA        DHE_DSS      AE4, 3, 2, 3S_256_CBC  SHA
// TLS_DHE_RSA_WITH_AES_256_CBC_SHA        DHE_RSA      AES_256_CBC  SHA
// TLS_DH_anon_WITH_AES_256_CBC_SHA        DH_anon      AES_256_CBC  SHA
// TLS_DH_DSS_WITH_AES_128_CBC_SHA256      DH_DSS       AES_128_CBC  SHA256
// TLS_DH_RSA_WITH_AES_128_CBC_SHA256      DH_RSA       AES_128_CBC  SHA256
// TLS_DHE_DSS_WITH_AES_128_CBC_SHA256     DHE_DSS      AES_128_CBC  SHA256
// TLS_DHE_RSA_WITH_AES_128_CBC_SHA256     DHE_RSA      AES_128_CBC  SHA256
// TLS_DH_anon_WITH_AES_128_CBC_SHA256     DH_anon      AES_128_CBC  SHA256
// TLS_DH_DSS_WITH_AES_256_CBC_SHA256      DH_DSS       AES_256_CBC  SHA256
// TLS_DH_RSA_WITH_AES_256_CBC_SHA256      DH_RSA       AES_256_CBC  SHA256
// TLS_DHE_DSS_WITH_AES_256_CBC_SHA256     DHE_DSS      AES_256_CBC  SHA256
// TLS_DHE_RSA_WITH_AES_256_CBC_SHA256     DHE_RSA      AES_256_CBC  SHA256
// TLS_DH_anon_WITH_AES_256_CBC_SHA256     DH_anon      AES_256_CBC  SHA256
//
//                         Key      IV   Block
// Cipher        Type    Material  Size  Size
// ------------  ------  --------  ----  -----
// NULL          Stream      0       0    N/A
// RC4_128       Stream     16       0    N/A
// 3DES_EDE_CBC  Block      24       8      8
// AES_128_CBC   Block      16      16     16
// AES_256_CBC   Block      32      16     16
//
// MAC       Algorithm    mac_length  mac_key_length
// --------  -----------  ----------  --------------
// NULL      N/A              0             0
// MD5       HMAC-MD5        16            16
// SHA       HMAC-SHA1       20            20
// SHA256    HMAC-SHA256     32            32
//
//    Type
//       Indicates whether this is a stream cipher or a block cipher
//       running in CBC mode.
//
//    Key Material
//       The number of bytes from the key_block that are used for
//       generating the write keys.
//
//    IV Size
//       The amount of data needed to be generated for the initialization
//       vector.  Zero for stream ciphers; equal to the block size for
//       block ciphers (this is equal to
//       SecurityParameters.record_iv_length).
//
//    Block Size
//       The amount of data a block cipher enciphers in one chunk; a block
//       cipher running in CBC mode can only encrypt an even multiple of
//       its block size.
