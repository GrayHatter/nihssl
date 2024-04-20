const std = @import("std");
const net = std.net;
const testing = std.testing;
const print = std.debug.print;
const fixedBufferStream = std.io.fixedBufferStream;

const TESTING_IP = "127.0.0.1";

const Alert = @import("alert.zig");

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
};

const TLSRecord = struct {
    type: ContentType,
    //version: ProtocolVersion = TLSv1_2,
    version: ProtocolVersion = .{ .major = 3, .minor = 3 },
    length: u16 = 0,
    fragment: union(enum) {
        client_handshake: ClientHandshake,
    },

    pub fn packFragment(record: TLSRecord, buffer: []u8) !usize {
        var fba = fixedBufferStream(buffer);
        const len = switch (record.fragment) {
            .client_handshake => |ch| try ch.pack(buffer[5..]),
        };
        var w = fba.writer().any();
        try w.writeByte(@intFromEnum(record.type));
        try w.writeByte(record.version.major);
        try w.writeByte(record.version.minor);
        try w.writeInt(u16, @truncate(len), std.builtin.Endian.big);
        return len + 5;
    }

    pub fn pack(record: TLSRecord, buffer: []u8) !usize {
        return record.packFragment(buffer);
    }
};

/// rfc5246
pub const ClientHello = struct {
    version: ProtocolVersion,
    random: Random,
    session_id: SessionID,
    ciphers: []const CipherSuite = &[0]CipherSuite{},
    compression: Compression,
    extensions: struct {},

    pub const SupportedSuiteList: [3]CipherSuite = [_]CipherSuite{
        CipherSuites.TLS_DH_DSS_WITH_AES_128_CBC_SHA256,
        CipherSuites.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
        CipherSuites.TLS_DH_RSA_WITH_AES_256_CBC_SHA256,
    };
    pub const length = @sizeOf(ClientHello);

    pub const SessionID = [32]u8;
    pub const Compression = enum(u8) {
        null = 0,
    };

    pub const Random = extern struct {
        unix_time: u32,
        random_bytes: [28]u8,
    };
    comptime {
        std.debug.assert(@sizeOf(Random) == 32);
    }

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
            .extensions = .{},
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
        var len: usize = 2; // version
        try w.writeStruct(ch.random);
        len += 32; // random

        try w.writeByte(32);
        len += 1; // sessid count
        try w.writeAll(&ch.session_id);
        len += 32; // sessionid

        const c_count: u16 = @truncate(ch.ciphers.len);
        try w.writeInt(u16, c_count * 2, std.builtin.Endian.big);
        len += 2;
        for (ch.ciphers) |cipher| {
            try w.writeByte(cipher[0]);
            try w.writeByte(cipher[1]);
            len += 2;
        }
        try w.writeByte(1);
        try w.writeByte(@intFromEnum(ch.compression));
        len += 2; // compression

        try w.writeInt(u16, 0, std.builtin.Endian.big);
        len += 2; // client extensions
        const printable = buffer[0..len];
        print("client hello full: {any}\n\n", .{printable});
        print("client hello srand: {any}\n\n", .{printable[2..]});
        print("client hello randonly: {any}\n\n", .{printable[2..][0..32]});
        print("client hello postrand: {any}\n\n", .{printable[34..]});
        return len;
    }
};

const RecordProto = struct {};
const ConnectionEnd = struct {};
const PRFAlgorithm = struct {};
const BulkCipherAlgorithm = struct {};
//const CipherType = struct {};
const MACAlgorithm = struct {};
const CompressionMethod = struct {};

const SecurityParameters = struct {
    entity: ConnectionEnd,
    prf_algorithm: PRFAlgorithm,
    bulk_cipher_algorithm: BulkCipherAlgorithm,
    cipher_type: CipherType,
    enc_key_length: u8,
    block_length: u8,
    fixed_iv_length: u8,
    record_iv_length: u8,
    mac_algorithm: MACAlgorithm,
    mac_length: u8,
    mac_key_length: u8,
    compression_algorithm: CompressionMethod,
    master_secret: [48]u8,
    client_random: [32]u8,
    server_random: [32]u8,
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

const TLSPlaintext = struct {
    pub fn init(frag: anytype) TLSPlaintext {
        switch (@TypeOf(frag)) {
            ClientHandshake => {
                return .{
                    .type = .handshake,
                    .length = @TypeOf(frag).length,
                    .fragment = .{ .client_handshake = frag },
                };
            },
            else => comptime unreachable,
        }
    }

    pub fn send(plain: TLSPlaintext, w: *std.io.AnyWriter) !void {
        var buffer: [0xfff]u8 = undefined;
        var fba = std.io.fixedBufferStream(&buffer);
        var frag = fba.writer().any();

        switch (plain.fragment) {
            .client_hello => try frag.write(plain.fragment),
            else => unreachable,
        }
        const fragment = fba.getWritten();
        _ = try w.write(&[1].{plain.type});
        _ = try w.write(plain.version);
        std.debug.assert(fragment.len < 0xFFFF);
        try w.writeInt(u16, @truncate(fragment.len), std.builtin.Endian.big);
        try w.writeAll(fragment);
    }
};

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
};

const ServerHello = struct {};
const Certificate = struct {};
const ServerKeyExchange = struct {};
const CertificateRequest = struct {};
const ServerHelloDone = struct {};
const CertificateVerify = struct {};
const ClientKeyExchange = struct {};
const Finished = struct {};

fn Handshake(comptime msg_type: HandshakeType) type {
    return struct {
        const Self = @This();
        msg_type: HandshakeType = msg_type,
        _length: u24 = 0, // unused
        body: switch (msg_type) {
            .hello_request => HelloRequest,
            .client_hello => ClientHello,
            .server_hello => ServerHello,
            .certificate => Certificate,
            .server_key_exchange => ServerKeyExchange,
            .certificate_request => CertificateRequest,
            .server_hello_done => ServerHelloDone,
            .certificate_verify => CertificateVerify,
            .client_key_exchange => ClientKeyExchange,
            .finished => Finished,
        },

        pub fn pack(self: Self, buffer: []u8) !usize {
            var fba = fixedBufferStream(buffer);
            var w = fba.writer().any();
            const len = try self.body.pack(buffer[4..]);
            std.debug.assert(len < std.math.maxInt(u24));
            try w.writeByte(@intFromEnum(msg_type));
            try w.writeInt(u24, @truncate(len), std.builtin.Endian.big);
            return len + 4;
        }
    };
}

const ClientHandshake = Handshake(.client_hello);

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

// SignatureAndHashAlgorithm
// supported_signature_algorithms<2..2^16-2>;

fn tlsHandshake(conn: net.Stream) !void {
    var buffer = [_]u8{0} ** 0x400;
    const client_handshake = ClientHandshake{
        .body = ClientHello.init(),
    };
    const record = TLSRecord{
        .type = .handshake,
        .fragment = .{
            .client_handshake = client_handshake,
        },
    };

    const len = try record.pack(&buffer);

    print("data count {}\n", .{try conn.write(buffer[0..len])});
    print("data out {any}\n", .{buffer[0..len]});
    var server_hello: [0xff]u8 = undefined;
    const s_hello_read = try conn.read(&server_hello);
    if (s_hello_read == 0) return error.InvalidSHello;

    print("server data: {any}\n", .{server_hello[0..s_hello_read]});
    //try conn.writeAll(&client_fin);
    try std.testing.expect(s_hello_read > 7);
}

fn tls(conn: net.Stream) !void {
    try tlsHandshake(conn);
}

test "Handshake ClientHello" {
    var buffer = [_]u8{0} ** 0x400;
    const client_handshake = ClientHandshake{
        .body = ClientHello.init(),
    };
    const record = TLSRecord{
        .type = .handshake,
        .fragment = .{
            .client_handshake = client_handshake,
        },
    };

    const len = try record.pack(&buffer);

    print("handshake test: {any}\n", .{buffer[0..len]});
}

test "tls" {
    const addr = net.Address.resolveIp(TESTING_IP, 443) catch |err| {
        print("unable to resolve address because {}\n", .{err});
        return err;
    };
    const con = try net.tcpConnectToAddress(addr);
    try tls(con);
}

const CipherSuite = [2]u8;

const CipherSuites = struct {
    pub const TLS_DHE_RSA_WITH_AES_256_CBC_SHA256: CipherSuite = .{ 0x00, 0x6B };
    pub const TLS_DH_RSA_WITH_AES_256_CBC_SHA256: CipherSuite = .{ 0x00, 0x69 };
    pub const TLS_DH_DSS_WITH_AES_128_CBC_SHA256: CipherSuite = .{ 0x00, 0x3E };
    TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA: CipherSuite = .{ 0x00, 0x0D },
    TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA: CipherSuite = .{ 0x00, 0x10 },
    TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA: CipherSuite = .{ 0x00, 0x13 },
    TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA: CipherSuite = .{ 0x00, 0x16 },
    TLS_DH_DSS_WITH_AES_128_CBC_SHA: CipherSuite = .{ 0x00, 0x30 },
    TLS_DH_RSA_WITH_AES_128_CBC_SHA: CipherSuite = .{ 0x00, 0x31 },
    TLS_DHE_DSS_WITH_AES_128_CBC_SHA: CipherSuite = .{ 0x00, 0x32 },
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA: CipherSuite = .{ 0x00, 0x33 },
    TLS_DH_DSS_WITH_AES_256_CBC_SHA: CipherSuite = .{ 0x00, 0x36 },
    TLS_DH_RSA_WITH_AES_256_CBC_SHA: CipherSuite = .{ 0x00, 0x37 },
    TLS_DHE_DSS_WITH_AES_256_CBC_SHA: CipherSuite = .{ 0x00, 0x38 },
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA: CipherSuite = .{ 0x00, 0x39 },

    TLS_DH_RSA_WITH_AES_128_CBC_SHA256: CipherSuite = .{ 0x00, 0x3F },
    TLS_DHE_DSS_WITH_AES_128_CBC_SHA256: CipherSuite = .{ 0x00, 0x40 },
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA256: CipherSuite = .{ 0x00, 0x67 },
    TLS_DH_DSS_WITH_AES_256_CBC_SHA256: CipherSuite = .{ 0x00, 0x68 },
    TLS_DH_RSA_WITH_AES_256_CBC_SHA256: CipherSuite = .{ 0x00, 0x69 },
    TLS_DHE_DSS_WITH_AES_256_CBC_SHA256: CipherSuite = .{ 0x00, 0x6A },
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
// TLS_DHE_DSS_WITH_AES_256_CBC_SHA        DHE_DSS      AES_256_CBC  SHA
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
