///      RFC 5246
///      ClientHello                  -------->
///                                                      ServerHello
///                                                     Certificate*
///                                               ServerKeyExchange*
///                                              CertificateRequest*
///                                   <--------      ServerHelloDone
///      Certificate*
///      ClientKeyExchange
///      CertificateVerify*
///      [ChangeCipherSpec]
///      Finished                     -------->
///                                               [ChangeCipherSpec]
///                                   <--------             Finished
///      Application Data             <------->     Application Data
///
///
const std = @import("std");
const State = @import("state.zig");
const Protocol = @import("protocol.zig");
const root = @import("root.zig");
const Random = root.Random;
const SessionID = root.SessionID;
const CipherSuite = root.CipherSuite;
const CipherSuites = root.CipherSuites;
const Extensions = @import("extensions.zig");
const Extension = Extensions.Extension;

const fixedBufferStream = std.io.fixedBufferStream;

var csprng = std.Random.ChaCha.init([_]u8{0} ** 32);

pub const Compression = enum(u8) {
    null = 0,
};

/// Client Section
pub const ClientHello = struct {
    version: Protocol.Version,
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

    pub fn unpack(buffer: []const u8, _: *State) !ClientHello {
        _ = buffer;
        unreachable;
    }
};

/// Combined Section
pub const Type = enum(u8) {
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

    pub fn fromByte(kind: u8) !Type {
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

    pub fn toType(kind: Type) type {
        return switch (kind) {
            inline .hello_request => unreachable,
            inline .client_hello => ClientHello,
            inline .server_hello => root.ServerHello,
            inline .certificate => root.Certificate,
            inline .server_key_exchange => root.ServerKeyExchange,
            inline .certificate_request => root.CertificateRequest,
            inline .server_hello_done => root.ServerHelloDone,

            .certificate_verify,
            .client_key_exchange,
            .finished,
            => unreachable,
            else => return error.UnknownHandshakeType,
        };
    }
};

fn handshakeFromHeader(kind: Type) type {
    return Handshake(kind);
}

const Handshakes = union(Type) {
    hello_request: void,
    client_hello: ClientHello,
    server_hello: root.ServerHello,
    certificate: root.Certificate,
    server_key_exchange: root.ServerKeyExchange,
    certificate_request: root.CertificateRequest,
    server_hello_done: root.ServerHelloDone,
    certificate_verify: void,
    client_key_exchange: root.ClientKeyExchange,
    finished: void,
};

pub const Handshake = struct {
    msg_type: Type,
    _length: u24 = 0, // unused
    body: Handshakes,

    pub fn wrap(any: anytype) !Handshake {
        const kind = @TypeOf(any);
        return switch (kind) {
            ClientHello => .{
                .msg_type = .client_hello,
                .body = .{ .client_hello = any },
            },
            root.ClientKeyExchange => .{
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

    pub fn unpack(buffer: []const u8, sess: *State) !Handshake {
        const hs_type = try Type.fromByte(buffer[0]);
        const hsbuf = buffer[4..];
        return .{
            .msg_type = hs_type,
            .body = switch (hs_type) {
                .client_hello => .{ .client_hello = try ClientHello.unpack(hsbuf, sess) },
                .server_hello => .{ .server_hello = try root.ServerHello.unpack(hsbuf, sess) },
                .certificate => .{ .certificate = try root.Certificate.unpack(hsbuf, sess) },
                .server_key_exchange => .{ .server_key_exchange = try root.ServerKeyExchange.unpack(hsbuf, sess) },
                .certificate_request => .{ .certificate_request = try root.CertificateRequest.unpack(hsbuf, sess) },
                .server_hello_done => .{ .server_hello_done = try root.ServerHelloDone.unpack(hsbuf, sess) },
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
