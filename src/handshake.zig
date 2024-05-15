const std = @import("std");

const ConnCtx = @import("context.zig");
const Protocol = @import("protocol.zig");
const root = @import("root.zig");
const Extensions = @import("extensions.zig");
const Cipher = @import("cipher.zig");

const Random = [32]u8;
const SessionID = root.SessionID;
const Extension = Extensions.Extension;

const fixedBufferStream = std.io.fixedBufferStream;
const print = std.debug.print;

const HmacSha384 = std.crypto.auth.hmac.sha2.HmacSha384;

var csprng = std.Random.ChaCha.init([_]u8{0} ** 32);

pub const Compression = enum(u8) {
    null = 0,
};

const HelloRequest = struct {};

/// Client Section
pub const ClientHello = struct {
    version: Protocol.Version = Protocol.TLSv1_2,
    random: Random,
    session_id: SessionID,
    ciphers: []const Cipher.Suites = &SupportedSuiteList,
    compression: Compression = .null,
    extensions: []const Extension = &[0]Extension{},

    pub const SupportedExtensions = [_]type{
        Extensions.SupportedGroups,
        Extensions.SignatureAlgorithms,
    };

    pub const SupportedSuiteList = [_]Cipher.Suites{
        .TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        .TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    };

    pub const length = @sizeOf(ClientHello);

    pub fn init(ctx: ConnCtx) ClientHello {
        var hello = ClientHello{
            .random = ctx.cli_random.?,
            .session_id = [_]u8{0} ** 32,
        };

        csprng.fill(&hello.session_id);
        return hello;
    }

    pub fn pack(ch: ClientHello, buffer: []u8) !usize {
        var fba = fixedBufferStream(buffer);
        var w = fba.writer().any();
        try w.writeByte(ch.version.major);
        try w.writeByte(ch.version.minor);
        try w.writeAll(&ch.random);
        // FIXME
        try w.writeByte(0);
        //try w.writeByte(ch.session_id.len);
        //try w.writeAll(&ch.session_id);

        try w.writeInt(u16, @truncate(ch.ciphers.len * 2), std.builtin.Endian.big);
        for (ch.ciphers) |cipher| {
            try w.writeInt(u16, @intFromEnum(cipher), .big);
        }
        try w.writeByte(1);
        try w.writeByte(@intFromEnum(ch.compression));

        var e_count: u16 = 0;
        var extension_buffer: [0x1000]u8 = undefined;
        inline for (SupportedExtensions) |extension| {
            var extt = extension{};
            var ext = extt.extension();
            e_count += @truncate(try ext.pack(extension_buffer[e_count..]));
        }
        try w.writeInt(u16, e_count, std.builtin.Endian.big);
        try w.writeAll(extension_buffer[0..e_count]);

        return fba.pos;
    }

    pub fn unpack(buffer: []const u8, _: *ConnCtx) !ClientHello {
        _ = buffer;
        unreachable;
    }
};

pub const ClientKeyExchange = struct {
    /// RFC 4492
    pve: enum(u8) {
        /// Provided in the client cert
        implicit = 0,
        /// specified next
        explicit = 1,
    } = .explicit,
    cipher: *const Cipher,

    pub fn init(ctx: *ConnCtx) !ClientKeyExchange {
        const cke = ClientKeyExchange{ .cipher = &ctx.cipher };
        return cke;
    }

    pub fn pack(cke: ClientKeyExchange, buffer: []u8) !usize {
        return switch (cke.cipher.suite) {
            .ecc => |ecc| ecc.packKeyExchange(buffer),
            .aes => |aes| aes.packKeyExchange(buffer),
            else => return error.NotImplemented,
        };
    }
};

pub const Finished = struct {
    pub fn pack(buffer: []u8, ctx: *const ConnCtx) !usize {
        var fba = fixedBufferStream(buffer);
        var w = fba.writer().any();

        const master = switch (ctx.cipher.suite) {
            .ecc => |ecc| ecc.material.master,
            .aes => |aes| aes.material.master,
            else => unreachable,
        };
        var hash: [48]u8 = undefined;
        std.crypto.hash.sha2.Sha384.hash(ctx.handshake_record.items, hash[0..], .{});

        const seed = "client finished" ++ hash;
        var a1: [48]u8 = undefined;
        HmacSha384.create(&a1, seed, &master);
        var verified: [48]u8 = undefined;
        HmacSha384.create(&verified, a1 ++ seed, &master);

        try w.writeAll(verified[0..12]);
        return 12;
    }
};

/// Server Section
pub const ServerHello = struct {
    version: Protocol.Version,
    random: Random,
    cipher: ?Cipher.Suites = null,
    compression: Compression,
    extensions: []const Extension,

    pub fn unpack(buffer: []const u8, ctx: *ConnCtx) !void {
        var fba = fixedBufferStream(buffer);
        const r = fba.reader().any();

        const version = Protocol.Version{
            .major = try r.readByte(),
            .minor = try r.readByte(),
        };
        std.debug.assert(version.major == 3 and version.minor == 3);

        ctx.srv_random = undefined;
        try r.readNoEof(&ctx.srv_random.?);

        const session_size = try r.readByte();
        var session_id: [32]u8 = [_]u8{0} ** 32;
        try r.readNoEof(session_id[0..session_size]);
        // TODO verify session id matches

        // FIXME
        const cipher_request = Cipher.Suites.fromInt(try r.readInt(u16, .big));
        switch (cipher_request) {
            .TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            .TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            => {
                ctx.cipher.suite = .{ .ecc = undefined };
            },
            //.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
            //.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
            //.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
            //.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
            //.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            .TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
            => {
                ctx.cipher.suite = .{ .aes = undefined };
            },
            //else => ctx.cipher.suite = .{ .ecc = undefined },
            else => return error.UnsupportedSuite,
        }

        // compression
        if (try r.readByte() != 0) return error.InvalidCompression;

        // extensions
        if (r.readInt(u16, .big)) |extbytes| {
            var extbuffer: [0x1000]u8 = undefined;
            try r.readNoEof(extbuffer[0..extbytes]);
        } else |err| switch (err) {
            error.EndOfStream => if (false) print("SrvHelo no extensions\n", .{}),
            else => return err,
        }
    }
};

pub const ServerKeyExchange = struct {
    buffer: []const u8,

    pub fn pack(_: ServerKeyExchange, _: []u8) !usize {
        return 0;
    }

    /// Will modify sess with supplied
    pub fn unpack(buffer: []const u8, ctx: *ConnCtx) !ServerKeyExchange {
        switch (ctx.cipher.suite) {
            .ecc => {
                try Cipher.EllipticCurve.unpackKeyExchange(buffer, ctx);
            },
            .aes => {
                try Cipher.AnyAES.unpackKeyExchange(buffer, ctx);
            },
            else => unreachable,
        }
        return .{
            .buffer = buffer,
        };
    }
};

pub const ServerHelloDone = struct {
    buffer: []const u8,
    session: *ConnCtx,

    pub fn unpack(buffer: []const u8, sess: *ConnCtx) !ServerHelloDone {
        return .{
            .buffer = buffer,
            .session = sess,
        };
    }
};

/// Certs
pub const Certificate = struct {
    buffer: []const u8,
    session: *ConnCtx,

    pub fn unpack(buffer: []const u8, sess: *ConnCtx) !Certificate {
        return .{
            .buffer = buffer,
            .session = sess,
        };
    }
};

pub const CertificateRequest = struct {
    buffer: []const u8,
    session: *ConnCtx,

    pub fn unpack(buffer: []const u8, sess: *ConnCtx) !CertificateRequest {
        return .{
            .buffer = buffer,
            .session = sess,
        };
    }
};

const CertificateVerify = struct {};

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

fn handshakeFromHeader(kind: Type) type {
    return Handshake(kind);
}

const Handshakes = union(Type) {
    hello_request: void,
    client_hello: ClientHello,
    server_hello: void,
    certificate: Certificate,
    server_key_exchange: ServerKeyExchange,
    certificate_request: CertificateRequest,
    server_hello_done: ServerHelloDone,
    certificate_verify: void,
    client_key_exchange: ClientKeyExchange,
    finished: Finished,
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
            ClientKeyExchange => .{
                .msg_type = .client_key_exchange,
                .body = .{ .client_key_exchange = any },
            },
            Finished => .{
                .msg_type = .finished,
                .body = .{ .finished = any },
            },
            else => comptime unreachable,
        };
    }

    pub fn pack(hs: Handshake, buffer: []u8, ctx: *ConnCtx) !usize {
        var fba = fixedBufferStream(buffer);
        var w = fba.writer().any();
        const len = switch (hs.body) {
            .client_hello => |ch| try ch.pack(buffer[4..]),
            .client_key_exchange => |cke| try cke.pack(buffer[4..]),
            .finished => try Finished.pack(buffer[4..], ctx),
            else => unreachable,
        };
        std.debug.assert(len < std.math.maxInt(u24));

        try w.writeByte(@intFromEnum(hs.msg_type));
        try w.writeInt(u24, @truncate(len), std.builtin.Endian.big);
        try ctx.handshake_record.appendSlice(buffer[0 .. len + 4]);
        return len + 4;
    }

    pub fn unpack(buffer: []const u8, ctx: *ConnCtx) !Handshake {
        const hs_type = try Type.fromByte(buffer[0]);
        const len = std.mem.readInt(u24, buffer[1..4], .big);

        // TODO choose real assert length
        std.debug.assert(len < 1024);
        try ctx.handshake_record.appendSlice(buffer[0 .. len + 4]);
        const hsbuf = buffer[4..][0..len];
        return .{
            .msg_type = hs_type,
            .body = switch (hs_type) {
                .client_hello => .{ .client_hello = try ClientHello.unpack(hsbuf, ctx) },
                .server_hello => .{ .server_hello = try ServerHello.unpack(hsbuf, ctx) },
                .certificate => .{ .certificate = try Certificate.unpack(hsbuf, ctx) },
                .server_key_exchange => .{ .server_key_exchange = try ServerKeyExchange.unpack(hsbuf, ctx) },
                .certificate_request => .{ .certificate_request = try CertificateRequest.unpack(hsbuf, ctx) },
                .server_hello_done => .{ .server_hello_done = try ServerHelloDone.unpack(hsbuf, ctx) },
                else => unreachable,
            },
        };
    }
};
