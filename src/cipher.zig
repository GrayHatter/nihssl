const std = @import("std");
const ConnCtx = @import("context.zig");

pub const X25519 = std.crypto.dh.X25519;

const print = std.debug.print;
const fixedBufferStream = std.io.fixedBufferStream;

//const cipherT = std.crypto.tls.ApplicationCipherT;
const hscipherT = std.crypto.tls.HandshakeCipherT;
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
const chacha_t = hscipherT(ChaCha20Poly1305, std.crypto.hash.sha2.Sha256);
const hkdfExpandLabel = std.crypto.tls.hkdfExpandLabel;

const ChaCha20 = ChaCha20Poly1305;
const Sha256 = std.crypto.auth.hmac.sha2.HmacSha256;

pub const Cipher = @This();

suite: union(enum) {
    invalid: void,
    ecc: EllipticCurve,
} = .{ .invalid = {} },
sequence: u72 = 0, // this is chacha20 specific :/

pub fn Material(comptime enc: anytype, comptime hmac: anytype) type {
    return struct {
        premaster: [X25519.shared_length]u8 = [_]u8{0} ** X25519.shared_length,
        master: [48]u8 = undefined,
        cli_mac: [hmac.mac_length]u8,
        srv_mac: [hmac.mac_length]u8,
        cli_key: [enc.key_length]u8,
        srv_key: [enc.key_length]u8,
        cli_iv: [enc.nonce_length]u8,
        srv_iv: [enc.nonce_length]u8,
    };
}

pub const UnsupportedSuites = enum(u16) {
    TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA = 0x0013,
    TLS_DHE_DSS_WITH_AES_128_CBC_SHA = 0x0032,
    TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 = 0x0040,
    TLS_DHE_DSS_WITH_AES_256_CBC_SHA = 0x0038,
    TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 = 0x006A,
    TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256 = 0xCCAD,
    TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA = 0x0016,
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA = 0x0033,
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 = 0x0067,
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA = 0x0039,
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 = 0x006B,
    TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xCCAA,
    TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA = 0x000D,
    TLS_DH_DSS_WITH_AES_128_CBC_SHA = 0x0030,
    TLS_DH_DSS_WITH_AES_128_CBC_SHA256 = 0x003E,
    TLS_DH_DSS_WITH_AES_256_CBC_SHA = 0x0036,
    TLS_DH_DSS_WITH_AES_256_CBC_SHA256 = 0x0068,
    TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA = 0x0010,
    TLS_DH_RSA_WITH_AES_128_CBC_SHA = 0x0031,
    TLS_DH_RSA_WITH_AES_128_CBC_SHA256 = 0x003F,
    TLS_DH_RSA_WITH_AES_256_CBC_SHA = 0x0037,
    TLS_DH_RSA_WITH_AES_256_CBC_SHA256 = 0x0069,
    TLS_DH_anon_WITH_3DES_EDE_CBC_SHA = 0x001B,
    TLS_DH_anon_WITH_AES_128_CBC_SHA = 0x0034,
    TLS_DH_anon_WITH_AES_128_CBC_SHA256 = 0x006C,
    TLS_DH_anon_WITH_AES_256_CBC_SHA = 0x003A,
    TLS_DH_anon_WITH_AES_256_CBC_SHA256 = 0x006D,
    TLS_DH_anon_WITH_RC4_128_MD5 = 0x0018,
    // Planned to implement
    TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256 = 0xCCAC,
    TLS_PSK_WITH_CHACHA20_POLY1305_SHA256 = 0xCCAB,
    TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256 = 0xCCAE,
};

pub const Suites = enum(u16) {
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = 0xCCA9,
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xCCA8,

    pub fn fromInt(s: u16) Suites {
        return switch (s) {
            0xCCA9 => .TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            0xCCA8 => .TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            //0xCCAC => .TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256,
            //0xCCAB => .TLS_PSK_WITH_CHACHA20_POLY1305_SHA256,
            //0xCCAE => .TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256,
            else => unreachable,
        };
    }
};

pub const EllipticCurve = struct {
    curve: Curves = .{ .invalid = {} },

    srv_dh: ?X25519.KeyPair = undefined,
    cli_dh: ?X25519.KeyPair = null,

    material: Material(ChaCha20, Sha256) = undefined,

    pub const Curves = union(CurveType) {
        invalid: void,
        explicit_prime: ExplicitPrime,
        explicit_char2: ExplicitChar2,
        named_curve: NamedCurve,
    };

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

    /// srv is copied, and will not zero any arguments
    pub fn init(srv: [X25519.public_length]u8) !EllipticCurve {
        return .{
            .srv_material = try X25519.KeyPair.create(srv),
        };
    }

    fn packNamed(_: EllipticCurve, buffer: []u8) !usize {
        var fba = fixedBufferStream(buffer);
        const w = fba.writer().any();

        //try w.writeByte(@intFromEnum(ecc.curve));
        //// TODO Plz doing the fix here
        //try w.writeByte(204);
        //try w.writeByte(169);

        var empty: [32]u8 = std.mem.zeroes([32]u8);

        @memcpy(&empty, "thisisagoodblob!" ** 2);
        @memcpy(&empty, "thisisagoodblob!" ** 2);
        var chacha = std.Random.ChaCha.init(empty);
        var charand = chacha.random();
        charand.bytes(&empty);

        const key_material = try std.crypto.dh.X25519.KeyPair.create(empty);

        //try w.writeByte(@intFromEnum(cke.pve));
        //try w.writeInt(u16, @truncate(key_material.public_key.len), std.builtin.Endian.big);
        try w.writeInt(u8, @truncate(key_material.public_key.len), std.builtin.Endian.big);
        try w.writeAll(&key_material.public_key);
        return 1 + key_material.public_key.len;
    }

    pub fn packKeyExchange(ecc: EllipticCurve, buffer: []u8) !usize {
        return switch (ecc.curve) {
            .named_curve => try ecc.packNamed(buffer),
            // LOL sorry future me!
            else => return try ecc.packNamed(buffer),
        };
    }

    fn buildKeyMaterial(ctx: *ConnCtx) !Material(ChaCha20, Sha256) {
        var material: Material(ChaCha20, Sha256) = ctx.cipher.suite.ecc.material;

        const our_seckey = ctx.cipher.suite.ecc.cli_dh.?.secret_key;
        const peer_key = &ctx.cipher.suite.ecc.srv_dh.?.public_key;
        material.premaster = try X25519.scalarmult(our_seckey, peer_key.*);

        const seed = "master secret" ++ ctx.our_random ++ ctx.peer_random.?;
        //var left = std.crypto.auth.hmac.sha2.HmacSha256.init(ctx.cipher.suite.ecc.premaster);

        var pre_left: [32]u8 = undefined;
        var pre_right: [32]u8 = undefined;
        Sha256.create(&pre_left, seed, &material.premaster);
        Sha256.create(&pre_right, &pre_left, &material.premaster);
        var left: [32]u8 = undefined;
        var right: [32]u8 = undefined;
        Sha256.create(&left, pre_left ++ seed, &material.premaster);
        Sha256.create(&right, pre_right ++ seed, &material.premaster);

        material.master = left ++ right[0..16].*;

        {
            const key_seed = "key expansion" ++ ctx.peer_random.? ++ ctx.our_random;
            var first: [32]u8 = undefined;
            Sha256.create(&first, key_seed, &material.master);
            var second: [32]u8 = undefined;
            Sha256.create(&second, &first, &material.master);
            var third: [32]u8 = undefined;
            Sha256.create(&third, &second, &material.master);
            var forth: [32]u8 = undefined;
            Sha256.create(&forth, &third, &material.master);
            var fifth: [32]u8 = undefined;
            Sha256.create(&fifth, &forth, &material.master);

            var p_first: [32]u8 = undefined;
            Sha256.create(&p_first, first ++ key_seed, &material.master);
            var p_second: [32]u8 = undefined;
            Sha256.create(&p_second, second ++ key_seed, &material.master);
            var p_third: [32]u8 = undefined;
            Sha256.create(&p_third, third ++ key_seed, &material.master);
            var p_forth: [32]u8 = undefined;
            Sha256.create(&p_forth, forth ++ key_seed, &material.master);
            var p_fifth: [32]u8 = undefined;
            Sha256.create(&p_fifth, fifth ++ key_seed, &material.master);
            const final = p_first ++ p_second ++ p_third ++ p_forth ++ p_fifth;

            material.cli_mac = final[0..][0..32].*;
            material.cli_mac = final[32..][0..32].*;
            material.cli_key = final[64..][0..32].*;
            material.srv_key = final[96..][0..32].*;
            material.srv_iv = final[128..][0..12].*;
            material.srv_iv = final[140..][0..12].*;
        }
        return material;
    }

    fn unpackNamed(buffer: []const u8, ctx: *ConnCtx) !void {
        var fba = fixedBufferStream(buffer);
        const r = fba.reader().any();
        const name = try r.readInt(u16, .big);
        if (name != 0x001d) return error.UnknownCurveName;
        ctx.cipher.suite.ecc.srv_dh = undefined;
        const peer_key = &ctx.cipher.suite.ecc.srv_dh.?.public_key;
        try r.readNoEof(peer_key);

        // TODO verify signature

        ctx.cipher.suite.ecc.material = try buildKeyMaterial(ctx);
    }

    pub fn unpackKeyExchange(buffer: []const u8, ctx: *ConnCtx) !void {
        if (ctx.cipher.suite != .ecc) unreachable;
        var fba = fixedBufferStream(buffer);
        const r = fba.reader().any();

        const curve_type = try CurveType.fromByte(try r.readByte());
        switch (curve_type) {
            .named_curve => try unpackNamed(buffer[1..], ctx),
            else => return error.UnsupportedCurve,
        }
    }
};

pub const Type = enum {
    stream,
    block,
    aead,
};

const GenericStreamCipher = struct {};
const GenericBlockCipher = struct {};
const GenericAEADCipher = struct {};

const ClientECDH = struct {
    _key_material: [255]u8 = [_]u8{8} ** 255,
    // 1..255
    point: []u8 = &[0]u8{},
};
