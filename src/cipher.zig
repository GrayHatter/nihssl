const std = @import("std");
const ConnCtx = @import("context.zig");
const Version = @import("protocol.zig");

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
    aes: AnyAES,
} = .{ .invalid = {} },
sequence: u72 = 0, // u72 is chacha20 specific :/

pub fn Material(comptime enc: anytype, comptime hmac: anytype) type {
    return struct {
        pub const Self = @This();

        //cli_random: [32]u8 = undefined,
        //srv_random: [32]u8 = undefined,

        srv_pub_key: [32]u8 = undefined,

        premaster: [X25519.shared_length]u8 = [_]u8{0} ** X25519.shared_length,
        master: [48]u8 = undefined,
        cli_mac: [hmac.mac_length]u8,
        srv_mac: [hmac.mac_length]u8,
        cli_key: [enc.key_length]u8,
        srv_key: [enc.key_length]u8,
        cli_iv: [enc.nonce_length]u8,
        srv_iv: [enc.nonce_length]u8,

        pub fn build(self: *Self, key_material: []const u8) void {
            var index: usize = 0;
            self.cli_mac = key_material[index..][0..hmac.mac_length].*;
            index += hmac.mac_length;
            self.srv_mac = key_material[index..][0..hmac.mac_length].*;
            index += hmac.mac_length;
            self.cli_key = key_material[index..][0..enc.key_length].*;
            index += enc.key_length;
            self.srv_key = key_material[index..][0..enc.key_length].*;
            index += enc.key_length;
            self.cli_iv = key_material[index..][0..enc.nonce_length].*;
            index += enc.nonce_length;
            self.srv_iv = key_material[index..][0..enc.nonce_length].*;
        }
    };
}

pub const Suites = enum(u16) {
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

    TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256 = 0xCCAC,
    TLS_PSK_WITH_CHACHA20_POLY1305_SHA256 = 0xCCAB,
    TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256 = 0xCCAE,

    /// TODO
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 = 0xC014,

    ///Current Supported
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = 0xCCA9,
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xCCA8,

    pub fn fromInt(s: u16) Suites {
        return switch (s) {
            0xCCA9 => .TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            0xCCA8 => .TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            //0xCCAC => .TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256,
            //0xCCAB => .TLS_PSK_WITH_CHACHA20_POLY1305_SHA256,
            //0xCCAE => .TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256,
            else => |t| @enumFromInt(t),
        };
    }

    pub fn unsupported(s: u16) Suites {
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

pub const AnyAES = struct {
    material: Material(AES(CBC), Sha256),

    block: union(enum) {
        cbc: CBC,
    },

    cli_dh: ?X25519.KeyPair = null,
    srv_dh: ?X25519.KeyPair = null,

    /// srv is copied, and will not zero any arguments
    pub fn init(srv: [X25519.public_length]u8) !EllipticCurve {
        return .{
            .srv_material = try X25519.KeyPair.create(srv),
        };
    }

    fn packEncryptedPremasterSecret(aes: AnyAES, buffer: []u8) !usize {
        var l_buffer: [1024]u8 = undefined;
        var fba = fixedBufferStream(l_buffer[0..]);
        const w = fba.writer().any();

        try w.writeByte(Version.Current.major);
        try w.writeByte(Version.Current.minor);

        const random: [46]u8 = [_]u8{0} ** 46;
        try w.writeAll(&random);
        switch (aes.block) {
            .cbc => try CBC.decrypt(aes.material.cli_key, l_buffer[0..48], buffer),
        }
        return 48;
    }

    fn packClientECDHE(aes: AnyAES, buffer: []u8) !usize {
        var fba = fixedBufferStream(buffer);
        const w = fba.writer().any();

        try w.writeByte(@truncate(aes.cli_dh.?.public_key.len));
        try w.writeAll(&aes.cli_dh.?.public_key);
        return 1 + aes.cli_dh.?.public_key.len;
    }

    fn packClientDHE(aes: AnyAES, buffer: []u8) !usize {
        var fba = fixedBufferStream(buffer);
        const w = fba.writer().any();
        try w.writeByte(1); // PublicValueEncoding.explicit
        _ = aes;
        // struct {
        //     select (PublicValueEncoding) {
        //         case implicit: struct { };
        //         case explicit: opaque dh_Yc<1..2^16-1>;
        //     } dh_public;
        // } ClientDiffieHellmanPublic;

        // dh_Yc
        //    The client's Diffie-Hellman public value (Yc).
        return 0;
    }

    /// TODO move this into the CBC struct
    fn packCBC(aes: AnyAES, buffer: []u8) !usize {
        //var fba = fixedBufferStream(buffer);
        //const w = fba.writer().any();
        return try aes.packClientECDHE(buffer);
        //return try aes.packEncryptedPremasterSecret(buffer);
        //w.writeAll(encrypted_premaster_secret);
    }

    pub fn packKeyExchange(aes: AnyAES, buffer: []u8) !usize {
        return switch (aes.block) {
            .cbc => aes.packCBC(buffer),
            // LOL sorry future me!
            //else => return error.NotImplemented,
        };
    }

    fn buildKeyMaterial(ctx: *ConnCtx) !Material(AES(CBC), Sha256) {
        var aes = &ctx.cipher.suite.aes;

        //const our_seckey = ctx.cipher.suite.aes.material.cli_dh.?.secret_key;
        //const peer_key = &ctx.cipher.suite.ecc.srv_dh.?.public_key;
        //material.premaster = try X25519.scalarmult(our_seckey, peer_key.*);

        const seed = "master secret" ++ ctx.cli_random.? ++ ctx.srv_random.?;
        //var left = std.crypto.auth.hmac.sha2.HmacSha256.init(ctx.cipher.suite.ecc.premaster);

        var pre_left: [32]u8 = undefined;
        var pre_right: [32]u8 = undefined;
        Sha256.create(&pre_left, seed, &aes.material.premaster);
        Sha256.create(&pre_right, &pre_left, &aes.material.premaster);
        var left: [32]u8 = undefined;
        var right: [32]u8 = undefined;
        Sha256.create(&left, pre_left ++ seed, &aes.material.premaster);
        Sha256.create(&right, pre_right ++ seed, &aes.material.premaster);

        aes.material.master = (left ++ right[0..16].*);

        {
            const key_seed = "key expansion" ++ ctx.cli_random.? ++ ctx.srv_random.?;
            var first: [32]u8 = undefined;
            Sha256.create(&first, key_seed, &aes.material.master);
            var second: [32]u8 = undefined;
            Sha256.create(&second, &first, &aes.material.master);
            var third: [32]u8 = undefined;
            Sha256.create(&third, &second, &aes.material.master);
            var forth: [32]u8 = undefined;
            Sha256.create(&forth, &third, &aes.material.master);
            var fifth: [32]u8 = undefined;
            Sha256.create(&fifth, &forth, &aes.material.master);

            var p_first: [32]u8 = undefined;
            Sha256.create(&p_first, first ++ key_seed, &aes.material.master);
            var p_second: [32]u8 = undefined;
            Sha256.create(&p_second, second ++ key_seed, &aes.material.master);
            var p_third: [32]u8 = undefined;
            Sha256.create(&p_third, third ++ key_seed, &aes.material.master);
            var p_forth: [32]u8 = undefined;
            Sha256.create(&p_forth, forth ++ key_seed, &aes.material.master);
            var p_fifth: [32]u8 = undefined;
            Sha256.create(&p_fifth, fifth ++ key_seed, &aes.material.master);
            const final = p_first ++ p_second ++ p_third ++ p_forth ++ p_fifth;

            aes.material.build(&final);
        }
        return aes.material;
    }

    fn unpackCBC(buffer: []const u8, ctx: *ConnCtx) !void {
        var fba = fixedBufferStream(buffer);
        const r = fba.reader().any();
        //const name = try r.readInt(u16, .big);
        //ctx.cipher.suite.aes.srv_dh = undefined;
        const peer_key = &ctx.cipher.suite.aes.material.srv_pub_key;
        try r.readNoEof(peer_key);

        // TODO verify signature
        ctx.cipher.suite.aes.material = try buildKeyMaterial(ctx);
    }

    fn unpackNamed(buffer: []const u8, ctx: *ConnCtx) !void {
        var fba = fixedBufferStream(buffer);
        const r = fba.reader().any();
        const name = try r.readInt(u16, .big);
        if (name != 0x001d) return error.UnknownCurveName;
        ctx.cipher.suite.aes.srv_dh = undefined;
        const peer_key = &ctx.cipher.suite.aes.srv_dh.?.public_key;
        try r.readNoEof(peer_key);

        // TODO verify signature

        ctx.cipher.suite.aes.material = try buildKeyMaterial(ctx);
    }

    pub fn unpackKeyExchange(buffer: []const u8, ctx: *ConnCtx) !void {
        if (ctx.cipher.suite != .aes) unreachable;
        var fba = fixedBufferStream(buffer);
        const r = fba.reader().any();

        const curve_type = try CurveType.fromByte(try r.readByte());
        switch (curve_type) {
            .named_curve => try unpackNamed(buffer[1..], ctx),
            else => return error.UnsupportedCurve,
        }
        return unpackCBC(buffer, ctx);
    }
};

pub const CBC = struct {
    pub const key_length = 32;
    pub const nonce_length = 16;

    pub fn decrypt(key: [32]u8, cipher: []const u8, clear: []u8) !void {
        if (cipher.len % 16 != 0) return error.InvalidCipherLength;
        if (clear.len < cipher.len) return error.InvalidClearLength;
        var ctx = std.crypto.core.aes.Aes256.initDec(key);
        const blocks = cipher.len / 16;
        var i: usize = 0;
        while (i < blocks) : (i += 1) {
            ctx.decrypt(
                clear[i * 16 ..][0..16],
                cipher[i * 16 ..][0..16],
            );
        }
    }

    pub fn encrypt(key: []const u8, cipher: []const u8, clear: []u8) !void {
        _ = key;
        _ = clear;
        _ = cipher;
        comptime unreachable;
    }
};

//pub const AESType = enum {
//    AES_128_CBC_SHA,
//};

pub fn AES(comptime T: type) type {
    return struct {
        pub const Kind = T;
        pub const key_length = T.key_length;
        pub const nonce_length = T.nonce_length;
    };
}
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

pub const EllipticCurve = struct {
    curve: Curves = .{ .invalid = {} },

    cli_dh: ?X25519.KeyPair = null,
    srv_dh: ?X25519.KeyPair = null,

    material: Material(ChaCha20, Sha256) = undefined,

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

        const seed = "master secret" ++ ctx.cli_random.? ++ ctx.srv_random.?;
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
            const key_seed = "key expansion" ++ ctx.cli_random.? ++ ctx.srv_random.?;
            var first: [32]u8 = undefined;
            Sha256.create(&first, key_seed, &material.master);
            var second: [32]u8 = undefined;
            Sha256.create(&second, &first, &material.master);
            var third: [32]u8 = undefined;
            Sha256.create(&third, &second, &material.master);
            //var forth: [32]u8 = undefined;
            //Sha256.create(&forth, &third, &material.master);
            //var fifth: [32]u8 = undefined;
            //Sha256.create(&fifth, &forth, &material.master);

            var p_first: [32]u8 = undefined;
            Sha256.create(&p_first, first ++ key_seed, &material.master);
            var p_second: [32]u8 = undefined;
            Sha256.create(&p_second, second ++ key_seed, &material.master);
            var p_third: [32]u8 = undefined;
            Sha256.create(&p_third, third ++ key_seed, &material.master);
            //var p_forth: [32]u8 = undefined;
            //Sha256.create(&p_forth, forth ++ key_seed, &material.master);
            //var p_fifth: [32]u8 = undefined;
            //Sha256.create(&p_fifth, fifth ++ key_seed, &material.master);
            //const final = p_first ++ p_second ++ p_third ++ p_forth ++ p_fifth;
            const final = p_first ++ p_second ++ p_third;

            //material.cli_mac = final[0..][0..32].*;
            //material.cli_mac = final[32..][0..32].*;
            material.cli_key = final[0..][0..32].*;
            material.srv_key = final[32..][0..32].*;
            material.cli_iv = final[64..][0..12].*;
            material.srv_iv = final[72..][0..12].*;
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
