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
const Sha1 = std.crypto.auth.hmac.HmacSha1;
const Sha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const Sha384 = std.crypto.auth.hmac.sha2.HmacSha384;

pub const Cipher = @This();

suite: union(enum) {
    invalid: void,
    ecc: EllipticCurve,
    aes: AnyAES,
} = .{ .invalid = {} },
key_xhg: KeyExchange = .{},
sequence: u72 = 0, // u72 is chacha20 specific :/

pub fn encrypt(c: *Cipher, clear_text: []const u8, cipher_text: []u8) !usize {
    var l_clear: [0x1000]u8 = undefined;
    @memcpy(l_clear[0..clear_text.len], clear_text);
    switch (c.suite) {
        .ecc => {
            const empty: [0]u8 = undefined;
            const encrypted_body = cipher_text;
            std.crypto.aead.chacha_poly.ChaCha20Poly1305.encrypt(
                encrypted_body,
                encrypted_body[0..16],
                clear_text,
                &empty,
                c.suite.ecc.material.cli_iv,
                c.suite.ecc.material.cli_key,
            );
            return error.NotImplemented;
        },
        .aes => |aes| {
            var len: usize = clear_text.len;
            {
                var mac_buf: [0x1000]u8 = undefined;
                var mac_fba = fixedBufferStream(&mac_buf);
                var mac_w = mac_fba.writer().any();
                try mac_w.writeInt(u64, @truncate(c.sequence), .big);
                try mac_w.writeAll(&[_]u8{ 22, 3, 3 });
                try mac_w.writeInt(u16, @truncate(len), .big);
                try mac_w.writeAll(clear_text);
                const mac_len = try mac_fba.getPos();

                const mac_out: *[48]u8 = l_clear[len..][0..48];
                const mac_text = mac_buf[0..mac_len];
                std.crypto.auth.hmac.sha2.HmacSha384.create(mac_out, mac_text, &aes.material.cli_mac);
                len += 48;
            }

            var aes_ctx = std.crypto.core.aes.Aes256.initEnc(aes.material.cli_key);
            const add = 16 - (len % 16);
            if (add != 0) {
                @memset(l_clear[len..][0..add], @truncate(add - 1));
            }
            len += add;
            if (cipher_text.len < len + aes.material.cli_iv.len)
                return error.NoSpaceLeft;
            var fba = fixedBufferStream(cipher_text);
            var w = fba.writer().any();
            try w.writeAll(aes.material.cli_iv[0..]);

            var xord: [16]u8 = aes.material.cli_iv;
            for (0..len / 16) |i| {
                var clear: [16]u8 = l_clear[i * 16 ..][0..16].*;
                var cipher: [16]u8 = undefined;
                var xclear: [16]u8 = undefined;
                for (xclear[0..], clear[0..], xord[0..]) |*xc, cl, xr| xc.* = cl ^ xr;
                aes_ctx.encrypt(cipher[0..], xclear[0..]);
                @memcpy(xord[0..16], cipher[0..16]);
                try w.writeAll(cipher[0..]);
            }
            return try fba.getPos();
        },
        else => return error.SuiteNotImplmented,
    }
    comptime unreachable;
}

pub fn decrypt(c: *Cipher, cipher_text: []const u8, clear: []u8) ![]const u8 {
    _ = cipher_text;
    switch (c.suite) {
        .ecc => |ecc| {
            _ = ecc;
        },
        .aes => |aes| {
            _ = aes;
        },
        else => unreachable,
    }
    return clear;
}

pub const KeyExchange = struct {};

pub fn Material(comptime ENC: anytype, comptime HMAC: anytype) type {
    return struct {
        pub const Self = @This();

        pub const MacLength = HMAC.mac_length;
        pub const KeyLength = ENC.key_length;
        pub const NonceLength = ENC.nonce_length;
        pub const BuildLength = 2 * (MacLength + KeyLength + NonceLength);

        pub const PRF = Sha384;

        srv_pub_key: [32]u8 = undefined,

        premaster: [X25519.shared_length]u8 = [_]u8{0} ** X25519.shared_length,
        master: [48]u8 = undefined,
        cli_mac: [MacLength]u8,
        srv_mac: [MacLength]u8,
        cli_key: [KeyLength]u8,
        srv_key: [KeyLength]u8,
        cli_iv: [NonceLength]u8,
        srv_iv: [NonceLength]u8,

        pub fn build(self: *Self, key_material: [BuildLength]u8) void {
            var keym: []const u8 = key_material[0..];
            self.cli_mac = keym[0..MacLength].*;
            keym = keym[MacLength..];
            self.srv_mac = keym[0..MacLength].*;
            keym = keym[MacLength..];
            self.cli_key = keym[0..KeyLength].*;
            keym = keym[KeyLength..];
            self.srv_key = keym[0..KeyLength].*;
            keym = keym[KeyLength..];
            self.cli_iv = keym[0..NonceLength].*;
            keym = keym[NonceLength..];
            self.srv_iv = keym[0..NonceLength].*;
        }

        pub fn keyExpansion(self: *Self, seed: [77]u8) void {
            var a1: [MacLength]u8 = undefined;
            var a2: [MacLength]u8 = undefined;
            var a3: [MacLength]u8 = undefined;
            var a4: [MacLength]u8 = undefined;
            var a5: [MacLength]u8 = undefined;
            PRF.create(&a1, &seed, &self.master);
            PRF.create(&a2, &a1, &self.master);
            PRF.create(&a3, &a2, &self.master);
            PRF.create(&a4, &a3, &self.master);
            PRF.create(&a5, &a4, &self.master);

            var p1: [MacLength]u8 = undefined;
            var p2: [MacLength]u8 = undefined;
            var p3: [MacLength]u8 = undefined;
            var p4: [MacLength]u8 = undefined;
            var p5: [MacLength]u8 = undefined;

            PRF.create(&p1, &a1 ++ seed, &self.master);
            PRF.create(&p2, &a2 ++ seed, &self.master);
            PRF.create(&p3, &a3 ++ seed, &self.master);
            PRF.create(&p4, &a4 ++ seed, &self.master);
            PRF.create(&p5, &a5 ++ seed, &self.master);

            const final: [BuildLength]u8 = (p1 ++ p2 ++ p3 ++ p4 ++ p5)[0..BuildLength].*;

            self.build(final);
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
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = 0xC014,
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 = 0xC028,

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

    pub fn toType(s: Suites) type {
        return switch (s) {
            .TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 => Material(AES(256, CBC), Sha384),
            .TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA => Material(AES(256, CBC), Sha1),
            .TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 => Material(ECC, Sha256),
            .TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => Material(ECC, Sha256),
            else => comptime unreachable,
        };
    }
};

pub const AnyAES = struct {
    material: Material(AES(256, CBC), Sha384),

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

    fn buildKeyMaterial(ctx: *ConnCtx) !Material(AES(256, CBC), Sha384) {
        var aes = &ctx.cipher.suite.aes;

        const our_seckey = ctx.cipher.suite.aes.cli_dh.?.secret_key;
        const peer_key = &ctx.cipher.suite.aes.srv_dh.?.public_key;
        const premaster = try X25519.scalarmult(our_seckey, peer_key.*);

        const seed = "master secret" ++ ctx.cli_random.? ++ ctx.srv_random.?;

        const PRF = Sha384;
        var a1: [48]u8 = undefined;
        PRF.create(&a1, seed, &premaster);
        var p1: [48]u8 = undefined;
        PRF.create(&p1, a1 ++ seed, &premaster);

        aes.material.master = p1;

        const key_seed = "key expansion" ++ ctx.srv_random.? ++ ctx.cli_random.?;
        aes.material.keyExpansion(key_seed.*);
        return aes.material;
    }

    fn unpackCBC(_: []const u8, _: *ConnCtx) !void {
        //var fba = fixedBufferStream(buffer);
        //const r = fba.reader().any();
        ////const name = try r.readInt(u16, .big);
        ////ctx.cipher.suite.aes.srv_dh = undefined;
        //const peer_key = &ctx.cipher.suite.aes.material.srv_pub_key;
        //try r.readNoEof(peer_key);

        //// TODO verify signature
        //ctx.cipher.suite.aes.material = try buildKeyMaterial(ctx);
    }

    fn unpackNamed(buffer: []const u8, ctx: *ConnCtx) !void {
        var fba = fixedBufferStream(buffer);
        const r = fba.reader().any();
        const name = try r.readInt(u16, .big);
        if (name != 0x001d) return error.UnknownCurveName;
        const key_len = try r.readByte();
        std.debug.assert(key_len == 32);
        ctx.cipher.suite.aes.srv_dh = undefined;
        try r.readNoEof(&ctx.cipher.suite.aes.srv_dh.?.public_key);

        // TODO verify signature
        ctx.cipher.suite.aes.cli_dh = try Cipher.X25519.KeyPair.create(null);
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
        //return unpackCBC(buffer, ctx);
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

pub fn AES(comptime S: u16, comptime M: type) type {
    return struct {
        pub const BIT_SIZE = S;
        pub const MODE = M;
        pub const key_length = M.key_length;
        pub const nonce_length = M.nonce_length;
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

pub const ECC = struct {
    pub const BIT_SIZE = 265;
    pub const MODE = ChaCha20;
    pub const key_length = ChaCha20.key_length;
    pub const nonce_length = ChaCha20.nonce_length;
};

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
        const key_len = try r.readByte();
        std.debug.assert(key_len == 32);
        ctx.cipher.suite.ecc.srv_dh = undefined;
        const peer_key = &ctx.cipher.suite.ecc.srv_dh.?.public_key;
        try r.readNoEof(peer_key);

        // TODO verify signature

        ctx.cipher.suite.ecc.cli_dh = try Cipher.X25519.KeyPair.create(null);
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

const ClientECDH = struct {
    _key_material: [255]u8 = [_]u8{8} ** 255,
    // 1..255
    point: []u8 = &[0]u8{},
};
