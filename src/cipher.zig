const std = @import("std");

const print = std.debug.print;
const fixedBufferStream = std.io.fixedBufferStream;

pub const Cipher = @This();

suite: union(enum) {
    invalid: void,
    ecc: EllipticCurve,
} = .{ .invalid = {} },

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
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = 0xCCA9,
    TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256 = 0xCCAC,
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xCCA8,
    TLS_PSK_WITH_CHACHA20_POLY1305_SHA256 = 0xCCAB,
    TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256 = 0xCCAE,

    pub fn fromInt(s: u16) Suites {
        return switch (s) {
            0xCCA9 => .TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            0xCCAC => .TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256,
            0xCCA8 => .TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            0xCCAB => .TLS_PSK_WITH_CHACHA20_POLY1305_SHA256,
            0xCCAE => .TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256,
            else => unreachable,
        };
    }
};

pub const EllipticCurve = struct {
    curve: Curves = .{ .invalid = {} },

    clt_key_mat: ?std.crypto.dh.X25519.KeyPair = null,
    srv_key_mat: ?std.crypto.dh.X25519.KeyPair = null,

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

    pub fn init() EllipticCurve {
        return .{};
    }

    fn packNamedCurve(_: EllipticCurve, buffer: []u8) !usize {
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
            .named_curve => try ecc.packNamedCurve(buffer),
            else => unreachable,
        };
    }

    pub fn unpackKeyExchange(buffer: []const u8) !EllipticCurve {
        var fba = fixedBufferStream(buffer);
        const r = fba.reader().any();

        const curve_type = try CurveType.fromByte(try r.readByte());
        //print("named curve {} {}\n", .{ try r.readByte(), try r.readByte() });
        //print("full buffer {any}\n", .{buffer[0..4]});
        //print("full buffer {any}\n", .{buffer[4..][0..32]});
        //print("full buffer {any}\n", .{buffer[36..]});
        return .{
            .curve = switch (curve_type) {
                .named_curve => .{ .named_curve = .{} },
                else => return error.UnsupportedCurve,
            },
        };
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
