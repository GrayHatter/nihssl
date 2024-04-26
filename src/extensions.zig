const Extensions = @This();
const std = @import("std");
const fixedBufferStream = std.io.fixedBufferStream;

pub const Flavor = union(enum) {
    sni: ServerNameIndicator,
};

pub const Extension = struct {
    ctx: *anyopaque,
    pack_fn: *const fn (*anyopaque, []u8) anyerror!usize,

    pub fn unpack(buffer: []const u8) anyerror!Flavor {
        _ = buffer;
    }

    pub fn pack(ext: Extension, buffer: []u8) !usize {
        return ext.pack_fn(ext.ctx, buffer);
    }
};

/// Server Name Indicator
pub const ServerNameIndicator = struct {
    pub fn pack(_: ServerNameIndicator, buffer: []u8) !usize {
        _ = buffer;
        //@memcpy(buffer[0..18], &[_]u8{ 0x00, 0x00, 0x00, 0x18, 0x00, 0x16, 0x00, 0x00, 0x13, 108, 111, 99, 97, 108, 104, 111, 115, 116 });
        return 0;
    }

    pub fn entension(sni: *ServerNameIndicator) Extension {
        return .{
            .ctx = sni,
            .pack_fn = pack,
        };
    }
};

/// Signed certificate timestamp
pub const SCT = struct {
    pub fn pack(_: *anyopaque, buffer: []u8) usize {
        @memcpy(buffer[0..4], &[_]u8{ 0, 18, 0, 0 });
        return 4;
    }
};

/// Status Request
pub const StatusRequest = struct {
    pub fn pack(_: *anyopaque, buffer: []u8) usize {
        @memcpy(buffer[0..9], &[_]u8{ 0, 5, 0, 5, 1, 0, 0, 0, 0 });
        return 9;
    }
};

//pub const SG = struct {
pub const SupportedGroups = struct {
    const EXT_TYPE: u16 = 0x000A;

    pub fn packUntyped(ptr: *anyopaque, buffer: []u8) !usize {
        const sg: *SupportedGroups = @alignCast(@ptrCast(ptr));
        return pack(sg, buffer);
    }

    pub fn pack(_: *SupportedGroups, buffer: []u8) !usize {
        var fba = fixedBufferStream(buffer);
        var w = fba.writer().any();
        try w.writeInt(u16, EXT_TYPE, .big);

        const supported = [_]u16{
            0x001d,
        };

        try w.writeInt(u16, 4, .big);
        try w.writeInt(u16, supported.len * 2, .big);
        for (supported) |each| try w.writeInt(u16, each, .big);

        return 6 + supported.len * 2;
    }

    pub fn extension(sg: *SupportedGroups) Extension {
        return .{
            .ctx = sg,
            .pack_fn = packUntyped,
        };
    }
};

const HashAlgos = enum(u8) {
    none = 0,
    md5 = 1,
    sha1 = 2,
    sha224 = 3,
    sha256 = 4,
    sha384 = 5,
    sha512 = 6,
    //7 Reserved
    //8 Intrinsic
    //9-223 Reserved
    //224-255 Private Use
};

const SignatureAlgos = enum(u8) {
    anon = 0,
    rsa = 1,
    dsa = 2,
    ecdsa = 3,
    // 4-6  Reserved
    ed25519 = 7,
    ed448 = 8,
    //9-63  Reserved
    gostr34102012_256 = 64,
    gostr34102012_512 = 65,
    // 66-223 Reserved
    // 224-255  Private Use
};

pub const SignatureAlgorithms = struct {
    const EXT_TYPE: u16 = 0x000D;
    pub fn packUntyped(ptr: *anyopaque, buffer: []u8) !usize {
        const sa: *SignatureAlgorithms = @alignCast(@ptrCast(ptr));
        return pack(sa, buffer);
    }

    pub fn pack(_: *SignatureAlgorithms, buffer: []u8) !usize {
        var fba = fixedBufferStream(buffer);
        var w = fba.writer().any();
        try w.writeInt(u16, EXT_TYPE, .big);

        //HashAlgorithm; enum { none(0), md5(1), sha1(2), sha224(3), sha256(4), sha384(5), sha512(6), }
        //SignatureAlgorithm; enum { anonymous(0), rsa(1), dsa(2), ecdsa(3), }

        const supported = [_]u16{
            0x0401,
            0x0403,
            //0x0007,
        };

        try w.writeInt(u16, supported.len * 2 + 2, .big);
        try w.writeInt(u16, supported.len * 2, .big);
        for (supported) |each| try w.writeInt(u16, each, .big);

        return 6 + supported.len * 2;
    }

    pub fn extension(sg: *SignatureAlgorithms) Extension {
        return .{
            .ctx = sg,
            .pack_fn = packUntyped,
        };
    }
};
