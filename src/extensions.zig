const Extensions = @This();

pub const Flavor = union(enum) {
    sni: ServerNameIndicator,
};

pub const Extension = struct {
    ctx: *anyopaque,
    pack_fn: *const fn (*anyopaque, []u8) usize,

    pub fn unpack(buffer: []const u8) anyerror!Flavor {
        _ = buffer;
    }

    pub fn pack(ext: Extension, buffer: []u8) usize {
        return ext.pack_fn(ext.ctx, buffer);
    }
};

/// Server Name Indicator
pub const ServerNameIndicator = struct {
    len: usize = 0,
    pub fn pack(_: ServerNameIndicator, buffer: []u8) usize {
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
    len: usize = 4,
    pub fn pack(_: *anyopaque, buffer: []u8) usize {
        @memcpy(buffer[0..4], &[_]u8{ 0, 18, 0, 0 });
        return 4;
    }
};

/// Status Request
pub const StatusRequest = struct {
    len: usize = 9,
    pub fn pack(_: *anyopaque, buffer: []u8) usize {
        @memcpy(buffer[0..9], &[_]u8{ 0, 5, 0, 5, 1, 0, 0, 0, 0 });
        return 9;
    }
};

//pub const SG = struct {
pub const SupportedGroups = struct {
    len: usize = 14,
    pub fn pack(_: *anyopaque, buffer: []u8) usize {
        @memcpy(buffer[0..14], &[_]u8{ 0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19 });
        return 14;
    }

    pub fn extension(sg: *SupportedGroups) Extension {
        return .{
            .ctx = sg,
            .pack_fn = pack,
        };
    }
};

pub const SignatureAlgorithms = struct {
    len: usize = 22,
    pub fn pack(_: *anyopaque, buffer: []u8) usize {
        @memcpy(buffer[0..22], &[_]u8{ 0x00, 0x0d, 0x00, 0x12, 0x00, 0x10, 0x04, 0x01, 0x04, 0x03, 0x05, 0x01, 0x05, 0x03, 0x06, 0x01, 0x06, 0x03, 0x02, 0x01, 0x02, 0x03 });
        return 22;
    }

    pub fn extension(sg: *SignatureAlgorithms) Extension {
        return .{
            .ctx = sg,
            .pack_fn = pack,
        };
    }
};
