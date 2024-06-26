const std = @import("std");
const net = std.net;
const testing = std.testing;
const print = std.debug.print;
const fixedBufferStream = std.io.fixedBufferStream;
const asBytes = std.mem.asBytes;

const TESTING_IP = "127.0.0.1";
const TESTING_PORT = 4433;

pub const Alert = @import("alert.zig");
pub const Protocol = @import("protocol.zig");
pub const ConnCtx = @import("context.zig");
pub const Handshake = @import("handshake.zig");
pub const Cipher = @import("cipher.zig");

const PRINT_DEBUG = true;

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

pub const TLSRecord = struct {
    version: Protocol.Version = Protocol.TLSv1_2,
    /// Length is the Header + Fragment.len
    length: u16 = 0,
    kind: union(ContentType) {
        change_cipher_spec: void, // This is const packet
        alert: Alert,
        handshake: Handshake.Handshake,
        application_data: []const u8,
    } = undefined,

    pub fn packFragment(record: TLSRecord, buffer: []u8, ctx: *ConnCtx) !usize {
        return switch (record.kind) {
            .handshake => |ch| try ch.pack(buffer, ctx),
            .change_cipher_spec => ChangeCipherSpec.pack(buffer),
            else => unreachable,
        };
    }

    fn packHeader(record: TLSRecord, buffer: []u8, len: usize) !usize {
        var fba = fixedBufferStream(buffer);
        var w = fba.writer().any();
        try w.writeByte(@intFromEnum(record.kind));
        try w.writeByte(record.version.major);
        try w.writeByte(record.version.minor);
        try w.writeInt(u16, @truncate(len), std.builtin.Endian.big);
        return len + 5;
    }

    pub fn pack(record: TLSRecord, buffer: []u8, ctx: *ConnCtx) !usize {
        const len = try record.packFragment(buffer[5..], ctx);
        return record.packHeader(buffer, len);
    }

    pub fn encrypt(record: TLSRecord, buffer: []u8, ctx: *ConnCtx) !usize {
        var clear: [0x1000]u8 = undefined;
        const len = try record.packFragment(&clear, ctx);

        const enc_len = try ctx.cipher.encrypt(clear[0..len], buffer[5..]);
        return try record.packHeader(buffer, enc_len);
    }

    pub fn decryptFragment(cipher: []const u8, clear: []u8, ctx: *ConnCtx) ![]const u8 {
        if (true) unreachable;
        return try ctx.cipher.decrypt(cipher, clear);
    }

    pub fn unpackFragment(buffer: []const u8, ctx: *ConnCtx) !TLSRecord {
        var fba = fixedBufferStream(buffer);
        var r = fba.reader().any();

        const fragtype = try ContentType.fromByte(try r.readByte());
        const version = Protocol.Version{
            .major = try r.readByte(),
            .minor = try r.readByte(),
        };
        const length = try r.readInt(u16, std.builtin.Endian.big);

        var decrypted: [0x1000]u8 = undefined;
        if (length > buffer[5..].len) return error.IncompleteFragment;
        const fragbuf: []const u8 = if (ctx.session_encrypted)
            try decryptFragment(buffer[5..][0..length], decrypted[0..length], ctx)
        else
            buffer[5..][0..length];

        return .{
            .version = version,
            .length = length + 5, // Record header size
            .kind = switch (fragtype) {
                .change_cipher_spec => .{
                    .change_cipher_spec = if (fragbuf[0] != 1) return error.InvalidCCSPacket else {},
                },
                .alert => .{ .alert = try Alert.unpack(fragbuf) },
                .handshake => .{
                    .handshake = try Handshake.Handshake.unpack(fragbuf, ctx),
                },
                .application_data => .{ .application_data = unreachable },
            },
        };
    }

    pub fn unpack(buffer: []const u8, ctx: *ConnCtx) !TLSRecord {
        return try unpackFragment(buffer, ctx);
    }
};

pub const Random = extern struct {
    random_bytes: [32]u8,
};

comptime {
    std.debug.assert(@sizeOf(Random) == 32);
}

pub const SessionID = [32]u8;

const RecordProto = struct {};
pub const ConnectionEnd = struct {};
pub const PRFAlgorithm = struct {};
pub const BulkCipherAlgorithm = struct {};
pub const MACAlgorithm = struct {};
pub const CompressionMethod = ?void;

pub const ChangeCipherSpec = struct {
    pub fn unpack(_: []const u8) !ChangeCipherSpec {
        unreachable;
    }

    pub fn pack(buffer: []u8) usize {
        buffer[0] = 0x01;
        return 1;
    }
};

fn startHandshakeCustomSuites(conn: std.net.Stream, suites: []const Cipher.Suites) !ConnCtx {
    var buffer = [_]u8{0} ** 0x1000;
    var ctx = ConnCtx.initClient(std.testing.allocator);
    var client_hello = Handshake.ClientHello.init(ctx);
    client_hello.ciphers = suites;
    const record = TLSRecord{
        .kind = .{
            .handshake = try Handshake.Handshake.wrap(client_hello),
        },
    };

    const len = try record.pack(&buffer, &ctx);
    const dout = try conn.write(buffer[0..len]);
    if (false) print("data count {}\n", .{dout});
    if (false) print("data out {any}\n", .{buffer[0..len]});
    return ctx;
}

fn startHandshake(conn: std.net.Stream) !ConnCtx {
    return startHandshakeCustomSuites(conn, &[_]Cipher.Suites{
        .TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        .TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        .TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
    });
}

/// Forgive me, I'm tired
fn readServer(conn: std.net.Stream, server: []u8) !usize {
    const s_read = try conn.read(server);
    if (s_read == 0) return error.InvalidSHello;

    const server_msg = server[0..s_read];
    if (false) print("server data: {any}\n", .{server_msg});
    try std.testing.expect(s_read > 7);
    return s_read;
}

fn buildServer(data: []const u8, ctx: *ConnCtx) !void {
    var next_block: []const u8 = data;

    while (next_block.len > 0) {
        if (false) print("server block\n{any}\n", .{next_block});
        const tlsr = try TLSRecord.unpack(next_block, ctx);

        next_block = next_block[tlsr.length..];

        switch (tlsr.kind) {
            .change_cipher_spec, .alert, .application_data => return error.UnexpectedResponse,
            .handshake => |hs| {
                switch (hs.body) {
                    .server_hello => |hello| {
                        if (false) print("server hello {}\n", .{@TypeOf(hello)});
                        if (false) print("srv selected suite {any}\n", .{ctx.cipher});
                    },
                    .certificate => |cert| {
                        if (false) print("server cert {}\n", .{@TypeOf(cert)});
                    },
                    .server_key_exchange => |keyex| {
                        if (false) print("server keyex {}\n", .{@TypeOf(keyex)});
                    },
                    .certificate_request => |req| {
                        if (false) print("server req {}\n", .{@TypeOf(req)});
                    },
                    .server_hello_done => |done| {
                        if (false) print("server done {}\n", .{@TypeOf(done)});
                    },
                    else => return error.UnexpectedHandshake,
                }
            },
        }
    }
}

fn completeClient(conn: std.net.Stream, ctx: *ConnCtx) !void {
    var buffer = [_]u8{0} ** 0x1000;

    const cke = try Handshake.ClientKeyExchange.init(ctx);
    const cke_record = TLSRecord{
        .kind = .{
            .handshake = try Handshake.Handshake.wrap(cke),
        },
    };

    const cke_len = try cke_record.pack(&buffer, ctx);
    if (false) print("CKE: {any}\n", .{buffer[0..cke_len]});
    const ckeout = try conn.write(buffer[0..cke_len]);
    if (false) print("cke delivered, {}\n", .{ckeout});

    var r_buf: [0x1000]u8 = undefined;
    if (false) { // check for alerts
        const num = try conn.read(&r_buf);
        if (false) print("sin: {any}\n", .{r_buf[0..num]});
        const sin = try TLSRecord.unpack(r_buf[0..num], ctx);
        if (false) print("server thing {}\n", .{sin});
    }

    const ccs_record = TLSRecord{
        .kind = .{ .change_cipher_spec = {} },
    };
    const ccs_len = try ccs_record.pack(&buffer, ctx);
    const ccsout = try conn.write(buffer[0..ccs_len]);
    try std.testing.expectEqual(6, ccsout);

    const fin = Handshake.Finished{};
    const fin_record = TLSRecord{
        .kind = .{
            .handshake = try Handshake.Handshake.wrap(fin),
        },
    };
    const fin_len = try fin_record.encrypt(&buffer, ctx);
    if (false) {
        print("fin: {any}\n", .{
            std.fmt.fmtSliceHexLower(buffer[0..fin_len]),
        });
        print("clientiv='{}'\n", .{
            std.fmt.fmtSliceHexLower(buffer[5..][0..16]),
        });
        print("clientkey='{}'\n", .{
            std.fmt.fmtSliceHexLower(&ctx.cipher.suite.aes.material.cli_key),
        });
        print("clientmac='{}'\n", .{
            std.fmt.fmtSliceHexLower(&ctx.cipher.suite.aes.material.cli_mac),
        });
        print("clientmsg='{}'\n", .{
            std.fmt.fmtSliceHexLower(buffer[5..][16..][0 .. fin_len - 5 - 16]),
        });
    }
    const finout = try conn.write(buffer[0..fin_len]);
    if (false) print("fin delivered, {}\n", .{finout});

    const num2 = try conn.read(&r_buf);
    if (false) print("sin: {any}\n", .{r_buf[0..num2]});
    const sin2 = try TLSRecord.unpack(r_buf[0..num2], ctx);
    if (true) print("server thing {}\n", .{sin2});

    if (num2 > sin2.length) {
        const n_buf = r_buf[sin2.length..];
        const sin3 = try TLSRecord.unpack(n_buf, ctx);
        if (true) print("server thing {}\n", .{sin3});
    } else {
        //const num3 = try conn.read(&r_buf);
    }

    ctx.raze();
}

fn fullHandshake(conn: std.net.Stream) !void {
    var ctx = try startHandshake(conn);
    var server: [0x1000]u8 = undefined;
    const l = try readServer(conn, &server);
    try buildServer(server[0..l], &ctx);
    try completeClient(conn, &ctx);
}

test "tls" {
    if (true) return error.SkipZigTest;
    const addr = net.Address.resolveIp(TESTING_IP, TESTING_PORT) catch |err| {
        print("unable to resolve address because {}\n", .{err});
        return err;
    };
    const conn = try net.tcpConnectToAddress(addr);

    var ctx = try startHandshake(conn);
    var server: [0x1000]u8 = undefined;
    const l = try readServer(conn, &server);
    try buildServer(server[0..l], &ctx);
    try completeClient(conn, &ctx);
}

test "cbc" {
    const addr = net.Address.resolveIp(TESTING_IP, TESTING_PORT) catch |err| {
        print("unable to resolve address because {}\n", .{err});
        return err;
    };
    const conn = try net.tcpConnectToAddress(addr);

    var ctx = try startHandshakeCustomSuites(conn, &[_]Cipher.Suites{
        .TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
    });
    errdefer ctx.handshake_record.deinit();
    var server: [0x1000]u8 = undefined;
    const l = try readServer(conn, &server);
    try buildServer(server[0..l], &ctx);
    std.debug.assert(ctx.cipher.suite == .aes);
    try completeClient(conn, &ctx);
}

test "mock server response" {
    var ctx = ConnCtx.initClient(std.testing.allocator);
    defer ctx.handshake_record.deinit();

    // zig fmt: off
    const server_data = [_]u8{
        22, 3, 3, 0, 74,
        2, 0, 0, 70,
            3, 3, 75, 127, 236, 41, 6, 185, 127, 156, 38, 101,
            41, 80, 93, 16, 140, 154, 60, 40, 250, 248, 115,
            110, 115, 15, 68, 79, 87, 78, 71, 82, 68, 1, 32,
            24, 187, 143, 225, 245, 127, 101, 130, 182, 200,
            134, 201, 74, 38, 128, 15, 14, 35, 146, 216, 106,
            109, 225, 72, 177, 41, 225, 227, 146, 101, 101,
            10, 204, 169, 0,
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

    try buildServer(&server_data, &ctx);
}

const test_key: [32]u8 = [_]u8{12} ** 32;
const test_iv: [16]u8 = [_]u8{6} ** 16;

test "aes" {
    const clear: [16]u8 = "this is a test!!".*;

    var cipher: [16]u8 = undefined;
    var aes_ctx_en = std.crypto.core.aes.Aes256.initEnc(test_key);
    var man_xor: [16]u8 = undefined;
    for (man_xor[0..], clear[0..], test_iv[0..]) |*out, in, iv| {
        out.* = in ^ iv;
    }
    aes_ctx_en.encrypt(cipher[0..], man_xor[0..]);
    if (false) print("clear {} \n", .{
        std.fmt.fmtSliceHexLower(clear[0..]),
    });

    if (false) print("man_xor {} \n", .{
        std.fmt.fmtSliceHexLower(man_xor[0..]),
    });

    if (false) print("crypto {} \n", .{
        std.fmt.fmtSliceHexLower(cipher[0..]),
    });

    const iv: [16]u8 = test_iv;
    var xord: [16]u8 = undefined;
    aes_ctx_en.xor(xord[0..], clear[0..], iv);
    if (false) print("man_xor {} \n", .{
        std.fmt.fmtSliceHexLower(xord[0..]),
    });

    var aes_ctx_de = std.crypto.core.aes.Aes256.initDec(test_key);
    var output: [16]u8 = undefined;
    aes_ctx_de.decrypt(output[0..], cipher[0..]);
    if (false) print("crypto {s} {any}\n", .{ output, cipher });
    for (output[0..], test_iv[0..]) |*out, iv2| {
        out.* = out.* ^ iv2;
    }
    if (false) print("crypto {s} {any}\n", .{ output, cipher });
}
