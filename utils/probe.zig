const std = @import("std");
const nihssl = @import("nihssl");
const Allocator = std.mem.Allocator;
const net = std.net;
const print = std.debug.print;

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    for (
        [_][]const u8{ "127.0.0.1", "144.126.209.12" },
        [_]u16{ 4433, 443 },
    ) |IP, PORT| {
        print("{s} :: {}\n", .{ IP, PORT });
        for (std.meta.tags(nihssl.Cipher.Suites)) |target| {
            const addr = net.Address.resolveIp(IP, PORT) catch |err| {
                print("unable to resolve address because {}\n", .{err});
                return err;
            };
            const conn = try net.tcpConnectToAddress(addr);
            defer conn.close();
            probe(alloc, conn, target) catch |err| switch (err) {
                error.UnsupportedSuite => {},
                else => return err,
            };
        }
    }
}

fn probe(a: Allocator, conn: std.net.Stream, target: nihssl.Cipher.Suites) !void {
    var buffer = [_]u8{0} ** 0x1000;
    var ctx = nihssl.ConnCtx.initClient(a);
    var client_hello = nihssl.Handshake.ClientHello.init(ctx);
    client_hello.ciphers = &[1]nihssl.Cipher.Suites{target};
    const record = nihssl.TLSRecord{
        .kind = .{
            .handshake = try nihssl.Handshake.Handshake.wrap(client_hello),
        },
    };

    const len = try record.pack(&buffer, &ctx);
    _ = try conn.write(buffer[0..len]);

    var server: [0x1000]u8 = undefined;
    const s_read = try conn.read(&server);
    if (s_read == 0) return error.InvalidSHello;

    const server_msg = server[0..s_read];
    if (s_read <= 7) {
        print("suite {} is unsupported\n", .{target});
        return;
    }
    print("FOUND {}\n", .{target});

    const tlsr = try nihssl.TLSRecord.unpack(server_msg, &ctx);

    switch (tlsr.kind) {
        .change_cipher_spec, .alert, .application_data => return error.UnexpectedResponse,
        .handshake => |hs| {
            switch (hs.body) {
                else => return,
            }
        },
    }
}

test "probe" {
    for (
        [_][]const u8{ "178.62.242.62", "127.0.0.1", "144.126.209.12" },
        [_]u16{ 443, 4433, 443 },
    ) |IP, PORT| {
        print("{s} :: {}\n", .{ IP, PORT });
        for (std.meta.tags(nihssl.Cipher.Suites)) |target| {
            const addr = net.Address.resolveIp(IP, PORT) catch |err| {
                print("unable to resolve address because {}\n", .{err});
                return err;
            };
            const conn = try net.tcpConnectToAddress(addr);
            defer conn.close();
            probe(conn, target) catch |err| switch (err) {
                error.UnsupportedSuite => {},
                else => return err,
            };
        }
    }
}
