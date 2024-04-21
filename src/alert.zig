pub const Alert = @This();

level: Level,
description: Description,

pub fn unpack(buffer: []const u8) !Alert {
    if (buffer.len != 2) return error.MalformedData;
    return .{
        .level = switch (buffer[0]) {
            1 => .warning,
            2 => .fatal,
            else => return error.UnexpectedAlertLevel,
        },
        .description = try Description.fromByte(buffer[1]),
    };
}

pub const Level = enum(u8) {
    warning = 1,
    fatal = 2,
};

pub const Description = enum(u8) {
    close_notify = 0,
    unexpected_message = 10,
    bad_record_mac = 20,
    decryption_failed_RESERVED = 21,
    record_overflow = 22,
    decompression_failure = 30,
    handshake_failure = 40,
    no_certificate_RESERVED = 41,
    bad_certificate = 42,
    unsupported_certificate = 43,
    certificate_revoked = 44,
    certificate_expired = 45,
    certificate_unknown = 46,
    illegal_parameter = 47,
    unknown_ca = 48,
    access_denied = 49,
    decode_error = 50,
    decrypt_error = 51,
    export_restriction_RESERVED = 60,
    protocol_version = 70,
    insufficient_security = 71,
    internal_error = 80,
    user_canceled = 90,
    no_renegotiation = 100,
    unsupported_extension = 110,

    pub fn fromByte(desc: u8) !Description {
        return switch (desc) {
            0 => .close_notify,
            10 => .unexpected_message,
            20 => .bad_record_mac,
            21 => .decryption_failed_RESERVED,
            22 => .record_overflow,
            30 => .decompression_failure,
            40 => .handshake_failure,
            41 => .no_certificate_RESERVED,
            42 => .bad_certificate,
            43 => .unsupported_certificate,
            44 => .certificate_revoked,
            45 => .certificate_expired,
            46 => .certificate_unknown,
            47 => .illegal_parameter,
            48 => .unknown_ca,
            49 => .access_denied,
            50 => .decode_error,
            51 => .decrypt_error,
            60 => .export_restriction_RESERVED,
            70 => .protocol_version,
            71 => .insufficient_security,
            80 => .internal_error,
            90 => .user_canceled,
            100 => .no_renegotiation,
            110 => .unsupported_extension,
            else => error.UnexpectedAlertDescription,
        };
    }
};
