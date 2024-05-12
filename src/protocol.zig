pub const Version = extern struct {
    major: u8,
    minor: u8,
};

pub const TLSv1_2: Version = .{
    .major = 3,
    .minor = 3,
};

pub const TLSv1_3: Version = .{
    .major = 3,
    .minor = 4,
};

pub const Current = TLSv1_2;
