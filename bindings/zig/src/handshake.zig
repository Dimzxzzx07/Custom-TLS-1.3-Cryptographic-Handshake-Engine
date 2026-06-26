const std = @import("std");

pub const Handshake = struct {
    pub fn parseClientHello(data: []const u8) !void {
        _ = data;
    }
    
    pub fn buildServerHello(random: []const u8, cipher: u16, out: []u8) !usize {
        _ = random;
        _ = cipher;
        _ = out;
        return 0;
    }
};