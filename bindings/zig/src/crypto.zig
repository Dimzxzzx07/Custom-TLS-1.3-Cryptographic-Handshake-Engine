const std = @import("std");

pub const X25519 = struct {
    pub fn generateKeypair(priv: []u8, pub_key: []u8) !void {
        _ = priv;
        _ = pub_key;
    }
    
    pub fn sharedSecret(priv: []const u8, peer: []const u8, out: []u8) !void {
        _ = priv;
        _ = peer;
        _ = out;
    }
};

pub const AESGCM = struct {
    pub fn encrypt(key: []const u8, iv: []const u8, plaintext: []const u8, aad: []const u8, ciphertext: []u8, tag: []u8) !void {
        _ = key;
        _ = iv;
        _ = plaintext;
        _ = aad;
        _ = ciphertext;
        _ = tag;
    }
    
    pub fn decrypt(key: []const u8, iv: []const u8, ciphertext: []const u8, aad: []const u8, plaintext: []u8, tag: []const u8) !void {
        _ = key;
        _ = iv;
        _ = ciphertext;
        _ = aad;
        _ = plaintext;
        _ = tag;
    }
};