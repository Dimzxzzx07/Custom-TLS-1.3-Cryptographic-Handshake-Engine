#include "handshake.h"
#include "constants.h"
#include "record.h"
#include "x25519.h"
#include "hkdf.h"
#include "sha256.h"
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

static int generate_random(uint8_t* buf, size_t len) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        return -1;
    }
    
    size_t total_read = 0;
    while (total_read < len) {
        ssize_t n = read(fd, buf + total_read, len - total_read);
        if (n <= 0) {
            close(fd);
            return -1;
        }
        total_read += n;
    }
    
    close(fd);
    return 0;
}

int axon_parse_client_hello(axon_context_t* ctx, const uint8_t* data, size_t len) {
    if (len < 40) return -1;
    
    size_t offset = 4;
    memcpy(ctx->client_random, data + offset, 32);
    offset += 32;
    
    uint8_t session_id_len = data[offset++];
    if (offset + session_id_len > len) return -1;
    offset += session_id_len;
    
    uint16_t cipher_suites_len = (data[offset] << 8) | data[offset + 1];
    offset += 2;
    if (offset + cipher_suites_len > len) return -1;
    
    int found_suite = 0;
    for (size_t i = 0; i < cipher_suites_len; i += 2) {
        uint16_t suite = (data[offset + i] << 8) | data[offset + i + 1];
        if (suite == TLS_CIPHER_AES_128_GCM_SHA256 ||
            suite == TLS_CIPHER_AES_256_GCM_SHA384 ||
            suite == TLS_CIPHER_CHACHA20_POLY1305) {
            found_suite = 1;
            ctx->cipher_suite = suite;
            break;
        }
    }
    if (!found_suite) return -1;
    
    offset += cipher_suites_len;
    
    uint8_t compression_len = data[offset++];
    if (offset + compression_len > len) return -1;
    offset += compression_len;
    
    if (offset + 2 > len) return -1;
    uint16_t extensions_len = (data[offset] << 8) | data[offset + 1];
    offset += 2;
    
    while (offset + 4 <= len && offset - 4 < extensions_len) {
        uint16_t ext_type = (data[offset] << 8) | data[offset + 1];
        uint16_t ext_len = (data[offset + 2] << 8) | data[offset + 3];
        offset += 4;
        
        if (ext_type == TLS_EXTENSION_KEY_SHARE && ext_len >= 32) {
            offset += 2;
            uint16_t group = (data[offset] << 8) | data[offset + 1];
            offset += 2;
            uint16_t key_len = (data[offset] << 8) | data[offset + 1];
            offset += 2;
            if (key_len == 32 && offset + 32 <= len) {
                memcpy(ctx->client_pubkey, data + offset, 32);
            }
            break;
        }
        offset += ext_len;
    }
    
    ctx->messages_received |= 0x01;
    return 0;
}

int axon_build_server_hello(axon_context_t* ctx, uint8_t* out, size_t* out_len) {
    if (!ctx || !out || !out_len) return -1;
    
    if (generate_random(ctx->server_random, 32) < 0) return -1;
    
    x25519_generate_keypair(ctx->server_privkey, ctx->server_public_key);
    x25519_shared_secret(ctx->server_privkey, ctx->client_pubkey, ctx->shared_secret);
    
    size_t offset = 0;
    out[offset++] = TLS_HANDSHAKE_SERVER_HELLO;
    out[offset++] = 0x00;
    out[offset++] = 0x00;
    out[offset++] = 0x00;
    
    size_t payload_start = offset;
    
    out[offset++] = TLS_VERSION_MAJOR;
    out[offset++] = TLS_VERSION_MINOR;
    
    memcpy(out + offset, ctx->server_random, 32);
    offset += 32;
    
    out[offset++] = 0x00;
    
    out[offset++] = (ctx->cipher_suite >> 8) & 0xFF;
    out[offset++] = ctx->cipher_suite & 0xFF;
    
    out[offset++] = 0x00;
    
    size_t ext_start = offset;
    out[offset++] = 0x00;
    out[offset++] = 0x00;
    
    size_t ext_len_start = offset;
    offset += 2;
    
    out[offset++] = (TLS_EXTENSION_KEY_SHARE >> 8) & 0xFF;
    out[offset++] = TLS_EXTENSION_KEY_SHARE & 0xFF;
    out[offset++] = 0x00;
    out[offset++] = 0x24;
    out[offset++] = 0x00;
    out[offset++] = 0x1D;
    out[offset++] = 0x00;
    out[offset++] = 0x20;
    
    memcpy(out + offset, ctx->server_public_key, 32);
    offset += 32;
    
    uint16_t ext_len = offset - ext_len_start - 2;
    out[ext_len_start] = (ext_len >> 8) & 0xFF;
    out[ext_len_start + 1] = ext_len & 0xFF;
    
    uint32_t payload_len = offset - payload_start;
    out[1] = (payload_len >> 16) & 0xFF;
    out[2] = (payload_len >> 8) & 0xFF;
    out[3] = payload_len & 0xFF;
    
    *out_len = offset;
    ctx->messages_received |= 0x02;
    
    axon_context_update_hash(ctx, out, *out_len);
    return 0;
}

int axon_build_encrypted_extensions(axon_context_t* ctx, uint8_t* out, size_t* out_len) {
    if (!ctx || !out || !out_len) return -1;
    
    size_t offset = 0;
    out[offset++] = TLS_HANDSHAKE_ENCRYPTED_EXTENSIONS;
    out[offset++] = 0x00;
    out[offset++] = 0x00;
    out[offset++] = 0x00;
    
    size_t payload_start = offset;
    out[offset++] = 0x00;
    out[offset++] = 0x00;
    
    uint32_t payload_len = offset - payload_start;
    out[1] = (payload_len >> 16) & 0xFF;
    out[2] = (payload_len >> 8) & 0xFF;
    out[3] = payload_len & 0xFF;
    
    *out_len = offset;
    ctx->messages_received |= 0x04;
    axon_context_update_hash(ctx, out, *out_len);
    return 0;
}

int axon_build_certificate(axon_context_t* ctx, uint8_t* out, size_t* out_len) {
    if (!ctx || !out || !out_len) return -1;
    
    size_t offset = 0;
    out[offset++] = TLS_HANDSHAKE_CERTIFICATE;
    out[offset++] = 0x00;
    out[offset++] = 0x00;
    out[offset++] = 0x00;
    
    size_t payload_start = offset;
    out[offset++] = 0x00;
    out[offset++] = 0x00;
    out[offset++] = 0x00;
    
    out[offset++] = 0x00;
    out[offset++] = 0x00;
    out[offset++] = 0x00;
    out[offset++] = 0x00;
    
    out[offset++] = 0x00;
    out[offset++] = 0x00;
    
    uint32_t payload_len = offset - payload_start;
    out[1] = (payload_len >> 16) & 0xFF;
    out[2] = (payload_len >> 8) & 0xFF;
    out[3] = payload_len & 0xFF;
    
    *out_len = offset;
    ctx->messages_received |= 0x08;
    axon_context_update_hash(ctx, out, *out_len);
    return 0;
}

static void compute_signature(const uint8_t* data, size_t len, uint8_t* sig, size_t* sig_len) {
    sha256_ctx_t ctx_hash;
    sha256_init(&ctx_hash);
    sha256_update(&ctx_hash, data, len);
    uint8_t digest[32];
    sha256_final(&ctx_hash, digest);
    
    for (int i = 0; i < 32; i++) {
        sig[i] = digest[i];
        sig[i + 32] = digest[31 - i];
    }
    *sig_len = 64;
}

int axon_build_certificate_verify(axon_context_t* ctx, uint8_t* out, size_t* out_len) {
    if (!ctx || !out || !out_len) return -1;
    
    size_t offset = 0;
    out[offset++] = TLS_HANDSHAKE_CERTIFICATE_VERIFY;
    out[offset++] = 0x00;
    out[offset++] = 0x00;
    out[offset++] = 0x00;
    
    size_t payload_start = offset;
    out[offset++] = 0x04;
    out[offset++] = 0x03;
    
    out[offset++] = 0x00;
    out[offset++] = 0x00;
    out[offset++] = 0x00;
    out[offset++] = 0x40;
    
    uint8_t signature[64];
    size_t sig_len = 0;
    compute_signature(ctx->handshake_buffer, ctx->buffer_offset, signature, &sig_len);
    
    memcpy(out + offset, signature, sig_len);
    offset += sig_len;
    
    uint32_t payload_len = offset - payload_start;
    size_t total_len = offset;
    out[1] = (payload_len >> 16) & 0xFF;
    out[2] = (payload_len >> 8) & 0xFF;
    out[3] = payload_len & 0xFF;
    
    *out_len = total_len;
    ctx->messages_received |= 0x10;
    axon_context_update_hash(ctx, out, *out_len);
    return 0;
}

static void compute_finished(const uint8_t* key, const uint8_t* transcript, size_t transcript_len, uint8_t* out) {
    sha256_ctx_t ctx_hash;
    sha256_init(&ctx_hash);
    sha256_update(&ctx_hash, transcript, transcript_len);
    uint8_t hash[32];
    sha256_final(&ctx_hash, hash);
    
    for (int i = 0; i < 16; i++) {
        out[i] = hash[i] ^ key[i];
        out[i + 16] = hash[i + 16] ^ key[i + 16];
    }
}

int axon_build_finished(axon_context_t* ctx, uint8_t* out, size_t* out_len) {
    if (!ctx || !out || !out_len) return -1;
    
    size_t offset = 0;
    out[offset++] = TLS_HANDSHAKE_FINISHED;
    out[offset++] = 0x00;
    out[offset++] = 0x00;
    out[offset++] = 0x00;
    
    size_t payload_start = offset;
    
    uint8_t finished_key[32];
    for (int i = 0; i < 32; i++) {
        finished_key[i] = ctx->master_secret[i] ^ 0x5C;
    }
    
    compute_finished(finished_key, ctx->handshake_buffer, ctx->buffer_offset, out + offset);
    offset += 32;
    
    uint32_t payload_len = offset - payload_start;
    out[1] = (payload_len >> 16) & 0xFF;
    out[2] = (payload_len >> 8) & 0xFF;
    out[3] = payload_len & 0xFF;
    
    *out_len = offset;
    ctx->messages_received |= 0x20;
    ctx->handshake_done = 1;
    axon_context_update_hash(ctx, out, *out_len);
    return 0;
}

int axon_verify_finished(axon_context_t* ctx, const uint8_t* data, size_t len) {
    if (!ctx || !data || len < 32) return -1;
    
    uint8_t finished_key[32];
    for (int i = 0; i < 32; i++) {
        finished_key[i] = ctx->master_secret[i] ^ 0x5C;
    }
    
    uint8_t computed[32];
    compute_finished(finished_key, ctx->handshake_buffer, ctx->buffer_offset, computed);
    
    if (memcmp(data, computed, 32) != 0) {
        return -1;
    }
    
    ctx->handshake_done = 1;
    return 0;
}

void axon_derive_handshake_keys(axon_context_t* ctx) {
    if (!ctx) return;
    
    uint8_t salt[32] = {0};
    uint8_t prk[32] = {0};
    uint8_t info[64] = {0};
    uint8_t key_material[96] = {0};
    
    for (int i = 0; i < 32; i++) {
        salt[i] = ctx->client_random[i] ^ ctx->server_random[i];
    }
    
    hkdf_extract(salt, 32, ctx->shared_secret, 32, prk);
    
    info[0] = 0x54;
    info[1] = 0x4C;
    info[2] = 0x53;
    info[3] = 0x20;
    info[4] = 0x31;
    info[5] = 0x2E;
    info[6] = 0x33;
    info[7] = 0x20;
    info[8] = 0x6B;
    info[9] = 0x65;
    info[10] = 0x79;
    info[11] = 0x73;
    info[12] = 0x00;
    
    hkdf_expand(prk, 32, info, 13, key_material, 96);
    
    memcpy(ctx->master_secret, key_material, 48);
}
