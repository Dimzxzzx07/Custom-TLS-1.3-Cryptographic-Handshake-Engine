#include "../include/chacha20.h"
#include <string.h>

#define ROTL32(a,b) (((a) << (b)) | ((a) >> (32 - (b))))
#define U32TO8(p,v) do { (p)[0] = (v) >> 24; (p)[1] = (v) >> 16; (p)[2] = (v) >> 8; (p)[3] = (v); } while (0)
#define U8TO32(p) (((uint32_t)(p)[0] << 24) | ((uint32_t)(p)[1] << 16) | ((uint32_t)(p)[2] << 8) | ((uint32_t)(p)[3]))

static void chacha20_quarter_round(uint32_t* a, uint32_t* b, uint32_t* c, uint32_t* d) {
    *a += *b; *d ^= *a; *d = ROTL32(*d, 16);
    *c += *d; *b ^= *c; *b = ROTL32(*b, 12);
    *a += *b; *d ^= *a; *d = ROTL32(*d, 8);
    *c += *d; *b ^= *c; *b = ROTL32(*b, 7);
}

static void chacha20_block(const uint8_t* key, const uint8_t* nonce, uint32_t counter, uint8_t* output) {
    uint32_t state[16] = {
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
        U8TO32(key + 0), U8TO32(key + 4), U8TO32(key + 8), U8TO32(key + 12),
        U8TO32(key + 16), U8TO32(key + 20), U8TO32(key + 24), U8TO32(key + 28),
        counter, U8TO32(nonce + 0), U8TO32(nonce + 4), U8TO32(nonce + 8)
    };
    
    uint32_t working[16];
    memcpy(working, state, 64);
    
    for (int i = 0; i < 10; i++) {
        chacha20_quarter_round(&working[0], &working[4], &working[8], &working[12]);
        chacha20_quarter_round(&working[1], &working[5], &working[9], &working[13]);
        chacha20_quarter_round(&working[2], &working[6], &working[10], &working[14]);
        chacha20_quarter_round(&working[3], &working[7], &working[11], &working[15]);
        chacha20_quarter_round(&working[0], &working[5], &working[10], &working[15]);
        chacha20_quarter_round(&working[1], &working[6], &working[11], &working[12]);
        chacha20_quarter_round(&working[2], &working[7], &working[8], &working[13]);
        chacha20_quarter_round(&working[3], &working[4], &working[9], &working[14]);
    }
    
    for (int i = 0; i < 16; i++) {
        working[i] += state[i];
    }
    
    for (int i = 0; i < 16; i++) {
        U32TO8(output + (i * 4), working[i]);
    }
}

void chacha20_xor(const uint8_t* key, const uint8_t* nonce, uint32_t counter, const uint8_t* input, size_t len, uint8_t* output) {
    uint8_t block[64];
    size_t offset = 0;
    
    while (offset < len) {
        chacha20_block(key, nonce, counter + (offset / 64), block);
        size_t remaining = len - offset;
        size_t block_size = (remaining < 64) ? remaining : 64;
        for (size_t i = 0; i < block_size; i++) {
            output[offset + i] = input[offset + i] ^ block[i];
        }
        offset += block_size;
    }
}

static void poly1305_mul(uint8_t* h, const uint8_t* r) {
    uint64_t h0 = U8TO32(h + 0) & 0x3ffffff;
    uint64_t h1 = (U8TO32(h + 3) >> 2) & 0x3ffffff;
    uint64_t h2 = (U8TO32(h + 6) >> 4) & 0x3ffffff;
    uint64_t h3 = (U8TO32(h + 9) >> 6) & 0x3ffffff;
    uint64_t h4 = U8TO32(h + 12) >> 8;
    
    uint64_t r0 = U8TO32(r + 0) & 0x3ffffff;
    uint64_t r1 = (U8TO32(r + 3) >> 2) & 0x3ffffff;
    uint64_t r2 = (U8TO32(r + 6) >> 4) & 0x3ffffff;
    uint64_t r3 = (U8TO32(r + 9) >> 6) & 0x3ffffff;
    uint64_t r4 = U8TO32(r + 12) >> 8;
    
    
    uint64_t s1 = r1 * 5;
    uint64_t s2 = r2 * 5;
    uint64_t s3 = r3 * 5;
    uint64_t s4 = r4 * 5;
    
    uint64_t d0 = (h0 * r0) + (h1 * s4) + (h2 * s3) + (h3 * s2) + (h4 * s1);
    uint64_t d1 = (h0 * r1) + (h1 * r0) + (h2 * s4) + (h3 * s3) + (h4 * s2);
    uint64_t d2 = (h0 * r2) + (h1 * r1) + (h2 * r0) + (h3 * s4) + (h4 * s3);
    uint64_t d3 = (h0 * r3) + (h1 * r2) + (h2 * r1) + (h3 * r0) + (h4 * s4);
    uint64_t d4 = (h0 * r4) + (h1 * r3) + (h2 * r2) + (h3 * r1) + (h4 * r0);
    
    uint64_t carry = d0 >> 26; d0 &= 0x3ffffff;
    d1 += carry; carry = d1 >> 26; d1 &= 0x3ffffff;
    d2 += carry; carry = d2 >> 26; d2 &= 0x3ffffff;
    d3 += carry; carry = d3 >> 26; d3 &= 0x3ffffff;
    d4 += carry; carry = d4 >> 26; d4 &= 0x3ffffff;
    d0 += carry * 5; carry = d0 >> 26; d0 &= 0x3ffffff;
    d1 += carry;
    
    U32TO8(h + 0, (uint32_t)d0 | ((uint32_t)d1 << 26));
    U32TO8(h + 4, (uint32_t)(d1 >> 6) | ((uint32_t)d2 << 20));
    U32TO8(h + 8, (uint32_t)(d2 >> 12) | ((uint32_t)d3 << 14));
    U32TO8(h + 12, (uint32_t)(d3 >> 18) | ((uint32_t)d4 << 8));
}

void poly1305_mac(const uint8_t* key, const uint8_t* data, size_t len, uint8_t* tag) {
    uint8_t h[16] = {0};
    uint8_t r[16];
    uint8_t pad[16];
    uint8_t block[16];
    size_t offset = 0;
    
    memcpy(r, key, 16);
    r[3] &= 0x0f; r[4] &= 0xfc;
    r[7] &= 0x0f; r[8] &= 0xfc;
    r[11] &= 0x0f; r[12] &= 0xfc;
    r[15] &= 0x0f;
    
    memcpy(pad, key + 16, 16);
    
    while (offset < len) {
        size_t remaining = len - offset;
        size_t block_size = (remaining < 16) ? remaining : 16;
        memset(block, 0, 16);
        memcpy(block, data + offset, block_size);
        block[block_size] = 1;
        poly1305_mul(h, r);
        for (int i = 0; i < 16; i++) {
            h[i] ^= block[i];
        }
        offset += block_size;
    }
    
    poly1305_mul(h, r);
    for (int i = 0; i < 16; i++) {
        h[i] += pad[i];
        tag[i] = h[i];
    }
}

int poly1305_verify(const uint8_t* key, const uint8_t* data, size_t len, const uint8_t* tag) {
    uint8_t computed_tag[16];
    poly1305_mac(key, data, len, computed_tag);
    return memcmp(tag, computed_tag, 16) == 0 ? 0 : -1;
}

int chacha20_poly1305_encrypt(const uint8_t* key, const uint8_t* iv, const uint8_t* plaintext, size_t pt_len, const uint8_t* aad, size_t aad_len, uint8_t* ciphertext, size_t* ct_len, uint8_t* tag) {
    if (!key || !iv || !plaintext || !ciphertext || !ct_len || !tag) return -1;
    
    uint8_t poly_key[32];
    chacha20_block(key, iv, 0, poly_key);
    chacha20_xor(key, iv, 1, plaintext, pt_len, ciphertext);
    *ct_len = pt_len;
    
    uint8_t mac_input[16 + pt_len + 16];
    size_t mac_len = 0;
    memcpy(mac_input + mac_len, aad, aad_len);
    mac_len += aad_len;
    memcpy(mac_input + mac_len, ciphertext, pt_len);
    mac_len += pt_len;
    
    uint64_t aad_bits = aad_len * 8;
    uint64_t pt_bits = pt_len * 8;
    mac_input[mac_len++] = (aad_bits >> 56) & 0xFF;
    mac_input[mac_len++] = (aad_bits >> 48) & 0xFF;
    mac_input[mac_len++] = (aad_bits >> 40) & 0xFF;
    mac_input[mac_len++] = (aad_bits >> 32) & 0xFF;
    mac_input[mac_len++] = (aad_bits >> 24) & 0xFF;
    mac_input[mac_len++] = (aad_bits >> 16) & 0xFF;
    mac_input[mac_len++] = (aad_bits >> 8) & 0xFF;
    mac_input[mac_len++] = aad_bits & 0xFF;
    mac_input[mac_len++] = (pt_bits >> 56) & 0xFF;
    mac_input[mac_len++] = (pt_bits >> 48) & 0xFF;
    mac_input[mac_len++] = (pt_bits >> 40) & 0xFF;
    mac_input[mac_len++] = (pt_bits >> 32) & 0xFF;
    mac_input[mac_len++] = (pt_bits >> 24) & 0xFF;
    mac_input[mac_len++] = (pt_bits >> 16) & 0xFF;
    mac_input[mac_len++] = (pt_bits >> 8) & 0xFF;
    mac_input[mac_len++] = pt_bits & 0xFF;
    
    poly1305_mac(poly_key, mac_input, mac_len, tag);
    return 0;
}

int chacha20_poly1305_decrypt(const uint8_t* key, const uint8_t* iv, const uint8_t* ciphertext, size_t ct_len, const uint8_t* aad, size_t aad_len, uint8_t* plaintext, size_t* pt_len, const uint8_t* tag) {
    if (!key || !iv || !ciphertext || !plaintext || !pt_len || !tag) return -1;
    
    uint8_t poly_key[32];
    uint8_t computed_tag[16];
    chacha20_block(key, iv, 0, poly_key);
    
    uint8_t mac_input[16 + ct_len + 16];
    size_t mac_len = 0;
    memcpy(mac_input + mac_len, aad, aad_len);
    mac_len += aad_len;
    memcpy(mac_input + mac_len, ciphertext, ct_len);
    mac_len += ct_len;
    
    uint64_t aad_bits = aad_len * 8;
    uint64_t ct_bits = ct_len * 8;
    mac_input[mac_len++] = (aad_bits >> 56) & 0xFF;
    mac_input[mac_len++] = (aad_bits >> 48) & 0xFF;
    mac_input[mac_len++] = (aad_bits >> 40) & 0xFF;
    mac_input[mac_len++] = (aad_bits >> 32) & 0xFF;
    mac_input[mac_len++] = (aad_bits >> 24) & 0xFF;
    mac_input[mac_len++] = (aad_bits >> 16) & 0xFF;
    mac_input[mac_len++] = (aad_bits >> 8) & 0xFF;
    mac_input[mac_len++] = aad_bits & 0xFF;
    mac_input[mac_len++] = (ct_bits >> 56) & 0xFF;
    mac_input[mac_len++] = (ct_bits >> 48) & 0xFF;
    mac_input[mac_len++] = (ct_bits >> 40) & 0xFF;
    mac_input[mac_len++] = (ct_bits >> 32) & 0xFF;
    mac_input[mac_len++] = (ct_bits >> 24) & 0xFF;
    mac_input[mac_len++] = (ct_bits >> 16) & 0xFF;
    mac_input[mac_len++] = (ct_bits >> 8) & 0xFF;
    mac_input[mac_len++] = ct_bits & 0xFF;
    
    poly1305_mac(poly_key, mac_input, mac_len, computed_tag);
    if (memcmp(tag, computed_tag, 16) != 0) return -1;
    
    chacha20_xor(key, iv, 1, ciphertext, ct_len, plaintext);
    *pt_len = ct_len;
    return 0;
}