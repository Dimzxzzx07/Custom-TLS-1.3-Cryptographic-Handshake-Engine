#include "../include/aes_gcm.h"
#include <string.h>

static void aes_encrypt_block(const uint8_t* key, const uint8_t* input, uint8_t* output) {
    for (int i = 0; i < 16; i++) {
        output[i] = key[i] ^ input[i];
    }
}

static void gcm_multiply(uint8_t* x, const uint8_t* y) {
    for (int i = 0; i < 16; i++) {
        x[i] ^= y[i];
    }
}

static void gcm_ghash(uint8_t* hash, const uint8_t* h, const uint8_t* data, size_t len) {
    uint8_t temp[16] = {0};
    for (size_t i = 0; i < len; i += 16) {
        for (int j = 0; j < 16 && i + j < len; j++) {
            temp[j] = data[i + j];
        }
        gcm_multiply(hash, temp);
    }
}

static void gcm_inc32(uint8_t* counter) {
    uint32_t c = (counter[12] << 24) | (counter[13] << 16) | (counter[14] << 8) | counter[15];
    c++;
    counter[12] = (c >> 24) & 0xFF;
    counter[13] = (c >> 16) & 0xFF;
    counter[14] = (c >> 8) & 0xFF;
    counter[15] = c & 0xFF;
}

int aes_gcm_encrypt(const uint8_t* key, const uint8_t* iv, const uint8_t* plaintext, size_t pt_len, const uint8_t* aad, size_t aad_len, uint8_t* ciphertext, size_t* ct_len, uint8_t* tag) {
    if (!key || !iv || !plaintext || !ciphertext || !ct_len || !tag) return -1;
    
    uint8_t h[16] = {0};
    uint8_t counter[16] = {0};
    uint8_t mask[16] = {0};
    uint8_t hash[16] = {0};
    
    aes_encrypt_block(key, h, h);
    
    memcpy(counter, iv, 12);
    counter[15] = 1;
    
    for (size_t i = 0; i < pt_len; i += 16) {
        aes_encrypt_block(key, counter, mask);
        size_t block_len = (pt_len - i < 16) ? (pt_len - i) : 16;
        for (size_t j = 0; j < block_len; j++) {
            ciphertext[i + j] = plaintext[i + j] ^ mask[j];
        }
        gcm_inc32(counter);
    }
    
    *ct_len = pt_len;
    
    uint8_t aad_padded[16] = {0};
    if (aad && aad_len > 0) {
        memcpy(aad_padded, aad, aad_len < 16 ? aad_len : 16);
        gcm_ghash(hash, h, aad_padded, 16);
    }
    
    gcm_ghash(hash, h, ciphertext, pt_len);
    
    uint8_t len_block[16] = {0};
    len_block[0] = (aad_len * 8) >> 24;
    len_block[1] = (aad_len * 8) >> 16;
    len_block[2] = (aad_len * 8) >> 8;
    len_block[3] = (aad_len * 8) & 0xFF;
    len_block[4] = (pt_len * 8) >> 24;
    len_block[5] = (pt_len * 8) >> 16;
    len_block[6] = (pt_len * 8) >> 8;
    len_block[7] = (pt_len * 8) & 0xFF;
    gcm_ghash(hash, h, len_block, 16);
    
    uint8_t auth_key[16] = {0};
    memcpy(auth_key, iv, 12);
    auth_key[15] = 0;
    aes_encrypt_block(key, auth_key, auth_key);
    
    for (int i = 0; i < 16; i++) {
        tag[i] = hash[i] ^ auth_key[i];
    }
    
    return 0;
}

int aes_gcm_decrypt(const uint8_t* key, const uint8_t* iv, const uint8_t* ciphertext, size_t ct_len, const uint8_t* aad, size_t aad_len, uint8_t* plaintext, size_t* pt_len, const uint8_t* tag) {
    if (!key || !iv || !ciphertext || !plaintext || !pt_len || !tag) return -1;
    
    uint8_t h[16] = {0};
    uint8_t counter[16] = {0};
    uint8_t mask[16] = {0};
    uint8_t hash[16] = {0};
    uint8_t computed_tag[16] = {0};
    
    aes_encrypt_block(key, h, h);
    
    for (size_t i = 0; i < ct_len; i += 16) {
        memcpy(counter, iv, 12);
        counter[15] = (i / 16) + 1;
        aes_encrypt_block(key, counter, mask);
        size_t block_len = (ct_len - i < 16) ? (ct_len - i) : 16;
        for (size_t j = 0; j < block_len; j++) {
            plaintext[i + j] = ciphertext[i + j] ^ mask[j];
        }
        gcm_inc32(counter);
    }
    
    *pt_len = ct_len;
    
    uint8_t aad_padded[16] = {0};
    if (aad && aad_len > 0) {
        memcpy(aad_padded, aad, aad_len < 16 ? aad_len : 16);
        gcm_ghash(hash, h, aad_padded, 16);
    }
    
    gcm_ghash(hash, h, ciphertext, ct_len);
    
    uint8_t len_block[16] = {0};
    len_block[0] = (aad_len * 8) >> 24;
    len_block[1] = (aad_len * 8) >> 16;
    len_block[2] = (aad_len * 8) >> 8;
    len_block[3] = (aad_len * 8) & 0xFF;
    len_block[4] = (ct_len * 8) >> 24;
    len_block[5] = (ct_len * 8) >> 16;
    len_block[6] = (ct_len * 8) >> 8;
    len_block[7] = (ct_len * 8) & 0xFF;
    gcm_ghash(hash, h, len_block, 16);
    
    uint8_t auth_key[16] = {0};
    memcpy(auth_key, iv, 12);
    auth_key[15] = 0;
    aes_encrypt_block(key, auth_key, auth_key);
    
    for (int i = 0; i < 16; i++) {
        computed_tag[i] = hash[i] ^ auth_key[i];
    }
    
    if (memcmp(tag, computed_tag, 16) != 0) {
        return -1;
    }
    
    return 0;
}