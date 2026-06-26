#include "../include/hkdf.h"
#include "../include/sha256.h"
#include <string.h>

int hkdf_extract(const uint8_t* salt, size_t salt_len, const uint8_t* ikm, size_t ikm_len, uint8_t* prk) {
    if (!ikm || !prk) return -1;
    
    uint8_t digest[32];
    sha256_ctx_t ctx;
    
    uint8_t* salt_ptr = (uint8_t*)salt;
    size_t salt_ptr_len = salt_len;
    
    if (!salt || salt_len == 0) {
        static uint8_t zero_salt[32] = {0};
        salt_ptr = zero_salt;
        salt_ptr_len = 32;
    }
    
    sha256_init(&ctx);
    sha256_update(&ctx, salt_ptr, salt_ptr_len);
    sha256_update(&ctx, ikm, ikm_len);
    sha256_final(&ctx, digest);
    
    memcpy(prk, digest, 32);
    return 0;
}

int hkdf_expand(const uint8_t* prk, size_t prk_len, const uint8_t* info, size_t info_len, uint8_t* okm, size_t okm_len) {
    if (!prk || !okm || prk_len != 32) return -1;
    
    uint8_t digest[32];
    uint8_t counter = 1;
    size_t generated = 0;
    uint8_t previous[32];
    
    sha256_ctx_t ctx;
    
    while (generated < okm_len) {
        sha256_init(&ctx);
        sha256_update(&ctx, prk, prk_len);
        
        if (generated > 0) {
            sha256_update(&ctx, previous, 32);
        }
        
        if (info && info_len > 0) {
            sha256_update(&ctx, info, info_len);
        }
        
        sha256_update(&ctx, &counter, 1);
        sha256_final(&ctx, digest);
        
        size_t to_copy = (okm_len - generated < 32) ? (okm_len - generated) : 32;
        memcpy(okm + generated, digest, to_copy);
        memcpy(previous, digest, 32);
        
        generated += to_copy;
        counter++;
    }
    
    return 0;
}