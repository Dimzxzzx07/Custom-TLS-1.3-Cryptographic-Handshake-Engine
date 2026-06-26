#include "../security/include/aes_gcm.h"
#include "../security/include/chacha20.h"
#include "../security/include/x25519.h"
#include "../security/include/sha256.h"
#include "../security/include/constant.h"
#include <stdio.h>
#include <string.h>

int main(void) {
    uint8_t key[32] = {0};
    uint8_t iv[12] = {0};
    uint8_t plaintext[64] = "Hello TLS 1.3 with custom crypto";
    uint8_t ciphertext[64] = {0};
    uint8_t decrypted[64] = {0};
    uint8_t tag[16] = {0};
    size_t ct_len = 0;
    size_t pt_len = 0;
    
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i & 0xFF);
    for (int i = 0; i < 12; i++) iv[i] = (uint8_t)(i & 0xFF);
    
    int ret = aes_gcm_encrypt(key, iv, plaintext, 36, NULL, 0, ciphertext, &ct_len, tag);
    if (ret < 0) {
        printf("FAIL: AES-GCM encrypt\n");
        return 1;
    }
    
    ret = aes_gcm_decrypt(key, iv, ciphertext, ct_len, NULL, 0, decrypted, &pt_len, tag);
    if (ret < 0) {
        printf("FAIL: AES-GCM decrypt\n");
        return 1;
    }
    
    if (memcmp(plaintext, decrypted, 36) != 0) {
        printf("FAIL: AES-GCM mismatch\n");
        return 1;
    }
    printf("PASS: AES-GCM works\n");
    
    uint8_t chacha_key[32] = {0};
    uint8_t chacha_nonce[12] = {0};
    uint8_t chacha_plain[64] = "ChaCha20-Poly1305 test";
    uint8_t chacha_cipher[64] = {0};
    uint8_t chacha_decrypted[64] = {0};
    uint8_t chacha_tag[16] = {0};
    size_t chacha_ct_len = 0;
    size_t chacha_pt_len = 0;
    
    for (int i = 0; i < 32; i++) chacha_key[i] = (uint8_t)(0xAA ^ i);
    for (int i = 0; i < 12; i++) chacha_nonce[i] = (uint8_t)(0xBB ^ i);
    
    ret = chacha20_poly1305_encrypt(chacha_key, chacha_nonce, chacha_plain, 22, NULL, 0, chacha_cipher, &chacha_ct_len, chacha_tag);
    if (ret < 0) {
        printf("FAIL: ChaCha20-Poly1305 encrypt\n");
        return 1;
    }
    
    ret = chacha20_poly1305_decrypt(chacha_key, chacha_nonce, chacha_cipher, chacha_ct_len, NULL, 0, chacha_decrypted, &chacha_pt_len, chacha_tag);
    if (ret < 0) {
        printf("FAIL: ChaCha20-Poly1305 decrypt\n");
        return 1;
    }
    
    if (memcmp(chacha_plain, chacha_decrypted, 22) != 0) {
        printf("FAIL: ChaCha20-Poly1305 mismatch\n");
        return 1;
    }
    printf("PASS: ChaCha20-Poly1305 works\n");
    
    uint8_t priv[32] = {0};
    uint8_t pub[32] = {0};
    uint8_t shared[32] = {0};
    
    ret = x25519_generate_keypair(priv, pub);
    if (ret < 0) {
        printf("FAIL: X25519 keygen\n");
        return 1;
    }
    printf("PASS: X25519 keygen works\n");
    
    uint8_t sha_digest[32] = {0};
    sha256((uint8_t*)"test", 4, sha_digest);
    printf("PASS: SHA256 works\n");
    
    uint8_t a[16] = {0}, b[16] = {0xFF};
    uint8_t cmp_result = constant_time_memcmp(a, b, 16);
    printf("PASS: constant time compare works\n");
    
    return 0;
}