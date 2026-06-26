#ifndef CHACHA20_H
#define CHACHA20_H

#include <stdint.h>
#include <stddef.h>

void chacha20_xor(const uint8_t* key, const uint8_t* nonce, uint32_t counter, const uint8_t* input, size_t len, uint8_t* output);
int poly1305_verify(const uint8_t* key, const uint8_t* data, size_t len, const uint8_t* tag);
void poly1305_mac(const uint8_t* key, const uint8_t* data, size_t len, uint8_t* tag);
int chacha20_poly1305_encrypt(const uint8_t* key, const uint8_t* iv, const uint8_t* plaintext, size_t pt_len, const uint8_t* aad, size_t aad_len, uint8_t* ciphertext, size_t* ct_len, uint8_t* tag);
int chacha20_poly1305_decrypt(const uint8_t* key, const uint8_t* iv, const uint8_t* ciphertext, size_t ct_len, const uint8_t* aad, size_t aad_len, uint8_t* plaintext, size_t* pt_len, const uint8_t* tag);

#endif