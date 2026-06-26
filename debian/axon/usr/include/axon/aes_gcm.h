#ifndef AES_GCM_H
#define AES_GCM_H

#include <stdint.h>
#include <stddef.h>

int aes_gcm_encrypt(const uint8_t* key, const uint8_t* iv, const uint8_t* plaintext, size_t pt_len, const uint8_t* aad, size_t aad_len, uint8_t* ciphertext, size_t* ct_len, uint8_t* tag);
int aes_gcm_decrypt(const uint8_t* key, const uint8_t* iv, const uint8_t* ciphertext, size_t ct_len, const uint8_t* aad, size_t aad_len, uint8_t* plaintext, size_t* pt_len, const uint8_t* tag);

#endif