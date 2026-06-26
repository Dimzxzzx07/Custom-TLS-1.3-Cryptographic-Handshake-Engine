#ifndef TLS_ENGINE_H
#define TLS_ENGINE_H

#include <stdint.h>
#include <stddef.h>
#include "context.h"
#include "state.h"

typedef struct tls_engine {
    tls_context_t context;
    tls_state_t   state;
} tls_engine_t;

tls_engine_t* tls_engine_create(void);
void tls_engine_destroy(tls_engine_t* eng);
int tls_engine_handshake(tls_engine_t* eng, const uint8_t* client_hello, size_t len, uint8_t* response, size_t* resp_len);
int tls_engine_decrypt(tls_engine_t* eng, const uint8_t* ciphertext, size_t len, uint8_t* plaintext, size_t* out_len);
int tls_engine_encrypt(tls_engine_t* eng, const uint8_t* plaintext, size_t len, uint8_t* ciphertext, size_t* out_len);
void tls_engine_reset(tls_engine_t* eng);

#endif