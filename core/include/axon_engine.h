#ifndef AXON_ENGINE_H
#define AXON_ENGINE_H

#include <stdint.h>
#include <stddef.h>
#include "context.h"
#include "state.h"

typedef struct axon_engine {
    axon_context_t context;
    axon_state_t state;
    uint8_t write_key[32];
    uint8_t read_key[32];
    uint8_t write_iv[12];
    uint8_t read_iv[12];
    uint64_t sequence_number;
} axon_engine_t;

axon_engine_t* axon_engine_create(void);
void axon_engine_destroy(axon_engine_t* eng);
int axon_engine_handshake(axon_engine_t* eng, const uint8_t* client_hello, size_t len, uint8_t* response, size_t* resp_len);
int axon_engine_decrypt(axon_engine_t* eng, const uint8_t* ciphertext, size_t len, uint8_t* plaintext, size_t* out_len);
int axon_engine_encrypt(axon_engine_t* eng, const uint8_t* plaintext, size_t len, uint8_t* ciphertext, size_t* out_len);
void axon_engine_reset(axon_engine_t* eng);

#endif
