#ifndef TLS_CONTEXT_H
#define TLS_CONTEXT_H

#include <stdint.h>
#include <stddef.h>

typedef struct axon_context {
    uint8_t client_random[32];
    uint8_t server_random[32];
    uint8_t session_id[32];
    uint8_t master_secret[48];
    uint8_t handshake_hash[32];
    uint8_t client_pubkey[32];
    uint8_t server_privkey[32];
    uint8_t server_public_key[32];
    uint8_t shared_secret[32];
    /* Session keys (populated after handshake key derivation) */
    uint8_t write_key[32];
    uint8_t read_key[32];
    uint8_t write_iv[12];
    uint8_t read_iv[12];
    uint64_t sequence_number;
    /* Handshake state */
    uint8_t handshake_buffer[8192];
    size_t buffer_offset;
    uint32_t messages_received;
    uint8_t handshake_done;
    uint8_t alert_triggered;
    uint16_t cipher_suite;
    uint8_t key_phase;
} axon_context_t;

void axon_context_init(axon_context_t* ctx);
void axon_context_wipe(axon_context_t* ctx);
void axon_context_update_hash(axon_context_t* ctx, const uint8_t* data, size_t len);

#endif