#ifndef TLS_CONTEXT_H
#define TLS_CONTEXT_H

#include <stdint.h>
#include <stddef.h>

typedef struct tls_context {
    uint8_t client_random[32];
    uint8_t server_random[32];
    uint8_t session_id[32];
    uint8_t master_secret[48];
    uint8_t handshake_hash[32];
    uint8_t client_pubkey[32];
    uint8_t server_privkey[32];
    uint8_t shared_secret[32];
    uint8_t handshake_buffer[8192];
    size_t buffer_offset;
    uint32_t messages_received;
    uint8_t handshake_done;
    uint8_t alert_triggered;
    uint8_t cipher_suite;
    uint8_t key_phase;
} tls_context_t;

void tls_context_init(tls_context_t* ctx);
void tls_context_wipe(tls_context_t* ctx);
void tls_context_update_hash(tls_context_t* ctx, const uint8_t* data, size_t len);

#endif