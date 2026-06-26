#include "../include/context.h"
#include "../include/constants.h"
#include <string.h>
#include <stdlib.h>

void tls_context_init(tls_context_t* ctx) {
    memset(ctx, 0, sizeof(tls_context_t));
    ctx->cipher_suite = TLS_CIPHER_AES_128_GCM_SHA256;
}

void tls_context_wipe(tls_context_t* ctx) {
    if (ctx) {
        volatile uint8_t* p = (volatile uint8_t*)ctx;
        for (size_t i = 0; i < sizeof(tls_context_t); i++) {
            p[i] = 0;
        }
    }
}

void tls_context_update_hash(tls_context_t* ctx, const uint8_t* data, size_t len) {
    if (ctx->buffer_offset + len < sizeof(ctx->handshake_buffer)) {
        memcpy(ctx->handshake_buffer + ctx->buffer_offset, data, len);
        ctx->buffer_offset += len;
    }
}