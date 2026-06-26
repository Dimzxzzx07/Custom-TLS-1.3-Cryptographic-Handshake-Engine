#include "context.h"
#include "constants.h"
#include "secure.h"
#include <string.h>
#include <stdlib.h>

void axon_context_init(axon_context_t* ctx) {
    memset(ctx, 0, sizeof(axon_context_t));
    ctx->cipher_suite = TLS_CIPHER_AES_128_GCM_SHA256;
}

void axon_context_wipe(axon_context_t* ctx) {
    if (ctx) {
        secure_zero(ctx, sizeof(axon_context_t));
    }
}

void axon_context_update_hash(axon_context_t* ctx, const uint8_t* data, size_t len) {
    if (!ctx || !data || len == 0) return;
    if (ctx->buffer_offset + len <= sizeof(ctx->handshake_buffer)) {
        memcpy(ctx->handshake_buffer + ctx->buffer_offset, data, len);
        ctx->buffer_offset += len;
    }
}
