#include "../include/record.h"
#include "../include/constants.h"
#include "../../crypto/include/aes_gcm.h"
#include "../../crypto/include/chacha20.h"
#include "../../crypto/include/constant.h"
#include "../../memory/include/secure.h"
#include <string.h>
#include <stdlib.h>

int tls_record_read(tls_context_t* ctx, const uint8_t* data, size_t len, tls_record_t* record) {
    if (!ctx || !data || !record || len < 5) return -1;
    
    record->content_type = data[0];
    record->version = (data[1] << 8) | data[2];
    record->length = (data[3] << 8) | data[4];
    
    if (record->length > len - 5) return -1;
    
    if (record->content_type == TLS_CONTENT_ALERT) {
        if (record->length >= 2) {
            uint8_t level = data[5];
            uint8_t desc = data[6];
            if (level == TLS_ALERT_LEVEL_FATAL) {
                return -1;
            }
            return -1;
        }
        return -1;
    }
    
    if (record->version != 0x0304 && record->version != 0x0303) {
        return -1;
    }
    
    record->fragment = (uint8_t*)secure_alloc(record->length);
    if (!record->fragment) return -1;
    memcpy(record->fragment, data + 5, record->length);
    
    return 0;
}

int tls_record_write(tls_context_t* ctx, uint8_t content_type, const uint8_t* payload, size_t payload_len, uint8_t* out, size_t* out_len) {
    if (!ctx || !out || !out_len) return -1;
    if (payload_len > 16384) return -1;
    
    out[0] = content_type;
    out[1] = 0x03;
    out[2] = 0x04;
    out[3] = (payload_len >> 8) & 0xFF;
    out[4] = payload_len & 0xFF;
    
    if (payload && payload_len > 0) {
        memcpy(out + 5, payload, payload_len);
    }
    
    *out_len = 5 + payload_len;
    return 0;
}

int tls_record_decrypt(tls_context_t* ctx, tls_record_t* record, uint8_t* plaintext, size_t* out_len) {
    if (!ctx || !record || !plaintext || !out_len) return -1;
    
    if (record->content_type != TLS_CONTENT_APPLICATION_DATA) {
        return -1;
    }
    
    if (record->length < 16) return -1;
    
    uint8_t nonce[12] = {0};
    uint8_t key[32] = {0};
    uint8_t tag[16] = {0};
    
    memcpy(nonce, record->fragment, 4);
    
    for (int i = 0; i < 4; i++) {
        nonce[8 + i] = (ctx->sequence_number >> ((3 - i) * 8)) & 0xFF;
    }
    ctx->sequence_number++;
    
    memcpy(key, ctx->read_key, 32);
    
    size_t ciphertext_len = record->length - 16;
    memcpy(tag, record->fragment + ciphertext_len + 4, 16);
    
    int ret = aes_gcm_decrypt(key, nonce, record->fragment + 4, ciphertext_len, NULL, 0, plaintext, out_len, tag);
    
    secure_free(record->fragment, record->length);
    record->fragment = NULL;
    
    return ret;
}

int tls_record_encrypt(tls_context_t* ctx, uint8_t content_type, const uint8_t* plaintext, size_t len, uint8_t* out, size_t* out_len) {
    if (!ctx || !out || !out_len) return -1;
    if (len > 16384) return -1;
    
    uint8_t nonce[12] = {0};
    uint8_t key[32] = {0};
    uint8_t tag[16] = {0};
    uint8_t ciphertext[16384] = {0};
    size_t ciphertext_len = 0;
    
    memcpy(key, ctx->write_key, 32);
    
    memcpy(nonce, ctx->write_iv, 12);
    for (int i = 0; i < 8; i++) {
        nonce[4 + i] ^= (ctx->sequence_number >> ((7 - i) * 8)) & 0xFF;
    }
    ctx->sequence_number++;
    
    int ret = aes_gcm_encrypt(key, nonce, plaintext, len, NULL, 0, ciphertext, &ciphertext_len, tag);
    if (ret < 0) return -1;
    
    out[0] = content_type;
    out[1] = 0x03;
    out[2] = 0x04;
    out[3] = ((ciphertext_len + 16) >> 8) & 0xFF;
    out[4] = (ciphertext_len + 16) & 0xFF;
    
    memcpy(out + 5, nonce, 4);
    memcpy(out + 9, ciphertext, ciphertext_len);
    memcpy(out + 9 + ciphertext_len, tag, 16);
    
    *out_len = 5 + ciphertext_len + 16;
    return 0;
}