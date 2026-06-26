#include "record.h"
#include "constants.h"
#include "aes_gcm.h"
#include "chacha20.h"
#include "constant.h"
#include "secure.h"
#include <string.h>
#include <stdlib.h>

int axon_record_read(axon_context_t* ctx, const uint8_t* data, size_t len, axon_record_t* record) {
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

int axon_record_write(axon_context_t* ctx, uint8_t content_type, const uint8_t* payload, size_t payload_len, uint8_t* out, size_t* out_len) {
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

static void build_nonce(uint8_t* nonce, const uint8_t* iv, uint64_t seq_num) {
    for (int i = 0; i < 12; i++) {
        nonce[i] = iv[i];
    }
    
    for (int i = 0; i < 8; i++) {
        uint8_t seq_byte = (seq_num >> ((7 - i) * 8)) & 0xFF;
        nonce[4 + i] ^= seq_byte;
    }
}

int axon_record_decrypt(axon_context_t* ctx, axon_record_t* record, uint8_t* plaintext, size_t* out_len) {
    if (!ctx || !record || !plaintext || !out_len) return -1;
    
    if (record->content_type != TLS_CONTENT_APPLICATION_DATA) {
        return -1;
    }
    
    if (record->length < 16) return -1;
    
    uint8_t nonce[12] = {0};
    uint8_t key[32] = {0};
    uint8_t tag[16] = {0};
    
    build_nonce(nonce, ctx->read_iv, ctx->sequence_number);
    ctx->sequence_number++;
    
    memcpy(key, ctx->read_key, 32);
    
    size_t ciphertext_len = record->length - 16;
    memcpy(tag, record->fragment + ciphertext_len, 16);
    
    int ret = aes_gcm_decrypt(key, nonce, record->fragment, ciphertext_len, NULL, 0, plaintext, out_len, tag);
    
    secure_free(record->fragment, record->length);
    record->fragment = NULL;
    
    return ret;
}

int axon_record_encrypt(axon_context_t* ctx, uint8_t content_type, const uint8_t* plaintext, size_t len, uint8_t* out, size_t* out_len) {
    if (!ctx || !out || !out_len) return -1;
    if (len > 16384) return -1;
    
    uint8_t nonce[12] = {0};
    uint8_t key[32] = {0};
    uint8_t tag[16] = {0};
    uint8_t ciphertext[16384] = {0};
    size_t ciphertext_len = 0;
    
    memcpy(key, ctx->write_key, 32);
    
    build_nonce(nonce, ctx->write_iv, ctx->sequence_number);
    ctx->sequence_number++;
    
    int ret = aes_gcm_encrypt(key, nonce, plaintext, len, NULL, 0, ciphertext, &ciphertext_len, tag);
    if (ret < 0) return -1;
    
    out[0] = content_type;
    out[1] = 0x03;
    out[2] = 0x04;
    out[3] = ((ciphertext_len + 16) >> 8) & 0xFF;
    out[4] = (ciphertext_len + 16) & 0xFF;
    
    memcpy(out + 5, ciphertext, ciphertext_len);
    memcpy(out + 5 + ciphertext_len, tag, 16);
    
    *out_len = 5 + ciphertext_len + 16;
    return 0;
}
