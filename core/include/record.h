#ifndef TLS_RECORD_H
#define TLS_RECORD_H

#include "context.h"
#include <stdint.h>
#include <stddef.h>

typedef struct tls_record {
    uint8_t content_type;
    uint16_t version;
    uint16_t length;
    uint8_t* fragment;
} tls_record_t;

int tls_record_read(tls_context_t* ctx, const uint8_t* data, size_t len, tls_record_t* record);
int tls_record_write(tls_context_t* ctx, uint8_t content_type, const uint8_t* payload, size_t payload_len, uint8_t* out, size_t* out_len);
int tls_record_decrypt(tls_context_t* ctx, tls_record_t* record, uint8_t* plaintext, size_t* out_len);
int tls_record_encrypt(tls_context_t* ctx, uint8_t content_type, const uint8_t* plaintext, size_t len, uint8_t* out, size_t* out_len);

#endif