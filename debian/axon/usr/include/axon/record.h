#ifndef TLS_RECORD_H
#define TLS_RECORD_H

#include "context.h"
#include <stdint.h>
#include <stddef.h>

typedef struct axon_record {
    uint8_t content_type;
    uint16_t version;
    uint16_t length;
    uint8_t* fragment;
} axon_record_t;

int axon_record_read(axon_context_t* ctx, const uint8_t* data, size_t len, axon_record_t* record);
int axon_record_write(axon_context_t* ctx, uint8_t content_type, const uint8_t* payload, size_t payload_len, uint8_t* out, size_t* out_len);
int axon_record_decrypt(axon_context_t* ctx, axon_record_t* record, uint8_t* plaintext, size_t* out_len);
int axon_record_encrypt(axon_context_t* ctx, uint8_t content_type, const uint8_t* plaintext, size_t len, uint8_t* out, size_t* out_len);

#endif