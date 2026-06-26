#ifndef TLS_HANDSHAKE_H
#define TLS_HANDSHAKE_H

#include "context.h"
#include <stdint.h>
#include <stddef.h>

int axon_parse_client_hello(axon_context_t* ctx, const uint8_t* data, size_t len);
int axon_build_server_hello(axon_context_t* ctx, uint8_t* out, size_t* out_len);
int axon_build_encrypted_extensions(axon_context_t* ctx, uint8_t* out, size_t* out_len);
int axon_build_certificate(axon_context_t* ctx, uint8_t* out, size_t* out_len);
int axon_build_certificate_verify(axon_context_t* ctx, uint8_t* out, size_t* out_len);
int axon_build_finished(axon_context_t* ctx, uint8_t* out, size_t* out_len);
int axon_verify_finished(axon_context_t* ctx, const uint8_t* data, size_t len);
void axon_derive_handshake_keys(axon_context_t* ctx);

#endif