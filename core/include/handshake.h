#ifndef TLS_HANDSHAKE_H
#define TLS_HANDSHAKE_H

#include "context.h"
#include <stdint.h>
#include <stddef.h>

int tls_parse_client_hello(tls_context_t* ctx, const uint8_t* data, size_t len);
int tls_build_server_hello(tls_context_t* ctx, uint8_t* out, size_t* out_len);
int tls_build_encrypted_extensions(tls_context_t* ctx, uint8_t* out, size_t* out_len);
int tls_build_certificate(tls_context_t* ctx, uint8_t* out, size_t* out_len);
int tls_build_certificate_verify(tls_context_t* ctx, uint8_t* out, size_t* out_len);
int tls_build_finished(tls_context_t* ctx, uint8_t* out, size_t* out_len);
int tls_verify_finished(tls_context_t* ctx, const uint8_t* data, size_t len);
void tls_derive_handshake_keys(tls_context_t* ctx);

#endif