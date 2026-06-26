#include "../include/tls_engine.h"
#include "../include/handshake.h"
#include "../include/record.h"
#include "../include/state.h"
#include "../include/constants.h"
#include "../../memory/include/secure.h"
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

tls_engine_t* tls_engine_create(void) {
    tls_engine_t* eng = (tls_engine_t*)calloc(1, sizeof(tls_engine_t));
    if (!eng) return NULL;
    tls_context_init(&eng->context);
    eng->state = STATE_INIT;
    return eng;
}

void tls_engine_destroy(tls_engine_t* eng) {
    if (!eng) return;
    tls_context_wipe(&eng->context);
    secure_zero(eng, sizeof(tls_engine_t));
    free(eng);
}

void tls_engine_reset(tls_engine_t* eng) {
    if (!eng) return;
    tls_context_wipe(&eng->context);
    tls_context_init(&eng->context);
    eng->state = STATE_INIT;
}

int tls_engine_handshake(tls_engine_t* eng, const uint8_t* client_hello, size_t len, uint8_t* response, size_t* resp_len) {
    if (!eng || !client_hello || !response || !resp_len) return -1;

    tls_record_t record = {0};
    int ret = tls_record_read(&eng->context, client_hello, len, &record);
    if (ret < 0) return ret;

    if (record.content_type != TLS_CONTENT_HANDSHAKE) {
        eng->state = STATE_ALERT_SENT;
        secure_free(record.fragment, record.length);
        return -1;
    }

    if (record.fragment[0] != TLS_HANDSHAKE_CLIENT_HELLO) {
        eng->state = STATE_ALERT_SENT;
        secure_free(record.fragment, record.length);
        return -1;
    }

    uint16_t version = (uint16_t)((record.fragment[1] << 8) | record.fragment[2]);
    if (version != 0x0304) {
        eng->state = STATE_ALERT_SENT;
        secure_free(record.fragment, record.length);
        return -1;
    }

    ret = tls_parse_client_hello(&eng->context, record.fragment, record.length);
    secure_free(record.fragment, record.length);
    if (ret < 0) {
        eng->state = STATE_ALERT_SENT;
        return ret;
    }

    eng->state = tls_state_machine(&eng->context, STATE_INIT, TLS_HANDSHAKE_CLIENT_HELLO);

    uint8_t* out_ptr   = response;
    size_t   out_total = 0;
    size_t   chunk_len = 0;

    ret = tls_build_server_hello(&eng->context, out_ptr, &chunk_len);
    if (ret < 0) return ret;
    out_ptr   += chunk_len;
    out_total += chunk_len;
    eng->state = tls_state_machine(&eng->context, eng->state, TLS_HANDSHAKE_SERVER_HELLO);

    ret = tls_build_encrypted_extensions(&eng->context, out_ptr, &chunk_len);
    if (ret < 0) return ret;
    out_ptr   += chunk_len;
    out_total += chunk_len;
    eng->state = tls_state_machine(&eng->context, eng->state, TLS_HANDSHAKE_ENCRYPTED_EXTENSIONS);

    /* Derive keys via HKDF — stored in context.master_secret */
    tls_derive_handshake_keys(&eng->context);

    /*
     * Key separation: write_key and read_key must not overlap.
     * write_key = first 32 bytes of master_secret
     * read_key  = XOR of master_secret halves (distinct from write_key)
     * write_iv  = bytes 32-43, read_iv = bytes 36-47
     * TODO: replace with proper HKDF-Expand per RFC 8446 §7.3
     */
    memcpy(eng->context.write_key, eng->context.master_secret, 32);
    for (int i = 0; i < 32; i++)
        eng->context.read_key[i] = eng->context.master_secret[i] ^ eng->context.master_secret[47 - i];
    memcpy(eng->context.write_iv, eng->context.master_secret + 32, 12);
    memcpy(eng->context.read_iv,  eng->context.master_secret + 36, 12);
    eng->context.sequence_number = 0;

    ret = tls_build_certificate(&eng->context, out_ptr, &chunk_len);
    if (ret < 0) return ret;
    out_ptr   += chunk_len;
    out_total += chunk_len;
    eng->state = tls_state_machine(&eng->context, eng->state, TLS_HANDSHAKE_CERTIFICATE);

    ret = tls_build_certificate_verify(&eng->context, out_ptr, &chunk_len);
    if (ret < 0) return ret;
    out_ptr   += chunk_len;
    out_total += chunk_len;
    eng->state = tls_state_machine(&eng->context, eng->state, TLS_HANDSHAKE_CERTIFICATE_VERIFY);

    ret = tls_build_finished(&eng->context, out_ptr, &chunk_len);
    if (ret < 0) return ret;
    out_ptr   += chunk_len;
    out_total += chunk_len;
    eng->state = tls_state_machine(&eng->context, eng->state, TLS_HANDSHAKE_FINISHED);
    eng->state = STATE_SENT_FINISHED;

    *resp_len = out_total;
    return 0;
}

int tls_engine_encrypt(tls_engine_t* eng, const uint8_t* plaintext, size_t len, uint8_t* ciphertext, size_t* out_len) {
    if (!eng || !plaintext || !ciphertext || !out_len) return -1;
    return tls_record_write(&eng->context, TLS_CONTENT_APPLICATION_DATA, plaintext, len, ciphertext, out_len);
}

int tls_engine_decrypt(tls_engine_t* eng, const uint8_t* ciphertext, size_t len, uint8_t* plaintext, size_t* out_len) {
    if (!eng || !ciphertext || !plaintext || !out_len) return -1;
    tls_record_t record = {0};
    int ret = tls_record_read(&eng->context, ciphertext, len, &record);
    if (ret < 0) return ret;
    memcpy(plaintext, record.fragment, record.length);
    *out_len = record.length;
    secure_free(record.fragment, record.length);
    return 0;
}

/* CLI entrypoint */
#include <stdio.h>
int main(int argc, char* argv[]) {
    (void)argc; (void)argv;
    printf("Axon TLS 1.3 Engine v1.0.0\n");
    tls_engine_t* eng = tls_engine_create();
    if (!eng) { fprintf(stderr, "Failed to create engine\n"); return 1; }
    printf("Engine initialized OK\n");
    tls_engine_destroy(eng);
    return 0;
}
