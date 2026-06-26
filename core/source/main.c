#include "axon_engine.h"
#include "constants.h"
#include "handshake.h"
#include "record.h"
#include "state.h"
#include "hkdf.h"
#include "secure.h"
#include <stdlib.h>
#include <string.h>

axon_engine_t* axon_engine_create(void) {
    axon_engine_t* eng = (axon_engine_t*)secure_alloc(sizeof(axon_engine_t));
    if (!eng) return NULL;
    axon_context_init(&eng->context);
    eng->state = STATE_INIT;
    eng->sequence_number = 0;
    memset(eng->write_key, 0, 32);
    memset(eng->read_key, 0, 32);
    memset(eng->write_iv, 0, 12);
    memset(eng->read_iv, 0, 12);
    return eng;
}

void axon_engine_destroy(axon_engine_t* eng) {
    if (eng) {
        axon_context_wipe(&eng->context);
        secure_free(eng, sizeof(axon_engine_t));
    }
}

int axon_engine_handshake(axon_engine_t* eng, const uint8_t* client_hello, size_t len, uint8_t* response, size_t* resp_len) {
    if (!eng || !client_hello || !response || !resp_len) return -1;
    
    axon_record_t record = {0};
    int ret = axon_record_read(&eng->context, client_hello, len, &record);
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
    
    uint16_t version = (record.fragment[1] << 8) | record.fragment[2];
    if (version != 0x0304) {
        eng->state = STATE_ALERT_SENT;
        secure_free(record.fragment, record.length);
        return -1;
    }
    
    ret = axon_parse_client_hello(&eng->context, record.fragment, record.length);
    axon_context_update_hash(&eng->context, record.fragment, record.length);
    secure_free(record.fragment, record.length);
    if (ret < 0) {
        eng->state = STATE_ALERT_SENT;
        return ret;
    }
    
    eng->state = axon_state_machine(&eng->context, STATE_INIT, TLS_HANDSHAKE_CLIENT_HELLO);
    
    uint8_t* out_ptr = response;
    size_t out_total = 0;
    size_t chunk_len = 0;
    
    ret = axon_build_server_hello(&eng->context, out_ptr, &chunk_len);
    if (ret < 0) return ret;
    out_ptr += chunk_len;
    out_total += chunk_len;
    
    eng->state = axon_state_machine(&eng->context, eng->state, TLS_HANDSHAKE_SERVER_HELLO);
    
    ret = axon_build_encrypted_extensions(&eng->context, out_ptr, &chunk_len);
    if (ret < 0) return ret;
    out_ptr += chunk_len;
    out_total += chunk_len;
    
    eng->state = axon_state_machine(&eng->context, eng->state, TLS_HANDSHAKE_ENCRYPTED_EXTENSIONS);
    
    axon_derive_handshake_keys(&eng->context);
    
    uint8_t key_material[96] = {0};
    uint8_t info[64] = {0};
    uint8_t prk[32] = {0};
    uint8_t salt[32] = {0};
    
    for (int i = 0; i < 32; i++) {
        salt[i] = eng->context.client_random[i] ^ eng->context.server_random[i];
    }
    hkdf_extract(salt, 32, eng->context.shared_secret, 32, prk);
    
    memcpy(info, "tls13 key", 9);
    hkdf_expand(prk, 32, info, 9, key_material, 96);
    
    memcpy(eng->write_key, key_material, 32);
    memcpy(eng->read_key, key_material + 32, 32);
    memcpy(eng->write_iv, key_material + 64, 12);
    memcpy(eng->read_iv, key_material + 76, 12);
    
    ret = axon_build_certificate(&eng->context, out_ptr, &chunk_len);
    if (ret < 0) return ret;
    out_ptr += chunk_len;
    out_total += chunk_len;
    
    eng->state = axon_state_machine(&eng->context, eng->state, TLS_HANDSHAKE_CERTIFICATE);
    
    ret = axon_build_certificate_verify(&eng->context, out_ptr, &chunk_len);
    if (ret < 0) return ret;
    out_ptr += chunk_len;
    out_total += chunk_len;
    
    eng->state = axon_state_machine(&eng->context, eng->state, TLS_HANDSHAKE_CERTIFICATE_VERIFY);
    
    ret = axon_build_finished(&eng->context, out_ptr, &chunk_len);
    if (ret < 0) return ret;
    out_ptr += chunk_len;
    out_total += chunk_len;
    
    eng->state = axon_state_machine(&eng->context, eng->state, TLS_HANDSHAKE_FINISHED);
    eng->state = STATE_SENT_FINISHED;
    
    *resp_len = out_total;
    return 0;
}

int axon_engine_decrypt(axon_engine_t* eng, const uint8_t* ciphertext, size_t len, uint8_t* plaintext, size_t* out_len) {
    if (!eng || !ciphertext || !plaintext || !out_len) return -1;
    if (eng->state != STATE_HANDSHAKE_COMPLETE) return -1;
    
    axon_record_t record = {0};
    int ret = axon_record_read(&eng->context, ciphertext, len, &record);
    if (ret < 0) return ret;
    
    if (record.content_type == TLS_CONTENT_ALERT) {
        eng->state = STATE_ALERT_SENT;
        secure_free(record.fragment, record.length);
        return -1;
    }
    
    return axon_record_decrypt(&eng->context, &record, plaintext, out_len);
}

int axon_engine_encrypt(axon_engine_t* eng, const uint8_t* plaintext, size_t len, uint8_t* ciphertext, size_t* out_len) {
    if (!eng || !plaintext || !ciphertext || !out_len) return -1;
    if (eng->state != STATE_HANDSHAKE_COMPLETE) return -1;
    
    return axon_record_encrypt(&eng->context, TLS_CONTENT_APPLICATION_DATA, plaintext, len, ciphertext, out_len);
}

void axon_engine_reset(axon_engine_t* eng) {
    if (eng) {
        axon_context_wipe(&eng->context);
        axon_context_init(&eng->context);
        eng->state = STATE_INIT;
        eng->sequence_number = 0;
    }
}
