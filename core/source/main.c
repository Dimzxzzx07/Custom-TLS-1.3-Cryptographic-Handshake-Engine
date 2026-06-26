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
    
    uint16_t version = (record.fragment[1] << 8) | record.fragment[2];
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
    
    uint8_t* out_ptr = response;
    size_t out_total = 0;
    size_t chunk_len = 0;
    
    ret = tls_build_server_hello(&eng->context, out_ptr, &chunk_len);
    if (ret < 0) return ret;
    out_ptr += chunk_len;
    out_total += chunk_len;
    
    eng->state = tls_state_machine(&eng->context, eng->state, TLS_HANDSHAKE_SERVER_HELLO);
    
    ret = tls_build_encrypted_extensions(&eng->context, out_ptr, &chunk_len);
    if (ret < 0) return ret;
    out_ptr += chunk_len;
    out_total += chunk_len;
    
    eng->state = tls_state_machine(&eng->context, eng->state, TLS_HANDSHAKE_ENCRYPTED_EXTENSIONS);
    
    tls_derive_handshake_keys(&eng->context);
    
    memcpy(eng->write_key, eng->context.master_secret, 32);
    memcpy(eng->read_key, eng->context.master_secret + 16, 32);
    memcpy(eng->write_iv, eng->context.master_secret + 8, 12);
    memcpy(eng->read_iv, eng->context.master_secret + 20, 12);
    
    ret = tls_build_certificate(&eng->context, out_ptr, &chunk_len);
    if (ret < 0) return ret;
    out_ptr += chunk_len;
    out_total += chunk_len;
    
    eng->state = tls_state_machine(&eng->context, eng->state, TLS_HANDSHAKE_CERTIFICATE);
    
    ret = tls_build_certificate_verify(&eng->context, out_ptr, &chunk_len);
    if (ret < 0) return ret;
    out_ptr += chunk_len;
    out_total += chunk_len;
    
    eng->state = tls_state_machine(&eng->context, eng->state, TLS_HANDSHAKE_CERTIFICATE_VERIFY);
    
    ret = tls_build_finished(&eng->context, out_ptr, &chunk_len);
    if (ret < 0) return ret;
    out_ptr += chunk_len;
    out_total += chunk_len;
    
    eng->state = tls_state_machine(&eng->context, eng->state, TLS_HANDSHAKE_FINISHED);
    eng->state = STATE_SENT_FINISHED;
    
    *resp_len = out_total;
    return 0;
}