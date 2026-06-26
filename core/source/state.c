#include "../include/state.h"
#include "../include/constants.h"
#include <string.h>

axon_state_t axon_state_machine(axon_context_t* ctx, axon_state_t current, uint8_t message_type) {
    if (!ctx) return STATE_ERROR;
    
    switch (current) {
        case STATE_INIT:
            if (message_type == TLS_HANDSHAKE_CLIENT_HELLO) {
                return STATE_WAITING_CLIENT_HELLO;
            }
            return STATE_ALERT_SENT;
            
        case STATE_WAITING_CLIENT_HELLO:
            if (message_type == TLS_HANDSHAKE_SERVER_HELLO) {
                return STATE_SENT_SERVER_HELLO;
            }
            return STATE_ALERT_SENT;
            
        case STATE_SENT_SERVER_HELLO:
            if (message_type == TLS_HANDSHAKE_ENCRYPTED_EXTENSIONS) {
                return STATE_SENT_ENCRYPTED_EXTENSIONS;
            }
            return STATE_ALERT_SENT;
            
        case STATE_SENT_ENCRYPTED_EXTENSIONS:
            if (message_type == TLS_HANDSHAKE_CERTIFICATE) {
                return STATE_SENT_CERTIFICATE;
            }
            return STATE_ALERT_SENT;
            
        case STATE_SENT_CERTIFICATE:
            if (message_type == TLS_HANDSHAKE_CERTIFICATE_VERIFY) {
                return STATE_SENT_CERTIFICATE_VERIFY;
            }
            return STATE_ALERT_SENT;
            
        case STATE_SENT_CERTIFICATE_VERIFY:
            if (message_type == TLS_HANDSHAKE_FINISHED) {
                return STATE_SENT_FINISHED;
            }
            return STATE_ALERT_SENT;
            
        case STATE_SENT_FINISHED:
            if (message_type == TLS_HANDSHAKE_FINISHED) {
                return STATE_HANDSHAKE_COMPLETE;
            }
            return STATE_ALERT_SENT;
            
        case STATE_HANDSHAKE_COMPLETE:
            if (message_type == TLS_CONTENT_APPLICATION_DATA) {
                return STATE_HANDSHAKE_COMPLETE;
            }
            return STATE_ALERT_SENT;
            
        default:
            return STATE_ERROR;
    }
}

const char* axon_state_to_string(axon_state_t state) {
    switch (state) {
        case STATE_INIT: return "INIT";
        case STATE_WAITING_CLIENT_HELLO: return "WAITING_CLIENT_HELLO";
        case STATE_SENT_SERVER_HELLO: return "SENT_SERVER_HELLO";
        case STATE_SENT_ENCRYPTED_EXTENSIONS: return "SENT_ENCRYPTED_EXTENSIONS";
        case STATE_SENT_CERTIFICATE: return "SENT_CERTIFICATE";
        case STATE_SENT_CERTIFICATE_VERIFY: return "SENT_CERTIFICATE_VERIFY";
        case STATE_SENT_FINISHED: return "SENT_FINISHED";
        case STATE_HANDSHAKE_COMPLETE: return "HANDSHAKE_COMPLETE";
        case STATE_ALERT_SENT: return "ALERT_SENT";
        case STATE_ERROR: return "ERROR";
        default: return "UNKNOWN";
    }
}

int axon_state_is_valid_transition(axon_state_t from, axon_state_t to) {
    switch (from) {
        case STATE_INIT:
            return to == STATE_WAITING_CLIENT_HELLO;
        case STATE_WAITING_CLIENT_HELLO:
            return to == STATE_SENT_SERVER_HELLO || to == STATE_ALERT_SENT;
        case STATE_SENT_SERVER_HELLO:
            return to == STATE_SENT_ENCRYPTED_EXTENSIONS || to == STATE_ALERT_SENT;
        case STATE_SENT_ENCRYPTED_EXTENSIONS:
            return to == STATE_SENT_CERTIFICATE || to == STATE_ALERT_SENT;
        case STATE_SENT_CERTIFICATE:
            return to == STATE_SENT_CERTIFICATE_VERIFY || to == STATE_ALERT_SENT;
        case STATE_SENT_CERTIFICATE_VERIFY:
            return to == STATE_SENT_FINISHED || to == STATE_ALERT_SENT;
        case STATE_SENT_FINISHED:
            return to == STATE_HANDSHAKE_COMPLETE || to == STATE_ALERT_SENT;
        case STATE_HANDSHAKE_COMPLETE:
            return to == STATE_HANDSHAKE_COMPLETE || to == STATE_ALERT_SENT;
        default:
            return 0;
    }
}