#ifndef TLS_STATE_H
#define TLS_STATE_H

#include "context.h"

typedef enum {
    STATE_INIT,
    STATE_WAITING_CLIENT_HELLO,
    STATE_SENT_SERVER_HELLO,
    STATE_SENT_ENCRYPTED_EXTENSIONS,
    STATE_SENT_CERTIFICATE,
    STATE_SENT_CERTIFICATE_VERIFY,
    STATE_SENT_FINISHED,
    STATE_WAITING_FINISHED,
    STATE_HANDSHAKE_COMPLETE,
    STATE_ALERT_SENT,
    STATE_ERROR
} tls_state_t;

tls_state_t tls_state_machine(tls_context_t* ctx, tls_state_t current, uint8_t message_type);
const char* tls_state_to_string(tls_state_t state);
int tls_state_is_valid_transition(tls_state_t from, tls_state_t to);

#endif