namespace tls {
namespace state {

enum State {
    INIT,
    WAITING_CLIENT_HELLO,
    SENT_SERVER_HELLO,
    HANDSHAKE_COMPLETE,
    ERROR
};

State transition(State current, uint8_t message_type) {
    switch (current) {
        case INIT:
            return (message_type == 0x01) ? WAITING_CLIENT_HELLO : ERROR;
        case WAITING_CLIENT_HELLO:
            return (message_type == 0x02) ? SENT_SERVER_HELLO : ERROR;
        case SENT_SERVER_HELLO:
            return (message_type == 0x14) ? HANDSHAKE_COMPLETE : ERROR;
        default:
            return ERROR;
    }
}

}
}
