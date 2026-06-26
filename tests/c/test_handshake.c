#include "axon_engine.h"
#include "constants.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(void) {
    axon_engine_t* eng = axon_engine_create();
    if (!eng) {
        printf("FAIL: engine create\n");
        return 1;
    }
    
    uint8_t client_hello[1024] = {0};
    size_t client_hello_len = 0;
    
    client_hello[0] = TLS_CONTENT_HANDSHAKE;
    client_hello[1] = 0x03;
    client_hello[2] = 0x04;
    client_hello[3] = 0x00;
    client_hello[4] = 0x01;
    client_hello[5] = TLS_HANDSHAKE_CLIENT_HELLO;
    client_hello[6] = 0x00;
    client_hello[7] = 0x00;
    client_hello[8] = 0x20;
    client_hello[9] = 0x03;
    client_hello[10] = 0x04;
    
    for (int i = 0; i < 32; i++) {
        client_hello[11 + i] = (uint8_t)(i & 0xFF);
    }
    client_hello[43] = 0x00;
    client_hello[44] = 0x02;
    client_hello[45] = 0x13;
    client_hello[46] = 0x01;
    client_hello[47] = 0x01;
    
    client_hello_len = 48;
    client_hello[3] = 0x00;
    client_hello[4] = 0x2B;
    
    uint8_t response[4096] = {0};
    size_t response_len = 0;
    
    int ret = axon_engine_handshake(eng, client_hello, client_hello_len, response, &response_len);
    if (ret < 0) {
        printf("FAIL: handshake failed\n");
        axon_engine_destroy(eng);
        return 1;
    }
    
    printf("PASS: handshake completed, response_len=%zu\n", response_len);
    axon_engine_destroy(eng);
    return 0;
}
