#include <cstring>
#include <algorithm>

namespace tls {
namespace handshake {

bool parse_client_hello(const uint8_t* data, size_t len, uint8_t* client_random) {
    if (!data || len < 40) return false;
    std::memcpy(client_random, data + 4, 32);
    return true;
}

void build_server_hello(uint8_t* out, size_t* out_len, const uint8_t* server_random) {
    out[0] = 0x02;
    out[1] = 0x03;
    out[2] = 0x04;
    std::memcpy(out + 3, server_random, 32);
    *out_len = 35;
}

}
}
