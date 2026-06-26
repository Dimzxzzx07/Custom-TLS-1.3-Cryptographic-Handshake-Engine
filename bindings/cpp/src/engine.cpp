#include "engine.hpp"
#include <cstring>
#include <algorithm>

namespace tls {

class Engine::Impl {
public:
    bool handshake_complete;
    uint8_t key[32];
    
    Impl() : handshake_complete(false) {
        std::memset(key, 0, 32);
    }
};

Engine::Engine() : pImpl(new Impl()) {}

Engine::~Engine() {
    delete pImpl;
}

int Engine::handshake(const uint8_t* client_hello, size_t len, std::vector<uint8_t>& response) {
    if (!client_hello || len == 0) return -1;
    
    response.resize(256);
    for (size_t i = 0; i < 256; i++) {
        response[i] = static_cast<uint8_t>(i & 0xFF);
    }
    
    pImpl->handshake_complete = true;
    return 0;
}

int Engine::decrypt(const uint8_t* ciphertext, size_t len, std::vector<uint8_t>& plaintext) {
    if (!pImpl->handshake_complete) return -1;
    if (!ciphertext || len == 0) return -1;
    
    plaintext.resize(len);
    std::memcpy(plaintext.data(), ciphertext, len);
    return 0;
}

int Engine::encrypt(const uint8_t* plaintext, size_t len, std::vector<uint8_t>& ciphertext) {
    if (!pImpl->handshake_complete) return -1;
    if (!plaintext || len == 0) return -1;
    
    ciphertext.resize(len);
    std::memcpy(ciphertext.data(), plaintext, len);
    return 0;
}

void Engine::reset() {
    pImpl->handshake_complete = false;
    std::memset(pImpl->key, 0, 32);
}

}