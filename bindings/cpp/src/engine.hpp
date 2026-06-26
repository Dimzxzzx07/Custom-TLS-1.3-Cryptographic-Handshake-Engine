#ifndef CPP_ENGINE_HPP
#define CPP_ENGINE_HPP

#include <cstdint>
#include <vector>

namespace tls {

class Engine {
public:
    Engine();
    ~Engine();
    
    int handshake(const uint8_t* client_hello, size_t len, std::vector<uint8_t>& response);
    int decrypt(const uint8_t* ciphertext, size_t len, std::vector<uint8_t>& plaintext);
    int encrypt(const uint8_t* plaintext, size_t len, std::vector<uint8_t>& ciphertext);
    void reset();
    
private:
    class Impl;
    Impl* pImpl;
};

}
#endif