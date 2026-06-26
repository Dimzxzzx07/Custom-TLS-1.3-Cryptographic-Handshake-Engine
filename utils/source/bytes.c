#include "bytes.h"
#include <string.h>

uint16_t bytes_to_uint16(const uint8_t* bytes) {
    if (!bytes) return 0;
    return (bytes[0] << 8) | bytes[1];
}

uint32_t bytes_to_uint32(const uint8_t* bytes) {
    if (!bytes) return 0;
    return (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
}

uint64_t bytes_to_uint64(const uint8_t* bytes) {
    if (!bytes) return 0;
    return ((uint64_t)bytes[0] << 56) | ((uint64_t)bytes[1] << 48) |
           ((uint64_t)bytes[2] << 40) | ((uint64_t)bytes[3] << 32) |
           ((uint64_t)bytes[4] << 24) | ((uint64_t)bytes[5] << 16) |
           ((uint64_t)bytes[6] << 8) | bytes[7];
}

void uint16_to_bytes(uint16_t value, uint8_t* bytes) {
    if (!bytes) return;
    bytes[0] = (value >> 8) & 0xFF;
    bytes[1] = value & 0xFF;
}

void uint32_to_bytes(uint32_t value, uint8_t* bytes) {
    if (!bytes) return;
    bytes[0] = (value >> 24) & 0xFF;
    bytes[1] = (value >> 16) & 0xFF;
    bytes[2] = (value >> 8) & 0xFF;
    bytes[3] = value & 0xFF;
}

void uint64_to_bytes(uint64_t value, uint8_t* bytes) {
    if (!bytes) return;
    bytes[0] = (value >> 56) & 0xFF;
    bytes[1] = (value >> 48) & 0xFF;
    bytes[2] = (value >> 40) & 0xFF;
    bytes[3] = (value >> 32) & 0xFF;
    bytes[4] = (value >> 24) & 0xFF;
    bytes[5] = (value >> 16) & 0xFF;
    bytes[6] = (value >> 8) & 0xFF;
    bytes[7] = value & 0xFF;
}

void bytes_xor(uint8_t* out, const uint8_t* a, const uint8_t* b, size_t len) {
    if (!out || !a || !b) return;
    for (size_t i = 0; i < len; i++) {
        out[i] = a[i] ^ b[i];
    }
}

void bytes_xor_inplace(uint8_t* a, const uint8_t* b, size_t len) {
    if (!a || !b) return;
    for (size_t i = 0; i < len; i++) {
        a[i] ^= b[i];
    }
}

int bytes_equal(const uint8_t* a, const uint8_t* b, size_t len) {
    if (!a || !b) return 0;
    for (size_t i = 0; i < len; i++) {
        if (a[i] != b[i]) return 0;
    }
    return 1;
}

void bytes_reverse(uint8_t* bytes, size_t len) {
    if (!bytes || len < 2) return;
    for (size_t i = 0; i < len / 2; i++) {
        uint8_t temp = bytes[i];
        bytes[i] = bytes[len - 1 - i];
        bytes[len - 1 - i] = temp;
    }
}

void bytes_clear(uint8_t* bytes, size_t len) {
    if (bytes && len > 0) {
        volatile uint8_t* p = (volatile uint8_t*)bytes;
        for (size_t i = 0; i < len; i++) {
            p[i] = 0;
        }
    }
}
