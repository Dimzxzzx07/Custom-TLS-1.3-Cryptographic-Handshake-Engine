#include "../include/constant.h"
#include <string.h>

uint32_t constant_time_eq(uint32_t a, uint32_t b) {
    uint32_t diff = a ^ b;
    diff = (diff >> 1) | (diff & 1);
    diff = (diff >> 1) | (diff & 1);
    diff = (diff >> 1) | (diff & 1);
    diff = (diff >> 1) | (diff & 1);
    diff = (diff >> 1) | (diff & 1);
    return (diff ^ 1) & 1;
}

uint32_t constant_time_lt(uint32_t a, uint32_t b) {
    return (a < b) ? 1 : 0;
}

uint32_t constant_time_ge(uint32_t a, uint32_t b) {
    return (a >= b) ? 1 : 0;
}

uint32_t constant_time_select(uint32_t mask, uint32_t true_val, uint32_t false_val) {
    return (mask & true_val) | (~mask & false_val);
}

uint8_t constant_time_memcmp(const uint8_t* a, const uint8_t* b, size_t len) {
    uint8_t result = 0;
    for (size_t i = 0; i < len; i++) {
        result |= a[i] ^ b[i];
    }
    return result == 0 ? 0 : 1;
}

void constant_time_memcpy(uint8_t* dest, const uint8_t* src, size_t len, uint32_t condition) {
    uint32_t mask = condition ? 0xFFFFFFFF : 0;
    for (size_t i = 0; i < len; i++) {
        dest[i] = (dest[i] & ~mask) | (src[i] & mask);
    }
}

uint32_t constant_time_msb(uint32_t value) {
    return (value >> 31) & 1;
}