#ifndef BYTE_UTILS_H
#define BYTE_UTILS_H

#include <stdint.h>
#include <stddef.h>

uint16_t bytes_to_uint16(const uint8_t* bytes);
uint32_t bytes_to_uint32(const uint8_t* bytes);
uint64_t bytes_to_uint64(const uint8_t* bytes);
void uint16_to_bytes(uint16_t value, uint8_t* bytes);
void uint32_to_bytes(uint32_t value, uint8_t* bytes);
void uint64_to_bytes(uint64_t value, uint8_t* bytes);
void bytes_xor(uint8_t* out, const uint8_t* a, const uint8_t* b, size_t len);
void bytes_xor_inplace(uint8_t* a, const uint8_t* b, size_t len);
int bytes_equal(const uint8_t* a, const uint8_t* b, size_t len);
void bytes_reverse(uint8_t* bytes, size_t len);
void bytes_clear(uint8_t* bytes, size_t len);

#endif