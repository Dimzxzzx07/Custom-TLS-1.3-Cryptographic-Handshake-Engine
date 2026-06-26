#ifndef CONSTANT_TIME_H
#define CONSTANT_TIME_H

#include <stdint.h>
#include <stddef.h>

uint32_t constant_time_eq(uint32_t a, uint32_t b);
uint32_t constant_time_lt(uint32_t a, uint32_t b);
uint32_t constant_time_ge(uint32_t a, uint32_t b);
uint32_t constant_time_select(uint32_t mask, uint32_t true_val, uint32_t false_val);
uint8_t constant_time_memcmp(const uint8_t* a, const uint8_t* b, size_t len);
void constant_time_memcpy(uint8_t* dest, const uint8_t* src, size_t len, uint32_t condition);
uint32_t constant_time_msb(uint32_t value);

#endif