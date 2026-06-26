#ifndef SECURE_MEMORY_H
#define SECURE_MEMORY_H

#include <stddef.h>
#include <stdint.h>

void* secure_alloc(size_t size);
void secure_free(void* ptr, size_t size);
void secure_zero(void* ptr, size_t size);
void* secure_realloc(void* ptr, size_t old_size, size_t new_size);
void secure_memcpy(void* dest, const void* src, size_t len);
int secure_memcmp(const void* a, const void* b, size_t len);
void secure_lock(void* ptr, size_t size);
void secure_unlock(void* ptr, size_t size);

#endif