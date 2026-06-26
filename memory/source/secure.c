#include "secure.h"
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

void* secure_alloc(size_t size) {
    if (size == 0) return NULL;
    void* ptr = malloc(size);
    if (ptr) {
        memset(ptr, 0, size);
        mlock(ptr, size);
    }
    return ptr;
}

void secure_free(void* ptr, size_t size) {
    if (ptr && size > 0) {
        munlock(ptr, size);
        volatile uint8_t* p = (volatile uint8_t*)ptr;
        for (size_t i = 0; i < size; i++) {
            p[i] = 0;
        }
        free(ptr);
    }
}

void secure_zero(void* ptr, size_t size) {
    if (ptr && size > 0) {
        volatile uint8_t* p = (volatile uint8_t*)ptr;
        for (size_t i = 0; i < size; i++) {
            p[i] = 0;
        }
    }
}

void* secure_realloc(void* ptr, size_t old_size, size_t new_size) {
    if (new_size == 0) {
        secure_free(ptr, old_size);
        return NULL;
    }
    
    void* new_ptr = secure_alloc(new_size);
    if (new_ptr && ptr && old_size > 0) {
        size_t copy_len = old_size < new_size ? old_size : new_size;
        memcpy(new_ptr, ptr, copy_len);
        secure_free(ptr, old_size);
    }
    return new_ptr;
}

void secure_memcpy(void* dest, const void* src, size_t len) {
    if (dest && src && len > 0) {
        memcpy(dest, src, len);
    }
}

int secure_memcmp(const void* a, const void* b, size_t len) {
    if (!a || !b) return -1;
    uint8_t result = 0;
    const uint8_t* pa = (const uint8_t*)a;
    const uint8_t* pb = (const uint8_t*)b;
    for (size_t i = 0; i < len; i++) {
        result |= pa[i] ^ pb[i];
    }
    return result == 0 ? 0 : 1;
}

void secure_lock(void* ptr, size_t size) {
    (void)ptr;
    (void)size;
}

void secure_unlock(void* ptr, size_t size) {
    (void)ptr;
    (void)size;
}
