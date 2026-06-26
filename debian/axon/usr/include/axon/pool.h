#ifndef MEMORY_POOL_H
#define MEMORY_POOL_H

#include <stddef.h>
#include <stdint.h>

typedef struct memory_pool {
    void* memory;
    size_t total_size;
    size_t used;
    size_t block_size;
    uint8_t* bitmap;
    size_t bitmap_size;
} memory_pool_t;

int memory_pool_init(memory_pool_t* pool, size_t size, size_t block_size);
void memory_pool_destroy(memory_pool_t* pool);
void* memory_pool_alloc(memory_pool_t* pool);
void memory_pool_free(memory_pool_t* pool, void* ptr);
void memory_pool_reset(memory_pool_t* pool);
size_t memory_pool_available(memory_pool_t* pool);
size_t memory_pool_used(memory_pool_t* pool);

#endif