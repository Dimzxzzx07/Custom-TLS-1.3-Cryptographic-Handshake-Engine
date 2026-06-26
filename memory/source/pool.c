#include "../include/pool.h"
#include "../include/secure.h"
#include <stdlib.h>
#include <string.h>

int memory_pool_init(memory_pool_t* pool, size_t size, size_t block_size) {
    if (!pool || size == 0 || block_size == 0) return -1;
    
    pool->total_size = size;
    pool->block_size = block_size;
    pool->used = 0;
    
    pool->memory = secure_alloc(size);
    if (!pool->memory) return -1;
    
    size_t num_blocks = size / block_size;
    pool->bitmap_size = (num_blocks + 7) / 8;
    pool->bitmap = (uint8_t*)secure_alloc(pool->bitmap_size);
    if (!pool->bitmap) {
        secure_free(pool->memory, size);
        return -1;
    }
    memset(pool->bitmap, 0, pool->bitmap_size);
    
    return 0;
}

void memory_pool_destroy(memory_pool_t* pool) {
    if (pool) {
        if (pool->memory) {
            secure_free(pool->memory, pool->total_size);
        }
        if (pool->bitmap) {
            secure_free(pool->bitmap, pool->bitmap_size);
        }
        memset(pool, 0, sizeof(memory_pool_t));
    }
}

void* memory_pool_alloc(memory_pool_t* pool) {
    if (!pool || !pool->memory || pool->used >= pool->total_size) return NULL;
    
    size_t num_blocks = pool->total_size / pool->block_size;
    for (size_t i = 0; i < num_blocks; i++) {
        size_t byte_idx = i / 8;
        size_t bit_idx = i % 8;
        if (!(pool->bitmap[byte_idx] & (1 << bit_idx))) {
            pool->bitmap[byte_idx] |= (1 << bit_idx);
            pool->used += pool->block_size;
            return (uint8_t*)pool->memory + (i * pool->block_size);
        }
    }
    return NULL;
}

void memory_pool_free(memory_pool_t* pool, void* ptr) {
    if (!pool || !ptr) return;
    
    if (ptr < pool->memory || (uint8_t*)ptr >= (uint8_t*)pool->memory + pool->total_size) return;
    
    size_t offset = (uint8_t*)ptr - (uint8_t*)pool->memory;
    if (offset % pool->block_size != 0) return;
    
    size_t block_idx = offset / pool->block_size;
    size_t byte_idx = block_idx / 8;
    size_t bit_idx = block_idx % 8;
    
    if (pool->bitmap[byte_idx] & (1 << bit_idx)) {
        pool->bitmap[byte_idx] &= ~(1 << bit_idx);
        pool->used -= pool->block_size;
        secure_zero(ptr, pool->block_size);
    }
}

void memory_pool_reset(memory_pool_t* pool) {
    if (pool) {
        memset(pool->bitmap, 0, pool->bitmap_size);
        memset(pool->memory, 0, pool->total_size);
        pool->used = 0;
    }
}

size_t memory_pool_available(memory_pool_t* pool) {
    if (!pool) return 0;
    return pool->total_size - pool->used;
}

size_t memory_pool_used(memory_pool_t* pool) {
    if (!pool) return 0;
    return pool->used;
}