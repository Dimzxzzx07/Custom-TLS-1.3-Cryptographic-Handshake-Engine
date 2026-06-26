module memory;

import core.stdc.string;

extern(C) void* secure_alloc(size_t size) {
    void* ptr = malloc(size);
    if (ptr !is null) {
        memset(ptr, 0, size);
    }
    return ptr;
}

extern(C) void secure_free(void* ptr, size_t size) {
    if (ptr !is null) {
        volatile ubyte* p = cast(ubyte*)ptr;
        for (size_t i = 0; i < size; i++) {
            p[i] = 0;
        }
        free(ptr);
    }
}
