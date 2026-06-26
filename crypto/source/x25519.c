static void fe_invert(uint64_t* out, const uint64_t* a) {
    uint64_t t[5];
    uint64_t temp[5];
    uint64_t square[5];
    uint64_t result[5];
    
    memcpy(t, a, 5 * sizeof(uint64_t));
    memcpy(result, a, 5 * sizeof(uint64_t));
    
    for (int i = 0; i < 254; i++) {
        fe_square(square, result);
        if (i < 253) {
            fe_mul(result, square, a);
        } else {
            memcpy(result, square, 5 * sizeof(uint64_t));
        }
    }
    
    memcpy(out, result, 5 * sizeof(uint64_t));
}