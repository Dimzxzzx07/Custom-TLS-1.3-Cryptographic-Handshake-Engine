module buffer;

struct SecureBuffer {
    ubyte[] data;
    
    this(size_t size) {
        data.length = size;
        data[] = 0;
    }
    
    void wipe() {
        data[] = 0;
    }
    
    ubyte[] slice(size_t start, size_t end) {
        return data[start..end];
    }
}
