from memory import memset_zero

fn constant_time_compare(a: DTypePointer[DType.uint8], b: DTypePointer[DType.uint8], len: Int) -> Bool:
    var result: UInt8 = 0
    for i in range(len):
        result = result | (a[i] ^ b[i])
    return result == 0

fn secure_zero(ptr: DTypePointer[DType.uint8], len: Int):
    memset_zero(ptr, len)
