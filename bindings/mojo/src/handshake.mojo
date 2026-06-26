struct HandshakeContext:
    var client_random: DTypePointer[DType.uint8]
    var server_random: DTypePointer[DType.uint8]
    var handshake_done: Bool
    
    fn __init__(inout self):
        self.client_random = DTypePointer[DType.uint8].alloc(32)
        self.server_random = DTypePointer[DType.uint8].alloc(32)
        self.handshake_done = False
    
    fn __del__(owned self):
        self.client_random.free()
        self.server_random.free()
    
    fn parse_client_hello(inout self, data: DTypePointer[DType.uint8], len: Int) -> Bool:
        if len < 40:
            return False
        for i in range(32):
            self.client_random[i] = data[4 + i]
        return True
