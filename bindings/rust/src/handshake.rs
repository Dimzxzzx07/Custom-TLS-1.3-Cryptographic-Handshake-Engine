pub struct HandshakeState {
    pub client_random: [u8; 32],
    pub server_random: [u8; 32],
    pub done: bool,
}

impl HandshakeState {
    pub fn new() -> Self {
        Self {
            client_random: [0; 32],
            server_random: [0; 32],
            done: false,
        }
    }
    
    pub fn parse_client_hello(&mut self, data: &[u8]) -> bool {
        if data.len() < 40 { return false; }
        self.client_random.copy_from_slice(&data[4..36]);
        true
    }
}
