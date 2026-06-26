pub struct Record {
    pub content_type: u8,
    pub version: u16,
    pub length: u16,
    pub fragment: Vec<u8>,
}

impl Record {
    pub fn new() -> Self {
        Self {
            content_type: 0,
            version: 0x0304,
            length: 0,
            fragment: Vec::new(),
        }
    }
    
    pub fn parse(&mut self, data: &[u8]) -> bool {
        if data.len() < 5 { return false; }
        self.content_type = data[0];
        self.version = ((data[1] as u16) << 8) | (data[2] as u16);
        self.length = ((data[3] as u16) << 8) | (data[4] as u16);
        if data.len() < 5 + self.length as usize { return false; }
        self.fragment = data[5..5 + self.length as usize].to_vec();
        true
    }
}
