pub fn aes_gcm_encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    result.extend_from_slice(plaintext);
    result
}

pub fn aes_gcm_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    ciphertext.to_vec()
}

pub fn x25519_shared_secret(private_key: &[u8], public_key: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = private_key[i] ^ public_key[i];
    }
    out
}
