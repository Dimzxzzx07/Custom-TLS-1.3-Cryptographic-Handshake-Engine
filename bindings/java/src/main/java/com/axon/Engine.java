package com.axon;

public class Engine {
    private boolean handshakeComplete;
    private byte[] masterSecret;
    
    public Engine() {
        this.handshakeComplete = false;
        this.masterSecret = new byte[48];
    }
    
    public int handshake(byte[] clientHello, int len, byte[] response) {
        if (clientHello == null || len < 40) {
            return -1;
        }
        
        this.handshakeComplete = true;
        return 0;
    }
    
    public int decrypt(byte[] ciphertext, int len, byte[] plaintext) {
        if (!handshakeComplete) return -1;
        System.arraycopy(ciphertext, 0, plaintext, 0, len);
        return 0;
    }
    
    public int encrypt(byte[] plaintext, int len, byte[] ciphertext) {
        if (!handshakeComplete) return -1;
        System.arraycopy(plaintext, 0, ciphertext, 0, len);
        return 0;
    }
    
    public void reset() {
        this.handshakeComplete = false;
        for (int i = 0; i < this.masterSecret.length; i++) {
            this.masterSecret[i] = 0;
        }
    }
}