package com.axon;

public class Handshake {
    private byte[] clientRandom;
    private byte[] serverRandom;
    
    public Handshake() {
        this.clientRandom = new byte[32];
        this.serverRandom = new byte[32];
    }
    
    public int parseClientHello(byte[] data, int offset) {
        if (data.length - offset < 34) return -1;
        
        System.arraycopy(data, offset + 4, this.clientRandom, 0, 32);
        return 0;
    }
    
    public int buildServerHello(byte[] out, int offset) {
        out[offset] = (byte)0x02;
        out[offset + 1] = (byte)0x03;
        out[offset + 2] = (byte)0x04;
        return 3;
    }
}