export interface TLSContext {
    clientRandom: Uint8Array;
    serverRandom: Uint8Array;
    sessionId: Uint8Array;
    masterSecret: Uint8Array;
    handshakeHash: Uint8Array;
    handshakeComplete: boolean;
}

export interface TLSRecord {
    contentType: number;
    version: number;
    length: number;
    fragment: Uint8Array;
}

export type CipherSuite = 0x1301 | 0x1302 | 0x1303;

export const CipherSuites = {
    AES_128_GCM_SHA256: 0x1301,
    AES_256_GCM_SHA384: 0x1302,
    CHACHA20_POLY1305: 0x1303
} as const;

export interface TLSHandshakeMessage {
    msgType: number;
    length: number;
    body: Uint8Array;
}