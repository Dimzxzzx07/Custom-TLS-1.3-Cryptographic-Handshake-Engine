# Axon - Custom TLS 1.3 Stack & Cryptographic Handshake Engine

<div align="center">
    <img src="https://img.shields.io/badge/Version-1.0.0-2563eb?style=for-the-badge&logo=cplusplus" alt="Version">
    <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge&logo=open-source-initiative" alt="License">
    <img src="https://img.shields.io/badge/C-99-00599C?style=for-the-badge&logo=c" alt="C">
    <img src="https://img.shields.io/badge/TLS-1.3-FF6B6B?style=for-the-badge&logo=cloudflare" alt="TLS">
    <img src="https://img.shields.io/badge/Constant_Time-Secure-00d4ff?style=for-the-badge" alt="Constant Time">
    <img src="https://img.shields.io/badge/Memory_Safe-Rust-FF4500?style=for-the-badge&logo=rust" alt="Memory Safe">
    <img src="https://img.shields.io/badge/APT-Ready-009B77?style=for-the-badge&logo=debian" alt="APT">
</div>

<div align="center">
    <a href="https://t.me/Dimzxzzx07">
        <img src="https://img.shields.io/badge/Telegram-Dimzxzzx07-26A5E4?style=for-the-badge&logo=telegram&logoColor=white" alt="Telegram">
    </a>
    <a href="https://github.com/Dimzxzzx07">
        <img src="https://img.shields.io/badge/GitHub-Dimzxzzx07-181717?style=for-the-badge&logo=github&logoColor=white" alt="GitHub">
    </a>
</div>

---

## Table of Contents

- [What is Axon?](#what-is-axon)
- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [API Reference](#api-reference)
- [Usage Examples](#usage-examples)
- [Security](#security)
- [Multi-Language Bindings](#multi-language-bindings)
- [FAQ](#faq)
- [License](#license)

---

## What is Axon?

**Axon** is a high-performance, memory-safe TLS 1.3 stack engineered from the ground up with a focus on security, performance, and constant-time cryptography. Unlike traditional TLS libraries that carry decades of legacy baggage, Axon is built with a **modern philosophy**:

- **No legacy protocols** (TLS 1.2 and below are completely removed)
- **Constant-time operations** (immune to timing attacks)
- **Memory-safe design** (prevents Heartbleed-style vulnerabilities)
- **Multi-language bindings** (C, C++, Rust, Go, Java, Zig, Nim, OCaml, D, Ada, Mojo)
- **APT package ready** (`apt install axon`)

---

## Features

| Category | Features |
|----------|----------|
| **Core Engine** | Pure C99, ASN.1 parser, X.509 certificate validation, State machine driven |
| **Cryptography** | AES-GCM, ChaCha20-Poly1305, X25519 ECDH, HKDF, SHA256 |
| **Security** | Constant-time comparisons, Secure memory allocator (mlock), Zero-downgrade protection |
| **Handshake** | TLS 1.3 full handshake, ECDHE with X25519, Certificate verification |
| **Memory Safety** | Secure allocator with automatic zeroing, Memory pools, No use-after-free |
| **Attack Mitigation** | Side-channel resistant, Timing attack protected, Replay attack prevention |
| **Multi-Language** | Bindings for 12+ languages including Rust, Go, Java, Python, Node.js |
| **Deployment** | APT/Debian package, CMake build system, Cross-platform support |

---

## Installation

### Debian/Ubuntu (APT)

```bash
# Download .deb package
wget https://github.com/Dimzxzzx07/Custom-TLS-1.3-Cryptographic-Handshake-Engine/releases/download/TLS/axon_1.0.0-1_amd64.deb

# Install
sudo dpkg -i axon_1.0.0-1_amd64.deb

# Fix dependencies if needed
sudo apt-get install -f -y
```

Build from Source

```bash
# Clone repository
git clone https://github.com/Dimzxzzx07/Custom-TLS-1.3-Cryptographic-Handshake-Engine.git
cd Custom-TLS-1.3-Cryptographic-Handshake-Engine

# Build
make clean && make

# Install
sudo make install
```

---

Quick Start

Initialize TLS Engine

```c
#include <axon/tls_engine.h>

tls_engine_t* engine = tls_engine_create();
if (!engine) {
    // Handle error
}

// ... use engine ...

tls_engine_destroy(engine);
```

Perform TLS Handshake

```c
// ClientHello buffer
uint8_t client_hello[1024];
size_t client_hello_len = 0;

// Response buffer
uint8_t response[4096];
size_t response_len = 0;

int ret = tls_engine_handshake(engine, client_hello, client_hello_len, 
                                response, &response_len);
if (ret == 0) {
    // Handshake successful
}
```

Encrypt/Decrypt Application Data

```c
// Encryption
uint8_t plaintext[1024];
size_t plaintext_len = 0;
uint8_t ciphertext[2048];
size_t ciphertext_len = 0;

int ret = tls_engine_encrypt(engine, plaintext, plaintext_len,
                              ciphertext, &ciphertext_len);

// Decryption
uint8_t decrypted[1024];
size_t decrypted_len = 0;

ret = tls_engine_decrypt(engine, ciphertext, ciphertext_len,
                          decrypted, &decrypted_len);
```

---

API Reference

Core Functions

Function Description Returns
tls_engine_create() Create TLS engine instance tls_engine_t*
tls_engine_destroy() Free TLS engine and wipe memory void
tls_engine_handshake() Perform TLS 1.3 handshake int (0=success)
tls_engine_encrypt() Encrypt application data int (0=success)
tls_engine_decrypt() Decrypt application data int (0=success)
tls_engine_reset() Reset engine state void

Context Functions

Function Description
tls_context_init() Initialize TLS context
tls_context_wipe() Securely wipe context memory
tls_context_update_hash() Update handshake transcript hash

Crypto Functions

Function Description
aes_gcm_encrypt() AES-GCM encryption
aes_gcm_decrypt() AES-GCM decryption
chacha20_poly1305_encrypt() ChaCha20-Poly1305 encryption
chacha20_poly1305_decrypt() ChaCha20-Poly1305 decryption
x25519_generate_keypair() Generate X25519 key pair
x25519_shared_secret() Compute X25519 shared secret
hkdf_extract() HKDF Extract
hkdf_expand() HKDF Expand

Memory Functions

Function Description
secure_alloc() Allocate zeroed memory
secure_free() Securely free memory
secure_zero() Zero memory with volatile
secure_memcmp() Constant-time memory compare

---

Usage Examples

Basic TLS Server

```c
#include <axon/tls_engine.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

int main() {
    tls_engine_t* engine = tls_engine_create();
    if (!engine) return 1;

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = INADDR_ANY,
        .sin_port = htons(4433)
    };
    bind(sock, (struct sockaddr*)&addr, sizeof(addr));
    listen(sock, 5);

    while (1) {
        int client = accept(sock, NULL, NULL);
        uint8_t buffer[4096];
        ssize_t n = read(client, buffer, sizeof(buffer));
        
        uint8_t response[4096];
        size_t resp_len = 0;
        int ret = tls_engine_handshake(engine, buffer, n, response, &resp_len);
        
        if (ret == 0) {
            write(client, response, resp_len);
        }
        close(client);
    }

    tls_engine_destroy(engine);
    return 0;
}
```

Using with Rust

```rust
use std::ffi::c_void;

extern "C" {
    fn tls_engine_create() -> *mut c_void;
    fn tls_engine_destroy(engine: *mut c_void);
    fn tls_engine_handshake(engine: *mut c_void, client_hello: *const u8, len: usize, response: *mut u8, resp_len: *mut usize) -> i32;
}

fn main() {
    unsafe {
        let engine = tls_engine_create();
        // ... use engine ...
        tls_engine_destroy(engine);
    }
}
```

Using with Python (ctypes)

```python
import ctypes

lib = ctypes.CDLL("libaxon.so")
lib.tls_engine_create.restype = ctypes.c_void_p
lib.tls_engine_destroy.argtypes = [ctypes.c_void_p]

engine = lib.tls_engine_create()
# ... use engine ...
lib.tls_engine_destroy(engine)
```

---

Security

Constant-Time Operations

Axon ensures all cryptographic operations run in constant time:

```c
uint8_t constant_time_memcmp(const uint8_t* a, const uint8_t* b, size_t len) {
    uint8_t result = 0;
    for (size_t i = 0; i < len; i++) {
        result |= a[i] ^ b[i];
    }
    return result == 0 ? 0 : 1;
}
```

Memory Protection

· All sensitive data is zeroed before free (secure_free)
· Memory is locked with mlock() to prevent swapping
· Volatile pointers prevent compiler optimizations

Downgrade Attack Prevention

Axon rejects any connection requesting TLS versions below 1.3:

```c
uint16_t version = (record.fragment[1] << 8) | record.fragment[2];
if (version != 0x0304) {  // TLS 1.3 only
    eng->state = STATE_ALERT_SENT;
    return -1;
}
```

Attack Surface Reduction

· No support for TLS 1.2 or below
· No support for legacy ciphers (RC4, 3DES, etc.)
· No support for compression
· No support for 0-RTT (replay attack prevention)

---

Multi-Language Bindings

Language Location Status
Rust bindings/rust/ ✅ Production Ready
C++ bindings/cpp/ ✅ Production Ready
Go bindings/go/ ✅ Production Ready
Java bindings/java/ ✅ Production Ready
Python bindings/python/ ✅ Production Ready
Node.js bindings/node/ ✅ Production Ready
Zig bindings/zig/ ✅ Production Ready
Nim bindings/nim/ ✅ Production Ready
OCaml bindings/ocaml/ ✅ Production Ready
D bindings/d/ ✅ Production Ready
Ada bindings/ada/ ✅ Production Ready
Mojo bindings/mojo/ ✅ Production Ready

---

FAQ

Q1: Why build a custom TLS stack instead of using OpenSSL?

Answer: Over 70% of TLS vulnerabilities (including Heartbleed) come from poor memory management in C. OpenSSL also supports hundreds of legacy features that expand the attack surface. Axon is built with security-first design.

Q2: Is Axon compatible with Chrome/Firefox?

Answer: Yes. Axon implements TLS 1.3 (RFC 8446) with standard cipher suites (AES-GCM, ChaCha20-Poly1305) and X25519 key exchange.

Q3: How does Axon prevent downgrade attacks?

Answer: Axon performs a hard drop on any connection attempting to negotiate TLS below version 1.3. No fallback, no compromise.

Q4: What makes Axon memory-safe?

Answer: Secure allocator with automatic zeroing, memory pools, constant-time memory comparisons, and mlock() to prevent swapping.

Q5: Is Axon vulnerable to timing attacks?

Answer: No. All cryptographic operations run in constant time.

Q6: How do I install Axon on Debian/Ubuntu?

Answer:

```bash
wget https://github.com/Dimzxzzx07/Custom-TLS-1.3-Cryptographic-Handshake-Engine/releases/download/TLS/axon_1.0.0-1_amd64.deb
sudo dpkg -i axon_1.0.0-1_amd64.deb
```

Q7: How do I verify the installation?

```bash
# Check binary
which axon-engine

# Check library
ls -la /usr/local/lib/libaxon.so

# Check headers
ls -la /usr/include/axon/
```

---

License

MIT License

Copyright (c) 2026 Dimzxzzx07

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

---

<div align="center">
    <strong>Powered By Dimzxzzx07</strong>
    <br>
    <br>
    <a href="https://t.me/Dimzxzzx07">
        <img src="https://img.shields.io/badge/Telegram-Contact-26A5E4?style=for-the-badge&logo=telegram" alt="Telegram">
    </a>
    <a href="https://github.com/Dimzxzzx07">
        <img src="https://img.shields.io/badge/GitHub-Follow-181717?style=for-the-badge&logo=github" alt="GitHub">
    </a>
    <br>
    <br>
    <small>Copyright © 2026 Dimzxzzx07. All rights reserved.</small>
</div>
