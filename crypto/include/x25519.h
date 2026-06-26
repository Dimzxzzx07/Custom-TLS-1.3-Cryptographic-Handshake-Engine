#ifndef X25519_H
#define X25519_H

#include <stdint.h>
#include <stddef.h>

int x25519_generate_keypair(uint8_t* private_key, uint8_t* public_key);
int x25519_shared_secret(const uint8_t* private_key, const uint8_t* peer_public_key, uint8_t* shared_secret);
int x25519_scalar_mult(uint8_t* out, const uint8_t* scalar, const uint8_t* point);

#endif