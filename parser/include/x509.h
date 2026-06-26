#ifndef X509_H
#define X509_H

#include "asn1.h"
#include <stdint.h>
#include <stddef.h>

typedef struct x509_cert {
    uint8_t* der_data;
    size_t der_len;
    uint8_t serial_number[20];
    size_t serial_len;
    uint8_t issuer[256];
    size_t issuer_len;
    uint8_t subject[256];
    size_t subject_len;
    uint8_t not_before[16];
    uint8_t not_after[16];
    uint8_t public_key[256];
    size_t public_key_len;
    uint8_t signature[256];
    size_t signature_len;
    uint8_t signature_algorithm[16];
    size_t sig_algo_len;
} x509_cert_t;

int x509_parse_certificate(x509_cert_t* cert, const uint8_t* data, size_t len);
int x509_verify_signature(x509_cert_t* cert, const uint8_t* data, size_t len, const uint8_t* signature, size_t sig_len);
int x509_get_subject_alt_name(x509_cert_t* cert, char** names, size_t* count);
void x509_free_certificate(x509_cert_t* cert);

#endif