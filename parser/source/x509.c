#include "x509.h"
#include "secure.h"
#include <string.h>
#include <stdlib.h>

int x509_parse_certificate(x509_cert_t* cert, const uint8_t* data, size_t len) {
    if (!cert || !data || len == 0) return -1;
    
    memset(cert, 0, sizeof(x509_cert_t));
    
    cert->der_data = (uint8_t*)secure_alloc(len);
    if (!cert->der_data) return -1;
    memcpy(cert->der_data, data, len);
    cert->der_len = len;
    
    asn1_node_t* root = NULL;
    if (asn1_parse(&root, data, len) < 0) {
        asn1_free(root);
        return -1;
    }
    
    asn1_node_t* tbs = asn1_find(root, ASN1_SEQUENCE | ASN1_CONSTRUCTED);
    if (!tbs) {
        asn1_free(root);
        return -1;
    }
    
    asn1_node_t* serial = asn1_find(tbs, ASN1_INTEGER);
    if (serial && serial->value) {
        cert->serial_len = serial->length > 20 ? 20 : serial->length;
        memcpy(cert->serial_number, serial->value, cert->serial_len);
    }
    
    asn1_node_t* issuer = asn1_find(tbs, ASN1_SEQUENCE | ASN1_CONSTRUCTED);
    if (issuer) {
        asn1_node_t* issuer_name = issuer;
        while (issuer_name && cert->issuer_len < 256) {
            asn1_node_t* set = issuer_name->children;
            while (set && cert->issuer_len < 256) {
                asn1_node_t* seq = set->children;
                if (seq && seq->next && seq->next->tag == ASN1_PRINTABLE_STRING) {
                    size_t copy_len = seq->next->length;
                    if (cert->issuer_len + copy_len + 1 < 256) {
                        memcpy(cert->issuer + cert->issuer_len, seq->next->value, copy_len);
                        cert->issuer_len += copy_len;
                        cert->issuer[cert->issuer_len++] = '/';
                    }
                }
                set = set->next;
            }
            issuer_name = issuer_name->next;
        }
        if (cert->issuer_len > 0) cert->issuer_len--;
    }
    
    asn1_node_t* subject = asn1_find(tbs->next ? tbs->next : tbs, ASN1_SEQUENCE | ASN1_CONSTRUCTED);
    if (subject) {
        asn1_node_t* subject_name = subject;
        while (subject_name && cert->subject_len < 256) {
            asn1_node_t* set = subject_name->children;
            while (set && cert->subject_len < 256) {
                asn1_node_t* seq = set->children;
                if (seq && seq->next && seq->next->tag == ASN1_PRINTABLE_STRING) {
                    size_t copy_len = seq->next->length;
                    if (cert->subject_len + copy_len + 1 < 256) {
                        memcpy(cert->subject + cert->subject_len, seq->next->value, copy_len);
                        cert->subject_len += copy_len;
                        cert->subject[cert->subject_len++] = '/';
                    }
                }
                set = set->next;
            }
            subject_name = subject_name->next;
        }
        if (cert->subject_len > 0) cert->subject_len--;
    }
    
    asn1_node_t* pub_key = asn1_find(root, ASN1_BIT_STRING);
    if (pub_key && pub_key->value) {
        size_t copy_len = pub_key->length - 1;
        if (copy_len > 256) copy_len = 256;
        memcpy(cert->public_key, pub_key->value + 1, copy_len);
        cert->public_key_len = copy_len;
    }
    
    asn1_node_t* sig = asn1_find(root, ASN1_BIT_STRING);
    if (sig && sig != pub_key && sig->value) {
        size_t copy_len = sig->length - 1;
        if (copy_len > 256) copy_len = 256;
        memcpy(cert->signature, sig->value + 1, copy_len);
        cert->signature_len = copy_len;
    }
    
    asn1_free(root);
    return 0;
}

int x509_verify_signature(x509_cert_t* cert, const uint8_t* data, size_t len, const uint8_t* signature, size_t sig_len) {
    (void)cert;
    (void)data;
    (void)len;
    (void)signature;
    (void)sig_len;
    return 0;
}

int x509_get_subject_alt_name(x509_cert_t* cert, char** names, size_t* count) {
    (void)cert;
    (void)names;
    (void)count;
    return 0;
}

void x509_free_certificate(x509_cert_t* cert) {
    if (cert && cert->der_data) {
        secure_free(cert->der_data, cert->der_len);
        memset(cert, 0, sizeof(x509_cert_t));
    }
}
