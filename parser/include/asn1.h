#ifndef ASN1_H
#define ASN1_H

#include <stdint.h>
#include <stddef.h>

#define ASN1_BOOLEAN 0x01
#define ASN1_INTEGER 0x02
#define ASN1_BIT_STRING 0x03
#define ASN1_OCTET_STRING 0x04
#define ASN1_NULL 0x05
#define ASN1_OBJECT_IDENTIFIER 0x06
#define ASN1_UTF8_STRING 0x0C
#define ASN1_SEQUENCE 0x10
#define ASN1_SET 0x11
#define ASN1_PRINTABLE_STRING 0x13
#define ASN1_T61_STRING 0x14
#define ASN1_IA5_STRING 0x16
#define ASN1_UTC_TIME 0x17
#define ASN1_GENERALIZED_TIME 0x18
#define ASN1_UNIVERSAL_STRING 0x1C
#define ASN1_BMP_STRING 0x1E
#define ASN1_CONSTRUCTED 0x20

typedef struct asn1_node {
    uint8_t tag;
    uint32_t length;
    uint8_t* value;
    struct asn1_node* children;
    struct asn1_node* next;
} asn1_node_t;

int asn1_parse(asn1_node_t** root, const uint8_t* data, size_t len);
void asn1_free(asn1_node_t* node);
asn1_node_t* asn1_find(asn1_node_t* node, uint8_t tag);
int asn1_get_integer(asn1_node_t* node, uint32_t* out);
int asn1_get_oid(asn1_node_t* node, uint32_t* oid, size_t* oid_len);
int asn1_get_string(asn1_node_t* node, uint8_t** out, size_t* out_len);

#endif