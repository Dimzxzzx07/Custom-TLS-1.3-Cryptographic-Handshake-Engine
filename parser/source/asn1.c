#include "asn1.h"
#include "secure.h"
#include <stdlib.h>
#include <string.h>

static int asn1_read_length(const uint8_t** data, size_t* remaining, uint32_t* length) {
    if (*remaining < 1) return -1;
    
    uint8_t first = **data;
    (*data)++;
    (*remaining)--;
    
    if (first < 0x80) {
        *length = first;
        return 0;
    }
    
    uint8_t num_bytes = first & 0x7F;
    if (num_bytes > 4 || *remaining < num_bytes) return -1;
    
    *length = 0;
    for (uint8_t i = 0; i < num_bytes; i++) {
        *length = (*length << 8) | **data;
        (*data)++;
        (*remaining)--;
    }
    
    return 0;
}

static int asn1_parse_node(asn1_node_t** node, const uint8_t** data, size_t* remaining) {
    if (*remaining < 1) return -1;
    
    asn1_node_t* new_node = (asn1_node_t*)secure_alloc(sizeof(asn1_node_t));
    if (!new_node) return -1;
    memset(new_node, 0, sizeof(asn1_node_t));
    
    new_node->tag = **data;
    (*data)++;
    (*remaining)--;
    
    if (asn1_read_length(data, remaining, &new_node->length) < 0) {
        secure_free(new_node, sizeof(asn1_node_t));
        return -1;
    }
    
    if (*remaining < new_node->length) {
        secure_free(new_node, sizeof(asn1_node_t));
        return -1;
    }
    
    if (new_node->tag & ASN1_CONSTRUCTED) {
        const uint8_t* child_data = *data;
        size_t child_remaining = new_node->length;
        asn1_node_t* last_child = NULL;
        
        while (child_remaining > 0) {
            asn1_node_t* child = NULL;
            if (asn1_parse_node(&child, &child_data, &child_remaining) < 0) {
                asn1_free(new_node);
                return -1;
            }
            
            if (!new_node->children) {
                new_node->children = child;
            } else if (last_child) {
                last_child->next = child;
            }
            last_child = child;
        }
        
        *data += new_node->length;
        *remaining -= new_node->length;
    } else {
        new_node->value = (uint8_t*)secure_alloc(new_node->length);
        if (!new_node->value) {
            secure_free(new_node, sizeof(asn1_node_t));
            return -1;
        }
        memcpy(new_node->value, *data, new_node->length);
        *data += new_node->length;
        *remaining -= new_node->length;
    }
    
    *node = new_node;
    return 0;
}

int asn1_parse(asn1_node_t** root, const uint8_t* data, size_t len) {
    if (!root || !data || len == 0) return -1;
    
    const uint8_t* ptr = data;
    size_t remaining = len;
    
    return asn1_parse_node(root, &ptr, &remaining);
}

void asn1_free(asn1_node_t* node) {
    if (!node) return;
    
    asn1_free(node->children);
    asn1_free(node->next);
    
    if (node->value) {
        secure_free(node->value, node->length);
    }
    secure_free(node, sizeof(asn1_node_t));
}

asn1_node_t* asn1_find(asn1_node_t* node, uint8_t tag) {
    if (!node) return NULL;
    
    if (node->tag == tag) return node;
    
    asn1_node_t* found = asn1_find(node->children, tag);
    if (found) return found;
    
    return asn1_find(node->next, tag);
}

int asn1_get_integer(asn1_node_t* node, uint32_t* out) {
    if (!node || !out || node->tag != ASN1_INTEGER || !node->value || node->length > 4) return -1;
    
    *out = 0;
    for (size_t i = 0; i < node->length; i++) {
        *out = (*out << 8) | node->value[i];
    }
    return 0;
}

int asn1_get_oid(asn1_node_t* node, uint32_t* oid, size_t* oid_len) {
    if (!node || !oid || !oid_len || node->tag != ASN1_OBJECT_IDENTIFIER || !node->value) return -1;
    
    *oid_len = 0;
    size_t i = 0;
    while (i < node->length && *oid_len < 32) {
        uint32_t val = 0;
        while (i < node->length && (node->value[i] & 0x80)) {
            val = (val << 7) | (node->value[i] & 0x7F);
            i++;
        }
        if (i < node->length) {
            val = (val << 7) | node->value[i];
            i++;
        }
        oid[(*oid_len)++] = val;
    }
    return 0;
}

int asn1_get_string(asn1_node_t* node, uint8_t** out, size_t* out_len) {
    if (!node || !out || !out_len || !node->value) return -1;
    
    if (node->tag != ASN1_OCTET_STRING && node->tag != ASN1_UTF8_STRING &&
        node->tag != ASN1_PRINTABLE_STRING && node->tag != ASN1_IA5_STRING) {
        return -1;
    }
    
    *out = node->value;
    *out_len = node->length;
    return 0;
}
