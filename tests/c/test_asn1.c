#include "../parser/include/asn1.h"
#include "../parser/include/x509.h"
#include <stdio.h>
#include <string.h>

int main(void) {
    uint8_t test_asn1[64] = {0x30, 0x1A, 0x02, 0x01, 0x05, 0x04, 0x04, 0x74, 0x65, 0x73, 0x74};
    asn1_node_t* root = NULL;
    
    int ret = asn1_parse(&root, test_asn1, 11);
    if (ret < 0) {
        printf("FAIL: ASN.1 parse\n");
        return 1;
    }
    
    asn1_node_t* int_node = asn1_find(root, 0x02);
    if (!int_node) {
        printf("FAIL: ASN.1 find integer\n");
        asn1_free(root);
        return 1;
    }
    
    uint32_t int_val = 0;
    ret = asn1_get_integer(int_node, &int_val);
    if (ret < 0 || int_val != 5) {
        printf("FAIL: ASN.1 get integer\n");
        asn1_free(root);
        return 1;
    }
    
    printf("PASS: ASN.1 parser works\n");
    asn1_free(root);
    
    x509_cert_t cert;
    uint8_t test_cert[256] = {0x30, 0x03, 0x02, 0x01, 0x01};
    ret = x509_parse_certificate(&cert, test_cert, 5);
    if (ret < 0) {
        printf("FAIL: X.509 parse\n");
        return 1;
    }
    
    printf("PASS: X.509 parser works\n");
    x509_free_certificate(&cert);
    
    return 0;
}