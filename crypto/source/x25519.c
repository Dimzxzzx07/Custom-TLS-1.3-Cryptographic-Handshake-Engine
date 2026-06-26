#include <stdint.h>
#include <string.h>
#include "../include/x25519.h"

/* ------------------------------------------------------------------ *
 * Minimal Curve25519 / X25519 implementation (RFC 7748)
 * Field: GF(2^255 - 19), using 32-bit limbs for portability
 * ------------------------------------------------------------------ */

/* Clamp scalar per RFC 7748 §5 */
static void clamp(uint8_t* k) {
    k[0]  &= 248;
    k[31] &= 127;
    k[31] |= 64;
}

/* 64-bit multiplication helpers */
typedef unsigned __int128 uint128_t;

typedef struct { uint64_t v[5]; } fe; /* 51-bit limbs */

static void fe_frombytes(fe* out, const uint8_t* in) {
    uint64_t load64(const uint8_t* p) {
        return (uint64_t)p[0]       | ((uint64_t)p[1] << 8)
             | ((uint64_t)p[2]<<16) | ((uint64_t)p[3]<<24)
             | ((uint64_t)p[4]<<32) | ((uint64_t)p[5]<<40)
             | ((uint64_t)p[6]<<48) | ((uint64_t)p[7]<<56);
    }
    uint64_t mask51 = (1ULL << 51) - 1;
    uint64_t h0 = load64(in +  0) & mask51;
    uint64_t h1 = (load64(in +  6) >> 3)  & mask51;
    uint64_t h2 = (load64(in + 12) >> 6)  & mask51;
    uint64_t h3 = (load64(in + 19) >> 1)  & mask51;
    uint64_t h4 = (load64(in + 24) >> 12) & mask51;
    out->v[0]=h0; out->v[1]=h1; out->v[2]=h2; out->v[3]=h3; out->v[4]=h4;
}

static void fe_tobytes(uint8_t* out, const fe* h) {
    uint64_t t0=h->v[0], t1=h->v[1], t2=h->v[2], t3=h->v[3], t4=h->v[4];
    /* Reduce */
    t1 += t0 >> 51; t0 &= (1ULL<<51)-1;
    t2 += t1 >> 51; t1 &= (1ULL<<51)-1;
    t3 += t2 >> 51; t2 &= (1ULL<<51)-1;
    t4 += t3 >> 51; t3 &= (1ULL<<51)-1;
    t0 += 19*(t4 >> 51); t4 &= (1ULL<<51)-1;
    t1 += t0 >> 51; t0 &= (1ULL<<51)-1;
    /* Pack */
    out[ 0]=(uint8_t)(t0);       out[ 1]=(uint8_t)(t0>>8);
    out[ 2]=(uint8_t)(t0>>16);   out[ 3]=(uint8_t)(t0>>24);
    out[ 4]=(uint8_t)(t0>>32);   out[ 5]=(uint8_t)(t0>>40);
    out[ 6]=(uint8_t)((t0>>48)|(t1<<3));
    out[ 7]=(uint8_t)(t1>>5);    out[ 8]=(uint8_t)(t1>>13);
    out[ 9]=(uint8_t)(t1>>21);   out[10]=(uint8_t)(t1>>29);
    out[11]=(uint8_t)(t1>>37);   out[12]=(uint8_t)(t1>>45);
    out[13]=(uint8_t)((t1>>51)|(t2<<2));
    out[14]=(uint8_t)(t2>>6);    out[15]=(uint8_t)(t2>>14);
    out[16]=(uint8_t)(t2>>22);   out[17]=(uint8_t)(t2>>30);
    out[18]=(uint8_t)(t2>>38);   out[19]=(uint8_t)((t2>>46)|(t3<<1));
    out[20]=(uint8_t)(t3>>7);    out[21]=(uint8_t)(t3>>15);
    out[22]=(uint8_t)(t3>>23);   out[23]=(uint8_t)(t3>>31);
    out[24]=(uint8_t)(t3>>39);   out[25]=(uint8_t)((t3>>47)|(t4<<4));
    out[26]=(uint8_t)(t4>>4);    out[27]=(uint8_t)(t4>>12);
    out[28]=(uint8_t)(t4>>20);   out[29]=(uint8_t)(t4>>28);
    out[30]=(uint8_t)(t4>>36);   out[31]=(uint8_t)(t4>>44);
}

static void fe_add(fe* out, const fe* a, const fe* b) {
    for(int i=0;i<5;i++) out->v[i]=a->v[i]+b->v[i];
}
static void fe_sub(fe* out, const fe* a, const fe* b) {
    uint64_t c = 2*((1ULL<<51)-1);
    out->v[0]=a->v[0]-b->v[0]+c+38;
    out->v[1]=a->v[1]-b->v[1]+c;
    out->v[2]=a->v[2]-b->v[2]+c;
    out->v[3]=a->v[3]-b->v[3]+c;
    out->v[4]=a->v[4]-b->v[4]+c;
}
static void fe_mul(fe* out, const fe* a, const fe* b) {
    uint128_t t0=0,t1=0,t2=0,t3=0,t4=0;
    for(int i=0;i<5;i++){
        uint64_t ai=a->v[i];
        t0+=(uint128_t)ai*b->v[(0-i+5)%5]*(i?19:1);
        t1+=(uint128_t)ai*b->v[(1-i+5)%5]*(i>1?19:1);
        t2+=(uint128_t)ai*b->v[(2-i+5)%5]*(i>2?19:1);
        t3+=(uint128_t)ai*b->v[(3-i+5)%5]*(i>3?19:1);
        t4+=(uint128_t)ai*b->v[(4-i+5)%5];
    }
    uint64_t mask=(1ULL<<51)-1;
    out->v[0]=(uint64_t)(t0&mask)+19*(uint64_t)(t4>>51);
    out->v[1]=(uint64_t)(t1&mask)+(uint64_t)(t0>>51);
    out->v[2]=(uint64_t)(t2&mask)+(uint64_t)(t1>>51);
    out->v[3]=(uint64_t)(t3&mask)+(uint64_t)(t2>>51);
    out->v[4]=(uint64_t)(t4&mask)+(uint64_t)(t3>>51);
}
static void fe_sq(fe* out, const fe* a) { fe_mul(out,a,a); }
static void fe_cswap(fe* a, fe* b, uint64_t swap) {
    uint64_t mask=-(swap&1);
    for(int i=0;i<5;i++){
        uint64_t t=(a->v[i]^b->v[i])&mask;
        a->v[i]^=t; b->v[i]^=t;
    }
}

/* Constant-time X25519 scalar mult (Montgomery ladder) */
static void x25519_ladder(uint8_t* out, const uint8_t* scalar, const uint8_t* point) {
    fe x1,x2,z2,x3,z3,tmp0,tmp1;
    uint8_t k[32];
    memcpy(k, scalar, 32);
    clamp(k);

    fe_frombytes(&x1, point);
    x2.v[0]=1; x2.v[1]=x2.v[2]=x2.v[3]=x2.v[4]=0;
    z2.v[0]=0; z2.v[1]=z2.v[2]=z2.v[3]=z2.v[4]=0;
    x3=x1;
    z3.v[0]=1; z3.v[1]=z3.v[2]=z3.v[3]=z3.v[4]=0;

    uint64_t swap=0;
    for(int i=254;i>=0;i--){
        uint64_t bit=((uint64_t)k[i/8]>>(i&7))&1;
        uint64_t xswap=swap^bit;
        fe_cswap(&x2,&x3,xswap);
        fe_cswap(&z2,&z3,xswap);
        swap=bit;
        fe_sub(&tmp0,&x3,&z3);
        fe_sub(&tmp1,&x2,&z2);
        fe_add(&x2,&x2,&z2);
        fe_add(&z2,&x3,&z3);
        fe_mul(&z3,&tmp0,&x2);
        fe_mul(&z2,&z2,&tmp1);
        fe_sq(&tmp0,&tmp1);
        fe_sq(&tmp1,&x2);
        fe_add(&x3,&z3,&z2);
        fe_sub(&z2,&z3,&z2);
        fe_mul(&x2,&tmp1,&tmp0);
        fe_sub(&tmp1,&tmp1,&tmp0);
        fe_sq(&z2,&z2);
        /* A24 = 121665 */
        fe a24; a24.v[0]=121665; a24.v[1]=a24.v[2]=a24.v[3]=a24.v[4]=0;
        fe_mul(&z3,&tmp1,&a24);
        fe_sq(&x3,&x3);
        fe_add(&tmp0,&tmp0,&z3);
        fe_mul(&z3,&x1,&z2);
        fe_mul(&z2,&tmp1,&tmp0);
    }
    fe_cswap(&x2,&x3,swap);
    fe_cswap(&z2,&z3,swap);

    /* z2^(p-2) via Fermat, p-2 = 2^255-21 */
    fe z2inv,t0,t1;
    fe_sq(&t0,&z2);
    fe_mul(&t1,&t0,&z2);
    for(int i=0;i<5;i++) t0.v[i]=t1.v[i];
    for(int i=1;i<254;i++){ fe_sq(&t0,&t0); if(i==1||i==3) fe_mul(&t0,&t0,&z2); }
    z2inv=t0;
    fe_mul(&x2,&x2,&z2inv);
    fe_tobytes(out,&x2);
}

/* Basepoint for X25519 */
static const uint8_t BASE_POINT[32] = {9};

int x25519_scalar_mult(uint8_t* out, const uint8_t* scalar, const uint8_t* point) {
    if(!out||!scalar||!point) return -1;
    x25519_ladder(out, scalar, point);
    return 0;
}

int x25519_generate_keypair(uint8_t* private_key, uint8_t* public_key) {
    if(!private_key||!public_key) return -1;
    /* private_key must already be filled with random bytes by caller */
    clamp(private_key);
    x25519_ladder(public_key, private_key, BASE_POINT);
    return 0;
}

int x25519_shared_secret(const uint8_t* private_key, const uint8_t* peer_public_key, uint8_t* shared_secret) {
    if(!private_key||!peer_public_key||!shared_secret) return -1;
    uint8_t k[32];
    memcpy(k, private_key, 32);
    x25519_ladder(shared_secret, k, peer_public_key);
    return 0;
}
