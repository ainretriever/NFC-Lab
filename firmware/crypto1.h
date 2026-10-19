/* SPDX-License-Identifier: GPL-3.0-or-later
 * Crypto1 core adapted from Proxmark3 common/crapto1/crypto1.c and crapto1.h.
 * Copyright (C) 2008-2014 bla <blapost@gmail.com>
 * Copyright (C) Proxmark3 contributors. See firmware/licenses/GPL-3.0.txt.
 * NFClab: bounded, allocation-free core for STM32F411.
 */
#ifndef NFCLAB_CRYPTO1_H
#define NFCLAB_CRYPTO1_H
#include <stdint.h>
struct crypto1 { uint32_t odd, even; };
static inline uint8_t parity32(uint32_t x) {
 x ^= x>>16; x ^= x>>8; x ^= x>>4;
 return (0x6996u>>(x&15))&1;
}
static inline uint8_t odd_parity(uint8_t x) { return parity32(x)^1; }
static inline uint8_t crypto1_filter(uint32_t x) {
 uint32_t f=(0xf22c0u>>(x&15))&16;
 f|=(0x6c9c0u>>((x>>4)&15))&8;
 f|=(0x3c8b0u>>((x>>8)&15))&4;
 f|=(0x1e458u>>((x>>12)&15))&2;
 f|=(0x0d938u>>((x>>16)&15))&1;
 return (0xec57e80au>>f)&1;
}
static inline void crypto1_init(struct crypto1 *s, const uint8_t key[6]) {
 s->odd=s->even=0;
 for (int i=47;i>0;i-=2) {
  unsigned a=(unsigned)((i-1)^7), b=(unsigned)(i^7);
  s->odd=(s->odd<<1)|((key[5-a/8]>>(a%8))&1);
  s->even=(s->even<<1)|((key[5-b/8]>>(b%8))&1);
 }
}
static inline uint8_t crypto1_bit(struct crypto1 *s, uint8_t in, int encrypted) {
 uint8_t out=crypto1_filter(s->odd);
 uint32_t feed=(out & !!encrypted)^!!in^(0x29ce5cu&s->odd)^(0x870804u&s->even);
 uint32_t t=s->odd;
 s->odd=(s->even<<1)|parity32(feed); s->even=t;
 return out;
}
static inline uint8_t crypto1_byte(struct crypto1 *s, uint8_t in, int encrypted) {
 uint8_t out=0;
 for (unsigned i=0;i<8;i++) out|=crypto1_bit(s,(in>>i)&1,encrypted)<<i;
 return out;
}
static inline uint32_t crypto1_word(struct crypto1 *s, uint32_t in, int encrypted) {
 uint32_t out=0;
 for (unsigned i=0;i<32;i++) out|=(uint32_t)crypto1_bit(s,(in>>(i^24))&1,encrypted)<<(i^24);
 return out;
}
static inline uint32_t crypto1_prng(uint32_t x, unsigned n) {
 x=__builtin_bswap32(x);
 while (n--) x=(x>>1)|((x>>16 ^ x>>18 ^ x>>19 ^ x>>21)<<31);
 return __builtin_bswap32(x);
}
#endif
