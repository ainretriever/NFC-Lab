/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef NFCLAB_M1_CODEC_H
#define NFCLAB_M1_CODEC_H
#include "crypto1.h"
#define M1_MAX_BYTES 18u
#define M1_RAW_BYTES 21u
static inline uint8_t raw_bit(const uint8_t *raw, unsigned bit) {
 return (raw[bit/8]>>(bit%8))&1;
}
static inline void raw_put(uint8_t *raw, unsigned bit, uint8_t value) {
 raw[bit/8]|=(value&1)<<(bit%8);
}
/* Each data byte is LSB-first, followed by its explicit parity bit. */
static int m1_encode(struct crypto1 *s, const uint8_t *plain, unsigned len,
                     unsigned feedback_bytes, uint8_t raw[M1_RAW_BYTES]) {
 if (!len || len>M1_MAX_BYTES || feedback_bytes>len) return 0;
 for (unsigned i=0;i<M1_RAW_BYTES;i++) raw[i]=0;
 for (unsigned i=0;i<len;i++) {
  uint8_t byte=plain[i], parity=odd_parity(byte);
  if (s) {
   byte^=crypto1_byte(s,i<feedback_bytes?plain[i]:0,0);
   parity^=crypto1_filter(s->odd);
  }
  for (unsigned b=0;b<8;b++) raw_put(raw,9*i+b,byte>>b);
  raw_put(raw,9*i+8,parity);
 }
 return (int)(len*9);
}
/* Parity consumes no cipher clock. Verify every parity bit in software. */
static int m1_decode(struct crypto1 *s, const uint8_t *raw, unsigned bits,
                     uint8_t *plain, unsigned capacity) {
 if (!bits || bits%9 || bits/9>capacity || bits/9>M1_MAX_BYTES) return 0;
 unsigned len=bits/9;
 int valid=1;
 for (unsigned i=0;i<len;i++) {
  uint8_t byte=0, parity=raw_bit(raw,9*i+8);
  for (unsigned b=0;b<8;b++) byte|=raw_bit(raw,9*i+b)<<b;
  if (s) { byte^=crypto1_byte(s,0,0); parity^=crypto1_filter(s->odd); }
  plain[i]=byte;
  if (parity!=odd_parity(byte)) valid=0;
 }
 return valid?(int)len:-1;
}
/* ACK/NAK uses four data bits without parity; every bit advances Crypto1. */
static int m1_nibble(struct crypto1 *s, const uint8_t *raw, unsigned bits, uint8_t *out) {
 if (bits!=4) return 0;
 *out=0;
 for (unsigned i=0;i<4;i++) {
  uint8_t bit=raw_bit(raw,i);
  if (s) bit^=crypto1_bit(s,0,0);
  *out|=bit<<i;
 }
 return 1;
}
#endif
