/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 NFClab contributors.
 */
#ifndef NFCLAB_SNIFF_CODEC_H
#define NFCLAB_SNIFF_CODEC_H
#include <stdint.h>
/* In-place packing, four samples/byte: bit0 IRQ/PA0, bit1 MISO/PA6.
   Writes trail reads, so no extra SRAM is needed. Other GPIOA bits discarded. */
static inline unsigned sniff_pack_channels(uint16_t *samples,unsigned count) {
 uint8_t *out=(uint8_t *)samples;
 unsigned bytes=0;
 for (unsigned i=0;i<count;i+=4) {
  unsigned value=0;
  for (unsigned j=0;j<4 && i+j<count;j++) {
   unsigned word=samples[i+j];
   value|=((word&1u)|((word>>5)&2u))<<(j*2);
  }
  out[bytes++]=(uint8_t)value;
 }
 return bytes;
}
#endif
