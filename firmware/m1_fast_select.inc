/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 NFClab contributors.
 */
/* Re-select a known UID without cycling the RF field or anticollision. */
#include "m1_timing.h"
static void m1_select_wait(void) {
 if (m1_timing.enabled && !m1_timing.guard_mode) return;
 uint32_t start=cycles(); delay_us(300);
 if (m1_timing.enabled) m1_timing.fixed_wait+=(uint32_t)(cycles()-start);
}
/* Return the card to IDLE so the next WUPA is answered.
 *
 * A card that just completed an authentication stays AUTHENTICATED and ignores
 * WUPA until it is halted, and the HALT must itself be sent encrypted with the
 * session cipher.  The frame is {0x50, 0x00, crc_lo, crc_hi} encrypted with a
 * zero feedback byte, matching proxmark3's
 * `mifare_sendcmd_short(pcs, CRYPT_ALL, ISO14443A_CMD_HALT, 0x00, ...)`.
 * The card sends no answer, so the result is deliberately ignored and no error
 * or timeout counter is touched.
 *
 * Without this the re-select falls back to cycling the RF field: measured at
 * ~24 ms per key hit instead of ~1.3 ms, which was over half of every key
 * batch.  Only this "about to re-select" path halts, so callers that keep a
 * session open on purpose (nested authentication, bulk reads) are unaffected.
 */
static void m1_classic_halt(struct crypto1 *cipher) {
 if (!cipher) return;
 uint8_t plain[4], tx[M1_RAW_BYTES], rx[4];
 plain[0]=0x50; plain[1]=0x00;
 uint16_t crc=crc_a(plain,2);
 plain[2]=(uint8_t)crc; plain[3]=(uint8_t)(crc>>8);
 unsigned bits=m1_encode(cipher,plain,4,0,tx);
 (void)transceive_bits(0xc5,tx,bits,0xc0,rx,sizeof(rx));
}
static int m1_fast_select(uint32_t expected_uid, struct crypto1 *cipher) {
 uint8_t tx[7], rx[16]; unsigned length=card.uid_length;
 if (!card.field_on || (length!=4 && length!=7 && length!=10)) return 0;
 uint32_t cuid=0;
 for (unsigned i=length-4;i<length;i++) cuid=(cuid<<8)|card.uid[i];
 if (cuid!=expected_uid) return 0;
 card.error=0; card.polls++;
 uint32_t start=cycles();
 int received=transceive(0xc7,0,0,1,rx,sizeof(rx));
 if (received!=2) {
  m1_classic_halt(cipher);
  received=transceive(0xc7,0,0,1,rx,sizeof(rx));
 }
 if (m1_timing.enabled) m1_timing.wupa+=(uint32_t)(cycles()-start);
 if (received!=2) return 0; /* WUPA */
 if (rx[0]!=card.atqa[0] || rx[1]!=card.atqa[1]) return 0;
 m1_select_wait();
 unsigned levels=(length-1)/3;
 for (unsigned level=0;level<levels;level++) {
  tx[0]=0x93+level*2; tx[1]=0x70;
  int cascade=level+1<levels;
  for (unsigned i=0;i<4;i++)
   tx[2+i]=cascade?(i?card.uid[level*3+i-1]:0x88):card.uid[level*3+i];
  tx[6]=tx[2]^tx[3]^tx[4]^tx[5];
  start=cycles();
  received=transceive(0xc4,tx,7,0,rx,sizeof(rx));
  if (m1_timing.enabled) m1_timing.select+=(uint32_t)(cycles()-start);
  if (received!=3) return 0;
  uint16_t crc=crc_a(rx,1);
  if (rx[1]!=(uint8_t)crc || rx[2]!=(uint8_t)(crc>>8) ||
      !!(rx[0]&4)!=cascade || (!cascade && rx[0]!=0x08)) return 0;
  m1_select_wait();
 }
 card.found=1; return 1;
}
