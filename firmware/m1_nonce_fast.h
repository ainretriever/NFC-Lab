/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 NFClab contributors.
 */
#ifndef NFCLAB_M1_NONCE_FAST_H
#define NFCLAB_M1_NONCE_FAST_H
/* Abort an unknown-key nested authentication with a deliberately incomplete
   reader response. PM3 CHK_TIMEOUT uses one byte + 1 ms authentication-failure
   recovery. NRT only shortens this deliberately unanswered dummy frame; restore
   the general 4.83 ms NRT before any real SELECT or AUTH. */
static int m1_nonce_abort(void) {
 uint8_t plain=0,tx[M1_RAW_BYTES],rx[4];
 unsigned bits=m1_encode(0,&plain,1,0,tx);
 int configured=write_reg(0x10,0);
 configured&=write_reg(0x11,43);
 uint32_t start=cycles();
 if (configured) (void)transceive_bits(0xc5,tx,bits,0xc0,rx,sizeof(rx));
 /* 1.2 ms from submission covers the short TX + >=1 ms recovery. */
 while ((uint32_t)(cycles()-start)<(core_hz/1000000)*1200u) {}
 int io_ok=card.error!=7;
 int high=write_reg(0x10,4),low=write_reg(0x11,0);
 return configured && io_ok && high && low;
}
#endif
