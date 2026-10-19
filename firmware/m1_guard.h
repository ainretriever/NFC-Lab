/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 NFClab contributors.
 */
#ifndef NFCLAB_M1_GUARD_H
#define NFCLAB_M1_GUARD_H
#include "m1_timing.h"
/* NFC-A 106 kbps: request start spacing >=7000/fc, RX end to next
   request >=1172/fc. Small margins cover the nominal HSI cycle conversion.
   TXE timestamp minus minimum wire duration is a conservative start bound. */
static void reader_guard(void) {
 if (!m1_timing.enabled || m1_timing.guard_mode) return;
 uint32_t start=cycles(), per_us=core_hz/1000000;
 while ((m1_timing.has_start && (uint32_t)(cycles()-m1_timing.guard_start)<530u*per_us) ||
        (m1_timing.has_rx && (uint32_t)(cycles()-m1_timing.guard_rx_end)<94u*per_us)) {}
 m1_timing.guard_wait+=(uint32_t)(cycles()-start);
}
#endif
