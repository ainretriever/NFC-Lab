/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 NFClab contributors.
 */
#ifndef NFCLAB_M1_TIMING_H
#define NFCLAB_M1_TIMING_H
/* Batch-local profiling; no logging, shared only by the main-loop RF path. */
struct m1_timing {
 uint64_t selection, wupa, select, fixed_wait, guard_wait, nt_rf, ar_rf;
 uint32_t response_min, response_max, responses, enabled, guard_mode, phase;
 uint32_t guard_start, guard_rx_end, has_start, has_rx;
};
static struct m1_timing m1_timing;
#endif
