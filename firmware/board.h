/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 NFClab contributors.
 */
#ifndef NFCLAB_BOARD_H
#define NFCLAB_BOARD_H

/* Hardware capability, NOT a request to change the CPU/USB clock tree.
 * Current PCB leaves ST25R3916B MCU_CLK disconnected. Future board builds
 * may override these definitions after the actual routing is finalized.
 * GPIO/pin describe wiring only; no pin or timer is configured here.
 */
#ifndef NFCLAB_NFC_MCU_CLK_CONNECTED
#define NFCLAB_NFC_MCU_CLK_CONNECTED 0
#endif
#ifndef NFCLAB_NFC_MCU_CLK_GPIO
#define NFCLAB_NFC_MCU_CLK_GPIO 0u
#endif
#ifndef NFCLAB_NFC_MCU_CLK_PIN
#define NFCLAB_NFC_MCU_CLK_PIN 0xffffffffu
#endif
#if NFCLAB_NFC_MCU_CLK_CONNECTED != 0 && NFCLAB_NFC_MCU_CLK_CONNECTED != 1
#error "NFCLAB_NFC_MCU_CLK_CONNECTED must be 0 or 1"
#endif
#if NFCLAB_NFC_MCU_CLK_CONNECTED
#if NFCLAB_NFC_MCU_CLK_GPIO == 0 || NFCLAB_NFC_MCU_CLK_PIN > 15
#error "Connected MCU_CLK requires the future PCB GPIO base and pin"
#endif
#elif NFCLAB_NFC_MCU_CLK_GPIO != 0 || NFCLAB_NFC_MCU_CLK_PIN != 0xffffffffu
#error "Disconnected MCU_CLK must not claim a routed GPIO/pin"
#endif

#define NFCLAB_NFC_TX_CLOCK_LOCAL 0u
#define NFCLAB_NFC_TX_CLOCK_FIELD 1u
#ifndef NFCLAB_NFC_TX_CLOCK_SOURCE
#define NFCLAB_NFC_TX_CLOCK_SOURCE NFCLAB_NFC_TX_CLOCK_LOCAL
#endif
/* Reserve field-clock selection without claiming a driver exists. Replace
 * this guard only alongside a real, validated field-clock timing backend.
 */
#if NFCLAB_NFC_TX_CLOCK_SOURCE == NFCLAB_NFC_TX_CLOCK_FIELD
#error "Field-synchronous NFC timing backend is not implemented yet"
#elif NFCLAB_NFC_TX_CLOCK_SOURCE != NFCLAB_NFC_TX_CLOCK_LOCAL
#error "Unknown NFC transmit clock source"
#endif

struct nfc_timing_diagnostics {
 uint32_t version, mcu_clk_connected, mcu_clk_gpio, mcu_clk_pin;
 uint32_t tx_clock_source, field_sync_available;
};

/* ST25R3916B H1.7 -> WeAct PA0 (formerly PB0). Keep MISO on PA6:
   both receive signals can be sampled in one GPIOA IDR DMA transfer.
   EXTI0's vector and mask stay unchanged; only its port selection changes. */
#define NFC_IRQ_GPIO 0x40020000u
#define NFC_IRQ_PIN 0u
#define NFC_IRQ_EXTI_PORT 0u /* SYSCFG EXTICR1: GPIOA */
static inline uint32_t nfc_irq_level(void) {
 return (R(NFC_IRQ_GPIO+0x10)>>NFC_IRQ_PIN)&1u;
}

#endif
