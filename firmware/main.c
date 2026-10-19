/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 NFClab contributors.
 */
#include <stdint.h>
#define R(a) (*(volatile uint32_t *)(a))
#define GPIOA 0x40020000u
#include "board.h"
#define SPI1 0x40013000u
#define RCC 0x40023800u
extern uint32_t _estack, _sidata, _sdata, _edata, _sbss, _ebss;
void Reset_Handler(void);
void EXTI0_Handler(void);
void OTG_FS_IRQHandler(void);
void HardFault_Handler(void);
void Default_Handler(void) { for (;;) {} }
/* Vector index = IRQ number + 16. EXTI0 is IRQ 6, OTG_FS is IRQ 67. */
__attribute__((section(".isr_vector"),used))
const uintptr_t vectors[84] = {
 (uintptr_t)&_estack, (uintptr_t)Reset_Handler,
 [2]=(uintptr_t)Default_Handler,
 [3]=(uintptr_t)HardFault_Handler,
 [4]=(uintptr_t)Default_Handler,
 [5]=(uintptr_t)Default_Handler,
 [6]=(uintptr_t)Default_Handler,
 [22]=(uintptr_t)EXTI0_Handler,
 [83]=(uintptr_t)OTG_FS_IRQHandler
};
/* All fields are 32-bit so OpenOCD can inspect with mdw. */
struct diagnostics {
 uint32_t magic, version, attempts, valid, invalid, timeouts;
 uint32_t last_id, first_id, changes, consecutive_valid, irq_level, spi_hz;
 uint32_t rw_pass, rw_fail, rw_original, rw_restored;
 uint32_t irq_trials, irq_pass, irq_fail, exti_edges, irq_status;
 uint32_t irq_high, irq_low_after_clear, op_final, test_errors, ready;
 uint32_t clock_src; /* 0 = HSI16, 1 = HSE (25 MHz crystal). */
 uint32_t fault_cfsr, fault_hfsr, fault_pc, fault_lr;
};
volatile struct diagnostics diag;
/* Separate symbol preserves all existing diagnostic/mailbox offsets.
 * Wiring metadata is deliberately separate from implemented timing support.
 */
volatile struct nfc_timing_diagnostics nfc_timing;
/* Latch the fault cause into diag before dying: a silent HardFault costs far
   more debugging time than four words of RAM. */
static void fault_report(uint32_t *frame) __attribute__((used,noreturn));
static void fault_report(uint32_t *frame) {
 diag.fault_cfsr=R(0xe000ed28);
 diag.fault_hfsr=R(0xe000ed2c);
 diag.fault_pc=frame[6];
 diag.fault_lr=frame[5];
 for (;;) {}
}
__attribute__((naked,noreturn)) void HardFault_Handler(void) {
 __asm__ volatile ("tst lr, #4\n\tite eq\n\tmrseq r0, msp\n\tmrsne r0, psp\n\tb fault_report\n\t");
}
static uint32_t core_hz=16000000;
static int clock_wait(uint32_t address, uint32_t mask, uint32_t value) {
 for (unsigned i=0;i<160000;i++) if ((R(address)&mask)==value) return 1;
 return 0;
}
static int pll_start(uint32_t pllm, uint32_t source_bit) {
 /* PLLQ=4 keeps the 48 MHz USB clock valid for both sources. */
 R(RCC+4)=pllm|(192u<<6)|(4u<<24)|source_bit;
 R(RCC)|=1u<<24;
 if (!clock_wait(RCC,1u<<25,1u<<25)) return 0;
 if (!clock_wait(0x40007004,1u<<14,1u<<14)) return 0;
 R(RCC+8)=(R(RCC+8)&~((15u<<4)|(7u<<10)|(7u<<13)|3u))|(4u<<10)|2u;
 return clock_wait(RCC+8,3u<<2,2u<<2);
}
static int clock_init(void) {
 /* Scale 1, Flash 3 WS + ART, AHB96/APB1 48/APB2 96 MHz. VDD measured 3.26 V.
    USB full speed needs much better than HSI's 1%, so prefer the 25 MHz crystal
    and keep HSI as a fallback: PLL M25 or M16, both N192/P2/Q4 = 96 MHz + 48 MHz. */
 R(RCC+0x40)|=1u<<28;
 R(0x40007000)=(R(0x40007000)&~(3u<<14))|(3u<<14);
 R(0x40023c00)=3u|(1u<<8)|(1u<<9)|(1u<<10);
 if (!clock_wait(0x40023c00,7,3)) return 0;
 R(RCC)|=1u<<16; /* HSEON */
 if (clock_wait(RCC,1u<<17,1u<<17)) {
  diag.clock_src=1;
  if (pll_start(25u,1u<<22)) { core_hz=96000000; return 1; }
  R(RCC)&=~(1u<<24); R(RCC)&=~(1u<<16); /* PLL and HSE back off before HSI retry */
  diag.clock_src=0;
 }
 if (!pll_start(16u,0)) return 0;
 core_hz=96000000;
 return 1;
}
static void delay_ms(uint32_t ms) {
 while (ms--) {
  R(0xe000e010)=0; R(0xe000e014)=core_hz/1000-1; R(0xe000e018)=0;
  R(0xe000e010)=5;
  while (!(R(0xe000e010)&(1u<<16))) {}
 }
 R(0xe000e010)=0;
}
static void delay_us(unsigned us) {
 uint32_t start=R(0xe0001004);
 while ((uint32_t)(R(0xe0001004)-start)<(core_hz/1000000)*us) {}
}
static int wait_spi(uint32_t mask, uint32_t value) {
 for (uint32_t n=0;n<160000;n++)
  if ((R(SPI1+8)&mask)==value) return 1;
 return 0;
}
static int exchange(uint8_t tx, uint8_t *rx) {
 if (!wait_spi(2,2)) return 0;
 *(volatile uint8_t *)(SPI1+12)=tx;
 if (!wait_spi(1,1)) return 0;
 *rx=*(volatile uint8_t *)(SPI1+12);
 return 1;
}
static unsigned spi_div=7;
static void spi_init(void) {
 R(RCC+0x30)|=3; R(RCC+0x44)|=1u<<12;
 R(RCC+0x24)|=1u<<12; R(RCC+0x24)&=~(1u<<12);
 R(GPIOA+0x18)=1u<<4; /* Raise CS before enabling output. */
 uint32_t mode=R(GPIOA);
 mode &= ~((3u<<8)|(3u<<10)|(3u<<12)|(3u<<14));
 R(GPIOA)=mode|(1u<<8)|(2u<<10)|(2u<<12)|(2u<<14);
 R(GPIOA+4)&=~(15u<<4);
 R(GPIOA+0x0c)&=~(255u<<8);
 R(GPIOA+8)=(R(GPIOA+8)&~(255u<<8))|(0xaau<<8);
 R(GPIOA+0x20)=(R(GPIOA+0x20)&~0xfff00000u)|0x55500000u;
 R(NFC_IRQ_GPIO)&=~(3u<<(NFC_IRQ_PIN*2)); /* PA0 IRQ input. */
 R(NFC_IRQ_GPIO+0x0c)&=~(3u<<(NFC_IRQ_PIN*2));
 /* APB2 = core clock; startup SPI /256 = 390.625 kHz. Mode 1. */
 R(SPI1)=1u|(1u<<2)|(spi_div<<3)|(1u<<8)|(1u<<9);
 R(SPI1)|=1u<<6;
}
static int set_spi_div(unsigned value) {
 if (value>4 || !wait_spi(0x80,0)) return 0;
 R(SPI1)&=~(1u<<6);
 /* API divider refers to the original 16 MHz clock. Choose the fastest
    actual divider not exceeding its requested 0.5..8 MHz SPI ceiling. */
 uint32_t ceiling=16000000u>>(value+1);
 spi_div=0;
 while ((core_hz>>(spi_div+1))>ceiling && spi_div<7) spi_div++;
 R(SPI1)=(R(SPI1)&~(7u<<3))|(spi_div<<3);
 R(SPI1)|=1u<<6;
 diag.spi_hz=core_hz>>(spi_div+1);
 return 1;
}
static int transfer(uint8_t command, uint8_t value, uint8_t *rx) {
 uint8_t dummy;
 R(GPIOA+0x18)=1u<<20;
 for (volatile unsigned n=0;n<16;n++) {}
 int ok=exchange(command,&dummy) && exchange(value,rx) && wait_spi(0x80,0);
 for (volatile unsigned n=0;n<16;n++) {}
 R(GPIOA+0x18)=1u<<4;
 if (!ok) { diag.timeouts++; spi_init(); }
 return ok;
}
static int read_reg(uint8_t address, uint8_t *value) {
 return transfer(0x40|address,0,value);
}
static int write_reg(uint8_t address, uint8_t value) {
 uint8_t dummy;
 return transfer(address,value,&dummy);
}
static int read_identity(uint8_t *id) { return read_reg(0x3f,id); }
void EXTI0_Handler(void) {
 if (R(0x40013c14)&1) {
  R(0x40013c14)=1;
  diag.exti_edges++;
 }
}
static void exti_init(void) {
 R(RCC+0x44)|=1u<<14; /* SYSCFG */
 R(0x40013808)=(R(0x40013808)&~15u)|NFC_IRQ_EXTI_PORT; /* EXTI0 = PA0 */
 R(0x40013c00)|=1; R(0x40013c08)|=1; R(0x40013c0c)&=~1u;
 R(0x40013c14)=1;
 R(0xe000e100)=1u<<6; /* NVIC EXTI0 */
}
static void rw_test(void) {
 uint8_t original=0, value=0;
 if (!read_reg(0x0f,&original)) { diag.test_errors|=1; return; }
 diag.rw_original=original;
 for (unsigned pattern=0;pattern<256;pattern++) {
  if (write_reg(0x0f,(uint8_t)pattern) && read_reg(0x0f,&value)
      && value==pattern) diag.rw_pass++;
  else diag.rw_fail++;
 }
 int ok=write_reg(0x0f,original) && read_reg(0x0f,&value);
 diag.rw_restored=ok && value==original;
 if (!diag.rw_restored) diag.test_errors|=2;
}
static void irq_test(void) {
 uint8_t masks[4], value=0, status=0;
 unsigned saved=0;
 int ok=1;
 diag.irq_trials++;
 /* Stop oscillator and all RF functions; retain power-down after test. */
 if (!write_reg(0x02,0)) { diag.test_errors|=4; ok=0; }
 delay_ms(5);
 for (;saved<4;saved++) {
  if (!read_reg(0x16+saved,&masks[saved])) { ok=0; break; }
 }
 if (saved!=4) goto cleanup;
 /* Mask every implemented source except oscillator stable. RFU bits stay zero. */
 if (!(write_reg(0x16,0x7e) && write_reg(0x17,0xff)
       && write_reg(0x18,0xfe) && write_reg(0x19,0xfb))) { ok=0; goto cleanup; }
 for (unsigned i=0;i<4;i++) if (!read_reg(0x1a+i,&value)) ok=0;
 delay_ms(1);
 if (nfc_irq_level()) ok=0;
 R(0x40013c14)=1;
 uint32_t edges=diag.exti_edges;
 if (!write_reg(0x02,0x80)) { ok=0; goto cleanup; }
 for (unsigned n=0;n<100 && !nfc_irq_level();n++) delay_ms(1);
 diag.irq_high=nfc_irq_level();
 if (!diag.irq_high || diag.exti_edges!=edges+1) ok=0;
 if (!read_reg(0x1a,&status)) ok=0;
 diag.irq_status=status;
 if (status!=0x80) ok=0;
 delay_ms(1);
 diag.irq_low_after_clear=!nfc_irq_level();
 if (!diag.irq_low_after_clear) ok=0;
 if (!read_reg(0x1a,&value) || value!=0) ok=0;
cleanup:
 if (!write_reg(0x02,0)) { ok=0; diag.test_errors|=4; }
 for (unsigned i=0;i<saved;i++) if (!write_reg(0x16+i,masks[i])) ok=0;
 if (!read_reg(0x02,&value) || value!=0) { ok=0; diag.test_errors|=8; }
 diag.op_final=value;
 if (ok) diag.irq_pass++; else diag.irq_fail++;
}
#include "reader.inc"
#include "m1.inc"
#include "m1_fast_select.inc"
#include "m1_bulk.inc"
#include "m1_gen1a_bulk.inc"
#include "m1_auth_write_bulk.inc"
#include "m1_keys.inc"
#include "m1_magic.inc"
#include "m1_recover.inc"
#include "usb_cdc.inc"
#include "usb_proto.inc"
#include "sniff.inc"
#include "uid_sim.inc"
/* Idle for `ms` while servicing USB continuously.  Servicing once per
   millisecond caps bulk transfers at one 64-byte packet per turn; spinning on
   the DWT counter lets a whole FIFO burst leave per EPENA instead. */
static void idle_wait(uint32_t ms) {
 uint32_t start=cycles();
 uint32_t ticks=(core_hz/1000u)*ms;
 while ((uint32_t)(cycles()-start)<ticks) { usb_task(); usb_service(); }
}
int main(void) {
 nfc_timing.version=1;
 nfc_timing.mcu_clk_connected=NFCLAB_NFC_MCU_CLK_CONNECTED;
 nfc_timing.mcu_clk_gpio=NFCLAB_NFC_MCU_CLK_GPIO;
 nfc_timing.mcu_clk_pin=NFCLAB_NFC_MCU_CLK_PIN;
 nfc_timing.tx_clock_source=NFCLAB_NFC_TX_CLOCK_SOURCE;
 nfc_timing.field_sync_available=0; /* Reserved backend, not implemented. */
 diag.magic=0x4e46434c; diag.version=2; diag.spi_hz=390625;
 if (!clock_init()) { diag.test_errors|=32; return 1; }
 spi_init(); exti_init(); delay_ms(100);
 uint8_t initial_id=0;
 if (read_identity(&initial_id) && (initial_id&0xf8)==0x30) {
  rw_test(); irq_test(); diag.ready=1;
 } else diag.test_errors|=16;
 int reader_ok=diag.ready && reader_init();
 sniff_init();
 m1.magic=0x4d31494f; m1.version=5; m1.clock_hz=core_hz;
 m1_recover.magic=0x4d314e43; m1_recover.version=2;
 m1_keys.magic=0x4d314b59; m1_keys.version=2; m1_keys.clock_hz=core_hz;
 m1_bulk.magic=0x4d314255; m1_bulk.version=2; m1_bulk.reserved=M1_GEN1A_BULK_CAP;
 bench.magic=0x4d31424d; bench.version=1; bench.clock_hz=core_hz;
 if (!reader_ok && !card.error) card.error=7;
 if (!usb_init()) diag.test_errors|=64u;
 uid_sim.magic=UID_SIM_MAGIC; uid_sim.version=1; uid_sim.clock_hz=core_hz;
 for (;;) {
  uid_sim_task();
  if (uid_sim.active || uid_sim_restore_failed) { usb_task(); usb_service(); continue; }
  run_sniff();
  if (reader_ok && !sniff.enabled) { run_select_benchmark(); run_m1(); run_m1_bulk(); run_m1_keys(); run_m1_recover(); }
  usb_task(); usb_service();
  uint8_t id=0;
  int ok=read_identity(&id);
  diag.attempts++;
  if (!ok) { diag.consecutive_valid=0; }
  else {
   if (diag.attempts==1) diag.first_id=id;
   else if (diag.last_id!=id) diag.changes++;
   diag.last_id=id;
   /* DS13541 table 121: type 00110, revision in low three bits. */
   if ((id&0xf8)==0x30) { diag.valid++; diag.consecutive_valid++; }
   else { diag.invalid++; diag.consecutive_valid=0; }
  }
  if (reader_ok && !sniff.enabled && !card.found && !uid_sim_reader_hold) {
   (void)poll_uid();
   if (!write_reg(0x02,0x80)) card.error=7;
   card.field_on=0;
   idle_wait(500);
  }
  diag.irq_level=nfc_irq_level();
  idle_wait(10);
 }
}
void Reset_Handler(void) {
 uint32_t *src=&_sidata;
 for (uint32_t *p=&_sdata;p<&_edata;) *p++=*src++;
 for (uint32_t *p=&_sbss;p<&_ebss;) *p++=0;
 R(0xe000ed08)=0x08000000;
 (void)main();
 for (;;) {}
}
