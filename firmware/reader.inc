/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 NFClab contributors.
 */
#include "m1_timing.h"
/* Minimal single-card NFC-A reader. Register definitions: ST DS13541 Rev 11. */
struct card_diagnostics {
 uint32_t magic, version, polls, found, stage, error, spi_errors;
 uint32_t atqa[2], uid_length, uid[10], sak;
 uint32_t irq_main, irq_timer, irq_error, fifo_count, fifo_status;
 uint32_t bcc_received, bcc_computed, oscillator, calibration, field_on;
};
volatile struct card_diagnostics card;
static int transaction(uint8_t cmd, const uint8_t *tx, uint8_t *rx, unsigned len) {
 uint8_t dummy;
 int ok;
 R(GPIOA+0x18)=1u<<20;
 for (volatile unsigned n=0;n<16;n++) {}
 ok=exchange(cmd,&dummy);
 for (unsigned i=0;ok && i<len;i++) {
  uint8_t value=0;
  ok=exchange(tx?tx[i]:0,&value);
  if (ok && rx) rx[i]=value;
 }
 if (ok) ok=wait_spi(0x80,0);
 for (volatile unsigned n=0;n<16;n++) {}
 R(GPIOA+0x18)=1u<<4;
 if (!ok) { card.spi_errors++; spi_init(); }
 return ok;
}
static int command(uint8_t cmd) { return transaction(cmd,0,0,0); }
static int irq_read(uint8_t irq[4]) { return transaction(0x5a,0,irq,4); }
static uint32_t cycles(void) { return R(0xe0001004); }
static int wait_event(unsigned bank, uint8_t bit, unsigned ms) {
 uint32_t start=cycles();
 uint8_t irq[4];
 do {
  if (!irq_read(irq)) return 0;
  if (irq[bank]&bit) return 1;
 } while ((uint32_t)(cycles()-start)<(core_hz/1000)*ms);
 return 0;
}
static int reader_init(void) {
 uint8_t value, irq[4];
 card.magic=0x55494441; card.version=1; card.stage=1;
 R(0xe000edfc)|=1u<<24; R(0xe0001000)|=1; /* DWT elapsed cycles */
 if (!command(0xc0)) return 0;
 delay_ms(2);
 /* Schematic VDD and VDD_TX are 3.3 V, differential antenna. */
 if (!write_reg(0x01,0x80) || !write_reg(0x02,0x80)) return 0;
 if (!wait_event(0,0x80,100)) { card.error=1; return 0; }
 if (!read_reg(0x31,&value)) return 0;
 card.oscillator=value;
 if (!command(0xea) || !wait_event(1,0x80,20)) { card.error=2; return 0; }
 card.calibration=1;
 /* NFC-A reader, OOK, 106 kbps, MRT 56.6 us, NRT 4.83 ms. */
 if (!(write_reg(0x03,0x08) && write_reg(0x04,0)
       && write_reg(0x05,1) && write_reg(0x0a,0)
       && write_reg(0x0f,12) && write_reg(0x10,4)
       && write_reg(0x11,0) && write_reg(0x12,0)
       && write_reg(0x16,0) && write_reg(0x17,0)
       && write_reg(0x18,0) && write_reg(0x19,0))) return 0;
 if (!irq_read(irq)) return 0;
 card.stage=2;
 return 1;
}
#include "m1_guard.h"
/* Exact bit lengths permit custom encrypted parity. Small frames only. */
static int transceive_bits_wait(uint8_t cmd, const uint8_t *tx, unsigned bits,
                           uint8_t framing, uint8_t *rx, unsigned capacity, unsigned wait_ms) {
 uint8_t irq[4], count, status;
 uint8_t main=0, timer=0, errors=0;
 unsigned len=(bits+7)/8;
 card.irq_main=card.irq_timer=card.irq_error=0;
 card.fifo_count=card.fifo_status=0;
 if (len>32 || capacity>64 || !rx || !capacity || (len && !tx)) {
  card.error=6; return -1;
 }
 if (!(command(0xc2) && command(0xdb) && irq_read(irq)
       && write_reg(0x05,framing)
       && write_reg(0x22,(uint8_t)(bits>>8)) && write_reg(0x23,(uint8_t)bits))) goto io_error;
 if (len && !transaction(0x80,tx,0,len)) goto io_error;
 reader_guard();
 if (!command(cmd)) goto io_error;
 uint32_t tx_end=0; int got_tx=0, got_rx_start=0;
 uint32_t start=cycles();
 do {
  if (nfc_irq_level()) {
   if (!irq_read(irq)) goto io_error;
   uint32_t event=cycles();
   if (m1_timing.enabled) {
    if ((irq[0]&0x08) && !got_tx) {
     unsigned wire_bits=bits;
     if (cmd==0xc6 || cmd==0xc7) wire_bits=7;
     else if (!(framing&0x80)) wire_bits+=bits/8;
     if (cmd==0xc4) wire_bits+=18;
     uint32_t minimum=wire_bits*(core_hz/1000000)*12800u/1356u;
     tx_end=event; got_tx=1; m1_timing.guard_start=event-minimum; m1_timing.has_start=1;
    }
    if ((irq[0]&0x20) && !got_rx_start) {
     if (got_tx && !(irq[0]&0x08) && m1_timing.phase==3) {
      uint32_t latency=event-tx_end;
      if (latency<m1_timing.response_min) m1_timing.response_min=latency;
      if (latency>m1_timing.response_max) m1_timing.response_max=latency;
      m1_timing.responses++;
     }
     got_rx_start=1;
    }
    if (irq[0]&0x10) { m1_timing.guard_rx_end=event; m1_timing.has_rx=1; }
   }
   main|=irq[0]; timer|=irq[1]; errors|=irq[2];
   if ((main&0x14) || (timer&0x40) || (errors&0xf0)) break;
  }
 } while ((uint32_t)(cycles()-start)<(core_hz/1000)*wait_ms);
 card.irq_main=main; card.irq_timer=timer; card.irq_error=errors;
 if (!(main&0x10)) { card.error=(main&4)?4:3; return -1; }
 if ((main&4) || (errors&0xf0)) { card.error=5; return -1; }
 if (!read_reg(0x1e,&count) || !read_reg(0x1f,&status)) goto io_error;
 unsigned bytes=count|((unsigned)(status&0xc0)<<2);
 card.fifo_count=bytes; card.fifo_status=status;
 if ((status&0x30) || bytes>capacity || !bytes) { card.error=6; return -1; }
 if (!transaction(0x9f,0,rx,bytes)) goto io_error;
 unsigned tail=(status>>1)&7;
 if (!(framing&0x40) && (tail || (status&1))) { card.error=6; return -1; }
 return (int)(bytes*8-(tail?8-tail:0));
io_error:
 card.error=7; return -1;
}
static int transceive_bits(uint8_t cmd, const uint8_t *tx, unsigned bits,
                           uint8_t framing, uint8_t *rx, unsigned capacity) {
 return transceive_bits_wait(cmd,tx,bits,framing,rx,capacity,20);
}
static int transceive(uint8_t cmd, const uint8_t *tx, unsigned len,
                      int anticollision, uint8_t *rx, unsigned capacity) {
 int bits=transceive_bits(cmd,tx,len*8,anticollision?1:0,rx,capacity);
 return bits<0 ? -1 : bits/8;
}
static uint16_t crc_a(const uint8_t *data, unsigned len) {
 uint16_t crc=0x6363;
 while (len--) {
  uint8_t x=*data++ ^ (uint8_t)crc;
  x^=(uint8_t)(x<<4);
  crc=(crc>>8)^((uint16_t)x<<8)^((uint16_t)x<<3)^(x>>4);
 }
 return crc;
}
static int poll_uid(void) {
 uint8_t rx[16], tx[7], uid[10];
 unsigned uid_len=0;
 card.polls++; card.error=0; card.stage=3;
 /* Each attempt starts with a field reset so REQA also works after SELECT. */
 if (!write_reg(0x02,0x80)) { card.error=7; return 0; }
 card.field_on=0; delay_ms(10);
 if (!write_reg(0x02,0xc8)) { card.error=7; return 0; }
 card.field_on=1; delay_ms(10);
 int received=transceive(0xc6,0,0,1,rx,sizeof(rx));
 if (received!=2) { if (received>=0) card.error=14; return 0; }
 card.atqa[0]=rx[0]; card.atqa[1]=rx[1];
 for (unsigned level=0;level<3;level++) {
  uint8_t sel=(uint8_t)(0x93+level*2);
  card.stage=4+level*2;
  tx[0]=sel; tx[1]=0x20;
  delay_ms(1);
  received=transceive(0xc5,tx,2,1,rx,sizeof(rx));
  if (received!=5) { if (received>=0) card.error=14; return 0; }
  uint8_t bcc=rx[0]^rx[1]^rx[2]^rx[3];
  card.bcc_computed=bcc; card.bcc_received=rx[4];
  if (bcc!=rx[4]) { card.error=8; return 0; }
  int cascade=rx[0]==0x88;
  if (level==2 && cascade) { card.error=9; return 0; }
  for (unsigned i=cascade?1:0;i<4;i++) uid[uid_len++]=rx[i];
  tx[1]=0x70;
  for (unsigned i=0;i<5;i++) tx[2+i]=rx[i];
  card.stage=5+level*2;
  delay_ms(1);
  received=transceive(0xc4,tx,7,0,rx,sizeof(rx));
  /* FIFO keeps SAK plus CRC_A with normal framing; check CRC explicitly. */
  if (received!=3) { if (received>=0) card.error=10; return 0; }
  uint16_t crc=crc_a(rx,1);
  if (rx[1]!=(uint8_t)crc || rx[2]!=(uint8_t)(crc>>8)) { card.error=11; return 0; }
  if (!!(rx[0]&4)!=cascade) { card.error=12; return 0; }
  card.sak=rx[0];
  if (!(rx[0]&4)) {
   for (unsigned i=0;i<uid_len;i++) card.uid[i]=uid[i];
   card.uid_length=uid_len; card.found=1; card.stage=10;
   return 1;
  }
 }
 card.error=13; return 0;
}

/* SWD mailbox: host sets requested while halted, then resumes. No USB per frame. */
struct select_benchmark {
 uint32_t magic, version, requested, running, completed, failures;
 uint32_t last_cycles, min_cycles, max_cycles, total_cycles, clock_hz;
 uint32_t card_type, last_error;
};
volatile struct select_benchmark bench;
static void run_select_benchmark(void) {
 unsigned count=bench.requested;
 if (!count) return;
 bench.requested=0;
 if (count>1000) { bench.last_error=15; return; }
 bench.running=1; bench.completed=bench.failures=0;
 bench.total_cycles=bench.max_cycles=0; bench.min_cycles=0xffffffffu;
 bench.last_error=0;
 for (unsigned i=0;i<count;i++) {
  card.found=0;
  uint32_t start=cycles();
  int ok=poll_uid();
  uint32_t elapsed=cycles()-start;
  if (!write_reg(0x02,0x80)) { card.error=7; ok=0; }
  card.field_on=0;
  bench.last_cycles=elapsed;
  if (ok) {
   bench.completed++; bench.total_cycles+=elapsed;
   if (elapsed<bench.min_cycles) bench.min_cycles=elapsed;
   if (elapsed>bench.max_cycles) bench.max_cycles=elapsed;
  } else { bench.failures++; bench.last_error=card.error; }
 }
 /* SAK identifies a candidate family; authentication must confirm compatibility. */
 bench.card_type=card.found ? (card.sak==0x08 ? 1 :
                             card.sak==0x18 ? 2 : card.sak==0x09 ? 3 : 0) : 0;
 bench.running=0;
}
