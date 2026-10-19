/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 NFClab contributors.
 */
/* UID-only NFC-A target: hardware anticollision/selection, no Crypto1/RF waveform. */
#define UID_SIM_MAGIC 0x55494453u
#define UID_SIM_LEASE_MS 3000u
struct uid_sim_mailbox {
 uint32_t magic, version, request, busy, active, error, uid_length, uid[4];
 uint32_t heartbeat, selected, halts, unsupported, field_on, field_off;
 uint32_t state, irq, lease_expired, sequence, clock_hz, reserved[2];
};
_Static_assert(sizeof(struct uid_sim_mailbox)==96,"UID simulator ABI");
volatile struct uid_sim_mailbox uid_sim;
static uint32_t uid_sim_heartbeat, uid_sim_deadline, uid_sim_poll_start;
static unsigned uid_sim_reader_hold, uid_sim_restore_failed;
static int uid_sim_stop(void) {
 uid_sim.active=0;
 int off=write_reg(0x02,0);
 int restored=reader_init();
 uid_sim_reader_hold=1; /* Stop stays RF quiet until an explicit reader command. */
 uid_sim_restore_failed=!(off && restored);
 if (uid_sim_restore_failed) { (void)write_reg(0x02,0); uid_sim.error=3; }
 return !uid_sim_restore_failed;
}
static int uid_sim_start(void) {
 uint8_t memory[15]={0}, irq[4];
 if (uid_sim.uid_length!=4 || uid_sim.uid[0]==0x88) { uid_sim.error=1; return 0; }
 for (unsigned i=0;i<4;i++) {
  if (uid_sim.uid[i]>255) { uid_sim.error=1; return 0; }
  memory[i]=(uint8_t)uid_sim.uid[i];
 }
 if (uid_sim.active || sniff.enabled || sniff.request || sniff.busy ||
     m1.requested || m1.running || m1_bulk.requested || m1_bulk.running ||
     m1_keys.requested || m1_keys.running || m1_recover.requested || m1_recover.running ||
     bench.requested || bench.running) { uid_sim.error=2; return 0; }
 memory[10]=4; memory[12]=memory[13]=memory[14]=8;
 if (!(reader_init() && set_spi_div(0) && command(0xc2) && write_reg(0x02,0x80)
       && write_reg(0x29,0x0f) && write_reg(0x03,0x88) && write_reg(0x04,0)
       && write_reg(0x05,0) && write_reg(0x08,0x5c) && write_reg(0x0a,0)
       && write_reg(0x0b,8) && write_reg(0x0c,0x2d) && write_reg(0x0d,0)
       && write_reg(0x0e,0) && write_reg(0x0f,2)
       && write_reg(0x2a,0x11) && write_reg(0x2b,0)
       && transaction(0xfb,(const uint8_t[]){0x0c,0x51},0,2)
       && transaction(0xfb,(const uint8_t[]){0x0d,0},0,2)
       && write_reg(0x16,0xef) && write_reg(0x17,0xe7)
       && write_reg(0x18,0xff) && write_reg(0x19,0xfe)
       && transaction(0xa0,memory,0,15) && irq_read(irq)
       && write_reg(0x02,0xc3) && command(0xcd))) {
  uid_sim.error=3; (void)uid_sim_stop(); return 0;
 }
 uid_sim.selected=uid_sim.halts=uid_sim.unsupported=0;
 uid_sim.field_on=uid_sim.field_off=uid_sim.state=uid_sim.irq=0;
 uid_sim.lease_expired=0; uid_sim_heartbeat=uid_sim.heartbeat;
 uid_sim_deadline=uid_sim_poll_start=cycles();
 uid_sim_restore_failed=0; uid_sim.active=1; return 1;
}
static void uid_sim_task(void) {
 if (uid_sim.request && !uid_sim.busy) {
  unsigned request=uid_sim.request;
  uid_sim.busy=1; uid_sim.error=0;
  if (request==1) (void)uid_sim_start();
  else if (request==2) (void)uid_sim_stop();
  else uid_sim.error=1;
  uid_sim.sequence++; uid_sim.request=0; uid_sim.busy=0;
 }
 if (!uid_sim.active) return;
 uint32_t now=cycles();
 if (uid_sim.heartbeat!=uid_sim_heartbeat) {
  uid_sim_heartbeat=uid_sim.heartbeat; uid_sim_deadline=now;
 }
 if ((uint32_t)(now-uid_sim_deadline)>core_hz/1000u*UID_SIM_LEASE_MS) {
  uid_sim.lease_expired=1; (void)uid_sim_stop(); return;
 }
 if (!nfc_irq_level() && (uint32_t)(now-uid_sim_poll_start)<core_hz/100u) return;
 uid_sim_poll_start=now;
 uint8_t irq[4], state, count, status, data[4];
 if (!irq_read(irq) || !read_reg(0x21,&state)) goto io_error;
 uid_sim.state=state;
 uid_sim.irq|=(uint32_t)irq[0]|((uint32_t)irq[1]<<8)|((uint32_t)irq[2]<<16)|((uint32_t)irq[3]<<24);
 if (irq[3]&1) uid_sim.selected++;
 if (irq[1]&0x10) uid_sim.field_on++;
 if (irq[1]&8) uid_sim.field_off++;
 /* Hardware follows field loss; do not reset anticollision on every EOF. */
 if (!(irq[0]&0x10)) return;
 if (!read_reg(0x1e,&count) || !read_reg(0x1f,&status)) goto io_error;
 if (count==4 && !status && !irq[2]) {
  if (!transaction(0x9f,0,data,4)) goto io_error;
  uint16_t crc=crc_a(data,2);
  if (data[0]==0x50 && !data[1] && data[2]==(uint8_t)crc && data[3]==(uint8_t)(crc>>8)) {
   uid_sim.halts++;
   if (!command(0xce)) goto io_error;
   return;
  }
 }
 uid_sim.unsupported++;
 if (!command(0xdb) || !command(0xd1)) goto io_error;
 return;
io_error:
 uid_sim.error=3; (void)uid_sim_stop();
}
