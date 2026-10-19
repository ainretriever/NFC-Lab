/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 NFClab contributors.
 */
/* mode 2 reuses the read mailbox, so SRAM and read ABI layout stay unchanged.
   keys[0..n) = ordered blocks, data[block*16..] = payload.
   keys[64..65] = submitted mask, [66..67] = ACK mask, [68] = final UID.
   valid_low/high = final readback mask. Never retry or restore a write. */
#define M1_GEN1A_BULK_CAP 0x47315736u
static void gen1a_bulk_bit(volatile uint32_t *low, volatile uint32_t *high, unsigned b) {
 if (b<32) *low|=1u<<b; else *high|=1u<<(b-32);
}
static int gen1a_bulk_compare(unsigned b, uint8_t out[16]) {
 if (!m1_read_data(0,(uint8_t)b,out,4)) return 0;
 for (unsigned i=0;i<16;i++) if (out[i]!=m1_bulk.data[b*16+i]) {
  m1.error=M1_DATA; return 0;
 }
 return 1;
}
static void run_m1_gen1a_bulk(void) {
 if (!m1_bulk.requested) return;
 m1_bulk.running=1; m1_bulk.requested=0;
 unsigned n=m1_bulk.sectors;
 uint32_t uid=m1_bulk.uid,seen_low=0,seen_high=0;
 uint32_t start=cycles();
 m1_bulk.completed=m1_bulk.error=m1_bulk.valid_low=m1_bulk.valid_high=0;
 m1_bulk.failed_block=0xffffffffu;
 m1_bulk.selects=m1_bulk.nested_auths=m1_bulk.recoveries=0;
 m1_bulk.cycles_low=m1_bulk.cycles_high=0;
 for (unsigned i=64;i<69;i++) m1_bulk.keys[i]=0;
 for (unsigned i=0;i<64;i++) m1_bulk.block_errors[i]=0;
 if (!n || n>64 || m1_bulk.first_sector || m1_bulk.count!=1 || m1_bulk.key_type || m1_bulk.spi_div>4) {
  m1_bulk.error=M1_ARGUMENT; goto done;
 }
 for (unsigned i=0;i<n;i++) {
  unsigned b=m1_bulk.keys[i];
  if (b>=64 || (!b && i!=n-1) || ((b<32?seen_low:seen_high)&(1u<<(b&31)))) {
   m1_bulk.error=M1_ARGUMENT; goto done;
  }
  gen1a_bulk_bit(&seen_low,&seen_high,b);
  for (unsigned j=0;j<16;j++) if (m1_bulk.data[b*16+j]>255) {
   m1_bulk.error=M1_ARGUMENT; goto done;
  }
 }
 if (!set_spi_div(m1_bulk.spi_div)) { m1_bulk.error=M1_RF; goto done; }
 m1.count=0; m1.requested=1; run_m1(); m1.error=0;
 m1_bulk.selects++;
 if (!m1_gen1a_unlock(uid,0)) { m1_bulk.error=m1.error; goto cleanup; }
 for (unsigned i=0;i<n;i++) {
  unsigned b=m1_bulk.keys[i]; uint8_t payload[16],out[16];
  for (unsigned j=0;j<16;j++) payload[j]=(uint8_t)m1_bulk.data[b*16+j];
  /* Conservative submission marker: even a missing ACK may hide a write. */
  gen1a_bulk_bit(&m1_bulk.keys[64],&m1_bulk.keys[65],b);
  if (!m1_write(0,b,payload)) goto block_error;
  gen1a_bulk_bit(&m1_bulk.keys[66],&m1_bulk.keys[67],b);
  if (!gen1a_bulk_compare(b,out)) goto block_error;
  continue;
block_error:
  m1_bulk.failed_block=b; m1_bulk.error=m1.error;
  m1_bulk.block_errors[b]=m1.error;
  goto cleanup;
 }
 /* Block 0 is last; reselect its new UID only after the last write. */
 if (m1_bulk.keys[n-1]==0) {
  uid=0;
  for (unsigned j=0;j<4;j++) uid=(uid<<8)|m1_bulk.data[j];
  m1_bulk.selects++;
  if (!m1_gen1a_unlock(uid,0)) {
   m1_bulk.failed_block=0; m1_bulk.error=m1.error; goto cleanup;
  }
 }
 m1_bulk.keys[68]=uid;
 /* Retain both immediate readback and an independent final traversal. */
 for (unsigned i=0;i<n;i++) {
  unsigned b=m1_bulk.keys[i]; uint8_t out[16];
  if (!gen1a_bulk_compare(b,out)) {
   m1_bulk.failed_block=b; m1_bulk.error=m1.error;
   m1_bulk.block_errors[b]=m1.error; goto cleanup;
  }
  gen1a_bulk_bit(&m1_bulk.valid_low,&m1_bulk.valid_high,b);
 }
 m1_bulk.completed=1;
cleanup:
 {
  int off=write_reg(0x02,0x80),framing=write_reg(0x05,0);
  if (off) card.field_on=0;
  if (!off || !framing) { m1_bulk.error=M1_CLEANUP; m1_bulk.completed=0; }
 }
done:
 m1_bulk.cycles_low=(uint32_t)(cycles()-start); m1_bulk.cycles_high=0;
 m1_bulk.reserved=M1_GEN1A_BULK_CAP;
 m1_bulk.running=0;
}
