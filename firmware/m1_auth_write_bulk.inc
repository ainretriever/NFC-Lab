/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 NFClab contributors.
 */
/* modes 3 (reselect) / 4 (nested): authenticated writes. keys = current A/B, valid = requested scope,
   block_errors = selected key types on input. sector_cycles[0..4] on output =
   submitted low/high, ACK low/high, final UID. No retries or rollback.
   Nested mode preserves the field across sector/key changes, including new
   trailer keys. Never fall back or resubmit a WRITE after a failed exchange. */
static int auth_write_select(struct crypto1 *cipher, const uint8_t *key,
                             unsigned b, unsigned t, uint32_t uid) {
 m1_bulk.selects++;
 return m1_select_auth(cipher,key,(uint8_t)b,(uint8_t)t,uid);
}
static int auth_write_auth(struct crypto1 *cipher, const uint8_t *key,
                          unsigned b, unsigned t, uint32_t uid, int active) {
 if (m1_bulk.mode==4 && active) {
  m1_bulk.nested_auths++;
  return m1_nested_auth(cipher,key,(uint8_t)b,(uint8_t)t,uid);
 }
 return auth_write_select(cipher,key,b,t,uid);
}
static int auth_write_acl(const uint8_t *p, unsigned *trailer_group) {
 unsigned c1=p[7]>>4,c2=p[8]&15,c3=p[8]>>4;
 if ((c1^(p[6]&15))!=15 || (c2^(p[6]>>4))!=15 || (c3^(p[7]&15))!=15) return 0;
 *trailer_group=((c1>>3)<<2)|((c2>>3)<<1)|(c3>>3);
 return 1;
}
static void run_m1_auth_write_bulk(void) {
 if (!m1_bulk.requested) return;
 m1_bulk.running=1; m1_bulk.requested=0;
 uint32_t scope[2]={m1_bulk.valid_low,m1_bulk.valid_high};
 uint32_t uid=m1_bulk.uid,start=cycles();
 uint8_t keys[192],types[64];
 unsigned active_sector=16,active_type=2,b=0,n=0;
 struct crypto1 cipher;
 m1_bulk.completed=m1_bulk.error=m1_bulk.valid_low=m1_bulk.valid_high=0;
 m1_bulk.failed_block=0xffffffffu;
 m1_bulk.selects=m1_bulk.nested_auths=m1_bulk.recoveries=0;
 m1_bulk.cycles_low=m1_bulk.cycles_high=0;
 for (unsigned i=0;i<16;i++) m1_bulk.sector_cycles[i]=0;
 if (m1_bulk.first_sector || m1_bulk.count!=1 || m1_bulk.key_type>1 ||
     m1_bulk.spi_div>4 || ((scope[0]&1) && !m1_bulk.key_type)) goto argument;
 for (unsigned i=0;i<192;i++) {
  if (m1_bulk.keys[i]>255) goto argument;
  keys[i]=(uint8_t)m1_bulk.keys[i];
 }
 for (unsigned i=0;i<64;i++) {
  types[i]=(uint8_t)m1_bulk.block_errors[i];
  if (scope[i/32]&(1u<<(i&31))) {
   n++;
   if (m1_bulk.block_errors[i]>1) goto argument;
   for (unsigned j=0;j<16;j++) if (m1_bulk.data[i*16+j]>255) goto argument;
  }
 }
 if (!n || n!=m1_bulk.sectors) goto argument;
 for (unsigned i=0;i<64;i++) m1_bulk.block_errors[i]=0;
 if (!set_spi_div(m1_bulk.spi_div)) { m1_bulk.error=M1_RF; goto done; }
 m1.count=0; m1.requested=1; run_m1(); m1.error=0;
 for (unsigned order=1;order<=64;order++) {
  b=order&63;
  if (!(scope[b/32]&(1u<<(b&31)))) continue;
  unsigned sector=b/4,t=types[b];
  uint8_t payload[16],out[16];
  for (unsigned j=0;j<16;j++) payload[j]=(uint8_t)m1_bulk.data[b*16+j];
  /* Sector 0's trailer has already changed when manufacturer block is last.
     Resolve its key from the NEW access bits, never stale preflight keys. */
  if (!b && (scope[0]&8)) {
   unsigned c1=m1_bulk.data[3*16+7]>>4;
   unsigned c2=m1_bulk.data[3*16+8]&15,c3=m1_bulk.data[3*16+8]>>4;
   unsigned group=((c1&1)<<2)|((c2&1)<<1)|(c3&1);
   if (group==0) t=0;
   else if (group==3 || group==4 || group==6) t=1;
   else { m1.error=M1_NAK; goto block_error; }
  }
  if (active_sector!=sector || active_type!=t) {
   if (!auth_write_auth(&cipher,keys+(t*16+sector)*6,b,t,uid,active_sector!=16)) goto block_error;
   active_sector=sector; active_type=t;
  }
  gen1a_bulk_bit(&m1_bulk.sector_cycles[0],&m1_bulk.sector_cycles[1],b);
  if (!m1_write(&cipher,b,payload)) goto block_error;
  gen1a_bulk_bit(&m1_bulk.sector_cycles[2],&m1_bulk.sector_cycles[3],b);
  if (!b) {
   uid=bytes_be(payload);
   if (!auth_write_select(&cipher,keys+(t*16+sector)*6,b,t,uid)) goto block_error;
  }
  if ((b&3)==3) {
   unsigned group;
   for (unsigned j=0;j<6;j++) {
    keys[sector*6+j]=payload[j];keys[(16+sector)*6+j]=payload[10+j];
   }
   if (!auth_write_acl(payload,&group)) { m1.error=M1_DATA; goto block_error; }
   /* Key A is hidden: prove it by a new authentication. Key B is either
      compared in READ or independently authenticated, never silently masked. */
   if (!auth_write_auth(&cipher,keys+sector*6,b,0,uid,1)) goto block_error;
   if (group>2 && !auth_write_auth(&cipher,keys+(16+sector)*6,b,1,uid,1)) goto block_error;
   if (!m1_read_data(&cipher,(uint8_t)b,out,4)) goto block_error;
   for (unsigned j=6;j<10;j++) if (out[j]!=payload[j]) { m1.error=M1_DATA; goto block_error; }
   if (group<=2) for (unsigned j=10;j<16;j++) if (out[j]!=payload[j]) { m1.error=M1_DATA; goto block_error; }
   active_sector=sector;active_type=group>2?1:0;
  } else {
   if (!m1_read_data(&cipher,(uint8_t)b,out,4) || !m1_compare(out,payload)) goto block_error;
  }
  gen1a_bulk_bit(&m1_bulk.valid_low,&m1_bulk.valid_high,b);
 }
 m1_bulk.sector_cycles[4]=uid;
 m1_bulk.completed=1;
 goto cleanup;
block_error:
 m1_bulk.failed_block=b;m1_bulk.error=m1.error;m1_bulk.block_errors[b]=m1.error;
cleanup:
 {
  int off=write_reg(0x02,0x80),framing=write_reg(0x05,0);
  if (off) card.field_on=0;
  if (!off || !framing) { m1_bulk.error=M1_CLEANUP;m1_bulk.completed=0; }
 }
 goto done;
argument:
 m1_bulk.error=M1_ARGUMENT;
done:
 m1_bulk.cycles_low=(uint32_t)(cycles()-start);m1_bulk.cycles_high=0;
 m1_bulk.reserved=M1_GEN1A_BULK_CAP;m1_bulk.running=0;
}
