/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 NFClab contributors.
 */
static int m1_nested_auth(struct crypto1 *cipher, const uint8_t key[6],
                           uint8_t block, uint8_t key_type, uint32_t cuid) {
 uint32_t start=cycles();
 int ok=m1_authenticate_ex(cipher,key,block,key_type,cuid,1);
 uint32_t elapsed=cycles()-start; m1.auth_last=elapsed;
 if (!ok) m1.auth_errors++;
 else {
  m1.auth_ok++; m1.auth_total+=elapsed;
  if (elapsed<m1.auth_min) m1.auth_min=elapsed;
  if (elapsed>m1.auth_max) m1.auth_max=elapsed;
 }
 return ok;
}
/* Read-only Classic 1K batches: one authentication per sector, local cipher continuity. */
struct m1_bulk_mailbox {
 uint32_t magic, version, requested, running, first_sector, sectors, count, key_type, uid;
 uint32_t completed, error, failed_block, valid_low, valid_high, cycles_low, cycles_high;
 uint32_t keys[192], data[1024], block_errors[64], sector_cycles[16];
 uint32_t mode, spi_div, selects, nested_auths, recoveries, min_cycles, max_cycles, reserved;
};
volatile struct m1_bulk_mailbox m1_bulk;
_Static_assert(sizeof(struct m1_bulk_mailbox)==1320*4, "bulk mailbox ABI");
static unsigned m1_bulk_read(struct crypto1 *cipher, unsigned base, unsigned mask) {
 int ok=1;
 for (unsigned b=0;b<4;b++) {
  if (mask&(1u<<b)) continue;
  uint8_t data[16]; unsigned block=base+b;
  if (ok) ok=m1_read_data(cipher,(uint8_t)block,data,4);
  if (!ok) { m1_bulk.block_errors[block]=m1.error; continue; }
  for (unsigned i=0;i<16;i++) m1_bulk.data[block*16+i]=data[i];
  m1_bulk.block_errors[block]=0; mask|=1u<<b;
 }
 return mask;
}
static void run_m1_gen1a_bulk(void);
static void run_m1_auth_write_bulk(void);
static void run_m1_bulk(void) {
 if (!m1_bulk.requested) return;
 if (m1_bulk.mode==2) { run_m1_gen1a_bulk(); return; }
 if (m1_bulk.mode==3 || m1_bulk.mode==4) { run_m1_auth_write_bulk(); return; }
 m1_bulk.running=1; m1_bulk.requested=0;
 unsigned first=m1_bulk.first_sector, sectors=m1_bulk.sectors, count=m1_bulk.count, type=m1_bulk.key_type;
 uint8_t keys[192];
 unsigned mode=m1_bulk.mode;
 m1_bulk.completed=m1_bulk.error=m1_bulk.valid_low=m1_bulk.valid_high=0;
 m1_bulk.selects=m1_bulk.nested_auths=m1_bulk.recoveries=m1_bulk.max_cycles=0;
 m1_bulk.min_cycles=0xffffffffu;
 m1_bulk.cycles_low=m1_bulk.cycles_high=0; m1_bulk.failed_block=0xffffffffu;
 for (unsigned i=0;i<1024;i++) m1_bulk.data[i]=0;
 for (unsigned i=0;i<64;i++) m1_bulk.block_errors[i]=0;
 for (unsigned i=0;i<16;i++) m1_bulk.sector_cycles[i]=0;
 if (first>=16 || !sectors || sectors>16-first || !count || count>100 || type>2 ||
     (mode>1 && mode!=5 && mode!=6) || (mode>=5 && (count!=1 || type!=0)) || m1_bulk.spi_div>4) {
  m1_bulk.error=M1_ARGUMENT; goto done;
 }
 for (unsigned i=0;i<192;i++) {
  if (m1_bulk.keys[i]>255 || (mode>=5 && m1_bulk.keys[i]!=255)) { m1_bulk.error=M1_ARGUMENT; goto done; }
  keys[i]=(uint8_t)m1_bulk.keys[i];
 }
 /* Mode 6 returns first nondefault sector + 1 and authenticated B bitmap.
    Input keys have already been copied locally. */
 if (mode==6) m1_bulk.keys[0]=m1_bulk.keys[1]=0;
 if (!set_spi_div(m1_bulk.spi_div)) { m1_bulk.error=M1_RF; goto done; }
 /* Reset shared protocol statistics without submitting an RF operation. */
 m1.count=0; m1.requested=1; run_m1(); m1.error=0;
 uint64_t total=0;
 for (unsigned trial=0;trial<count;trial++) {
  uint32_t start=cycles(); int all_ok=1, active=0;
  struct crypto1 cipher;
  m1_bulk.valid_low=m1_bulk.valid_high=0;
  for (unsigned sector=first;sector<first+sectors;sector++) {
   uint32_t sector_start=cycles(); unsigned base=sector*4, mask=mode>=5?7:0;
   int default_rejected=0;
   /* Auto tries A first, then B for missing blocks after fresh select. */
   for (unsigned attempt=0;attempt<(type==2?2u:1u) && mask!=15;attempt++) {
    unsigned kt=type==2?attempt:type;
    m1.error=m1.rf_error=0;
    int ok;
    if (active && mode!=1) {
     m1_bulk.nested_auths++;
     ok=m1_nested_auth(&cipher,keys+(kt*16+sector)*6,(uint8_t)base,(uint8_t)kt,m1_bulk.uid);
     if (!ok) { active=0; m1_bulk.recoveries++; }
    } else ok=0;
    if (!active || mode==1) {
     m1_bulk.selects++;
     ok=m1_select_auth(&cipher,keys+(kt*16+sector)*6,base,kt,m1_bulk.uid);
    }
    active=ok;
    if (!ok) default_rejected=(m1.error==M1_RF && m1.rf_error==3) || m1.error==M1_NAK;
    if (ok) {
     mask=m1_bulk_read(&cipher,base,mask);
     if (mask!=15) {
      /* One bounded fresh authentication with the same key after a failed
         READ; only then try the alternate key if auto was requested. */
      m1_bulk.recoveries++; m1_bulk.selects++;
      m1.error=m1.rf_error=0;
      ok=m1_select_auth(&cipher,keys+(kt*16+sector)*6,base,kt,m1_bulk.uid);
      if (ok) mask=m1_bulk_read(&cipher,base,mask);
      active=ok && mask==15;
     }
    }
    if (mask!=15) for (unsigned b=0;b<4;b++)
     if (!(mask&(1u<<b))) m1_bulk.block_errors[base+b]=m1.error;
   }
   unsigned valid=mode>=5?mask&8:mask;
   if (base<32) m1_bulk.valid_low|=valid<<base;
   else m1_bulk.valid_high|=valid<<(base-32);
   m1_bulk.sector_cycles[sector]=cycles()-sector_start;
   if (mask!=15) {
    all_ok=0;
    for (unsigned b=0;b<4;b++) if (!(mask&(1u<<b)) && !m1_bulk.error) {
     m1_bulk.failed_block=base+b; m1_bulk.error=m1_bulk.block_errors[base+b];
    }
   }
   if (mode==6) {
    if (mask!=15) {
     /* Keep transport/CRC/UID faults as errors, never as unknown keys. */
     if (default_rejected) {
      m1_bulk.keys[0]=sector+1; m1_bulk.error=0;
     }
     all_ok=0; break;
    }
    uint8_t trailer[16];
    for (unsigned i=0;i<16;i++) trailer[i]=(uint8_t)m1_bulk.data[(base+3)*16+i];
    unsigned c1=trailer[7]>>4,c2=trailer[8]&15,c3=trailer[8]>>4;
    if ((c1^(trailer[6]&15))!=15 || (c2^(trailer[6]>>4))!=15 || (c3^(trailer[7]&15))!=15) {
     m1_bulk.error=M1_DATA; m1_bulk.failed_block=base+3; all_ok=0; break;
    }
    unsigned group=((c1>>3)<<2)|((c2>>3)<<1)|(c3>>3);
    int good=1;
    if (group<=2) {
     for (unsigned i=10;i<16;i++) if (trailer[i]!=255) good=0;
    } else {
     m1.error=m1.rf_error=0; m1_bulk.nested_auths++;
     good=m1_nested_auth(&cipher,keys+(16+sector)*6,(uint8_t)base,1,m1_bulk.uid);
     if (!good) {
      m1_bulk.recoveries++; m1_bulk.selects++;
      m1.error=m1.rf_error=0;
      good=m1_select_auth(&cipher,keys+(16+sector)*6,base,1,m1_bulk.uid);
     }
     active=good;
     if (good) m1_bulk.keys[1]|=1u<<sector;
     else if (!((m1.error==M1_RF && m1.rf_error==3) || m1.error==M1_NAK)) m1_bulk.error=m1.error;
    }
    if (!good) {
     if (!m1_bulk.error) m1_bulk.keys[0]=sector+1;
     m1_bulk.failed_block=base+3; all_ok=0; break;
    }
   }
   if (mode==1 || !active) {
    int off=write_reg(0x02,0x80), framing=write_reg(0x05,0);
    if (off) card.field_on=0;
    if (!off || !framing) { all_ok=0; m1_bulk.error=M1_CLEANUP; }
    active=0;
   }
  }
  int off=write_reg(0x02,0x80), framing=write_reg(0x05,0);
  if (off) card.field_on=0;
  if (!off || !framing) { all_ok=0; m1_bulk.error=M1_CLEANUP; }
  uint32_t elapsed=cycles()-start;
  if (elapsed<m1_bulk.min_cycles) m1_bulk.min_cycles=elapsed;
  if (elapsed>m1_bulk.max_cycles) m1_bulk.max_cycles=elapsed;
  total+=(uint32_t)(cycles()-start);
  if (all_ok) m1_bulk.completed++; else break;
 }
 m1_bulk.cycles_low=(uint32_t)total; m1_bulk.cycles_high=(uint32_t)(total>>32);
done:
 m1_bulk.running=0;
}
