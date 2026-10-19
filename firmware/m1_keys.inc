/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 NFClab contributors.
 */
/* Read-only local candidate batches. Keys are packed bytes, no host/frame round trips. */
#define M1_KEY_CAPACITY 1024u
struct m1_keys_mailbox {
 uint32_t magic, version, requested, running, operation, block, key_type, key_count;
 uint32_t repeat, targets, uid, spi_div, nrt_units, processed, matched, rejected;
 uint32_t inconclusive, error, last_stage, last_rf, full_selects, fast_selects, nested_auths, retries;
 uint32_t cycles_low, cycles_high, clock_hz, found_mask, auth_cycles_low, auth_cycles_high, last_index, reserved;
 uint8_t keys[M1_KEY_CAPACITY*6], status[M1_KEY_CAPACITY];
 uint32_t found_index[32]; uint8_t found_keys[32][6]; uint32_t target_checked[32];
 uint32_t guard_mode, timing[17];
};
volatile struct m1_keys_mailbox m1_keys;
_Static_assert(sizeof(struct m1_keys_mailbox)==7816, "key mailbox ABI");
/* `cipher` is the session that authenticated the card, when there is one: the
   fast path needs it to halt the card before re-selecting (see
   m1_classic_halt).  Pass NULL when no authentication is outstanding. */
static int m1_key_select_inner(uint32_t uid, int force_full, struct crypto1 *cipher) {
 m1.stage=1;
 if (!force_full) {
  m1_keys.fast_selects++;
  if (m1_fast_select(uid,cipher)) return 1;
 }
 m1_keys.full_selects++; card.found=0;
 if (!poll_uid()) { m1.error=M1_SELECT; m1.rf_error=card.error; return 0; }
 uint32_t cuid=0;
 for (unsigned i=card.uid_length-4;i<card.uid_length;i++) cuid=(cuid<<8)|card.uid[i];
 if (card.sak!=8 || cuid!=uid) { m1.error=M1_UID; return 0; }
 return 1;
}
static int m1_key_select(uint32_t uid, int force_full, struct crypto1 *cipher) {
 uint32_t start=cycles();
 int ok=m1_key_select_inner(uid,force_full,cipher);
 m1_timing.selection+=(uint32_t)(cycles()-start);
 return ok;
}
/* 1=matched, 2=authentication rejected, 3=inconclusive transport/card failure. */
static unsigned m1_try_key(struct crypto1 *cipher, const uint8_t key[6],
                           unsigned block, unsigned type, uint32_t uid, int nested,
                           uint64_t *auth_cycles) {
 for (unsigned retry=0;retry<2;retry++) {
  m1.error=m1.rf_error=0;
  if (!nested && !m1_key_select(uid,retry || !card.field_on,cipher)) return 3;
  m1_keys.nested_auths+=nested;
  uint32_t start=cycles();
  int ok=m1_authenticate_ex(cipher,key,(uint8_t)block,(uint8_t)type,uid,nested);
  *auth_cycles+=(uint32_t)(cycles()-start);
  m1_keys.last_stage=m1.stage; m1_keys.last_rf=m1.rf_error;
  if (ok) return 1; /* full At check performed in m1_authenticate_ex */
  if (!nested && m1.stage==3 &&
      ((m1.error==M1_RF && m1.rf_error==3) || m1.error==M1_NAK)) return 2;
  if (!retry) { m1_keys.retries++; nested=0; }
 }
 return 3;
}
static void run_m1_keys(void) {
 if (!m1_keys.requested) return;
 m1_keys.running=1; m1_keys.requested=0;
 unsigned op=m1_keys.operation, count=m1_keys.key_count, repeats=m1_keys.repeat;
 uint32_t targets=m1_keys.targets, uid=m1_keys.uid;
 m1_keys.processed=m1_keys.matched=m1_keys.rejected=m1_keys.inconclusive=0;
 m1_keys.error=m1_keys.last_stage=m1_keys.last_rf=0;
 m1_keys.full_selects=m1_keys.fast_selects=m1_keys.nested_auths=m1_keys.retries=0;
 m1_keys.cycles_low=m1_keys.cycles_high=m1_keys.found_mask=0;
 m1_keys.auth_cycles_low=m1_keys.auth_cycles_high=0; m1_keys.last_index=0xffffffffu;
 for (unsigned i=0;i<M1_KEY_CAPACITY;i++) m1_keys.status[i]=0;
 for (unsigned i=0;i<32;i++) {
  m1_keys.found_index[i]=0xffffffffu; m1_keys.target_checked[i]=0;
  for (unsigned j=0;j<6;j++) m1_keys.found_keys[i][j]=0;
 }
 if (op>2 || !count || count>M1_KEY_CAPACITY || m1_keys.block>=64 || m1_keys.key_type>1 ||
     m1_keys.spi_div>4 || m1_keys.nrt_units<43 || m1_keys.nrt_units>1024 || m1_keys.guard_mode>1 ||
     (op==1 && (count!=1 || !repeats || repeats>10000)) || (op==2 && !targets)) {
  m1_keys.error=M1_ARGUMENT; goto done;
 }
 m1_timing.selection=m1_timing.wupa=m1_timing.select=m1_timing.fixed_wait=0;
 m1_timing.guard_wait=m1_timing.nt_rf=m1_timing.ar_rf=0;
 m1_timing.response_min=0xffffffffu; m1_timing.response_max=m1_timing.responses=0;
 m1_timing.has_start=m1_timing.has_rx=0;
 m1_timing.guard_mode=m1_keys.guard_mode; m1_timing.enabled=1;
 if (!set_spi_div(m1_keys.spi_div)) { m1_keys.error=M1_RF; goto done; }
 m1.count=0; m1.requested=1; run_m1(); m1.error=0;
 if (!write_reg(0x10,m1_keys.nrt_units>>8) || !write_reg(0x11,m1_keys.nrt_units)) {
  m1_keys.error=M1_RF; goto cleanup;
 }
 uint64_t total=0, auth_cycles=0;
 struct crypto1 cipher; int active=0;
 unsigned limit=op==1?repeats:count;
 for (unsigned target=0;target<(op==2?32u:1u);target++) {
  if (op==2 && !(targets&(1u<<target))) continue;
  unsigned block=op==2?(target/2)*4:m1_keys.block;
  unsigned type=op==2?target%2:m1_keys.key_type;
  for (unsigned i=0;i<limit;i++) {
   uint8_t key[6]; unsigned index=op==1?0:i;
   for (unsigned j=0;j<6;j++) key[j]=m1_keys.keys[index*6+j];
   uint32_t start=cycles();
   unsigned result=m1_try_key(&cipher,key,block,type,uid,op==1 && active,&auth_cycles);
   total+=(uint32_t)(cycles()-start); active=result==1;
   m1_keys.processed++; m1_keys.last_index=index;
   if (op!=2) m1_keys.status[index]=result;
   else m1_keys.target_checked[target]++;
   if (result==1) {
    m1_keys.matched++;
    if (op==2) {
     m1_keys.found_mask|=1u<<target; m1_keys.found_index[target]=index;
     for (unsigned j=0;j<6;j++) m1_keys.found_keys[target][j]=key[j];
     break;
    }
   } else if (result==2) m1_keys.rejected++;
   else { m1_keys.inconclusive++; m1_keys.error=m1.error?m1.error:M1_RF; goto finished; }
  }
 }
finished:
 /* A final rejection has no At; verify the card remains present before
    reporting a completed negative batch. Missing card is inconclusive. */
 if (!active && !m1_keys.error) {
  uint32_t start=cycles();
  if (!m1_key_select(uid,0,0)) { m1_keys.inconclusive++; m1_keys.error=m1.error; }
  total+=(uint32_t)(cycles()-start);
 }
 m1_keys.cycles_low=(uint32_t)total; m1_keys.cycles_high=(uint32_t)(total>>32);
 m1_keys.auth_cycles_low=(uint32_t)auth_cycles; m1_keys.auth_cycles_high=(uint32_t)(auth_cycles>>32);
cleanup:
 {
  int off=write_reg(0x02,0x80), framing=write_reg(0x05,0);
  int high=write_reg(0x10,4), low=write_reg(0x11,0);
  if (!off || !framing || !high || !low) m1_keys.error=M1_CLEANUP;
  if (off) card.field_on=0;
 }
done:
 {
  const uint64_t totals[7]={m1_timing.selection,m1_timing.wupa,m1_timing.select,
   m1_timing.fixed_wait,m1_timing.guard_wait,m1_timing.nt_rf,m1_timing.ar_rf};
  for (unsigned i=0;i<7;i++) {
   m1_keys.timing[i*2]=(uint32_t)totals[i];
   m1_keys.timing[i*2+1]=(uint32_t)(totals[i]>>32);
  }
  m1_keys.timing[14]=m1_timing.response_min;
  m1_keys.timing[15]=m1_timing.response_max; m1_keys.timing[16]=m1_timing.responses;
  m1_timing.enabled=0;
 }
 m1_keys.running=0;
}
