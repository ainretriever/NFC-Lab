/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 NFClab contributors.
 */
/* Nonce collection and fixed info diagnostics; profile 5 probes WRITE ACK
   without a data frame. Capture modes never require an unknown target key. */
#include "m1_nonce_fast.h"
#define M1_NONCES 150u
#define M1_LEGACY_NONCES 50u
struct m1_recover_mailbox {
 uint32_t magic, version, requested, running, count, uid, source_block, source_type;
 uint32_t key[6], target_block, target_type, profile, completed, error, clock_hz;
 /* Nested source authentications performed before probing the target.  Probing
    the same target at two depths yields two independent keystreams for the same
    key, which is what lets the host intersect candidate lists instead of
    verifying tens of thousands of keys on the card.  proxmark3's
    MifareStaticNested does the same with its dist1/dist2 collections. */
 uint32_t depth;
 /* Nt source(before probe), Nt encrypted, parity bits, Nt plain(profile), cycles, error */
 uint32_t records[M1_NONCES][6];
};
volatile struct m1_recover_mailbox m1_recover;
_Static_assert(sizeof(struct m1_recover_mailbox)==3684,"nonce mailbox prefix ABI + fast capture capacity");
static void run_m1_recover(void) {
 if (!m1_recover.requested) return;
 m1_recover.running=1; m1_recover.requested=0;
 m1_recover.completed=m1_recover.error=0; m1_recover.clock_hz=core_hz;
 unsigned count=m1_recover.count;
 for (unsigned i=0;i<M1_NONCES;i++) for (unsigned j=0;j<6;j++) m1_recover.records[i][j]=0;
 /* Fixed profiles: 4=non-writing Magic, 5=WRITE-command ACK only,
    6=initial nonce samples without a key. No arbitrary raw-frame API. */
 if (m1_recover.profile==4 || m1_recover.profile==5) {
  if (count!=1 || m1_recover.source_block || m1_recover.target_block ||
      m1_recover.target_type || m1_recover.source_type>1 || m1_recover.depth) {
   m1_recover.error=M1_ARGUMENT; goto done;
  }
  uint8_t key[6]; uint32_t flags=0;
  for (unsigned i=0;i<6;i++) {
   if (m1_recover.key[i]>255) { m1_recover.error=M1_ARGUMENT; goto done; }
   key[i]=m1_recover.key[i];
  }
  m1.count=0; m1.requested=1; run_m1();
  m1_timing.enabled=1; m1_timing.guard_mode=0;
  m1_timing.has_start=m1_timing.has_rx=0;
  m1_recover.error=m1_magic_probe(m1_recover.uid,m1_recover.profile==5,
                                 key,m1_recover.source_type,&flags);
  m1_recover.records[0][0]=flags;
  m1_recover.completed=!m1_recover.error;
  m1_timing.enabled=0; goto done;
 }
 if (m1_recover.profile==6) {
  if (!count || count>M1_LEGACY_NONCES || m1_recover.source_block>=64 ||
      m1_recover.source_type>1 || m1_recover.target_block ||
      m1_recover.target_type || m1_recover.depth) { m1_recover.error=M1_ARGUMENT; goto done; }
  m1.count=0; m1.requested=1; run_m1();
  m1_timing.enabled=1; m1_timing.guard_mode=0;
  m1_timing.has_start=m1_timing.has_rx=0;
  for (unsigned i=0;i<count;i++) {
   uint8_t plain[4]={0x60+m1_recover.source_type,m1_recover.source_block,0,0};
   uint8_t tx[M1_RAW_BYTES],rx[M1_RAW_BYTES];
   if (!m1_key_select(m1_recover.uid,1,0)) { m1_recover.error=m1.error; break; }
   uint16_t crc=crc_a(plain,2); plain[2]=crc; plain[3]=crc>>8;
   unsigned bits=m1_encode(0,plain,4,0,tx); m1.stage=2;
   int received=m1_rf(tx,bits,rx);
   if (received!=36 || m1_decode(0,rx,received,plain,4)!=4) {
    m1_recover.error=received<0?M1_RF:M1_PARITY; break;
   }
   m1_recover.records[i][0]=bytes_be(plain); m1_recover.completed++;
  }
  if (!write_reg(0x02,0x80) || !write_reg(0x05,0)) m1_recover.error=M1_CLEANUP;
  card.field_on=0; m1_timing.enabled=0; goto done;
 }
 if (m1_recover.profile==2 && !count) {
  card.found=0;
  if (!poll_uid()) m1_recover.error=M1_SELECT;
  else if (card.sak!=8 || card.uid_length<4) m1_recover.error=M1_UID;
  else {
   uint32_t uid=0;
   for (unsigned i=card.uid_length-4;i<card.uid_length;i++) uid=(uid<<8)|card.uid[i];
   m1_recover.uid=uid;
  }
  if (!write_reg(0x02,0x80) || !write_reg(0x05,0)) m1_recover.error=M1_CLEANUP;
  card.field_on=0; goto done;
 }
 /* Diagnostic mode: one AUTH (60/61/64/65) followed by READ of `count`
    consecutive blocks inside that sector.  Key types 4/5 are the FM11RF08S
    backdoor opcodes 0x64/0x65, so authenticating once per sector and reading
    its four blocks is the read-only way to dump a backdoored card without
    knowing any key (Momentum's BackdoorReadSector does exactly this).  No
    arbitrary opcode and no card write is accepted by this mode. */
 if (m1_recover.profile==3) {
  if (!count || count>4 || m1_recover.source_block>=64 || m1_recover.target_block ||
      m1_recover.target_type ||
      m1_recover.source_block/4 != (m1_recover.source_block+count-1)/4 ||
      (m1_recover.source_type!=0 && m1_recover.source_type!=1 &&
       m1_recover.source_type!=4 && m1_recover.source_type!=5)) {
   m1_recover.error=M1_ARGUMENT; goto done;
  }
  uint8_t diagnostic_key[6], data[16];
  for (unsigned j=0;j<6;j++) {
   if (m1_recover.key[j]>255) { m1_recover.error=M1_ARGUMENT; goto done; }
   diagnostic_key[j]=m1_recover.key[j];
  }
  m1.count=0; m1.requested=1; run_m1(); m1.error=m1.rf_error=0;
  m1_timing.enabled=1; m1_timing.guard_mode=0;
  m1_timing.has_start=m1_timing.has_rx=0;
  struct crypto1 diagnostic_cipher;
  if (!m1_key_select(m1_recover.uid,1,0) ||
      !m1_authenticate(&diagnostic_cipher,diagnostic_key,m1_recover.source_block,
                       m1_recover.source_type,m1_recover.uid)) {
   m1_recover.error=m1.error?m1.error:M1_RF;
   m1_recover.records[0][5]=m1_recover.error;
  } else {
   for (unsigned i=0;i<count;i++) {
    if (!m1_read_data(&diagnostic_cipher,m1_recover.source_block+i,data,4)) {
     m1_recover.error=m1.error?m1.error:M1_RF;
     m1_recover.records[i][5]=m1_recover.error;
     break;
    }
    m1_recover.records[i][0]=m1.nt;
    for (unsigned j=0;j<4;j++) m1_recover.records[i][j+1]=bytes_be(data+j*4);
    m1_recover.completed++;
   }
  }
  int off=write_reg(0x02,0x80), framing=write_reg(0x05,0);
  if (!off || !framing) m1_recover.error=M1_CLEANUP;
  if (off) card.field_on=0;
  m1_timing.enabled=0; goto done;
 }
 /* Key types 0/1 are Key A/B, 4/5 are the FM11RF08S backdoor opcodes 0x64/0x65.
    A capture may arm the session with the backdoor key and probe with the
    regular command, which is how the static-encrypted-nonce evidence is
    collected; profile=1 still requires matching types because its decryption
    key is the session key. */
 if (!count || count>M1_NONCES || (count>M1_LEGACY_NONCES && m1_recover.profile!=7) ||
     m1_recover.source_block>=64 || m1_recover.target_block>=64 ||
     (m1_recover.source_type!=0 && m1_recover.source_type!=1 &&
      m1_recover.source_type!=4 && m1_recover.source_type!=5) ||
     (m1_recover.target_type!=0 && m1_recover.target_type!=1 &&
      m1_recover.target_type!=4 && m1_recover.target_type!=5) ||
     (m1_recover.profile>1 && m1_recover.profile!=7) ||
     m1_recover.depth>3 ||
     (m1_recover.profile==7 && (m1_recover.depth || m1_recover.source_type>1 ||
                               m1_recover.target_type>1)) ||
     (m1_recover.profile==1 && (m1_recover.source_block!=m1_recover.target_block ||
                             m1_recover.source_type!=m1_recover.target_type))) {
  m1_recover.error=M1_ARGUMENT; goto done;
 }
 uint8_t key[6];
 for (unsigned i=0;i<6;i++) {
  if (m1_recover.key[i]>255) { m1_recover.error=M1_ARGUMENT; goto done; }
  key[i]=m1_recover.key[i];
 }
 unsigned depth=m1_recover.depth;
 m1.count=0; m1.requested=1; run_m1(); m1.error=0;
 m1_timing.enabled=1; m1_timing.guard_mode=0;
 m1_timing.has_start=m1_timing.has_rx=0;
 for (unsigned i=0;i<count;i++) {
  struct crypto1 cipher;
  m1.error=m1.rf_error=0;
  if (!m1_key_select(m1_recover.uid,i==0,0) ||
      !m1_authenticate(&cipher,key,m1_recover.source_block,m1_recover.source_type,m1_recover.uid)) {
   m1_recover.error=m1.error?m1.error:M1_RF; break;
  }
  /* Advance the source cipher and the card's PRNG in lockstep, so the AUTH
     command below stays valid while the target is probed one step deeper. */
  for (unsigned k=0;k<depth;k++) {
   if (!m1_authenticate_ex(&cipher,key,m1_recover.source_block,m1_recover.source_type,
                           m1_recover.uid,1)) break;
  }
  if (m1.error) { m1_recover.error=m1.error; break; }
  /* The nonce the target's prediction is measured from: the last source nonce
     before the probe, which equals the first one when depth is zero. */
  m1_recover.records[i][0]=m1.nt;
  uint8_t plain[4],tx[M1_RAW_BYTES],rx[M1_RAW_BYTES];
  plain[0]=0x60+m1_recover.target_type; plain[1]=m1_recover.target_block;
  uint16_t crc=crc_a(plain,2); plain[2]=crc; plain[3]=crc>>8;
  unsigned bits=m1_encode(&cipher,plain,4,0,tx);
  m1.stage=2; uint32_t start=cycles();
  int received=m1_rf(tx,bits,rx);
  m1_recover.records[i][4]=cycles()-start;
  if (received!=36) {
   m1_recover.error=received<0?M1_RF:M1_LENGTH;
   m1_recover.records[i][5]=m1_recover.error; break;
  }
  uint32_t enc=0,par=0;
  for (unsigned j=0;j<4;j++) {
   uint8_t byte=0;
   for (unsigned b=0;b<8;b++) byte|=raw_bit(rx,9*j+b)<<b;
   enc=(enc<<8)|byte; par|=raw_bit(rx,9*j+8)<<j;
   plain[j]=byte;
  }
  m1_recover.records[i][1]=enc; m1_recover.records[i][2]=par;
  if (m1_recover.profile==1) {
   crypto1_init(&cipher,key);
   for (unsigned j=0;j<4;j++) {
    plain[j]^=crypto1_byte(&cipher,plain[j]^(uint8_t)(m1_recover.uid>>(24-j*8)),1);
    if (((par>>j)&1)!=(odd_parity(plain[j])^crypto1_filter(cipher.odd))) {
     m1_recover.error=M1_PARITY; break;
    }
   }
   if (m1_recover.error) break;
   m1_recover.records[i][3]=bytes_be(plain);
  }
  if (m1_recover.profile==7 && !m1_nonce_abort()) {
   m1_recover.error=M1_RF; m1_recover.records[i][5]=M1_RF; break;
  }
  m1_recover.completed++;
  /* The target AUTH is deliberately unfinished. Fresh select before next sample. */
 }
 {
  int off=write_reg(0x02,0x80), framing=write_reg(0x05,0);
  if (!off || !framing) m1_recover.error=M1_CLEANUP;
  if (off) card.field_on=0;
 }
 m1_timing.enabled=0;
done:
 m1_recover.running=0;
}
