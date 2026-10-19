/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 NFClab contributors.
 */
/* Known-key M1 operations. Block permissions are enforced by the card, not by software. */
#include "m1_codec.h"
#include "m1_timing.h"
enum m1_error {
 M1_OK, M1_ARGUMENT, M1_SELECT, M1_UID, M1_RF, M1_LENGTH,
 M1_PARITY, M1_AUTH_ANSWER, M1_CRC, M1_DATA, M1_NAK, M1_CLEANUP,
 M1_RESERVED12, M1_RESTORE
};
struct m1_mailbox {
 uint32_t magic, version, requested, running, count, operation, block, key_type;
 uint32_t key[6], expected_uid, expected[16];
 uint32_t completed, failures, auth_ok, read_ok, stage, error, rf_error;
 uint32_t timeouts, fifo_errors, parity_errors, auth_errors, crc_errors, mismatches;
 uint32_t auth_last, auth_min, auth_max, auth_total;
 uint32_t read_last, read_min, read_max, read_total;
 uint32_t clock_hz, nt, rx_bits, nak, data[16];
 uint32_t nonce_ok, rejected, select_errors, uid_errors, read_matched;
 uint32_t batch_cycles_low, batch_cycles_high;
 uint32_t write_data[16], original_data[16];
 uint32_t backup_valid, write_commands, data_frames, acks, payload_ok;
 uint32_t write_verified, restore_attempts, restore_ok, restore_error, write_error;
 uint32_t write_last, write_min, write_max, write_total, reserved125;
 uint32_t restore_failures, writes_acknowledged;
};
_Static_assert(sizeof(struct m1_mailbox)==128*4, "SWD mailbox ABI");
volatile struct m1_mailbox m1;
static int m1_rf(const uint8_t *tx, unsigned bits, uint8_t *rx) {
 uint32_t start=m1_timing.enabled?cycles():0, phase=m1.stage;
 m1_timing.phase=phase;
 int received=transceive_bits(0xc5,tx,bits,0xc0,rx,M1_RAW_BYTES);
 m1_timing.phase=0;
 if (m1_timing.enabled) {
  uint32_t elapsed=cycles()-start;
  if (phase==2) m1_timing.nt_rf+=elapsed;
  if (phase==3) m1_timing.ar_rf+=elapsed;
 }
 m1.rx_bits=received<0?0:(uint32_t)received;
 if (received<0) {
  m1.error=M1_RF; m1.rf_error=card.error;
  if (card.error==3) m1.timeouts++;
  if (card.error==6) m1.fifo_errors++;
 }
 return received;
}
static uint32_t bytes_be(const uint8_t *p) {
 return (uint32_t)p[0]<<24 | (uint32_t)p[1]<<16 | (uint32_t)p[2]<<8 | p[3];
}
static void put_be(uint8_t *p, uint32_t value) {
 for (unsigned i=0;i<4;i++) p[i]=(uint8_t)(value>>(24-i*8));
}
static int m1_receive(struct crypto1 *s, const uint8_t *raw, int bits,
                      uint8_t *plain, unsigned len) {
 if (bits<0) return 0;
 if (bits==4) {
  uint8_t nak=0;
  (void)m1_nibble(s,raw,4,&nak);
  m1.nak=nak; m1.error=M1_NAK; return 0;
 }
 if ((unsigned)bits!=len*9) { m1.error=M1_LENGTH; return 0; }
 if (m1_decode(s,raw,(unsigned)bits,plain,len)<0) {
  m1.parity_errors++; m1.error=M1_PARITY; return 0;
 }
 return 1;
}
static int m1_authenticate_ex(struct crypto1 *cipher, const uint8_t key[6],
                           uint8_t block, uint8_t key_type, uint32_t cuid, int nested) {
 uint8_t plain[8], tx[M1_RAW_BYTES], rx[M1_RAW_BYTES];
 plain[0]=0x60+key_type; plain[1]=block;
 uint16_t crc=crc_a(plain,2); plain[2]=(uint8_t)crc; plain[3]=(uint8_t)(crc>>8);
 m1.stage=2;
 int bits=m1_encode(nested?cipher:0,plain,4,0,tx);
 int received=m1_rf(tx,(unsigned)bits,rx);
 if (nested) {
  if (received<0) return 0;
  if (received!=36) { m1.error=M1_LENGTH; return 0; }
  /* AUTH command uses the old cipher; Nt uses a fresh cipher with the
     target key and encrypted UID^Nt feedback (not ordinary READ decoding). */
  crypto1_init(cipher,key);
  for (unsigned i=0;i<4;i++) {
   uint8_t encrypted=0;
   for (unsigned b=0;b<8;b++) encrypted|=raw_bit(rx,9*i+b)<<b;
   plain[i]=encrypted^crypto1_byte(cipher,encrypted^(uint8_t)(cuid>>(24-i*8)),1);
   if (raw_bit(rx,9*i+8)!=(odd_parity(plain[i])^crypto1_filter(cipher->odd))) {
    m1.parity_errors++; m1.error=M1_PARITY; return 0;
   }
  }
 } else {
  if (!m1_receive(0,rx,received,plain,4)) return 0;
  crypto1_init(cipher,key); (void)crypto1_word(cipher,bytes_be(plain)^cuid,0);
 }
 m1.nonce_ok++;
 uint32_t nt=bytes_be(plain); m1.nt=nt;
 /* F411 has no TRNG. Vary reader nonce with cycles and request progress;
    this bench nonce is not a cryptographic random-number source. */
 uint32_t nr=cycles()^nt^(m1.completed+m1.failures+1)*0x9e3779b9u;
 nr^=nr<<13; nr^=nr>>17; nr^=nr<<5;
 put_be(plain,nr); put_be(plain+4,crypto1_prng(nt,64));
 bits=m1_encode(cipher,plain,8,4,tx);
 m1.stage=3;
 received=m1_rf(tx,(unsigned)bits,rx);
 if (!m1_receive(cipher,rx,received,plain,4)) return 0;
 if (bytes_be(plain)!=crypto1_prng(nt,96)) { m1.error=M1_AUTH_ANSWER; return 0; }
 return 1;
}
static int m1_authenticate(struct crypto1 *cipher, const uint8_t key[6],
                           uint8_t block, uint8_t key_type, uint32_t cuid) {
 return m1_authenticate_ex(cipher,key,block,key_type,cuid,0);
}
enum m1_operation { M1_AUTH, M1_READ, M1_WRITE, M1_WRITE_TEST, M1_READ_RAW, M1_WRITE_GEN1A, M1_READ_GEN1A, M1_WIPE_GEN1A, M1_READ_GEN1A_UNSELECTED };
static int m1_block_valid(unsigned block) {
 return block<64;
}
static int m1_read_data(struct crypto1 *cipher, uint8_t block, uint8_t out[16], unsigned stage) {
 uint8_t plain[18], tx[M1_RAW_BYTES], rx[M1_RAW_BYTES];
 uint32_t start=cycles();
 plain[0]=0x30; plain[1]=block;
 uint16_t crc=crc_a(plain,2); plain[2]=(uint8_t)crc; plain[3]=(uint8_t)(crc>>8);
 int bits=m1_encode(cipher,plain,4,0,tx);
 m1.stage=stage;
 int received=m1_rf(tx,(unsigned)bits,rx);
 if (!m1_receive(cipher,rx,received,plain,18)) return 0;
 crc=crc_a(plain,16);
 if (plain[16]!=(uint8_t)crc || plain[17]!=(uint8_t)(crc>>8)) {
  m1.crc_errors++; m1.error=M1_CRC; return 0;
 }
 for (unsigned i=0;i<16;i++) { m1.data[i]=plain[i]; out[i]=plain[i]; }
 uint32_t elapsed=cycles()-start;
 m1.read_ok++; m1.read_last=elapsed; m1.read_total+=elapsed;
 if (elapsed<m1.read_min) m1.read_min=elapsed;
 if (elapsed>m1.read_max) m1.read_max=elapsed;
 return 1;
}
static int m1_compare(const uint8_t data[16], const uint8_t expected[16]) {
 for (unsigned i=0;i<16;i++) if (data[i]!=expected[i]) {
  m1.mismatches++; m1.error=M1_DATA; return 0;
 }
 m1.read_matched++; return 1;
}
static int m1_compare_block(const uint8_t data[16], const uint8_t expected[16], unsigned block) {
 if ((block&3)!=3) return m1_compare(data,expected);
 /* Only access bytes + GPB can be compared reliably; keys may be hidden. */
 for (unsigned i=6;i<10;i++) if (data[i]!=expected[i]) {
  m1.mismatches++; m1.error=M1_DATA; return 0;
 }
 m1.read_matched++; return 1;
}
static int m1_ack(struct crypto1 *cipher, const uint8_t *raw, int bits) {
 uint8_t ack;
 if (bits<0) return 0;
 if (!m1_nibble(cipher,raw,(unsigned)bits,&ack)) { m1.error=M1_LENGTH; return 0; }
 if (ack!=0x0a) { m1.nak=ack; m1.error=M1_NAK; return 0; }
 m1.acks++; return 1;
}
static int m1_write(struct crypto1 *cipher, unsigned block, const uint8_t data[16]) {
 /* Check the full address BEFORE narrowing to uint8_t or touching RF. */
 if (!m1_block_valid(block)) { m1.error=M1_ARGUMENT; return 0; }
 uint8_t plain[18], tx[M1_RAW_BYTES], rx[M1_RAW_BYTES];
 plain[0]=0xa0; plain[1]=(uint8_t)block;
 uint16_t crc=crc_a(plain,2); plain[2]=(uint8_t)crc; plain[3]=(uint8_t)(crc>>8);
 int bits=m1_encode(cipher,plain,4,0,tx);
 m1.stage=6; m1.write_commands++;
 int received=m1_rf(tx,(unsigned)bits,rx);
 if (!m1_ack(cipher,rx,received)) return 0;
 for (unsigned i=0;i<16;i++) plain[i]=data[i];
 crc=crc_a(plain,16); plain[16]=(uint8_t)crc; plain[17]=(uint8_t)(crc>>8);
 bits=m1_encode(cipher,plain,18,0,tx);
 m1.stage=7; m1.data_frames++;
 received=m1_rf(tx,(unsigned)bits,rx);
 if (!m1_ack(cipher,rx,received)) return 0;
 m1.writes_acknowledged++; return 1;
}
/* Gen1a requires a selected, UID-checked card before HALT and backdoor wakeup.
   All frames stay on the MCU; never authenticate or encrypt this session. */
static int m1_gen1a_start(uint32_t uid, int unselected) {
 uint8_t plain[4]={0x50,0,0,0},tx[M1_RAW_BYTES],rx[M1_RAW_BYTES];
 if (unselected) {
  /* Read-only diagnostic: erased manufacturer bytes may prevent SELECT. */
  if (!write_reg(0x02,0x80)) { m1.error=M1_RF; return 0; }
  card.field_on=0; delay_ms(10);
  if (!write_reg(0x02,0xc8)) { m1.error=M1_RF; return 0; }
  card.field_on=1; delay_ms(10);
 } else {
  if (!poll_uid()) { m1.error=M1_SELECT; return 0; }
  uint32_t found=0;
  if (card.uid_length!=4 || card.sak!=8) { m1.error=M1_UID; return 0; }
  for (unsigned i=0;i<4;i++) found=(found<<8)|card.uid[i];
  if (found!=uid) { m1.error=M1_UID; return 0; }
 }
 uint16_t crc=crc_a(plain,2); plain[2]=crc; plain[3]=crc>>8;
 unsigned bits=m1_encode(0,plain,4,0,tx);
 int halted=m1_rf(tx,bits,rx); /* HALT normally times out. */
 if (halted<0 && card.error!=3) return 0;
 m1.error=m1.rf_error=0;
 tx[0]=0x40;
 int received=m1_rf(tx,7,rx);
 if (!m1_ack(0,rx,received)) return 0;
 return 1;
}
static int m1_gen1a_unlock(uint32_t uid, int unselected) {
 if (!m1_gen1a_start(uid,unselected)) return 0;
 uint8_t plain=0x43,tx[M1_RAW_BYTES],rx[M1_RAW_BYTES];
 unsigned bits=m1_encode(0,&plain,1,0,tx);
 int received=m1_rf(tx,bits,rx);
 return m1_ack(0,rx,received);
}
static int m1_gen1a_wipe(uint32_t uid) {
 /* PM3 MAGIC_WIPE: HALT -> 40(7 bits) -> 41(8 bits+parity), no CRC.
    Never send 43, A0 or a block payload in this operation. */
 if (!m1_gen1a_start(uid,0)) return 0;
 uint8_t ctl,high,low,tx[M1_RAW_BYTES],rx[M1_RAW_BYTES],plain=0x41;
 if (!read_reg(0x12,&ctl) || !read_reg(0x10,&high) || !read_reg(0x11,&low)) {
  m1.error=M1_RF; return 0;
 }
 /* ceil(2s * 13.56MHz / 4096) = 6622, software limit 2100ms. */
 int configured=write_reg(0x12,ctl|1);
 configured&=write_reg(0x10,6622>>8);
 configured&=write_reg(0x11,6622&255);
 int ok=0;
 if (configured) {
  unsigned bits=m1_encode(0,&plain,1,0,tx);
  m1.stage=8; m1.write_commands++;
  int received=transceive_bits_wait(0xc5,tx,bits,0xc0,rx,sizeof(rx),2100);
  m1.rx_bits=received<0?0:(unsigned)received;
  if (received<0) { m1.error=M1_RF; m1.rf_error=card.error; }
  ok=m1_ack(0,rx,received);
  /* Some clones ACK before EEPROM work finishes. Keep RF powered even
     after a fast ACK; do not mistake an interrupted erase for no support. */
  delay_ms(2000);
 } else m1.error=M1_RF;
 int restored=write_reg(0x12,ctl);
 restored&=write_reg(0x10,high);
 restored&=write_reg(0x11,low);
 if (!restored) { m1.error=M1_CLEANUP; ok=0; }
 return ok;
}
static int m1_select_auth(struct crypto1 *cipher, const uint8_t key[6], unsigned block,
                          unsigned key_type, uint32_t expected_uid) {
 m1.stage=1; card.found=0;
 if (!poll_uid()) {
  m1.select_errors++; m1.error=M1_SELECT; m1.rf_error=card.error;
  if (card.error==3) m1.timeouts++;
  if (card.error==6) m1.fifo_errors++;
  return 0;
 }
 uint32_t cuid=0;
 for (unsigned i=card.uid_length-4;i<card.uid_length;i++) cuid=(cuid<<8)|card.uid[i];
 if (card.sak!=0x08 || cuid!=expected_uid) { m1.uid_errors++; m1.error=M1_UID; return 0; }
 uint32_t start=cycles();
 int ok=m1_authenticate(cipher,key,(uint8_t)block,(uint8_t)key_type,cuid);
 uint32_t elapsed=cycles()-start; m1.auth_last=elapsed;
 if (!ok) {
  m1.auth_errors++;
  if (m1.stage==3 && ((m1.error==M1_RF && m1.rf_error==3) ||
      m1.error==M1_PARITY || m1.error==M1_AUTH_ANSWER || m1.error==M1_NAK)) m1.rejected++;
 } else {
  m1.auth_ok++; m1.auth_total+=elapsed;
  if (elapsed<m1.auth_min) m1.auth_min=elapsed;
  if (elapsed>m1.auth_max) m1.auth_max=elapsed;
 }
 return ok;
}
static int m1_restore(const uint8_t key[6], unsigned block, unsigned key_type,
                      uint32_t uid, const uint8_t original[16], int possibly_changed) {
 /* A missing final ACK can still mean EEPROM was changed. Re-select and
    authenticate before restoring; never reuse a cipher after a failed frame. */
 for (unsigned attempt=0;attempt<2;attempt++) {
  struct crypto1 cipher; uint8_t data[16];
  m1.restore_attempts++; m1.error=m1.rf_error=0;
  int ok=m1_select_auth(&cipher,key,block,key_type,uid);
  if (ok && possibly_changed) ok=m1_write(&cipher,block,original);
  if (ok) ok=m1_read_data(&cipher,(uint8_t)block,data,9) && m1_compare_block(data,original,block);
  if (ok) { m1.restore_ok++; m1.restore_error=0; return 1; }
  m1.restore_error=m1.error; m1.restore_failures++;
 }
 return 0;
}
static int m1_write_transaction(struct crypto1 *cipher, const uint8_t key[6],
                                unsigned block, unsigned key_type, uint32_t uid,
                                const uint8_t expected[16], const uint8_t payload[16], int test) {
 uint8_t original[16], readback[16];
 if (!m1_read_data(cipher,(uint8_t)block,original,4)) return 0;
 if (!m1_compare_block(original,expected,block)) return 0; /* no writes on stale reference */
 if ((block&3)==3) {
  /* READ hides key material. Full original trailer must come from the caller. */
  for (unsigned i=0;i<16;i++) original[i]=expected[i];
 }
 for (unsigned i=0;i<16;i++) m1.original_data[i]=original[i];
 m1.backup_valid=1;
 uint32_t data_frames=m1.data_frames, start=cycles();
 int ok=m1_write(cipher,block,payload);
 uint32_t elapsed=cycles()-start; m1.write_last=elapsed;
 if (ok) {
  m1.payload_ok++; m1.write_total+=elapsed;
  if (elapsed<m1.write_min) m1.write_min=elapsed;
  if (elapsed>m1.write_max) m1.write_max=elapsed;
  ok=m1_read_data(cipher,(uint8_t)block,readback,8) && m1_compare_block(readback,payload,block);
  if (ok) m1.write_verified++;
 }
 uint32_t primary_error=m1.error, primary_rf=m1.rf_error, primary_stage=m1.stage;
 m1.write_error=ok?0:primary_error;
 int changed=m1.data_frames!=data_frames;
 if (test || (!ok && changed)) {
  if (!m1_restore(key,block,key_type,uid,original,changed)) {
   m1.error=M1_RESTORE; return 0;
  }
 }
 if (!ok) { m1.error=primary_error; m1.rf_error=primary_rf; m1.stage=primary_stage; }
 return ok;
}
static void run_m1(void) {
 if (!m1.requested) return;
 m1.running=1; m1.requested=0;
 unsigned count=m1.count, block=m1.block, key_type=m1.key_type, op=m1.operation;
 uint32_t uid=m1.expected_uid;
 uint8_t key[6], expected[16], payload[16];
 m1.error=m1.rf_error=m1.stage=0;
 m1.completed=m1.failures=m1.auth_ok=m1.read_ok=0;
 m1.timeouts=m1.fifo_errors=m1.parity_errors=m1.auth_errors=m1.crc_errors=m1.mismatches=0;
 m1.auth_last=m1.auth_max=m1.auth_total=m1.read_last=m1.read_max=m1.read_total=0;
 m1.auth_min=m1.read_min=0xffffffffu;
 m1.nt=m1.rx_bits=m1.nak=0;
 m1.nonce_ok=m1.rejected=m1.select_errors=m1.uid_errors=m1.read_matched=0;
 m1.batch_cycles_low=m1.batch_cycles_high=0;
 m1.backup_valid=m1.write_commands=m1.data_frames=m1.acks=m1.payload_ok=0;
 m1.write_verified=m1.restore_attempts=m1.restore_ok=m1.restore_error=m1.write_error=0;
 m1.write_last=m1.write_max=m1.write_total=m1.reserved125=0;
 m1.restore_failures=m1.writes_acknowledged=0; m1.write_min=0xffffffffu;
 for (unsigned i=0;i<16;i++) m1.data[i]=m1.original_data[i]=0;
 if (op==M1_WRITE || op==M1_WRITE_TEST || op==M1_WRITE_GEN1A) {
  if (((op==M1_WRITE || op==M1_WRITE_GEN1A) && count!=1) || (op==M1_WRITE_TEST && count>20)) goto bad_argument;
 }
 if (op==M1_WIPE_GEN1A && (count!=1 || block!=0)) goto bad_argument;
 if (!count || count>1000 || block>=64 || key_type>1 || op>M1_READ_GEN1A_UNSELECTED) goto bad_argument;
 for (unsigned i=0;i<6;i++) { if (m1.key[i]>255) goto bad_argument; key[i]=m1.key[i]; }
 for (unsigned i=0;i<16;i++) {
  if (m1.expected[i]>255 || ((op==M1_WRITE || op==M1_WRITE_TEST || op==M1_WRITE_GEN1A) && m1.write_data[i]>255)) goto bad_argument;
  expected[i]=(uint8_t)m1.expected[i]; payload[i]=(uint8_t)m1.write_data[i];
 }
 if (op==M1_WRITE_TEST) {
  int different=0;
  for (unsigned i=0;i<16;i++) if (expected[i]!=payload[i]) different=1;
  if (!different) goto bad_argument; /* test must actually change the data */
 }
 uint64_t batch_cycles=0;
 for (unsigned trial=0;trial<count;trial++) {
  uint32_t trial_start=cycles();
  m1.error=m1.rf_error=0;
  struct crypto1 cipher; uint8_t data[16];
  int gen1a=op==M1_WRITE_GEN1A || op==M1_READ_GEN1A || op==M1_READ_GEN1A_UNSELECTED;
  int ok;
  if (op==M1_WIPE_GEN1A) ok=m1_gen1a_wipe(uid);
  else ok=gen1a?m1_gen1a_unlock(uid,op==M1_READ_GEN1A_UNSELECTED):m1_select_auth(&cipher,key,block,key_type,uid);
  if (ok && (op==M1_READ || op==M1_READ_RAW || op==M1_READ_GEN1A || op==M1_READ_GEN1A_UNSELECTED)) {
   ok=m1_read_data(gen1a?0:&cipher,(uint8_t)block,data,4);
   if (ok && op==M1_READ) ok=m1_compare(data,expected);
  } else if (ok && (op==M1_WRITE || op==M1_WRITE_GEN1A)) {
   /* Normal WRITE: no preread, masked trailer comparison, or rollback.
      Allows changed keys/ACL/UID and unreadable targets. */
   uint32_t start=cycles();
   ok=m1_write(op==M1_WRITE_GEN1A?0:&cipher,block,payload);
   uint32_t elapsed=cycles()-start; m1.write_last=elapsed;
   if (ok) {
    m1.payload_ok++; m1.write_total+=elapsed;
    if (elapsed<m1.write_min) m1.write_min=elapsed;
    if (elapsed>m1.write_max) m1.write_max=elapsed;
   } else m1.write_error=m1.error;
  } else if (ok && op==M1_WRITE_TEST) {
   ok=m1_write_transaction(&cipher,key,block,key_type,uid,expected,payload,op==M1_WRITE_TEST);
  }
  int off=write_reg(0x02,0x80);
  int restored=write_reg(0x05,0);
  if (off) card.field_on=0;
  if (!off || !restored) { m1.error=M1_CLEANUP; ok=0; }
  if (ok) { m1.completed++; m1.stage=5; } else { m1.failures++; }
  batch_cycles+=(uint32_t)(cycles()-trial_start);
  if (!ok && (op==M1_WRITE || op==M1_WRITE_TEST || op==M1_WRITE_GEN1A)) break;
 }
 m1.batch_cycles_low=(uint32_t)batch_cycles;
 m1.batch_cycles_high=(uint32_t)(batch_cycles>>32);
done:
 m1.running=0; return;
bad_argument:
 m1.error=M1_ARGUMENT; goto done;
}
