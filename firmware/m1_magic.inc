/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 NFClab contributors.
 */
/* PM3 MifareCIdent subset. Default probes never issue WRITE or config changes. */
enum magic_flags { MAGIC_GEN1A=1, MAGIC_GEN1B=2, MAGIC_GTU=4,
 MAGIC_GDM_AUTH=8, MAGIC_GDM_GEN1=16, MAGIC_GDM_ALT=32,
 MAGIC_GEN2_ATS=64, MAGIC_GEN2_ACK=128 };
static unsigned magic_error;
/* Explicit parity permits 7-bit wakeups and ACKs; long config replies need
   up to 34*9 bits. CRC-bearing responses are checked before identifying. */
static int magic_exchange(const uint8_t *data, unsigned length, int short7,
                          int response_crc, uint8_t response[34]) {
 uint8_t plain[18],tx[M1_RAW_BYTES],rx[64]; unsigned bits;
 if (length>16) { magic_error=M1_ARGUMENT; return 0; }
 for (unsigned i=0;i<length;i++) plain[i]=data[i];
 if (short7) { tx[0]=data[0]; bits=7; }
 else {
  uint16_t crc=crc_a(plain,length); plain[length]=crc; plain[length+1]=crc>>8;
  bits=m1_encode(0,plain,length+2,0,tx);
 }
 card.error=0;
 int received=transceive_bits(0xc5,tx,bits,0xc0,rx,sizeof(rx));
 if (received<0) { if (card.error!=3) magic_error=M1_RF; return 0; }
 if (received==4) { response[0]=rx[0]&15; return 1; }
 if (!received || received%9 || received/9>34) { magic_error=M1_LENGTH; return 0; }
 unsigned n=received/9;
 for (unsigned j=0;j<n;j++) {
  uint8_t b=0; for (unsigned k=0;k<8;k++) b|=raw_bit(rx,j*9+k)<<k;
  if (raw_bit(rx,j*9+8)!=odd_parity(b)) { magic_error=M1_PARITY; return 0; }
  response[j]=b;
 }
 if (response_crc) {
  if (n<3) { magic_error=M1_LENGTH; return 0; }
  uint16_t crc=crc_a(response,n-2);
  if (response[n-2]!=(uint8_t)crc || response[n-1]!=(uint8_t)(crc>>8)) {
   magic_error=M1_CRC; return 0;
  }
 }
 return n;
}
/* Wakeup second byte is sent without CRC, unlike ordinary commands. */
static int magic_second(uint8_t value) {
 uint8_t tx[M1_RAW_BYTES],rx[4];
 unsigned bits=m1_encode(0,&value,1,0,tx);
 card.error=0;
 int n=transceive_bits(0xc5,tx,bits,0xc0,rx,sizeof(rx));
 if (n<0 && card.error!=3) magic_error=M1_RF;
 return n==4 && (rx[0]&15)==10;
}
static int magic_select(uint32_t uid) {
 m1.error=0;
 if (!m1_key_select(uid,1,0)) { magic_error=m1.error?m1.error:M1_SELECT; return 0; }
 return 1;
}
static unsigned m1_magic_probe(uint32_t uid, int deep, const uint8_t key[6],
                                unsigned key_type, uint32_t *flags) {
 magic_error=0; *flags=0;
 uint8_t response[34];
 if (!magic_select(uid)) goto done;
 if (deep) {
  struct crypto1 cipher; uint8_t plain[4]={0xa0,0,0,0},tx[M1_RAW_BYTES],rx[M1_RAW_BYTES];
  if (!m1_authenticate(&cipher,key,0,key_type,uid)) {
   magic_error=m1.error?m1.error:M1_RF; goto done;
  }
  uint16_t crc=crc_a(plain,2); plain[2]=crc; plain[3]=crc>>8;
  unsigned bits=m1_encode(&cipher,plain,4,0,tx);
  m1.stage=5; m1.write_commands++;
  int received=m1_rf(tx,bits,rx); uint8_t answer=0;
  if (m1_nibble(&cipher,rx,received,&answer)) {
   if (answer==10) { *flags=MAGIC_GEN2_ACK; m1.acks++; }
  } else magic_error=m1.error?m1.error:M1_LENGTH;
  /* No data frame is ever generated. Close RF immediately, ACK or NAK. */
  goto done;
 }
 {
  const uint8_t halt[]={0x50,0},wake[]={0x40},cfg[]={0xe0,0},hidden[]={0x38,0};
  (void)magic_exchange(halt,2,0,0,response);
  if (magic_exchange(wake,1,1,0,response)==1 && response[0]==10) {
   *flags|=magic_second(0x43)?MAGIC_GEN1A:MAGIC_GEN1B;
   int n=magic_exchange(cfg,2,0,1,response);
   if (n>2 && magic_exchange(hidden,2,0,1,response)>2) *flags|=MAGIC_GDM_GEN1;
  }
 }
 if (!magic_select(uid)) goto done;
 {
  const uint8_t gtu[]={0xcf,0,0,0,0,0xc6};
  int n=magic_exchange(gtu,sizeof(gtu),0,1,response);
  if (n==32 || n==34) *flags|=MAGIC_GTU;
 }
 if (!magic_select(uid)) goto done;
 {
  const uint8_t rats[]={0xe0,0x80};
  int n=magic_exchange(rats,2,0,1,response);
  const uint8_t ats4[]={9,0x78,0,0x91,2,0xda,0xbc,0x19,0x10};
  const uint8_t ats7[]={0x0d,0x78,0,0x71,2,0x88,0x49,0xa1,0x30,0x20,0x15,6,8};
  if (n>3 && response[0]==n-2) {
   int match4=n>=11,match7=n>=15;
   for (unsigned i=0;i<sizeof(ats4) && match4;i++) match4=response[i]==ats4[i];
   for (unsigned i=0;i<sizeof(ats7) && match7;i++) match7=response[i]==ats7[i];
   if (match4 || match7) *flags|=MAGIC_GEN2_ATS;
  }
 }
 if (!magic_select(uid)) goto done;
 {
  const uint8_t auth[]={0x80,0};
  if (magic_exchange(auth,2,0,0,response)==4) *flags|=MAGIC_GDM_AUTH;
 }
 if (!magic_select(uid)) goto done;
 {
  const uint8_t halt[]={0x50,0},wake[]={0x20},cfg[]={0xe0,0};
  (void)magic_exchange(halt,2,0,0,response);
  if (magic_exchange(wake,1,1,0,response)==1 && response[0]==10) {
   *flags|=MAGIC_GDM_ALT;
   if (magic_second(0x23)) (void)magic_exchange(cfg,2,0,1,response);
  }
 }
done:
 if (!write_reg(0x02,0x80) || !write_reg(0x05,0)) magic_error=M1_CLEANUP;
 card.field_on=0;
 return magic_error;
}
