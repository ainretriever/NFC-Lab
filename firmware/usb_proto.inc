/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 NFClab contributors.
 */
/* Framed command protocol carried over the CDC bulk endpoints.
 *
 * Frame: 'N' 'F' | version | opcode | seq | flags | len_lo len_hi | payload | crc16_lo crc16_hi
 * CRC16-CCITT (poly 0x1021, init 0xFFFF) covers everything before it.
 * A frame whose wire length would be a multiple of 64 gets one pad byte, so the
 * USB bulk IN transfer always ends with a short packet and the host read returns.
 */
#define USB_FRAME_HEADER 8u
#define USB_FRAME_TRAILER 2u
/* One frame must carry a full 1K key batch (1024*6 B) or a bulk read result. */
#define USB_MAX_PAYLOAD 8192u
#define USB_FRAME_MAX (USB_FRAME_HEADER+USB_FRAME_TRAILER+USB_MAX_PAYLOAD+1u)
#define USB_MEM_BYTES USB_MAX_PAYLOAD
/* Mailbox RAM window the memory commands may touch. */
#define USB_MEM_BASE 0x20000000u
#define USB_MEM_LIMIT 0x20020000u

#define USB_OP_ECHO 0x01u
#define USB_OP_INFO 0x02u
#define USB_OP_READ_MEM 0x10u
#define USB_OP_WRITE_MEM 0x11u

static uint8_t usb_frame[USB_FRAME_MAX];
static uint8_t usb_inbuf[USB_FRAME_MAX];
static uint8_t usb_mem_buf[USB_MEM_BYTES];
static unsigned usb_inlen;

static uint32_t usb_rd32(const uint8_t *p) {
 return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);
}
static void usb_wr32(uint8_t *p, uint32_t value) {
 p[0]=(uint8_t)value; p[1]=(uint8_t)(value>>8);
 p[2]=(uint8_t)(value>>16); p[3]=(uint8_t)(value>>24);
}

static uint16_t usb_crc16(const uint8_t *data, unsigned len) {
 uint16_t crc=0xffff;
 for (unsigned i=0;i<len;i++) {
  crc^=(uint16_t)data[i]<<8;
  for (unsigned bit=0;bit<8;bit++)
   crc=(crc&0x8000u)?(uint16_t)((crc<<1)^0x1021u):(uint16_t)(crc<<1);
 }
 return crc;
}

static void usb_send_frame(uint8_t opcode, uint8_t seq, const uint8_t *payload, unsigned len) {
 if (len>USB_MAX_PAYLOAD) { usb_errors++; return; }
 usb_frame[0]='N'; usb_frame[1]='F'; usb_frame[2]=1; usb_frame[3]=opcode;
 usb_frame[4]=seq; usb_frame[5]=0;
 usb_frame[6]=(uint8_t)len; usb_frame[7]=(uint8_t)(len>>8);
 for (unsigned i=0;i<len;i++) usb_frame[USB_FRAME_HEADER+i]=payload[i];
 uint16_t crc=usb_crc16(usb_frame,USB_FRAME_HEADER+len);
 usb_frame[USB_FRAME_HEADER+len]=(uint8_t)crc;
 usb_frame[USB_FRAME_HEADER+len+1]=(uint8_t)(crc>>8);
 unsigned wire=USB_FRAME_HEADER+USB_FRAME_TRAILER+len;
 if ((wire&63u)==0u) usb_frame[wire++]=0;
 usb_write(usb_frame,wire);
 usb_frames_tx++;
}

/* Mailbox RAM access: one round trip replaces a whole mww/mdw burst.
   Addresses are word aligned; the length may end mid-word, so the partial tail
   word is merged with a read-modify-write (as load_image/dump_image would). */
static int usb_mem_ok(uint32_t address, uint32_t bytes) {
 if (bytes==0u || bytes>USB_MEM_BYTES) return 0;
 if ((address&3u)!=0u || address<USB_MEM_BASE || address>USB_MEM_LIMIT) return 0;
 return bytes<=USB_MEM_LIMIT-address;
}

static void usb_dispatch_frame(uint8_t opcode, uint8_t seq,
                               const uint8_t *payload, unsigned len) {
 if (opcode==USB_OP_ECHO) { usb_send_frame(USB_OP_ECHO,seq,payload,len); return; }
 if (opcode==USB_OP_INFO) {
  uint8_t info[12];
  info[0]=2; info[1]=0;                 /* firmware protocol version */
  info[2]=(uint8_t)usb_state;
  info[3]=0;
  info[4]=(uint8_t)core_hz; info[5]=(uint8_t)(core_hz>>8);
  info[6]=(uint8_t)(core_hz>>16); info[7]=(uint8_t)(core_hz>>24);
  info[8]=(uint8_t)diag.clock_src;
  info[9]=0; info[10]=0; info[11]=0;
  usb_send_frame(USB_OP_INFO,seq,info,sizeof(info));
  return;
 }
 if (opcode==USB_OP_READ_MEM && len==8u) {
  uint32_t address=usb_rd32(payload), bytes=usb_rd32(payload+4);
  if (!usb_mem_ok(address,bytes)) { usb_errors++; usb_send_frame(0xffu,seq,0,0); return; }
  uint32_t whole=bytes&~3u;
  for (uint32_t i=0;i<whole;i+=4) usb_wr32(usb_mem_buf+i,R(address+i));
  if (whole!=bytes) {
   uint32_t tail=R(address+whole);
   for (uint32_t i=whole;i<bytes;i++) usb_mem_buf[i]=(uint8_t)(tail>>((i-whole)*8));
  }
  usb_send_frame(USB_OP_READ_MEM,seq,usb_mem_buf,bytes);
  return;
 }
 if (opcode==USB_OP_WRITE_MEM && len>=8u) {
  uint32_t address=usb_rd32(payload), bytes=usb_rd32(payload+4);
  if (bytes!=len-8u || !usb_mem_ok(address,bytes)) {
   usb_errors++; usb_send_frame(0xffu,seq,0,0); return;
  }
  uint32_t whole=bytes&~3u;
  for (uint32_t i=0;i<whole;i+=4) R(address+i)=usb_rd32(payload+8+i);
  if (whole!=bytes) {
   uint32_t tail=R(address+whole);
   for (uint32_t i=whole;i<bytes;i++) {
    uint32_t shift=(i-whole)*8;
    tail=(tail&~(0xffu<<shift))|((uint32_t)payload[8+i]<<shift);
   }
   R(address+whole)=tail;
  }
  uint8_t confirm[4]; usb_wr32(confirm,bytes);
  usb_send_frame(USB_OP_WRITE_MEM,seq,confirm,4);
  return;
 }
 usb_errors++;
 usb_send_frame(0xffu,seq,0,0); /* unknown opcode or bad length */
}

/* Consume whatever the host sent and answer every complete frame. */
static void usb_service(void) {
 uint8_t chunk[64];
 while (usb_rx_count()) {
  unsigned n=usb_read(chunk,sizeof(chunk));
  if (!n) break;
  for (unsigned i=0;i<n;i++) {
   if (usb_inlen<sizeof(usb_inbuf)) usb_inbuf[usb_inlen++]=chunk[i];
   else { usb_inlen=0; usb_errors++; }
  }
 }
 for (;;) {
  if (usb_inlen<USB_FRAME_HEADER) return;
  if (usb_inbuf[0]!='N' || usb_inbuf[1]!='F' || usb_inbuf[2]!=1u) {
   /* Resynchronise on the next plausible magic byte. */
   unsigned skip=1;
   while (skip<usb_inlen && !(usb_inbuf[skip]=='N' && skip+1<usb_inlen && usb_inbuf[skip+1]=='F')) skip++;
   for (unsigned i=0;i+skip<usb_inlen;i++) usb_inbuf[i]=usb_inbuf[i+skip];
   usb_inlen-=skip;
   usb_errors++;
   continue;
  }
  unsigned len=(unsigned)usb_inbuf[6]|((unsigned)usb_inbuf[7]<<8);
  if (len>USB_MAX_PAYLOAD) { usb_inlen=0; usb_errors++; return; }
  unsigned total=USB_FRAME_HEADER+USB_FRAME_TRAILER+len;
  unsigned wire=total; if ((wire&63u)==0u) wire++;
  if (usb_inlen<wire) return;
  uint16_t crc=usb_crc16(usb_inbuf,USB_FRAME_HEADER+len);
  uint16_t want=(uint16_t)(usb_inbuf[USB_FRAME_HEADER+len]|
                           (usb_inbuf[USB_FRAME_HEADER+len+1]<<8));
  if (crc!=want) {
   usb_errors++;
  } else {
   usb_frames_rx++;
   usb_dispatch_frame(usb_inbuf[3],usb_inbuf[4],usb_inbuf+USB_FRAME_HEADER,len);
  }
  for (unsigned i=0;i+wire<usb_inlen;i++) usb_inbuf[i]=usb_inbuf[i+wire];
  usb_inlen-=wire;
 }
}
