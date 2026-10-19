/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 NFClab contributors.
 */
/* Bare-metal USB full-speed device + CDC-ACM for the STM32F411 OTG_FS.
 *
 * No HAL and no vendor library, matching the rest of this firmware: register
 * level, -nostdlib, no heap. The 48 MHz USB clock comes from PLLQ=4, which is
 * only accurate enough because clock_init() selects the 25 MHz HSE crystal.
 *
 * Endpoints: EP0 control, EP1 IN CDC notification, EP2 OUT / EP2 IN bulk data.
 * FIFO RAM is 320 words (1280 B): RX 128, EP0 TX 96, EP1 TX 16, EP2 TX 80.
 */
#define OTG 0x50000000u
#define GOTGCTL   (OTG+0x000)
#define GOTGINT   (OTG+0x004)
#define GAHBCFG   (OTG+0x008)
#define GUSBCFG   (OTG+0x00c)
#define GRSTCTL   (OTG+0x010)
#define GINTSTS   (OTG+0x014)
#define GINTMSK   (OTG+0x018)
#define GRXSTSP   (OTG+0x020)
#define GRXFSIZ   (OTG+0x024)
#define GNPTXFSIZ (OTG+0x028)
#define GCCFG     (OTG+0x038)
#define DIEPTXF1  (OTG+0x104)
#define DIEPTXF2  (OTG+0x108)
#define DCFG      (OTG+0x800)
#define DCTL      (OTG+0x804)
#define DSTS      (OTG+0x808)
#define DIEPMSK   (OTG+0x810)
#define DOEPMSK   (OTG+0x814)
#define DAINT     (OTG+0x818)
#define DAINTMSK  (OTG+0x81c)
#define DIEPCTL(n) (OTG+0x900u+((n)*0x20u))
#define DIEPINT(n) (OTG+0x908u+((n)*0x20u))
#define DIEPTSIZ(n)(OTG+0x910u+((n)*0x20u))
#define DOEPCTL(n) (OTG+0xb00u+((n)*0x20u))
#define DOEPINT(n) (OTG+0xb08u+((n)*0x20u))
#define DOEPTSIZ(n)(OTG+0xb10u+((n)*0x20u))
#define DFIFO(n)   (OTG+0x1000u+((n)*0x1000u))

/* GINTSTS/GINTMSK */
#define GINT_RXFLVL (1u<<4)
#define GINT_USBRST (1u<<10)
#define GINT_ENUMDNE (1u<<13)
#define GINT_IEPINT (1u<<18)
#define GINT_OEPINT (1u<<19)
/* DIEPCTL/DOEPCTL */
#define EP_ENA  (1u<<31)
#define EP_DIS  (1u<<30)
#define EP_CNAK (1u<<26)
#define EP_SNAK (1u<<27)
#define EP_STALL (1u<<21)
#define EP_ACTIVE (1u<<15)
#define EP_TYPE_BULK (2u<<18)
#define EP_TYPE_INT  (3u<<18)
#define MPS_64 64u
/* DIEPINT/DOEPINT */
#define EPINT_XFRC (1u<<0)
#define EPINT_TXFE (1u<<7)
#define EPINT_STUP (1u<<3)
/* RX FIFO packet status */
#define PKTSTS_OUT_DATA 2u
#define PKTSTS_SETUP_DONE 4u
#define PKTSTS_SETUP_DATA 6u

#define USB_MPS 64u
#define USB_RX_RING 4096u
#define USB_TX_RING 9216u
/* EP2 IN FIFO depth in words; also the largest burst one EPENA can carry. */
#define EP2_TX_WORDS 80u
/* Bulk OUT is re-armed in 8-packet bursts; pause when the ring cannot take one. */
#define USB_OUT_BURST (64u*8u)

/* 0 = offline, 1 = reset seen, 2 = configured. Kept global so the SWD
   fallback can still inspect the link while CDC is being brought up. */
volatile uint32_t usb_state, usb_rx_bytes, usb_tx_bytes, usb_errors, usb_setups;
volatile uint32_t usb_frames_rx, usb_frames_tx;
static volatile uint8_t usb_configured;
static uint8_t usb_setup[8];
static uint8_t usb_ep0_in[80];
static uint8_t usb_ep0_out[80];
static uint16_t usb_ep0_in_len, usb_ep0_out_len, usb_ep0_out_want;
static uint8_t usb_ep0_need_status_out;
static uint16_t usb_ep0_in_pos;
static uint8_t usb_ep0_zlp;
static uint8_t usb_line_coding[7] = {0x00,0xc2,0x01,0x00,0x00,0x00,0x08};
static volatile uint8_t usb_rx_ring[USB_RX_RING];
static volatile uint32_t usb_rx_head, usb_rx_tail;
static volatile uint8_t usb_tx_ring[USB_TX_RING];
static volatile uint32_t usb_tx_head, usb_tx_tail;
static volatile uint8_t usb_rx_paused;

/* Probed at reset from PA11/PA12 being usable; kept for host diagnostics. */
static const uint8_t usb_device_desc[] = {
 18, 0x01, 0x00,0x02, 0xef,0x02,0x01, 64,
 0x83,0x04, 0x40,0x57, 0x00,0x01,
 0, 2, 0, 1
};
static const uint8_t usb_config_desc[] = {
 /* configuration */
 9, 0x02, 75,0x00, 2, 1, 0, 0x80, 50,
 /* interface association: two interfaces, CDC */
 8, 0x0b, 0, 2, 0x02, 0x02, 0x01, 0,
 /* interface 0: CDC communication */
 9, 0x04, 0, 0, 1, 0x02, 0x02, 0x01, 0,
 5, 0x24, 0x00, 0x10, 0x01,             /* header functional */
 5, 0x24, 0x01, 0x00, 0x01,             /* call management */
 4, 0x24, 0x02, 0x02,                   /* abstract control model */
 5, 0x24, 0x06, 0x00, 0x01,             /* union: interface 0 and 1 */
 7, 0x05, 0x81, 0x03, 0x10, 0x00, 0x10, /* EP1 IN interrupt */
 /* interface 1: CDC data */
 9, 0x04, 1, 0, 2, 0x0a, 0x00, 0x00, 0,
 7, 0x05, 0x02, 0x02, 0x40, 0x00, 0x00, /* EP2 OUT bulk */
 7, 0x05, 0x82, 0x02, 0x40, 0x00, 0x00  /* EP2 IN bulk */
};
static const uint8_t usb_string0[] = {4, 0x03, 0x09, 0x04};
static const uint8_t usb_string2[] = {22, 0x03, 'N',0,'F',0,'C',0,'l',0,'a',0,'b',0,' ',0,'C',0,'D',0,'C',0};

static void usb_fifo_read(uint8_t *dst, unsigned bytes) {
 unsigned words=(bytes+3u)>>2;
 for (unsigned i=0;i<words;i++) {
  uint32_t value=R(DFIFO(0));
  unsigned n=bytes-(i<<2); if (n>4) n=4;
  for (unsigned j=0;j<n;j++) dst[(i<<2)+j]=(uint8_t)(value>>(j<<3));
 }
}
static void usb_fifo_write(unsigned ep, const uint8_t *src, unsigned bytes) {
 unsigned words=(bytes+3u)>>2;
 for (unsigned i=0;i<words;i++) {
  uint32_t value=0;
  unsigned n=bytes-(i<<2); if (n>4) n=4;
  for (unsigned j=0;j<n;j++) value|=(uint32_t)src[(i<<2)+j]<<(j<<3);
  R(DFIFO(ep))=value;
 }
}
static unsigned usb_rx_count(void) {
 return (usb_rx_head-usb_rx_tail+USB_RX_RING)%USB_RX_RING;
}
static unsigned usb_tx_count(void) {
 return (usb_tx_head-usb_tx_tail+USB_TX_RING)%USB_TX_RING;
}
static void usb_rx_push(const uint8_t *src, unsigned bytes) {
 for (unsigned i=0;i<bytes;i++) {
  uint32_t next=(usb_rx_head+1u)%USB_RX_RING;
  if (next==usb_rx_tail) { usb_errors++; return; } /* ring full: drop */
  usb_rx_ring[usb_rx_head]=src[i]; usb_rx_head=next; usb_rx_bytes++;
 }
}
static unsigned usb_read(uint8_t *dst, unsigned max) {
 unsigned n=0;
 while (n<max && usb_rx_tail!=usb_rx_head) {
  dst[n++]=usb_rx_ring[usb_rx_tail];
  usb_rx_tail=(usb_rx_tail+1u)%USB_RX_RING;
 }
 return n;
}
static void usb_write(const uint8_t *src, unsigned bytes) {
 for (unsigned i=0;i<bytes;i++) {
  uint32_t next=(usb_tx_head+1u)%USB_TX_RING;
  if (next==usb_tx_tail) { usb_errors++; return; }
  usb_tx_ring[usb_tx_head]=src[i]; usb_tx_head=next; usb_tx_bytes++;
 }
}

static void usb_ep0_stall(void) {
 R(DIEPCTL(0))|=EP_STALL; R(DOEPCTL(0))|=EP_STALL;
}
/* Arm the EP0 data stage. Payload must already be in usb_ep0_in. */
static void usb_ep0_send_next(void) {
 unsigned n=usb_ep0_in_len-usb_ep0_in_pos;
 if (n>USB_MPS) n=USB_MPS;
 R(DIEPTSIZ(0))=n|(1u<<19);
 R(DIEPCTL(0))=(R(DIEPCTL(0))&~3u)|EP_ACTIVE|EP_ENA|EP_CNAK;
 usb_fifo_write(0,usb_ep0_in+usb_ep0_in_pos,n);
 usb_ep0_in_pos+=(uint16_t)n;
}
static void usb_ep0_setup_arm(void) {
 R(DOEPTSIZ(0))=(3u<<29)|(1u<<19)|24u;
}
static void usb_ep0_in_stage(uint16_t len) {
 usb_ep0_in_len=len; usb_ep0_in_pos=0;
 usb_ep0_need_status_out=1;
 usb_ep0_send_next();
}
/* Status stage for a control write: zero-length IN. */
static void usb_ep0_status_in(void) {
 usb_ep0_need_status_out=0;
 R(DIEPTSIZ(0))=1u<<19;
 R(DIEPCTL(0))=(R(DIEPCTL(0))&~3u)|EP_ACTIVE|EP_ENA|EP_CNAK;
}
/* Status stage for a control read: zero-length OUT, one setup packet. */
static void usb_ep0_status_out(void) {
 R(DOEPTSIZ(0))=(1u<<29)|(1u<<19);
 R(DOEPCTL(0))=(R(DOEPCTL(0))&~3u)|EP_ACTIVE|EP_ENA|EP_CNAK;
}
static void usb_ep0_out_stage(uint16_t want) {
 usb_ep0_out_want=want; usb_ep0_out_len=0;
 R(DOEPTSIZ(0))=(want&0x7ffffu)|(1u<<19);
 R(DOEPCTL(0))=(R(DOEPCTL(0))&~3u)|EP_ACTIVE|EP_ENA|EP_CNAK;
}
/* Accept the next burst of bulk OUT packets. */
static void usb_out_arm(void) {
 R(DOEPTSIZ(2))=USB_OUT_BURST|(8u<<19);
 R(DOEPCTL(2))=(R(DOEPCTL(2))&~0x7ffu)|USB_MPS|EP_TYPE_BULK|EP_ACTIVE|EP_ENA|EP_CNAK;
}

static void usb_configure_endpoints(int on) {
 if (on) {
  /* EP1 IN: CDC notification, idle but must be armed. */
  R(DIEPTSIZ(1))=0;
  R(DIEPCTL(1))=(R(DIEPCTL(1))&~0x7ffu)|16|(1u<<22)|EP_TYPE_INT|EP_ACTIVE|EP_SNAK;
  R(DIEPCTL(2))=USB_MPS|(2u<<22)|(1u<<28)|EP_TYPE_BULK|EP_ACTIVE|EP_SNAK;
  usb_out_arm();
  usb_rx_paused=0;
  R(DAINTMSK)|=(1u<<2)|(1u<<(16+2));
  usb_configured=1;
  usb_state=2;
 } else {
  usb_configured=0;
  usb_state=1;
  R(DAINTMSK)&=~((1u<<2)|(1u<<(16+2)));
 }
}

static void usb_handle_setup(void) {
 uint8_t type=usb_setup[0], request=usb_setup[1];
 uint16_t value=(uint16_t)(usb_setup[2]|(usb_setup[3]<<8));
 uint16_t index=(uint16_t)(usb_setup[4]|(usb_setup[5]<<8));
 uint16_t length=(uint16_t)(usb_setup[6]|(usb_setup[7]<<8));
 usb_setups++;
 usb_ep0_zlp=0; usb_ep0_need_status_out=0;
 usb_ep0_out_want=usb_ep0_out_len=0;
 (void)index;
 if ((type&0x60u)==0x20u) { /* CDC class requests on interface 0 */
  if (request==0x20u && length==7u) { usb_ep0_out_stage(length); return; }
  if (request==0x21u) { /* GET_LINE_CODING */
   uint16_t n=length<7u?length:7u;
   for (unsigned i=0;i<n;i++) usb_ep0_in[i]=usb_line_coding[i];
   usb_ep0_in_stage(n); return;
  }
  if (request==0x22u) { usb_ep0_status_in(); return; }
  usb_ep0_stall(); return;
 }
 if ((type&0x60u)!=0u) { usb_ep0_stall(); return; }
 switch (request) {
  case 0x06: { /* GET_DESCRIPTOR */
   const uint8_t *desc=0; uint16_t size=0;
   if ((value>>8)==1u) { desc=usb_device_desc; size=sizeof(usb_device_desc); }
   else if ((value>>8)==2u) { desc=usb_config_desc; size=sizeof(usb_config_desc); }
   else if ((value>>8)==3u) {
    switch (value&0xffu) {
     case 0: desc=usb_string0; size=sizeof(usb_string0); break;
     case 2: desc=usb_string2; size=sizeof(usb_string2); break;
     default: break;
    }
   }
   if (!desc) { usb_ep0_stall(); return; }
   { uint16_t n=size<length?size:length;
     for (unsigned i=0;i<n;i++) usb_ep0_in[i]=desc[i];
     usb_ep0_zlp=(n<length && (n%USB_MPS)==0u); usb_ep0_in_stage(n); }
   return;
  }
  case 0x05: /* Program the OTG device address for SET_ADDRESS. */
   R(DCFG)=(R(DCFG)&~0x7f0u)|((uint32_t)(value&0x7fu)<<4);
   usb_ep0_status_in(); return;
  case 0x09: /* SET_CONFIGURATION */
   usb_configure_endpoints(value!=0u);
   usb_ep0_status_in(); return;
  case 0x08: /* GET_CONFIGURATION */
   usb_ep0_in[0]=usb_configured?1u:0u; usb_ep0_in_stage(1); return;
  case 0x00: /* GET_STATUS */
   usb_ep0_in[0]=0; usb_ep0_in[1]=0; usb_ep0_in_stage(2); return;
  case 0x01: case 0x03: /* CLEAR/SET_FEATURE: only endpoint halt is meaningful. */
   usb_ep0_status_in(); return;
  default: usb_ep0_stall(); return;
 }
}

/* Drain the shared RX FIFO. `setup` reports whether a SETUP packet was seen. */
static int usb_rx_pump(void) {
 int have_setup=0;
 while (R(GINTSTS)&GINT_RXFLVL) {
  uint32_t status=R(GRXSTSP);
  unsigned epnum=status&0xfu, bytes=(status>>4)&0x7ffu, pktsts=(status>>17)&0xfu;
  if (pktsts==PKTSTS_SETUP_DATA) {
   usb_fifo_read(usb_setup,8); have_setup=1;
  } else if (pktsts==PKTSTS_OUT_DATA) {
   if (epnum==0u) {
    unsigned room=sizeof(usb_ep0_out)-usb_ep0_out_len;
    unsigned n=bytes<room?bytes:room;
    usb_fifo_read(usb_ep0_out+usb_ep0_out_len,n);
    usb_ep0_out_len+=(uint16_t)n;
    for (unsigned i=n;i<bytes;i++) { uint8_t drop[4]; usb_fifo_read(drop,bytes-i>4?4:bytes-i); i=bytes; }
   } else if (epnum==2u) {
    uint8_t chunk[64];
    while (bytes) {
     unsigned n=bytes>sizeof(chunk)?sizeof(chunk):bytes;
     usb_fifo_read(chunk,n); usb_rx_push(chunk,n); bytes-=n;
    }
   } else {
    uint8_t drop[64];
    while (bytes) { unsigned n=bytes>sizeof(drop)?sizeof(drop):bytes; usb_fifo_read(drop,n); bytes-=n; }
   }
  }
  /* OUT/SETUP completion packets carry no payload. */
 }
 return have_setup;
}

void OTG_FS_IRQHandler(void) {
 uint32_t status=R(GINTSTS)&R(GINTMSK);
 if (status&GINT_RXFLVL) {
  (void)usb_rx_pump();
 }
 if (status&GINT_USBRST) {
  R(GINTSTS)=GINT_USBRST;
  R(DCFG)=(R(DCFG)&~(3u|0x7f0u))|3u;              /* full-speed serial transceiver */
  /* DCTL has no endpoint-disable bit. */
  R(DAINTMSK)|=(1u<<0)|(1u<<16);         /* EP0 IN and OUT */
  R(DIEPMSK)=EPINT_XFRC;
  R(DOEPMSK)=EPINT_XFRC|EPINT_STUP;
  R(DIEPCTL(0))=(R(DIEPCTL(0))&~3u)|EP_ACTIVE|EP_CNAK|EP_SNAK;
  R(DOEPCTL(0))=(R(DOEPCTL(0))&~3u)|EP_ACTIVE|EP_CNAK;
  usb_ep0_out_want=usb_ep0_out_len=usb_ep0_in_len=0;
  usb_configured=0; usb_state=1;
  usb_rx_head=usb_rx_tail=usb_tx_head=usb_tx_tail=0;
  usb_rx_paused=0;
  usb_ep0_setup_arm();
 }
 if (status&GINT_ENUMDNE) {
  R(GINTSTS)=GINT_ENUMDNE;
  R(GUSBCFG)=(R(GUSBCFG)&~(15u<<10))|(6u<<10);
  R(GINTMSK)|=GINT_USBRST|GINT_ENUMDNE;
 }
 if (status&GINT_IEPINT) {
  uint32_t pending=R(DAINT)&0xffffu;
  if (pending&1u) { /* EP0 IN: control data or status stage done */
   uint32_t flags=R(DIEPINT(0));
   R(DIEPINT(0))=flags;
   if ((flags&EPINT_XFRC) && usb_ep0_need_status_out) {
    /* Control read: the OUT status stage follows the data stage. */
    if (usb_ep0_in_pos<usb_ep0_in_len) usb_ep0_send_next();
    else if (usb_ep0_zlp) { usb_ep0_zlp=0; usb_ep0_send_next(); }
    else { usb_ep0_need_status_out=0; usb_ep0_status_out(); }
   }
  }
  if (pending&(1u<<2)) { /* EP2 IN: bulk packet handed to the host */
   if (R(DIEPINT(2))&EPINT_XFRC) R(DIEPINT(2))=EPINT_XFRC;
  }
 }
 if (status&GINT_OEPINT) {
  uint32_t pending=(R(DAINT)>>16)&0xffffu;
  if (pending&1u) {
   uint32_t flags=R(DOEPINT(0));
   R(DOEPINT(0))=flags;
   if (flags&EPINT_STUP) usb_handle_setup();
   if ((flags&EPINT_XFRC) && !(flags&EPINT_STUP)) {
    if (usb_ep0_out_want && usb_ep0_out_len==usb_ep0_out_want) {
     for (unsigned i=0;i<7;i++) usb_line_coding[i]=usb_ep0_out[i];
     usb_ep0_out_want=0; usb_ep0_status_in();
    }
    usb_ep0_setup_arm();
   }
  }
  if (pending&(1u<<2)) {
   uint32_t flags=R(DOEPINT(2));
   R(DOEPINT(2))=flags;
   if (flags&EPINT_XFRC) {
    /* Only accept another burst if the host-side ring can absorb it. */
    if (USB_RX_RING-usb_rx_count()>=USB_OUT_BURST) usb_out_arm();
    else usb_rx_paused=1;
   }
  }
 }
}

/* Called from the main loop: hand queued bytes to the bulk IN endpoint.
   One EPENA can carry up to the whole EP2 TX FIFO, so a bulk reply leaves in
   FIFO-sized bursts instead of one 64-byte packet per call. */
static void usb_task(void) {
 if (!usb_configured) return;
 if (usb_rx_paused && USB_RX_RING-usb_rx_count()>=USB_OUT_BURST) {
  usb_rx_paused=0; usb_out_arm();
 }
 if (R(DIEPCTL(2))&EP_ENA) return;
 unsigned count=usb_tx_count();
 if (!count) return;
 unsigned depth=EP2_TX_WORDS*4u;
 unsigned n=count<depth?count:depth;
 uint8_t chunk[EP2_TX_WORDS*4u];
 for (unsigned i=0;i<n;i++) {
  chunk[i]=usb_tx_ring[usb_tx_tail];
  usb_tx_tail=(usb_tx_tail+1u)%USB_TX_RING;
 }
 unsigned packets=(n+USB_MPS-1u)/USB_MPS;
 R(DIEPTSIZ(2))=n|((packets&0x3ffu)<<19);
 R(DIEPCTL(2))=(R(DIEPCTL(2))&~0x7ffu)|USB_MPS|(2u<<22)|EP_TYPE_BULK|EP_ACTIVE|EP_ENA|EP_CNAK;
 usb_fifo_write(2,chunk,n);
}

static int usb_init(void) {
 R(RCC+0x34)|=1u<<7; /* OTGFSEN */
 /* PA11/PA12 alternate function 10, very high speed, no pull. */
 R(GPIOA)&=~((3u<<22)|(3u<<24));
 R(GPIOA)|=(2u<<22)|(2u<<24);
 R(GPIOA+8)=(R(GPIOA+8)&~((3u<<22)|(3u<<24)))|(3u<<22)|(3u<<24);
 R(GPIOA+0x24)=(R(GPIOA+0x24)&~((15u<<12)|(15u<<16)))|(10u<<12)|(10u<<16); /* AFR[1]: PA11/PA12 = AF10 */
 R(GPIOA+0x0c)&=~((3u<<22)|(3u<<24));
 R(GCCFG)=(1u<<21)|(1u<<16);              /* no VBUS sensing */
 R(GUSBCFG)=(1u<<30)|(1u<<6)|(6u<<10);
 delay_ms(50);
 if (R(GINTSTS)&1u) return 0;  /* PHYSEL: FS serial transceiver; TRDT 6 */
 for (unsigned i=0;i<160000 && !(R(GRSTCTL)&(1u<<31));i++) {}
 R(DCTL)|=1u<<1;               /* soft disconnect while configuring */
 delay_ms(10);
 R(GRSTCTL)|=1u<<0;            /* core soft reset */
 for (unsigned i=0;i<160000 && (R(GRSTCTL)&1u);i++) {}
 if (R(GRSTCTL)&1u) return 0;
 for (unsigned i=0;i<160000 && !(R(GRSTCTL)&(1u<<31));i++) {}
 R(GRXFSIZ)=128u;              /* RX FIFO: 128 words */
 R(GNPTXFSIZ)=(96u<<16)|128u;  /* EP0 TX at 128, 96 words */
 R(DIEPTXF1)=(16u<<16)|224u;   /* EP1 TX at 224, 16 words */
 R(DIEPTXF2)=(80u<<16)|240u;   /* EP2 TX at 240, 80 words */
 R(GRSTCTL)=(1u<<4)|(1u<<5)|(16u<<6); /* flush RX and all TX FIFOs */
 for (unsigned i=0;i<160000 && (R(GRSTCTL)&((1u<<4)|(1u<<5)));i++) {}
 R(GINTMSK)=0;
 R(GINTSTS)=0xffffffffu;       /* clear every pending global interrupt */
 R(GAHBCFG)=1u;                /* global interrupt enable */
 R(DCFG)=3u;                   /* full-speed device */
 R(DAINTMSK)=(1u<<0)|(1u<<16);
 R(DIEPMSK)=EPINT_XFRC;
 R(DOEPMSK)=EPINT_XFRC|EPINT_STUP;
 R(DIEPCTL(0))=(R(DIEPCTL(0))&~3u)|EP_ACTIVE|EP_CNAK|EP_SNAK;
 R(DOEPCTL(0))=(R(DOEPCTL(0))&~3u)|EP_ACTIVE|EP_CNAK;
 /* DAINT is read-only; clear individual endpoint interrupts. */
 for (unsigned ep=0;ep<3;ep++) { R(DIEPINT(ep))=0xffffffffu; R(DOEPINT(ep))=0xffffffffu; }
 usb_ep0_setup_arm();
 R(GCCFG)|=(1u<<16);
 R(DCTL)|=1u<<1;
 delay_ms(10);
 /* DCTL has no endpoint-disable bit. */
 R(GINTMSK)=GINT_RXFLVL|GINT_USBRST|GINT_ENUMDNE|GINT_IEPINT|GINT_OEPINT;
 R(0xe000e108)=1u<<3;          /* NVIC ISER2 bit 3: OTG_FS is IRQ 67 */
 R(DCTL)&=~(1u<<1); /* connect only after interrupt setup */
 return 1;
}
