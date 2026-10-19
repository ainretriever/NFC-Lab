/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 NFClab contributors.
 */
/* Passive transparent RX. TIM1_UP -> DMA2 stream 5/channel 6 -> GPIOA IDR.
 * PA0=IRQ, PA6=MISO are acquired in the SAME halfword. No MCU_CLK required
 * for experimental asynchronous capture. RM0383 DMA mapping; DS13541 4.4.13.
 * Ring capture retains pretrigger data. No ST register access while transparent.
 */
#define SNIFF_CAPACITY 32768u
#define SNIFF_TIM 0x40010000u
#define SNIFF_DMA 0x40026400u
#define SNIFF_STREAM (SNIFF_DMA+0x88u)
#define SNIFF_DMA_FLAGS (0x3du<<6)
#define SNIFF_DMA_ERRORS (0x0du<<6)
#include "sniff_codec.h"
#define SD_CLOCK() cycles()
#include "sniff_decode.h"
#define SNIFF_LIVE_COUNT 16384u
#define SNIFF_LIVE_FRAMES 80u
struct sniff_live_mailbox {
 uint32_t magic,version,frames,frame_size,capacity,count;
 uint32_t chunks,samples,max_cycles,budget_cycles,overruns,queue_full;
 uint32_t decoder_dropped,stop_reason,elapsed_cycles,channel0_cycles,channel1_cycles,max_backlog;
};
volatile struct sniff_live_mailbox sniff_live;
_Static_assert(sizeof(struct sniff_live_mailbox)==72,"live sniff mailbox ABI");
_Static_assert(sizeof(struct sd_frame)==88,"live sniff frame ABI");
struct sniff_mailbox {
 uint32_t magic, version, request, busy;
 uint32_t enabled, operation, period, count, timeout_ms, trigger_mask;
 uint32_t target, sclk_high, p2p_rx, status, clock_hz, sample_hz;
 uint32_t buffer, capacity, valid, oldest, trigger_index, elapsed_cycles;
 uint32_t dma_flags, remaining, op_before, op_after, aux_before, aux_after;
 uint32_t transitions_miso, transitions_irq, sequence, cleanup_error;
 uint32_t holdoff_ms, first_edge_cycles;
};
_Static_assert(sizeof(struct sniff_mailbox)==136,"sniff mailbox ABI");
volatile struct sniff_mailbox sniff;
/* Reader/sniff and target probe never run concurrently. Share capture RAM
 * with transparent TX rather than consuming the reserved stack space. */
static union {
 uint16_t samples[SNIFF_CAPACITY];
 uint32_t tx_wave[SNIFF_CAPACITY/2];
 struct {
  uint16_t dma[SNIFF_LIVE_COUNT];
  struct sd_decoder decoder;
  struct sd_frame frames[SNIFF_LIVE_FRAMES];
 } live;
} nfc_wave_buffer __attribute__((aligned(4)));
#define sniff_samples nfc_wave_buffer.samples
_Static_assert(sizeof(nfc_wave_buffer.live)<=sizeof(nfc_wave_buffer.samples),"live sniff fits shared RAM");
static void sniff_live_emit(void *context,const struct sd_frame *frame) {
 (void)context;
 if (sniff_live.count<SNIFF_LIVE_FRAMES) {
  volatile uint8_t *out=(volatile uint8_t *)&nfc_wave_buffer.live.frames[sniff_live.count++];
  const uint8_t *in=(const uint8_t *)frame;
  for(unsigned i=0;i<sizeof(*frame);i++) out[i]=in[i];
 }
 else sniff_live.queue_full++;
}
static void sniff_live_init(void) {
 sd_zero((void *)&sniff_live,sizeof(sniff_live));
 sniff_live.magic=0x53444d41; sniff_live.version=1;
 sniff_live.frames=(uint32_t)nfc_wave_buffer.live.frames;
 sniff_live.frame_size=sizeof(struct sd_frame);sniff_live.capacity=SNIFF_LIVE_FRAMES;
 sd_init(&nfc_wave_buffer.live.decoder,sniff.sample_hz,sniff_live_emit,0);
 sniff_live.budget_cycles=(SNIFF_LIVE_COUNT/2u)*sniff.period;
}
static int sniff_dma_stop(void);
static void sniff_live_run(uint32_t start) {
 uint32_t deadline=(core_hz/1000u)*sniff.timeout_ms;
 unsigned produced=0,consumed=0,previous=0;
 uint32_t polled=start;
 while ((uint32_t)(cycles()-start)<deadline) {
  uint32_t now=cycles(),flags=R(SNIFF_DMA+4)&SNIFF_DMA_FLAGS;
  if(flags&SNIFF_DMA_ERRORS) {sniff.status=5;break;}
  unsigned position=(SNIFF_LIVE_COUNT-R(SNIFF_STREAM+4))%SNIFF_LIVE_COUNT;
  if((uint32_t)(now-polled)>=SNIFF_LIVE_COUNT*sniff.period) {
   sniff.status=9;sniff_live.overruns++;break;
  }
  produced+=(position+SNIFF_LIVE_COUNT-previous)%SNIFF_LIVE_COUNT;
  previous=position;polled=now;
  unsigned available=produced-consumed;
  if(available>sniff_live.max_backlog) sniff_live.max_backlog=available;
  if(available>=SNIFF_LIVE_COUNT) {sniff.status=9;sniff_live.overruns++;break;}
  if(available<256u) continue;
  __asm__ volatile ("dmb" ::: "memory");
  unsigned saved=sniff_live.count;
  uint32_t begun=cycles();
  sd_feed(&nfc_wave_buffer.live.decoder,nfc_wave_buffer.live.dma+consumed%SNIFF_LIVE_COUNT,256u);
  uint32_t ended=cycles(),elapsed=ended-begun;
  if(elapsed>sniff_live.max_cycles) {
   sniff_live.max_cycles=elapsed;
   sniff_live.budget_cycles=(SNIFF_LIVE_COUNT-available)*sniff.period;
   sniff_live.channel0_cycles=nfc_wave_buffer.live.decoder.channel_cycles[0];
   sniff_live.channel1_cycles=nfc_wave_buffer.live.decoder.channel_cycles[1];
  }
  position=(SNIFF_LIVE_COUNT-R(SNIFF_STREAM+4))%SNIFF_LIVE_COUNT;
  produced+=(position+SNIFF_LIVE_COUNT-previous)%SNIFF_LIVE_COUNT;
  previous=position;
  available=produced-consumed;
  if(available>sniff_live.max_backlog) sniff_live.max_backlog=available;
  if((uint32_t)(ended-polled)>=SNIFF_LIVE_COUNT*sniff.period || available>=SNIFF_LIVE_COUNT) {
   sniff_live.count=saved;sniff_live.overruns++;sniff.status=9;
   sd_discontinuity(&nfc_wave_buffer.live.decoder);break;
  }
  polled=ended;consumed+=256u;
  sniff_live.chunks++;sniff_live.samples+=256u;
  if(sniff_live.queue_full) {sniff.status=10;break;}
 }
 /* Freeze and drain owned samples at the requested end. Do not fabricate an
    idle suffix: a burst cut by the recording boundary must remain unfinished. */
 if(!sniff.status) {
  if(!sniff_dma_stop()) sniff.status=5;
  else {
   uint32_t now=cycles();
   unsigned position=(SNIFF_LIVE_COUNT-R(SNIFF_STREAM+4))%SNIFF_LIVE_COUNT;
   produced+=(position+SNIFF_LIVE_COUNT-previous)%SNIFF_LIVE_COUNT;
   if(now-polled>=SNIFF_LIVE_COUNT*sniff.period || produced-consumed>=SNIFF_LIVE_COUNT) {
    sniff.status=9;sniff_live.overruns++;
   } else while(consumed<produced) {
    unsigned n=produced-consumed;if(n>256u) n=256u;
    sd_feed(&nfc_wave_buffer.live.decoder,nfc_wave_buffer.live.dma+consumed%SNIFF_LIVE_COUNT,n);
    consumed+=n;sniff_live.samples+=n;sniff_live.chunks++;
    if(sniff_live.queue_full) {sniff.status=10;break;}
   }
  }
 }
 sniff_live.decoder_dropped=nfc_wave_buffer.live.decoder.dropped;
 sniff_live.stop_reason=sniff.status;sniff_live.elapsed_cycles=cycles()-start;
}

static void sniff_init(void) {
 sniff.magic=0x534e4946; sniff.version=3; sniff.period=16;
 sniff.count=SNIFF_CAPACITY; sniff.timeout_ms=3000; sniff.trigger_mask=0x40;
 sniff.target=1; sniff.sclk_high=1; sniff.p2p_rx=0x51;
 sniff.clock_hz=core_hz; sniff.buffer=(uint32_t)sniff_samples;
 sniff.capacity=SNIFF_CAPACITY;
#ifdef NFCLAB_SNIFF_BOOT
 sniff.enabled=1;
#endif
}
static int sniff_space_b(uint8_t address,uint8_t value) {
 uint8_t bytes[2]={address,value};
 return transaction(0xfb,bytes,0,2);
}
static int sniff_dma_stop(void) {
 R(SNIFF_TIM)=0; R(SNIFF_TIM+0x0c)=0;
 R(SNIFF_STREAM)&=~1u;
 uint32_t start=cycles();
 while (R(SNIFF_STREAM)&1u)
  if ((uint32_t)(cycles()-start)>core_hz/1000u) return 0;
 return 1;
}
static int sniff_dma_start(unsigned period,unsigned count,int circular) {
 R(RCC+0x30)|=1u<<22; R(RCC+0x44)|=1;
 if (!sniff_dma_stop()) return 0;
 R(SNIFF_DMA+0x0c)=SNIFF_DMA_FLAGS;
 R(SNIFF_STREAM+4)=count;
 R(SNIFF_STREAM+8)=GPIOA+0x10;
 R(SNIFF_STREAM+12)=(uint32_t)sniff_samples;
 R(SNIFF_STREAM+20)=0; /* direct mode, no FIFO */
 R(SNIFF_STREAM)=(6u<<25)|(3u<<16)|(1u<<13)|(1u<<11)|(1u<<10)
                  |(circular?(1u<<8):0u); /* P->M, halfword, MINC */
 R(SNIFF_TIM+0x28)=0; R(SNIFF_TIM+0x2c)=period-1;
 R(SNIFF_TIM+0x24)=0; R(SNIFF_TIM+0x14)=1; R(SNIFF_TIM+0x10)=0;
 R(SNIFF_STREAM)|=1; R(SNIFF_TIM+0x0c)=1u<<8;
 R(SNIFF_TIM)=1;
 return 1;
}
static void sniff_count_edges(unsigned count,unsigned oldest) {
 unsigned previous=sniff_samples[oldest];
 for (unsigned i=1;i<count;i++) {
  unsigned value=sniff_samples[(oldest+i)%count],diff=value^previous;
  sniff.transitions_miso+=(diff>>6)&1; sniff.transitions_irq+=diff&1;
  previous=value;
 }
}
static void run_sniff(void) {
 if (!sniff.request || sniff.busy) return;
 sniff.busy=1; sniff.request=0; sniff.enabled=1; sniff.sequence++;
 sniff.status=0; sniff.valid=0; sniff.oldest=0; sniff.trigger_index=0xffffffffu;
 sniff.dma_flags=0; sniff.elapsed_cycles=0; sniff.cleanup_error=0;
 sniff.first_edge_cycles=0;
 sniff.transitions_miso=sniff.transitions_irq=0;
 unsigned period=sniff.period,count=sniff.count,timeout=sniff.timeout_ms;
 unsigned mask=sniff.trigger_mask,operation=sniff.operation,holdoff=sniff.holdoff_ms;
 if (period<16 || period>960 || count<256 || count>SNIFF_CAPACITY ||
     timeout<1 || timeout>10000 || (mask&~0x41u) || !mask ||
     operation>3 || sniff.target>1 || sniff.sclk_high>1 || sniff.p2p_rx>255 || holdoff>1000) {
  sniff.status=6; sniff.busy=0; return;
 }
 if(operation==3 && (period!=32 || count!=SNIFF_LIVE_COUNT)) {sniff.status=6;sniff.busy=0;return;}
 sniff.sample_hz=core_hz/period;
 /* A request accepted at the end of idle_wait may leave its USB ACK queued.
    Flush it BEFORE the blocking capture, or a host-triggered reader starts
    only after the capture timeout. USB IRQ remains enabled throughout. */
 uint32_t flush_start=cycles();
 while (usb_tx_count()) {
  usb_task();
  if ((uint32_t)(cycles()-flush_start)>core_hz/200u) {
   sniff.status=8; sniff.busy=0; return;
  }
 }
 uint32_t exti=R(0x40013c00);
 R(0x40013c00)&=~1u; /* IRQ becomes waveform, never an EXTI storm. */
 uint8_t value=0;
 int transparent=0;
 if (!(command(0xc2) && write_reg(0x02,0x80) &&
       write_reg(0x03,sniff.target?0x88:0x08) && write_reg(0x08,0x0d) &&
       sniff_space_b(0x0b,(uint8_t)sniff.p2p_rx) && write_reg(0x02,0xc3) &&
       read_reg(0x02,&value))) { sniff.status=4; goto cleanup; }
 sniff.op_before=value;
 if (value&8) { sniff.status=4; goto cleanup; }
 if (!read_reg(0x31,&value)) { sniff.status=4; goto cleanup; }
 sniff.aux_before=value;
 if (operation!=1) {
  if (!(command(0xd1) && command(0xdc))) { sniff.status=4; goto cleanup; }
  transparent=1;
 } else if (!write_reg(0x02,0x80)) { sniff.status=4; goto cleanup; }
 R(SPI1)&=~(1u<<6);
 /* PA5 receiver gate, PA7 inactive modulation; PA6 input. BSS stays high. */
 R(GPIOA+0x18)=(1u<<(7+16))|(sniff.sclk_high?(1u<<5):(1u<<(5+16)));
 R(GPIOA)=(R(GPIOA)&~((3u<<10)|(3u<<12)|(3u<<14)))|(1u<<10)|(1u<<14);
 if(operation==3) sniff_live_init();
 if (!sniff_dma_start(period,count,operation!=1)) { sniff.status=5; goto cleanup; }
 uint32_t start=cycles(),trigger=0;
 if(operation==3) {
  sniff_live_run(start);
 } else if (operation==1) {
  /* Finite DMA timing/self-test: toggle PA5 every ~10 us with RF disabled. */
  uint32_t next=start;
  while (!(R(SNIFF_DMA+4)&((1u<<11)|SNIFF_DMA_ERRORS))) {
   uint32_t now=cycles();
   if ((uint32_t)(now-next)>=core_hz/100000u) {
    R(GPIOA+0x14)^=1u<<5; next=now;
   }
   if ((uint32_t)(now-start)>count*period+core_hz/100u) { sniff.status=3; break; }
  }
 } else {
  /* Fill ring once before accepting trigger, so all returned samples are valid. */
  while ((uint32_t)(cycles()-start)<count*period) {}
  unsigned baseline=R(GPIOA+0x10)&mask;
  uint32_t armed=cycles();
  while ((R(GPIOA+0x10)&mask)==baseline) {
   if (R(SNIFF_DMA+4)&SNIFF_DMA_ERRORS) { sniff.status=5; break; }
   if ((uint32_t)(cycles()-armed)>(core_hz/1000u)*timeout) { sniff.status=3; break; }
  }
  if (!sniff.status && holdoff) {
   sniff.first_edge_cycles=cycles()-start;
   uint32_t first=cycles();
   while ((uint32_t)(cycles()-first)<(core_hz/1000u)*holdoff) {}
   baseline=R(GPIOA+0x10)&mask;
   while ((R(GPIOA+0x10)&mask)==baseline) {
    if (R(SNIFF_DMA+4)&SNIFF_DMA_ERRORS) { sniff.status=5; break; }
    if ((uint32_t)(cycles()-armed)>(core_hz/1000u)*timeout) { sniff.status=3; break; }
   }
  }
  if (!sniff.status) {
   trigger=cycles();
   unsigned pos=(count-R(SNIFF_STREAM+4))%count;
   sniff.trigger_index=pos; /* ring index, host normalises after stop */
   uint32_t post=(count*3u/4u)*period;
   while ((uint32_t)(cycles()-trigger)<post)
    if (R(SNIFF_DMA+4)&SNIFF_DMA_ERRORS) { sniff.status=5; break; }
   if ((uint32_t)(cycles()-trigger)>=count*period) sniff.status=7;
  }
 }
 sniff.elapsed_cycles=cycles()-start;
 if (!sniff_dma_stop()) sniff.status=5;
 sniff.dma_flags=R(SNIFF_DMA+4)&SNIFF_DMA_FLAGS;
 sniff.remaining=R(SNIFF_STREAM+4);
 if (sniff.dma_flags&SNIFF_DMA_ERRORS) sniff.status=5;
 if(operation==3) sniff.valid=0;
 else if (operation==1) sniff.valid=count-sniff.remaining;
 else { sniff.valid=count; sniff.oldest=(count-sniff.remaining)%count; }
 __asm__ volatile ("dmb" ::: "memory"); /* DMA writes visible before CPU reads. */
 if (trigger) sniff.trigger_index=(sniff.trigger_index+count-sniff.oldest)%count;
 if (!sniff.status) sniff.status=2;
 sniff_count_edges(sniff.valid,sniff.oldest);
 if (operation==2) (void)sniff_pack_channels(sniff_samples,sniff.valid);
cleanup:
 if ((R(RCC+0x30)&(1u<<22)) && !sniff_dma_stop()) sniff.cleanup_error|=32;
 /* Exiting transparent is the first SPI command. Explicitly turn RF/RX off;
    stop-all alone does not clear tx_en. Restore the ordinary reader profile. */
 spi_init();
 if (transparent && !command(0xc2)) sniff.cleanup_error|=1;
 if (!write_reg(0x02,0x80) || !read_reg(0x02,&value)) sniff.cleanup_error|=2;
 sniff.op_after=value;
 if (value!=0x80) sniff.cleanup_error|=4;
 if (!read_reg(0x31,&value)) sniff.cleanup_error|=8;
 sniff.aux_after=value;
 if (!write_reg(0x03,0x08) || !write_reg(0x08,0)) sniff.cleanup_error|=16;
 R(0x40013c14)=1; R(0xe000e280)=1u<<6; R(0x40013c00)=exti;
 if (sniff.cleanup_error) sniff.status=4;
 __asm__ volatile ("dmb" ::: "memory"); /* Publish samples before completion. */
 sniff.busy=0;
}
