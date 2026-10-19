/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 NFClab contributors.
 */
#ifndef NFCLAB_SNIFF_DECODE_H
#define NFCLAB_SNIFF_DECODE_H
#include <stdint.h>
/* Incremental 106k decoder prototype. Input chunks may end at any sample.
 * Bounded bursts: overlong input is discarded until an idle gap. No heap/FPU.
 * Caller owns protocol validation (CRC, authentication state, encrypted parity).
 */
#define SD_SAMPLES 12288u
#define SD_BYTES 32u
struct sd_frame {
 uint32_t start, end, bits, length, ambiguous;
 uint8_t tag, data[SD_BYTES], parity[SD_BYTES];
};
typedef void (*sd_emit)(void *,const struct sd_frame *);
struct sd_channel { uint32_t origin,n,last,edges,fast; uint8_t previous,active,overflow; uint8_t samples[SD_SAMPLES]; };
struct sd_decoder { struct sd_channel ch[2]; uint32_t position,period,gap,dropped; uint32_t reader_history[16][2],reader_count,channel_cycles[2]; sd_emit emit; void *context; };
static inline void sd_zero(void *p,unsigned n) {
 volatile uint8_t *v=(volatile uint8_t *)p;while(n--) *v++=0;
}
static inline unsigned sd_round(unsigned q) { return (q+128u)>>8; }
static inline void sd_bit(struct sd_frame *f,unsigned i,unsigned bit) {
 if(i%9u==8u) f->parity[i/9u]=(uint8_t)bit;
 else f->data[i/9u]|=(uint8_t)(bit<<(i%9u));
}
static int sd_reader(struct sd_decoder *d,struct sd_channel *c,struct sd_frame *f) {
 uint8_t pulses[SD_BYTES*18u+5u];sd_zero(pulses,sizeof(pulses));
 unsigned last=0,falls=0,fall=0,origin=0;
 for(unsigned i=0;i<=c->last;i++) {
  unsigned before=i?c->samples[i-1]:1u,now=c->samples[i];
  if(before && !now) {
   if(!falls) origin=i;
   unsigned delta=(i-origin)*256u;
   unsigned half=(delta*2u+d->period/2u)/d->period;
   unsigned error=delta*2u>half*d->period?delta*2u-half*d->period:half*d->period-delta*2u;
   if(error>d->period/4u || half>=sizeof(pulses)) return 0;
   if(falls) pulses[half]=1;
   last=half; fall=i; falls++;
  } else if(!before && now) {
   unsigned width=(i-fall)*256u;
   if(width*100u<d->period*15u || width*10u>d->period*4u) return 0;
  }
 }
 if(falls<2 || !c->samples[c->last]) return 0;
 for(unsigned n=7;n<=SD_BYTES*9u;n=(n==7?9:n+9)) {
  if(n!=7 && (n*2u+4u<last || n*2u>last+4u)) continue;
  unsigned previous=0,used=0,valid=1;
  for(unsigned j=0;j<SD_BYTES;j++) f->data[j]=f->parity[j]=0;
  for(unsigned i=0;i<n;i++) {
   unsigned early=pulses[2u*(i+1u)],middle=pulses[2u*(i+1u)+1u],bit;
   if(middle && !early) {bit=1;used++;}
   else if(early && !middle && !previous) {bit=0;used++;}
   else if(!early && !middle && previous) bit=0;
   else {valid=0;break;}
   sd_bit(f,i,bit); previous=bit;
  }
  if(!valid) continue;
  if(!previous) {if(!pulses[2u*(n+1u)]) continue;used++;}
  if(used!=falls-1u) continue;
  f->bits=n;f->length=n==7?1:n/9u;f->start=c->origin+origin;return 1;
 }
 return 0;
}
static int sd_tag(struct sd_decoder *d,struct sd_channel *c,struct sd_frame *f) {
 if(c->edges<8 || c->fast<4) return 0;
 unsigned lo=sd_round(d->period*65u/100u),hi=sd_round(d->period*90u/100u),ones=0;
 if(hi>=c->n || hi<=lo) return 0;
 for(unsigned i=lo;i<hi;i++) ones+=c->samples[i];
 unsigned idle=ones*2u>hi-lo;
 unsigned n=((c->last*256u+d->period*9u/2u)/(d->period*9u))*9u;
 if(n<9 || n>SD_BYTES*9u) return 0;
 for(unsigned i=0;i<n;i++) {
  unsigned activity[2],width[2];
  for(unsigned h=0;h<2;h++) {
   lo=sd_round((i+1u)*d->period+h*d->period/2u+d->period*4u/100u);
   hi=sd_round((i+1u)*d->period+(h+1u)*d->period/2u-d->period*4u/100u);
   if(hi>c->n || hi<=lo) return 0;
   activity[h]=0;width[h]=hi-lo;
   for(unsigned j=lo;j<hi;j++) activity[h]+=c->samples[j]!=idle;
  }
  int delta=(int)(activity[0]*width[1])-(int)(activity[1]*width[0]);
  unsigned magnitude=(unsigned)(delta<0?-delta:delta);
  f->ambiguous+=magnitude*100u<15u*width[0]*width[1];
  sd_bit(f,i,delta>0);
 }
 f->bits=n;f->length=n/9u;f->start=c->origin;return 1;
}
static void sd_finish(struct sd_decoder *d,unsigned channel) {
 struct sd_channel *c=&d->ch[channel];struct sd_frame f;sd_zero(&f,sizeof(f));
 f.tag=(uint8_t)channel;f.end=c->origin+c->last;
 if(c->overflow) d->dropped++;
 else if(!channel ? sd_reader(d,c,&f) : sd_tag(d,c,&f)) {
  if(!channel) {
   unsigned h=d->reader_count++%16u;
   d->reader_history[h][0]=f.start;d->reader_history[h][1]=f.end;
  }
  unsigned duplicate=0;
  if(channel) for(unsigned h=0;h<d->reader_count && h<16u;h++)
   if(c->origin+d->period/512u>=d->reader_history[h][0] && c->origin<=d->reader_history[h][1]+d->period/512u) duplicate=1;
  if(!duplicate) d->emit(d->context,&f);
 }
 c->active=0;c->n=0;c->overflow=0;c->edges=0;c->fast=0;
}
static void sd_init(struct sd_decoder *d,unsigned hz,sd_emit emit,void *context) {
 sd_zero(d,sizeof(*d));d->period=(hz*128u/1000u*256u+6780u)/13560u;
 d->gap=hz/33333u;d->emit=emit;d->context=context;
}
typedef uint32_t sd_alias_u32 __attribute__((__may_alias__));
static inline void sd_fill(uint8_t *out,unsigned count,unsigned value) {
 while(count && ((uintptr_t)out&3u)) {*out++=(uint8_t)value;count--;}
 uint32_t word=value?0x01010101u:0;
 while(count>=4u) {*(volatile sd_alias_u32 *)(void *)out=word;out+=4;count-=4;}
 while(count--) *out++=(uint8_t)value;
}
static void sd_feed(struct sd_decoder *d,const uint16_t *samples,unsigned count) {
 for(unsigned k=0;k<2;k++) {
#ifdef SD_CLOCK
  uint32_t channel_start=SD_CLOCK();
#endif
  struct sd_channel *c=&d->ch[k];unsigned mask=k?1u:64u;
  unsigned n=c->n,last=c->last,origin=c->origin,edges=c->edges,fast=c->fast;
  unsigned active=c->active,previous=c->previous,overflow=c->overflow;
  unsigned gap=d->gap,fast_limit=(d->period-1u)/1024u;
  for(unsigned i=0;i<count;) {
   unsigned raw=samples[i],value=!!(raw&mask),end=i+1u;
   while(end<count && !((samples[end]^raw)&mask)) end++;
   unsigned position=d->position+i;
   if(position && value!=previous) {
    if(!active) {active=1;origin=position;n=0;edges=0;fast=0;last=0;}
    if(edges && n-last<=fast_limit) fast++;
    last=n;edges++;
   }
   if(active) {
    unsigned span=end-i,until=last+gap+2u-n;
    if(span>until) span=until;
    unsigned room=n<SD_SAMPLES?SD_SAMPLES-n:0,write=span<room?span:room;
    sd_fill(c->samples+(n<SD_SAMPLES?n:SD_SAMPLES),write,value);
    n+=span;if(write<span) overflow=1;
    if(n>last+gap+1u) {
     c->n=n;c->last=last;c->origin=origin;c->edges=edges;c->fast=fast;c->overflow=(uint8_t)overflow;
     sd_finish(d,k);active=0;n=0;overflow=0;
    }
   }
   previous=value;i=end;
  }
  c->n=n;c->last=last;c->origin=origin;c->edges=edges;c->fast=fast;
  c->active=(uint8_t)active;c->previous=(uint8_t)previous;c->overflow=(uint8_t)overflow;
#ifdef SD_CLOCK
  d->channel_cycles[k]=SD_CLOCK()-channel_start;
#endif
 }
 d->position+=count;
}
/* Discontinuity: discard unfinished bursts, never join across lost samples. */
static inline void sd_discontinuity(struct sd_decoder *d) {
 for(unsigned k=0;k<2;k++) {
  d->ch[k].active=0;d->ch[k].n=0;d->ch[k].overflow=0;
  d->ch[k].edges=0;d->ch[k].fast=0;d->ch[k].previous=0;
 }
 d->reader_count=0;d->dropped++;d->position=0;
}
#endif
