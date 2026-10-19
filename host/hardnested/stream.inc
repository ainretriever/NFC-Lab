/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 NFClab contributors.
 */
/* GPL-3.0-or-later. Included after PM3's reduction helpers in generated driver.
 * Protocol contains CUID and ciphertext/parity only; never a known key.
 */
static const char *nfclab_simd_name(void) {
 switch (GetSIMDInstrAuto()) {
#if defined(COMPILER_HAS_SIMD_AVX512)
  case SIMD_AVX512: return "AVX512";
#endif
#if defined(COMPILER_HAS_SIMD_X86)
  case SIMD_AVX2: return "AVX2";
  case SIMD_AVX: return "AVX";
  case SIMD_SSE2: return "SSE2";
  case SIMD_MMX: return "MMX";
#endif
#if defined(COMPILER_HAS_SIMD_NEON)
  case SIMD_NEON: return "NEON";
#endif
  default: return "scalar";
 }
}
static int acquire_nonces(uint8_t a, uint8_t b, uint8_t *c, uint8_t d,
                          uint8_t e, bool f, bool g, char *h) {
 (void)a; (void)b; (void)c; (void)d; (void)e; (void)f; (void)g; (void)h;
 char line[128], extra; unsigned uid=0, raw=0;
 known_target_key=UINT64_MAX;
 printf("NFCLAB_STATE={\"ready\":true,\"rate\":%.0f,\"cpus\":%u,\"simd\":\"%s\"}\n",
        brute_force_per_second,nfclab_cpus,nfclab_simd_name());
 if(!fgets(line,sizeof(line),stdin) || sscanf(line,"CUID %x %c",&uid,&extra)!=1)
  return PM3_EINVARG;
 cuid=uid;
 bool sum_applied=false;
 unsigned checks=0;
 float previous=0;
 while(fgets(line,sizeof(line),stdin)) {
  if(!strcmp(line,"FINISH\n")) {
   if(!sum_applied || first_byte_num!=256) return PM3_EINVARG;
   /* Complete all pending constraints before generating candidates. */
   last_sample_clock=msclock();
   update_nonce_data(false);
   float depth; shrink_key_space(&depth);
   return PM3_SUCCESS;
  }
  unsigned count=0, period=0;
  if(sscanf(line,"BATCH %u %u %c",&count,&period,&extra)!=2 ||
     !count || count>1000 || !period || period>3600000) return PM3_EINVARG;
  for(unsigned i=0;i<count;i++) {
   unsigned enc=0, par=0;
   if(!fgets(line,sizeof(line),stdin) ||
      sscanf(line,"%x %x %c",&enc,&par,&extra)!=2 || par>15) return PM3_EINVARG;
   int added=add_nonce(enc,par);
   if(added==PM3_EMALLOC) return added;
   num_acquired_nonces+=added;
  }
  raw+=count;
  if(first_byte_num==256 && !sum_applied) {
   bool found=false;
   for(unsigned i=0;i<NUM_SUMS;i++) if(first_byte_Sum==sums[i]) {
    first_byte_Sum=i; found=true; break;
   }
   if(!found) return PM3_ESOFT;
   hardnested_stage|=CHECK_2ND_BYTES;
   apply_sum_a0(); sum_applied=true;
   /* Do not mix pre-Sum(a0) estimates into the stopping regression. */
   update_reduction_rate(0,true); checks=0;
  }
  sample_period=period;
  last_sample_clock=msclock();
  update_nonce_data(true);
  float depth=0;
  bool upstream_stop=shrink_key_space(&depth);
  if(sum_applied) checks++;
  /* Avoid plateau-based stopping on incomplete time-budgeted constraints or
     before four comparable estimates exist. The low-state bound is safe as
     soon as all first bytes and Sum(a0) are known. */
  bool low=sum_applied && depth<0xF00000;
  bool stop=low || (sum_applied && checks>=4 && upstream_stop &&
                   !(hardnested_stage & CHECK_1ST_BYTES));
  double gain=checks>1 ? (double)previous-depth : 0;
  previous=depth;
  printf("NFCLAB_STATE={\"raw\":%u,\"unique\":%u,\"first_bytes\":%u,"
         "\"states\":%.0f,\"gain\":%.0f,\"period_ms\":%u,\"checks\":%u,"
         "\"stop\":%s,\"reason\":\"%s\"}\n",
         raw,num_acquired_nonces,first_byte_num,depth,gain,period,checks,
         stop?"true":"false",low?"small-search-space":stop?"marginal-gain":"continue");
 }
 return PM3_EINVARG; /* EOF/abort is never permission to brute force. */
}
