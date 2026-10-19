/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 NFClab contributors.
 */
/* Minimal host services for the GPL Proxmark3 hardnested algorithms. */
#ifndef NFCLAB_HARDNESTED_COMPAT_H
#define NFCLAB_HARDNESTED_COMPAT_H
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include "common.h"
#include "pm3_cmd.h"
#define _YELLOW_(s) s
#define _GREEN_(s) s
#define _RED_(s) s
#define INFO 0
#define NORMAL 0
#define WARNING 1
#define ERR 1
#define FAILED 1
#ifndef MAX
#define MAX(a,b) ((a)>(b)?(a):(b))
#endif
#ifndef MIN
#define MIN(a,b) ((a)<(b)?(a):(b))
#endif
#ifndef ARRAYLEN
#define ARRAYLEN(a) (sizeof(a)/sizeof((a)[0]))
#endif
extern unsigned nfclab_cpus;
extern const char *nfclab_resources;
static inline unsigned num_CPUs(void) { return nfclab_cpus; }
static inline uint64_t msclock(void) {
 struct timespec now; clock_gettime(CLOCK_MONOTONIC,&now);
 return (uint64_t)now.tv_sec*1000+now.tv_nsec/1000000;
}
static inline void PrintAndLogEx(int level, const char *format, ...) {
 (void)level; va_list args; va_start(args,format);
 flockfile(stdout); vprintf(format,args); putchar('\n'); funlockfile(stdout);
 va_end(args);
}
static inline uint64_t bytes_to_num(const uint8_t *bytes, size_t size) {
 uint64_t value=0; while(size--) value=(value<<8)|*bytes++; return value;
}
static inline const char *get_my_executable_directory(void) { return nfclab_resources; }
static inline int searchFile(char **path, const char *subdir, const char *name,
                             const char *suffix, bool silent) {
 (void)subdir; (void)silent;
 size_t size=strlen(nfclab_resources)+strlen(name)+strlen(suffix)+2;
 char *result=malloc(size); if(!result) return PM3_EMALLOC;
 snprintf(result,size,"%s/%s%s",nfclab_resources,name,suffix);
 if(access(result,R_OK)) { free(result); return PM3_EFILE; }
 *path=result; return PM3_SUCCESS;
}
void hardnested_print_progress(uint32_t, const char *, float, uint64_t);
void hardnested_print_key_found_progress(uint32_t, const char *);
#endif
