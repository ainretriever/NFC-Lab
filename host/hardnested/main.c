/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 NFClab contributors.
 */
/* File/stream adapter for Proxmark3's GPL-3.0-or-later reduction driver.
 * There is deliberately no API for a known source or target key or RF device.
 */
#include <dirent.h>
#include <errno.h>
#include <inttypes.h>
#include "compat.h"
unsigned nfclab_cpus=4;
const char *nfclab_resources;
int mfnestedhard(uint8_t, uint8_t, uint8_t *, uint8_t, uint8_t, uint8_t *,
                 bool, bool, bool, int, uint64_t *, char *);
static bool valid_evidence(const char *path) {
 FILE *file=fopen(path,"rb"); if(!file) return false;
 uint8_t header[6], pair[9]; bool seen[256]={0}; unsigned distinct=0, count=0;
 bool ok=fread(header,1,6,file)==6 && header[4]<64 && header[5]<2;
 size_t size=0;
 while(ok && (size=fread(pair,1,9,file))==9) {
  for(unsigned j=0;j<2;j++) if(!seen[pair[j*4]]) {
   seen[pair[j*4]]=true; distinct++;
  }
  count++;
 }
 ok=ok && !ferror(file) && size==0 && count && distinct==256;
 fclose(file); return ok;
}
static bool valid_resources(const char *path) {
 size_t length=strlen(path)+32; char *tables=malloc(length);
 if(!tables) return false;
 snprintf(tables,length,"%s/hardnested_tables",path);
 DIR *dir=opendir(tables); free(tables); if(!dir) return false;
 bool even=false, odd=false; struct dirent *entry;
 while((entry=readdir(dir))) {
  if(!strncmp(entry->d_name,"bitflip_0_",10)) even=true;
  if(!strncmp(entry->d_name,"bitflip_1_",10)) odd=true;
 }
 closedir(dir); return even && odd;
}
int main(int argc, char **argv) {
 bool stream=argc==5 && !strcmp(argv[1],"--stream");
 if(argc!=4 && !stream) {
  fprintf(stderr,"Usage: %s NONCES.bin RESOURCE_DIRECTORY CPUS\n       %s --stream RESOURCE_DIRECTORY CPUS v1\n",argv[0],argv[0]); return 2;
 }
 const char *resources=argv[2];
 const char *cpu_arg=argv[3];
 if(stream && strcmp(argv[4],"v1")) return 2;
 char *end; errno=0; unsigned long cpus=strtoul(cpu_arg,&end,10);
 if(errno || *end || cpus<1 || cpus>256) return 2;
 if(!stream && !valid_evidence(argv[1])) {
  fprintf(stderr,"Invalid nonce evidence or incomplete first-byte coverage\n"); return 2;
 }
 if(!valid_resources(resources)) {
  fprintf(stderr,"Hardnested lookup tables unavailable\n"); return 2;
 }
 nfclab_cpus=cpus; nfclab_resources=resources;
 setvbuf(stdout,NULL,_IOLBF,0);
 uint64_t found=0;
 int status=mfnestedhard(0,0,NULL,0,0,NULL,!stream,false,false,0,&found,stream?NULL:argv[1]);
 if(status!=PM3_SUCCESS) { fprintf(stderr,"Solver failed: %d\n",status); return 1; }
 printf("NFCLAB_KEY=%012"PRIx64"\n",found);
 return 0;
}
