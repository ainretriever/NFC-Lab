# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 NFClab contributors.
"""Automatic Classic 1K Read: discovery, keys, reuse, nested, incremental reads.

Key order is revalidated resume keys, the short common list, then user dictionaries;
the large bundled dictionary is opt-in (`builtin=`) because on a card whose keys
are not in it, it costs minutes of RF time before nested recovery even starts.

No write operations are exposed. Keys are private local session data.
"""
import importlib.util
import json
import os
import time
from pathlib import Path
from swd import ROOT
from m1_keys_host import COMMON_KEYS, dictionary, parse_dictionary, run_keys
from m1_host import read_live
from m1_strategies import run_recovery
from m1_auth_timeout import next_timeout
from m1_write_review import access_conditions, TRAILER_ACCESS

spec=importlib.util.spec_from_file_location('m1_dump',Path(__file__).with_name('m1-dump.py'))
dump_module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(dump_module)
COMMON=[bytes.fromhex(k) for k in COMMON_KEYS]
# Opt-in only: 2511 keys is minutes of RF time on a card whose keys are not in it.
BUILTIN=ROOT/'resources/mfc_default_keys.dic'


class ReadSession:
    def __init__(self,path,card,resume=False,builtin=None, *, auth_timeout_us=200):
        if not 200 <= auth_timeout_us <= 4833:
            raise ValueError('authentication timeout must be 200..4833 us')
        self.auth_timeout_us=auth_timeout_us
        self.path=Path(path) if path is not None else None
        self.card=card
        self.builtin=parse_dictionary(builtin) if builtin else []
        self.stale_trailers=set()
        if resume:
            self.state=json.loads((self.path/'session.json').read_text())
            if self.state['version']!=1 or self.state['card']!=card:
                raise ValueError('resume card does not match saved session')
            # Retain data but revalidate all saved authentication keys before using them.
            self.stale_trailers={s for s in range(16) if self.state['blocks'][s*4+3] is not None}
            self.cached=list(dict.fromkeys(bytes.fromhex(t['key']) for t in self.state['keys'] if t['key']))
            self.state['keys']=[{'key':None,'authenticated':False,'provenance':None} for _ in range(32)]
        else:
            if self.path is not None:
                self.path.mkdir(parents=True,exist_ok=False,mode=0o700)
            self.cached=[]
            self.state={'version':1,'card':card,'phase':'identified','status':'running',
                        'keys':[{'key':None,'authenticated':False,'provenance':None} for _ in range(32)],
                        'blocks':[None]*64,'block_errors':[None]*64,'events':[],
                        'recovery_attempts':[], 'writes':0,'write_data_frames':0,
                        'nonce_profile':None,'recovery_path':None}
        self.state.setdefault('nonce_profile',None)
        self.state.setdefault('recovery_path',None)
        self.state['dictionary_auth_timeout_us']=auth_timeout_us
        self.reused=set()
        self.save()

    def save(self):
        self.state['keys_known']=sum(bool(k['key']) for k in self.state['keys'])
        self.state['keys_authenticated']=sum(k['authenticated'] for k in self.state['keys'])
        self.state['blocks_read']=sum(b is not None for b in self.state['blocks'])
        self.state['data_complete']=self.state['blocks_read']==64
        self.state['keys_complete']=self.state['keys_known']==32
        self.state['updated_at']=time.time()
        if self.path is None:
            return
        tmp=self.path/'session.tmp'
        tmp.write_text(json.dumps(self.state,indent=2)+'\n');os.chmod(tmp,0o600)
        tmp.replace(self.path/'session.json')

    def event(self,phase,message):
        self.state['phase']=phase
        self.state['events'].append({'phase':phase,'message':message,'time':time.time()})
        self.save()
        print(f"[{phase}] {message} | Blocks {self.state['blocks_read']}/64, Keys {self.state['keys_known']}/32",flush=True)

    def pending(self):
        return sum(1<<i for i,k in enumerate(self.state['keys']) if not k['key'])

    def accept_report(self,report,provenance,*,allow_incomplete=False):
        added=[]
        for target in report['targets']:
            if target['found']:
                index=target['sector']*2+(target['key_type']=='B')
                self.state['keys'][index]={'key':target['key'],'authenticated':True,'provenance':provenance}
                added.append(bytes.fromhex(target['key']))
        self.save()
        if not report['complete'] and not allow_incomplete:
            raise RuntimeError('inconclusive dictionary/card communication; retain partial session')
        return list(dict.fromkeys(added))

    def search(self,keys,provenance,*,targets=None):
        scope=self.pending() if targets is None else self.pending() & targets
        if not keys or not scope:
            return []
        keys=list(dict.fromkeys(keys))
        self.event(provenance,f'Checking {len(keys)}  candidates, targets {scope.bit_count()}')
        added=[]
        while True:
            report=dictionary(keys,self.card['cuid'],(self.pending() & scope) or scope,
                              auth_timeout_us=self.auth_timeout_us)
            self.state['events'].append({'phase':provenance,'processed':report['processed'],
                'mcu_ms':report['mcu_ms'],'auth_timeout_us':self.auth_timeout_us,
                'complete':report['complete']})
            # Slow Nt can make a batch incomplete; slow At can look like a
            # rejection. Recheck a complete negative batch if no entry exists.
            following=next_timeout(self.auth_timeout_us)
            retry=following is not None and (not report['complete'] or (
                not any(k['authenticated'] for k in self.state['keys']) and
                not any(t['found'] for t in report['targets'])))
            added+=self.accept_report(report,provenance,allow_incomplete=retry)
            if not retry:
                break
            previous=self.auth_timeout_us
            self.auth_timeout_us=following
            self.state['dictionary_auth_timeout_us']=following
            self.event('auth-timeout-fallback',
                       f'{previous} us -> {following} us; retrying {provenance}')
        # Every still-pending target exhausted this complete search, so reuse
        # must not immediately retry the same keys against those targets.
        if targets is None:
            self.reused.update(keys)
        return added

    def read_available(self):
        self.refresh_trailers()
        groups=[]
        for sector in range(16):
            if all(self.state['blocks'][sector*4+b] is not None for b in range(4)):
                continue
            known=[t for t in (0,1) if self.state['keys'][sector*2+t]['authenticated']]
            if not known:
                continue
            mode=2 if len(known)==2 else known[0]
            if groups and groups[-1][1]==mode and groups[-1][0][-1]+1==sector:
                groups[-1][0].append(sector)
            else:
                groups.append(([sector],mode))
        for sectors,mode in groups:
            self.read_group(sectors,mode)
            # A failed continuous batch may stop before later sectors. Retry
            # each incomplete sector separately so it cannot hide other data.
            if len(sectors)>1:
                for sector in sectors:
                    if any(self.state['blocks'][sector*4+b] is None for b in range(4)):
                        self.read_group([sector],mode)

    def sector_keys(self,sectors):
        """Pack authenticated keys in the shared A-then-B mailbox layout."""
        keys=bytearray(192)
        for sector in sectors:
            for t in (0,1):
                entry=self.state['keys'][sector*2+t]
                if entry['authenticated']:
                    offset=(t*16+sector)*6
                    keys[offset:offset+6]=bytes.fromhex(entry['key'])
        return bytes(keys)

    def read_group(self,sectors,mode):
        keys=self.sector_keys(sectors)
        label=str(sectors[0]) if len(sectors)==1 else f'{sectors[0]}-{sectors[-1]}'
        self.event('read',f'Reading sector {label}')
        raw,report=dump_module.read_batch(keys,self.card['cuid'],first=sectors[0],
                                          sectors=len(sectors),key_type=mode,allow_partial=True)
        if report['writes'] or report['write_data_frames']:
            raise RuntimeError('unexpected WRITE counters')
        valid=int(report['valid_bitmap'],16)
        for sector in sectors:
            for block in range(sector*4,sector*4+4):
                if valid&(1<<block):
                    self.state['blocks'][block]=raw[block*16:(block+1)*16].hex()
                    self.state['block_errors'][block]=None
                else:
                    self.state['block_errors'][block]=report['block_errors'][block]
        # All blocks arrived together. Checkpoint the full result before any
        # additional RF verification, rather than committing once per sector.
        self.save()
        for sector in sectors:
            if valid & (1 << (sector*4+3)):
                self.stale_trailers.discard(sector)
                if self.accept_trailer(sector):
                    self.save()

    def accept_trailer(self,sector):
        """Extract Key B only from a trailer read in this run under verified A."""
        trailer=self.state['blocks'][sector*4+3]
        if not trailer or not self.state['keys'][sector*2]['authenticated']:
            return
        data=bytes.fromhex(trailer)
        errors,groups=access_conditions(data)
        if errors or not TRAILER_ACCESS[groups[3]][3] or self.state['keys'][sector*2+1]['key']:
            return
        key=data[10:16]
        checked=run_keys([key],self.card['cuid'],block=sector*4,key_type=1)
        if not checked['complete']:
            raise RuntimeError('inconclusive readable Key B verification')
        self.state['keys'][sector*2+1]={'key':key.hex(),
            'authenticated':checked['status'][0]=='matched','provenance':'readable-trailer'}
        return True

    def refresh_trailers(self):
        # Cached bytes cannot establish current Key B; authenticate A first,
        # then reread the trailer even when the saved sector is already complete.
        for sector in sorted(self.stale_trailers):
            if not self.pending() & (1 << (sector*2+1)) or not self.state['keys'][sector*2]['authenticated']:
                continue
            keys=self.sector_keys([sector])
            raw=read_live(sector*4+3,keys,self.card['cuid'],0)
            self.state['blocks'][sector*4+3]=raw.hex()
            self.state['block_errors'][sector*4+3]=None
            self.stale_trailers.discard(sector)
            self.accept_trailer(sector)
            self.save()

    def advance(self,new_keys):
        while True:
            self.read_available()
            values=list(dict.fromkeys(new_keys+[bytes.fromhex(k['key']) for k in self.state['keys'] if k['key']]))
            fresh=[key for key in values if key not in self.reused]
            if not fresh or not self.pending():
                break
            self.reused.update(fresh)
            new_keys=self.search(fresh,'key-reuse')

    def run(self,dictionaries,*,cross_card_keys=()):
        if self.cached:
            self.advance(self.search(self.cached,'cached-keys'))
        self.advance(self.search(COMMON,'common-dictionary'))
        if cross_card_keys:
            self.advance(self.search(cross_card_keys,'library-keys'))
        for keys in dictionaries:
            self.advance(self.search(keys,'user-dictionary'))
        if self.pending():
            self.advance(self.search(self.builtin,'builtin-dictionary'))
        if self.pending():
            self.recover()
        self.finish()
        return self.state

    def recover(self):
        """Delegate the strategy ladder to m1_strategies (see docs/module-layout.md)."""
        run_recovery(self)

    def export(self):
        """Write the data files; usable at any point, before or after finish()."""
        self.save()
        if self.path is None:
            return
        raw=b''.join(bytes.fromhex(b) if b is not None else bytes(16) for b in self.state['blocks'])
        # Sparse file is explicitly named partial, and its validity lives in session.json.
        if self.state['data_complete']:
            (self.path/'raw.bin').write_bytes(raw)
        else:
            (self.path/'partial-raw.bin').write_bytes(raw)
        if self.state['keys_complete']:
            keys=b''.join(bytes.fromhex(self.state['keys'][s*2+t]['key']) for t in (0,1) for s in range(16))
            (self.path/'keys.bin').write_bytes(keys);os.chmod(self.path/'keys.bin',0o600)
            if self.state['data_complete']:
                complete=bytearray(raw)
                for s in range(16):
                    offset=(s*4+3)*16
                    complete[offset:offset+6]=keys[s*6:s*6+6]
                    complete[offset+10:offset+16]=keys[(s+16)*6:(s+17)*6]
                (self.path/'dump.bin').write_bytes(complete);os.chmod(self.path/'dump.bin',0o600)

    def finish(self):
        self.export()
        self.state['status']='complete' if self.state['data_complete'] and self.state['keys_complete'] else 'partial'
        self.event('finished',f"Read {self.state['status']}")
