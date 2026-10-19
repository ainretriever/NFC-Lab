# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 NFClab contributors.
"""Read-only MCU candidate transport, one packed key upload per batch."""
import math
import struct
import time
from pathlib import Path
from m1_host import ERRORS
from transport import active
from swd import (CLOCKS, read_bytes, snapshot_running, snapshot, symbol,
                 write_words_many)

CAPACITY = 1024
COMMON_KEYS = ('ffffffffffff', '000000000000', 'a0a1a2a3a4a5', 'd3f7d3f7d3f7')

def parse_dictionary(path, binary=False):
    data = Path(path).read_bytes()
    if binary:
        if not data or len(data) % 6:
            raise ValueError('binary dictionary must contain complete six-byte keys')
        values = [data[i:i+6] for i in range(0,len(data),6)]
    else:
        values = []
        for number, line in enumerate(data.decode('utf-8').splitlines(),1):
            line = line.split('#',1)[0].strip()
            if not line:
                continue
            token = ''.join(line.split())
            if len(token) != 12:
                raise ValueError(f'dictionary line {number}: expected 12 hex digits')
            try:
                values.append(bytes.fromhex(token))
            except ValueError:
                raise ValueError(f'dictionary line {number}: invalid hex') from None
    if not values:
        raise ValueError('dictionary is empty')
    return list(dict.fromkeys(values))

def run_keys(keys, uid, *, operation=0, block=0, key_type=0, repeat=1,
             targets=0xffffffff, spi_div=0, auth_timeout_us=4833, select_mode="adaptive"):
    if not 1 <= len(keys) <= CAPACITY or any(len(k)!=6 for k in keys):
        raise ValueError('batch requires 1..1024 six-byte keys')
    if operation not in (0,1,2) or not 0 <= block < 64 or key_type not in (0,1):
        raise ValueError('invalid operation, block or key type')
    if not 0 <= uid <= 0xffffffff or not 0 <= targets <= 0xffffffff or not 0 <= spi_div <= 4:
        raise ValueError('invalid UID, targets or SPI ceiling')
    if operation==1 and (len(keys)!=1 or not 1 <= repeat <= 10000):
        raise ValueError('benchmark requires one key and 1..10000 repeats')
    if operation==2 and not targets:
        raise ValueError('no dictionary targets selected')
    if select_mode not in ("adaptive","fixed"):
        raise ValueError("invalid select mode")
    if not 200 <= auth_timeout_us <= 4833:
        raise ValueError('authentication timeout must be 200..4833 us')
    units=min(1024,math.ceil(auth_timeout_us*13.56/64))
    address=symbol('m1_keys')
    initial=snapshot_running(address,32)
    if initial[:2]!=[0x4d314b59,2] or initial[2] or initial[3]:
        raise RuntimeError('key firmware mismatch or batch busy')
    for name in ('m1','m1_bulk','bench','m1_recover'):
        state=snapshot_running(symbol(name),4)
        if state[2] or state[3]:
            raise RuntimeError(f'{name} batch already pending/running')
    total_attempts=repeat if operation==1 else len(keys)*(targets.bit_count() if operation==2 else 1)
    started=time.monotonic()
    config=[operation,block,key_type,len(keys),repeat,targets,uid,spi_div,units]
    write_words_many([(address+128,b''.join(keys)),
                      (address+16,config),
                      (address+7744,[int(select_mode=="fixed")]),
                      (address+8,[1])])
    deadline=time.monotonic()+total_attempts*0.12+10
    while time.monotonic()<deadline:
        header=snapshot_running(address,32)
        if not header[2] and not header[3]:
            break
        time.sleep(0.005 if active().name == "cdc" else 0.1)
    else:
        raise RuntimeError('key batch timeout; submitted request may still be running')
    results=read_bytes(address+6272,1472)
    if len(results)!=1472:
        raise RuntimeError('incomplete key results')
    timing=snapshot(address+7744,18)
    stats=snapshot(symbol('m1'),128)
    if stats[112] or stats[113]:
        raise RuntimeError('unexpected WRITE counters in read-only batch')
    hz=header[26]
    if hz not in CLOCKS:
        raise RuntimeError('unexpected clock')
    elapsed=(header[24]|header[25]<<32)/hz
    indices=struct.unpack_from('<32I',results,1024)
    checked=struct.unpack_from('<32I',results,1344)
    report={'operation':['check','bench','dictionary'][operation],
            'processed':header[13], 'matched':header[14], 'rejected':header[15],
            'inconclusive':header[16], 'error':ERRORS[header[17]] if header[17]<len(ERRORS) else str(header[17]),
            'last_stage':header[18], 'last_rf':header[19],
            'full_selects':header[20], 'fast_selects':header[21], 'nested_auths':header[22],
            'retries':header[23], 'mcu_ms':elapsed*1000,
            'keys_per_second':header[13]/elapsed if elapsed else None,
            'auth_mean_us':(header[28]|header[29]<<32)*1e6/hz/header[13] if header[13] else None,
            'clock_hz':hz,'auth_timeout_us':units*64/13.56,
            'found_mask':f'{header[27]:08x}', 'spi_hz':snapshot(symbol('diag'),26)[11],
            'writes':stats[112], 'write_data_frames':stats[113],
            'host_elapsed_ms':(time.monotonic()-started)*1000}
    names=['selection','wupa','select','fixed_wait','guard_wait','auth_nt_rf','auth_ar_at_rf']
    report['timing_us']={name:(timing[1+i*2]|timing[2+i*2]<<32)*1e6/hz for i,name in enumerate(names)}
    report['select_mode']=select_mode
    report['at_response_start_us']={
        'samples':timing[17], 'min':timing[15]*1e6/hz if timing[17] else None,
        'max':timing[16]*1e6/hz if timing[17] else None}
    if operation!=2:
        report['status']=[{0:'not-tested',1:'matched',2:'rejected',3:'inconclusive'}[v]
                          for v in results[:len(keys)]]
    else:
        report['targets']=[{'sector':i//2,'key_type':['A','B'][i%2],
                            'found':bool(header[27]&(1<<i)), 'checked':checked[i],
                            'index':indices[i] if header[27]&(1<<i) else None,
                            'key':results[1152+i*6:1158+i*6].hex() if header[27]&(1<<i) else None}
                           for i in range(32) if targets&(1<<i)]
    report['complete']=header[17]==0 and header[16]==0 and (
        header[13]==total_attempts if operation!=2 else
        all(t['found'] or t['checked']==len(keys) for t in report['targets']))
    return report

def dictionary(keys,uid,targets,*,on_progress=None,**options):
    pending=targets; reports=[]; found={}
    checked={i:0 for i in range(32) if targets&(1<<i)}
    for offset in range(0,len(keys),CAPACITY):
        if not pending:
            break
        report=run_keys(keys[offset:offset+CAPACITY],uid,operation=2,targets=pending,**options)
        reports.append(report)
        for target in report['targets']:
            index=target['sector']*2+(target['key_type']=='B')
            checked[index]+=target['checked']
            if target['found']:
                target['index']+=offset; found[index]=target; pending&=~(1<<index)
        if on_progress:
            on_progress(sum(checked.values()))
        if not report['complete']:
            break
    complete=bool(reports) and all(r['complete'] for r in reports)
    result={'operation':'dictionary','candidates':len(keys),'complete':complete,
            'all_found':not pending,'found_mask':f'{targets&~pending:08x}',
            'targets':[dict(found.get(i,{'sector':i//2,'key_type':['A','B'][i%2],
                                        'found':False,'index':None,'key':None}),checked=checked[i])
                       for i in checked], 'batches':reports}
    attempts=sum(r['processed'] for r in reports); milliseconds=sum(r['mcu_ms'] for r in reports)
    result.update(processed=attempts,mcu_ms=milliseconds,
                  keys_per_second=attempts*1000/milliseconds if milliseconds else None)
    return result
