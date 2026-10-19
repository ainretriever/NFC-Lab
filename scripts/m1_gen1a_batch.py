# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 NFClab contributors.
"""Gen1a batch writer using mode 2 of the fixed-size m1_bulk mailbox."""
import time
from m1_host import ERRORS, MAILBOXES
from swd import symbol, snapshot_running, write_words_many

WORDS=1320
CAPABILITY=0x47315732


def request_batch(plan, uid, *, confirmed=False, submitted=None):
    if not confirmed:
        raise ValueError('batch WRITE requires explicit authorization')
    writes=plan['writes']
    blocks=[w['block'] for w in writes]
    if not 1<=len(blocks)<=64 or any(type(b) is not int or not 0<=b<64 for b in blocks) or len(set(blocks))!=len(blocks):
        raise ValueError('invalid batch block scope')
    if 0 in blocks and blocks[-1]!=0:
        raise ValueError('manufacturer block must be last')
    payload=[0]*1024
    for w in writes:
        data=bytes.fromhex(w['data'])
        if len(data)!=16:raise ValueError('batch block payload must be 16 bytes')
        payload[w['block']*16:w['block']*16+16]=data
    address=symbol('m1_bulk')
    header=snapshot_running(address,16)
    if header[:2]!=[0x4d314255,2]:raise RuntimeError('bulk ABI mismatch')
    if snapshot_running(address+1319*4,1)[0] not in (CAPABILITY,0x47315733,0x47315734,0x47315735,0x47315736):
        raise RuntimeError('Gen1a batch firmware required; update firmware before writing')
    for name in MAILBOXES:
        if any(snapshot_running(symbol(name),4)[2:4]):raise RuntimeError(f'{name} busy')
    segments=[(address+16,[0,len(blocks),1,0,uid]),
              (address+16*4,blocks+[0]*(192-len(blocks))),
              (address+208*4,payload),(address+1312*4,[2,0])]
    if submitted is not None:submitted()
    write_words_many(segments+[(address+8,[1])])
    deadline=time.monotonic()+20
    while time.monotonic()<deadline:
        state=snapshot_running(address,16)
        if not state[2] and not state[3]:
            words=snapshot_running(address,WORDS)
            return dict(completed=words[9],error=words[10],failed_block=words[11],
                verified=words[12]|words[13]<<32,submitted=words[80]|words[81]<<32,
                ack=words[82]|words[83]<<32,uid=words[84],
                block_errors=words[1232:1296],cycles=words[14]|words[15]<<32,selects=words[1314])
        time.sleep(.005)
    raise RuntimeError('Gen1a batch timeout; submitted MCU batch may still be running')


def execute_batch(plan, card, results):
    from m1_recover_host import identify
    for item in plan['writes']:
        results[str(item['block'])]=dict(state='not-submitted',data=item['data'])
    def submitted():
        for result in results.values():result['state']='submission-unknown'
    report=request_batch(plan,card['cuid'],confirmed=True,submitted=submitted)
    for item in plan['writes']:
        b=item['block'];bit=1<<b;result=results[str(b)]
        result['state']=('verified' if report['verified']&bit else 'ack' if report['ack']&bit else
                         'submission-unknown' if report['submitted']&bit else 'not-submitted')
        if report['verified']&bit:result['verification']='full-block-readback'
        if report['failed_block']==b:
            result['error']=ERRORS[report['error']] if report['error']<len(ERRORS) else str(report['error'])
            if report['ack']&bit:result['state']='unverified'
    if report['error'] or report['completed']!=1 or any(r['state']!='verified' for r in results.values()):
        code=report['error']
        where=f"block {report['failed_block']}" if report['failed_block']<64 else 'selection/cleanup'
        raise RuntimeError(f"Gen1a batch failed at {where}: {ERRORS[code] if code<len(ERRORS) else code}")
    after=dict(card)
    if plan['include_uid']:
        expected=bytes.fromhex(next(w['data'] for w in plan['writes'] if w['block']==0))[:4].hex()
        after=identify()
        if after['uid'].lower()!=expected:
            results['0'].update(state='unverified',error='target UID after batch does not match planned UID')
            raise RuntimeError('target UID after batch does not match planned UID')
    return results,after
