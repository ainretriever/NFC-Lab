# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 NFClab contributors.
"""Modes 3/4 authenticated writers; current credentials come from ACL preflight."""
import time
from m1_host import ERRORS, MAILBOXES
from swd import symbol, snapshot_running, write_words_many

CAPABILITY=0x47315734


def request_batch(plan, card, authenticated, *, card_type, confirmed=False, submitted=None, nested=None):
    if not confirmed:raise ValueError('batch WRITE requires explicit authorization')
    if card_type not in ('standard','gen2'):raise ValueError('invalid authenticated card type')
    nested=True if nested is None else nested
    writes=plan['writes'];blocks=[w['block'] for w in writes]
    if not 1<=len(blocks)<=64 or any(type(b) is not int or not 0<=b<64 for b in blocks) or len(set(blocks))!=len(blocks):
        raise ValueError('invalid batch block scope')
    if blocks!=sorted(blocks,key=lambda b:(b==0,b)):
        raise ValueError('data before trailers; manufacturer block last')
    if 0 in blocks and card_type=='standard':raise ValueError('Standard M1 writes exclude block 0')
    payload=[0]*1024;types=[0]*64;keys=[0]*192;slots={};mask=0
    for item in writes:
        b=item['block'];raw=bytes.fromhex(item['data'])
        if len(raw)!=16:raise ValueError('batch payload requires 16 bytes')
        t,key=authenticated[b]
        if t not in (0,1) or len(key)!=6:raise ValueError('invalid current key')
        slot=(t*16+b//4)*6
        if slot in slots and slots[slot]!=key:raise ValueError('conflicting sector keys')
        slots[slot]=key;keys[slot:slot+6]=key;types[b]=t
        payload[b*16:b*16+16]=raw;mask|=1<<b
    address=symbol('m1_bulk')
    if snapshot_running(address,2)!=[0x4d314255,2]:raise RuntimeError('bulk ABI mismatch')
    capability=snapshot_running(address+1319*4,1)[0]
    if capability not in ((CAPABILITY,0x47315735,0x47315736) if nested else (0x47315733,CAPABILITY,0x47315735,0x47315736)):
        raise RuntimeError('authenticated batch firmware required; update firmware before writing')
    for name in MAILBOXES:
        if any(snapshot_running(symbol(name),4)[2:4]):raise RuntimeError(f'{name} busy')
    segments=[(address+16,[0,len(blocks),1,int(card_type=='gen2'),card['cuid']]),
              (address+12*4,[mask&0xffffffff,mask>>32]),(address+16*4,keys),
              (address+208*4,payload),(address+1232*4,types),(address+1312*4,[4 if nested else 3,0])]
    if submitted is not None:submitted()
    write_words_many(segments+[(address+8,[1])])
    deadline=time.monotonic()+20
    while time.monotonic()<deadline:
        state=snapshot_running(address,4)
        if not any(state[2:4]):
            w=snapshot_running(address,1320)
            return dict(completed=w[9],error=w[10],failed_block=w[11],verified=w[12]|w[13]<<32,
                        submitted=w[1296]|w[1297]<<32,ack=w[1298]|w[1299]<<32,uid=w[1300],
                        cycles=w[14]|w[15]<<32,selects=w[1314],nested_auths=w[1315],recoveries=w[1316])
        time.sleep(.005)
    raise RuntimeError('authenticated batch timeout; submitted MCU batch may still be running')


def execute_batch(plan, card, authenticated, results, *, card_type, nested=None):
    from m1_recover_host import identify
    for item in plan['writes']:
        results[str(item['block'])]=dict(state='not-submitted',data=item['data'])
    def submitted():
        for r in results.values():r['state']='submission-unknown'
    report=request_batch(plan,card,authenticated,card_type=card_type,confirmed=True,submitted=submitted,nested=nested)
    for item in plan['writes']:
        b=item['block'];bit=1<<b;r=results[str(b)]
        r['state']=('verified' if report['verified']&bit else 'ack' if report['ack']&bit else
                    'submission-unknown' if report['submitted']&bit else 'not-submitted')
        if report['verified']&bit:
            r['verification']='readback-and-key-verification'
            if b%4==3:
                from m1_write_review import access_conditions,TRAILER_ACCESS
                _,groups=access_conditions(bytes.fromhex(item['data']))
                r['keys']={'A':'authenticated','B':
                    'readback-match' if TRAILER_ACCESS[groups[3]][3] else 'authenticated'}
        if report['failed_block']==b:
            r['error']=ERRORS[report['error']] if report['error']<len(ERRORS) else str(report['error'])
            if report['ack']&bit:r['state']='unverified'
    if report['error'] or report['completed']!=1 or any(r['state']!='verified' for r in results.values()):
        code=report['error']
        raise RuntimeError(f"authenticated batch failed at block {report['failed_block']}: {ERRORS[code] if code<len(ERRORS) else code}")
    after=dict(card)
    if plan['include_uid']:
        expected=bytes.fromhex(next(i['data'] for i in plan['writes'] if i['block']==0))[:4].hex()
        after=identify()
        if after['uid'].lower()!=expected:
            results['0'].update(state='unverified',error='target UID after batch does not match planned UID')
            raise RuntimeError('target UID after batch does not match planned UID')
    return results,after
