# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 NFClab contributors.
"""Read-only mode 6: check default A/B keys, stopping at the first nondefault sector."""
import time
from m1_host import ERRORS,MAILBOXES
from swd import symbol,snapshot_running,write_words_many


def request_trailers(card):
    address=symbol('m1_bulk')
    if snapshot_running(address,2)!=[0x4d314255,2]:raise RuntimeError('bulk ABI mismatch')
    if snapshot_running(address+1319*4,1)!=[0x47315736]:
        raise RuntimeError('early-stop default-key inspection firmware required; update firmware')
    for name in MAILBOXES:
        if any(snapshot_running(symbol(name),4)[2:4]):raise RuntimeError(f'{name} busy')
    write_words_many([(address+16,[0,16,1,0,card['cuid']]),(address+64,[255]*192),
                      (address+1312*4,[6,0]),(address+8,[1])])
    deadline=time.monotonic()+20
    while time.monotonic()<deadline:
        header=snapshot_running(address,4)
        if not any(header[2:4]):break
        time.sleep(.005)
    else:raise RuntimeError('default-key inspection timeout; MCU batch may still be running')
    w=snapshot_running(address,1320)
    stats=snapshot_running(symbol('m1'),128)
    if stats[112] or stats[113]:raise RuntimeError('unexpected WRITE during default-key inspection')
    if w[10]:
        code=w[10];raise RuntimeError(f'default-key inspection failed: {ERRORS[code] if code<len(ERRORS) else code}')
    if any(code not in (0,4,10) for code in w[1232:1296]):
        raise RuntimeError('default-key inspection has an inconclusive block error')
    if not 0 <= w[16] <= 16:
        raise RuntimeError('invalid default-key inspection result')
    if not w[16] and (w[9]!=1 or w[12]!=0x88888888 or w[13]!=0x88888888):
        raise RuntimeError('incomplete default-key inspection')
    valid=w[12]|w[13]<<32
    return dict(nondefault=[w[16]-1] if w[16] else [], verified_b=w[17], trailers={s:bytes(w[208+(s*4+3)*16:208+(s*4+4)*16]) for s in range(16) if valid&(1<<(s*4+3))},
                selects=w[1314],nested_auths=w[1315],recoveries=w[1316],cycles=w[14]|w[15]<<32)
