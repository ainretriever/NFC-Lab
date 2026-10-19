# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 NFClab contributors.
"""Select a write protocol using Magic evidence or authenticated block-0 ACK.

No block payload is submitted. An unavailable key/permission/transport is never
interpreted as proof of standard-card behavior.
"""
from m1_keys_host import run_keys
from m1_host import read_live
from m1_write_review import access_conditions,DATA_ACCESS,TRAILER_ACCESS


def detect(card, candidates=(), *, magic=True):
    from m1_info_host import request_info
    if magic:
        report=request_info(card['cuid'],4)
        if report['error']:
            raise RuntimeError('Card type detection failed; check the connection or specify --card-type')
        flags=report['values'][0]
        if flags&1:return 'gen1a'
        if flags&64:return 'gen2'
        if flags:
            raise ValueError('Unsupported magic card type; specify --card-type')
    for t in (0,1):
        keys=list(dict.fromkeys(k for kt,k in candidates if kt==t))
        if not keys:continue
        checked=run_keys(keys,card['cuid'],block=0,key_type=t)
        if not checked['complete']:
            raise RuntimeError('Card type detection: key authentication incomplete')
        matches=[k for k,s in zip(keys,checked['status']) if s=='matched']
        if not matches:continue
        key=matches[0];packed=bytearray(192)
        packed[t*96:t*96+6]=key
        trailer=read_live(3,bytes(packed),card['cuid'],t)
        errors,groups=access_conditions(trailer)
        if errors:raise ValueError('Sector 0: invalid access bits; cannot detect card type')
        if ('AB'[t] not in DATA_ACCESS[groups[0]][1]
                or t==1 and TRAILER_ACCESS[groups[3]][3]):continue
        report=request_info(card['cuid'],5,key=key,key_type=t)
        if (report['error'] or report['completed']!=1 or report['write_commands']!=1
                or report['write_data_frames'] or report['field_off'] is not True):
            raise RuntimeError('Card type detection failed; no block data submitted. Check the connection or specify --card-type')
        return 'gen2' if report['values'][0]&128 else 'standard'
    return None
