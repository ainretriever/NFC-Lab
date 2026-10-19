# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 NFClab contributors.
"""Whole-card policy: copy onto default-key cards; erase with verified Library keys."""
DEFAULT_KEY=bytes([255])*6


def default_credentials():
    return {s:{0:DEFAULT_KEY,1:DEFAULT_KEY} for s in range(16)}


def inspect_defaults(card, *, batch=True):
    from nfclab_write import check_key
    from m1_host import read_live
    from m1_write_review import access_conditions,TRAILER_ACCESS
    packed=bytes([255])*192
    verified={};nondefault=[]
    if batch:
        from m1_defaults_batch import request_trailers
        report=request_trailers(card)
        if report.get('nondefault'):
            return dict(uid=card['uid'],nondefault=report['nondefault'],verified={})
    for s in range(16):
        trailer=report['trailers'].get(s) if batch else None
        if trailer is None:
            if not check_key(DEFAULT_KEY,card['cuid'],s*4,0):
                nondefault.append(s);break
            trailer=read_live(s*4+3,packed,card['cuid'],0)
        errors,groups=access_conditions(trailer)
        if errors:raise ValueError(f'Sector {s}: invalid access bits; cannot write or erase.')
        matched=[(0,DEFAULT_KEY)]
        if TRAILER_ACCESS[groups[3]][3]:
            good=trailer[10:]==DEFAULT_KEY
        else:
            good=bool(report['verified_b'] & (1<<s)) if batch and 'verified_b' in report else check_key(DEFAULT_KEY,card['cuid'],s*4,1)
            if good:matched.append((1,DEFAULT_KEY))
        if not good:
            nondefault.append(s);break
        verified[s]=dict(matched=matched,trailer=trailer)
    return dict(uid=card['uid'],nondefault=nondefault,verified=verified)


def warning(state):
    return 'UNKNOWN KEYS ERASE FIRST'


def require_defaults(state):
    if state['nondefault']:raise ValueError(warning(state))


def erase_credentials(card, library, state):
    if not state['nondefault']:return default_credentials()
    try:source=library.card(card['uid'])
    except ValueError:
        raise ValueError('No complete keys for this UID in Card Library; read the card before erasing.') from None
    slots=source['payload']['keys']
    if len(slots)!=32 or any(k['state']!='known' for k in slots):
        raise ValueError('Current library version has incomplete keys; read the card before erasing.')
    return {s:{t:bytes.fromhex(slots[s*2+t]['value']) for t in (0,1)} for s in range(16)}
