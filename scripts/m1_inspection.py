# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 NFClab contributors.
"""Card capabilities and nonce behavior, separate from manufacturer fingerprint."""
from m1_info_host import request_info
from m1_keys_host import COMMON_KEYS, run_keys
from m1_recover_host import capture
from m1_recovery import probe, nonce_distances

MAGIC_NAMES = {1:'Gen1a',2:'Gen1b',4:'Gen4 GTU',8:'Gen4 GDM (Magic Auth)',
               16:'Gen4 GDM (Gen1 wakeup)',32:'Gen4 GDM (Gen4 wakeup)',
               64:'Gen2 / CUID (ATS signature)',128:'Gen2 / CUID (WRITE ACK)'}
STATE_LABELS = dict(untested='Untested',unsupported='Untested (unsupported firmware)',
                    failed='Detection failed',not_detected='No supported features detected')


def magic_result(report):
    caps = [name for bit,name in MAGIC_NAMES.items() if report['values'][0]&bit]
    status = ('unsupported' if report['error']==1 else 'failed' if report['error'] else
              'matched' if caps else 'not_detected')
    return dict(status=status,label=' / '.join(caps) if status=='matched' else STATE_LABELS[status],
                capabilities=caps,evidence=report)


def nonce_result(profile):
    records = [r for r in profile['records'] if not r.get('error')]
    if len(records)<2:
        return dict(status='failed',prng='Detection failed',nonce='Detection failed')
    checks = nonce_distances([(r['nt'],r['nt']) for r in records])
    valid = sum(a for a,_,_ in checks)
    prng = 'weak' if valid==len(checks) else 'hard' if valid==0 else 'mixed'
    classification = probe(records)['class'] if 'plain' in records[0] else (
        'static-nonce' if len({r['nt'] for r in records})==1 else 'dynamic')
    nonce = {'static-nonce':'static','static-encrypted':'static-encrypted',
             'weak':'dynamic','hard':'dynamic','insufficient':'Untested'}.get(classification,classification)
    if 'plain' not in records[0] and nonce=='dynamic':
        nonce = 'dynamic(nested nonce untested)'
    return dict(status='matched',prng=prng,nonce=nonce,samples=len(records),
                classification=classification)


def inspect(card, supplied_keys=(), write_probe_key=None, write_probe_type=0,
            allow_write_probe=True, force_write_probe=False):
    magic = magic_result(request_info(card['cuid'],4))
    magic['gen2_diagnostic'] = dict(status='untested',label='Untested (no authenticated entry key)')
    if not allow_write_probe:
        magic['gen2_diagnostic']['label'] = 'Untested (write commands disabled)'
    elif magic['capabilities'] and not force_write_probe:
        magic['gen2_diagnostic']['label'] = 'Untested (Magic features already identified)'
    keys = list(dict.fromkeys([*([write_probe_key] if write_probe_key else []),
                              *supplied_keys,*(bytes.fromhex(k) for k in COMMON_KEYS)]))
    cached = None
    types = (write_probe_type, 1-write_probe_type)
    for key_type in types:
        checked = run_keys(keys,card['cuid'],block=0,key_type=key_type)
        if not checked['complete']:
            if allow_write_probe and not magic['capabilities']:
                magic['gen2_diagnostic']['label'] = 'Untested (entry key authentication failed)'
            return dict(magic=magic,nonce=dict(status='failed',prng='Detection failed',nonce='Detection failed')),None
        matches = [i for i,value in enumerate(checked['status']) if value=='matched']
        if matches:
            key = keys[matches[0]]
            if allow_write_probe and (force_write_probe or not magic['capabilities']):
                deep = magic_result(request_info(card['cuid'],5,key=key,key_type=key_type))
                magic['gen2_diagnostic'] = deep
                if deep['status']=='matched':
                    magic['capabilities'] += deep['capabilities']
                    label = ' / '.join(magic['capabilities'])
                    if magic['status']=='failed':
                        magic['label'] = f'Detection failed (partial match:{label})'
                    else:
                        magic.update(status='matched',label=label)
            data = capture(card['cuid'],key_type,key,count=16)
            cached = dict(source=key_type,key=key.hex(),data=data)
            return dict(magic=magic,nonce=nonce_result(data)),cached
    raw = request_info(card['cuid'],6,count=4)
    if raw['error'] or raw['completed']!=4:
        nonce = dict(status='unsupported' if raw['error']==1 else 'failed',
                     prng='Untested (unsupported firmware)' if raw['error']==1 else 'Detection failed',
                     nonce='Untested (unsupported firmware)' if raw['error']==1 else 'Detection failed',evidence=raw)
    else:
        nonce = nonce_result(dict(records=[dict(nt=nt) for nt in raw['values']]))
        nonce['evidence'] = raw
    return dict(magic=magic,nonce=nonce),cached
