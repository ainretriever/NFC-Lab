# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 NFClab contributors.
"""Read-only Classic 1K fingerprints ported from PM3 dd8bf6c CmdHF14AMfInfo.

Block-0 patterns identify compatible signatures, not an unforgeable chip ID.
SAK/UID or a failed backdoor probe alone never identify an IC manufacturer.
"""
from m1_recover_host import probe_auth_read
from m1_keys_host import COMMON_KEYS

# Same priority as PM3's block-0 backdoor reads; successful AUTH + CRC READ
# is required before a model rule may use the backdoor key as evidence.
BACKDOOR_KEYS = ('a396efa4e24f', 'a31667a8cec1', '518b3354e760', '73b9836cf168')


def classify_block0(sak, block, backdoor_key=None):
    """The PM3 fingerprint branches applicable to our Classic 1K reader."""
    if len(block) != 16:
        raise ValueError('fingerprint requires exactly 16 block-0 bytes')
    if sak != 0x20 and block[8:] == bytes.fromhex('6263646566676869'):
        return 'Fudan based card'
    signature = f'{block[8]:02X}{block[15]:02X}'
    standard = sak == 0x08 and block[5:8] == bytes.fromhex('080400')
    if backdoor_key == BACKDOOR_KEYS[0] and sak == 0x08:
        if standard and block[8] in (3, 4, 5) and block[15] == 0x90:
            return f'Fudan FM11RF08S {signature}'
        if standard and block[8] in (3, 4) and block[15] == 0x91:
            return f'Fudan FM11RF08 {signature} with advanced verification method'
        if block[5:9] == bytes.fromhex('00030010') and block[15] == 0x90:
            return f'Fudan FM11RF08S-7B {signature}'
    if backdoor_key == BACKDOOR_KEYS[1] and sak == 0x08:
        if standard and block[8] in (4, 5) and block[15] == 0x98:
            return f'Fudan FM11RF08S {signature}'
        if standard and block[8] in (1, 2, 3) and block[15] == 0x1D:
            return 'Fudan FM11RF08'
        if block[5:9] == bytes.fromhex('00010010') and block[15] == 0x1D:
            return 'Fudan FM11RF08-7B'
        for prefix, name in (('88040044', 'NXP MF1ICS5003'), ('88040045', 'NXP MF1ICS5004')):
            if block[5:9] == bytes.fromhex(prefix):
                return name
    if backdoor_key is not None:
        return 'Unknown card with backdoor'
    if sak == 0x08:
        for prefix, name in (('88040046', 'NXP MF1ICS5005'), ('88040047', 'NXP MF1ICS5006'),
                             ('88040048', 'NXP MF1ICS5007'), ('880400c0', 'NXP MF1ICS5035')):
            if block[5:9] == bytes.fromhex(prefix):
                return name
    return None


def detect(card, supplied_keys=()):
    """Bounded AUTH/READ probes, without recovery, writes or session caches.

    Transport/ABI errors propagate; ordinary on-card rejection is a negative
    probe, not proof that a backdoor or a vendor is absent.
    """
    attempts = []
    for key in BACKDOOR_KEYS:
        report = probe_auth_read(card['cuid'], bytes.fromhex(key), key_type=4, block=0)
        attempts.append(dict(key_type=4, matched=report['matched'], error=report['error']))
        if report['matched']:
            block = bytes.fromhex(report['data'])
            return dict(label=classify_block0(card['sak'], block, key), status='matched',
                        source='block0-and-backdoor-auth', block0=block.hex(), probes=attempts)
    keys = list(dict.fromkeys([*supplied_keys, *(bytes.fromhex(k) for k in COMMON_KEYS)]))
    for key_type in (0, 1):
        for key in keys:
            report = probe_auth_read(card['cuid'], key, key_type=key_type, block=0)
            attempts.append(dict(key_type=key_type, matched=report['matched'], error=report['error']))
            if report['matched']:
                block = bytes.fromhex(report['data'])
                label = classify_block0(card['sak'], block)
                return dict(label=label or 'Unknown', status='matched' if label else 'unknown',
                            source='block0', block0=block.hex(), probes=attempts)
    return dict(label='Unknown (manufacturer block unreadable)', status='unavailable',
                source=None, probes=attempts)
