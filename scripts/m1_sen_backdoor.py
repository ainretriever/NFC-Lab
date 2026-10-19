# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 NFClab contributors.
"""Bounded Fudan backdoor discovery and read-only sector/card dumps."""
import time
from m1_recover_host import probe_auth_read

# Public keys in the same order as PM3 cmdhfmfsen.c.
BACKDOOR_KEYS = ('a396efa4e24f', 'a31667a8cec1', '518b3354e760', '73b9836cf168')


def find_backdoor(uid):
    """First backdoor key that authenticates on block 0, or None.

    Uses the read-only profile=3 diagnostic (AUTH 0x64 + READ).  A card without a
    working backdoor returns None and would need the known-key collection path.
    """
    for key in BACKDOOR_KEYS:
        try:
            report = probe_auth_read(uid, bytes.fromhex(key), key_type=4, block=0)
        except RuntimeError:
            continue
        if report['matched']:
            return key
    return None



def read_sector(uid, backdoor_key, sector):
    """One backdoor auth opens the sector, then its four blocks are read."""
    for key_type in (4, 5):
        report = probe_auth_read(uid, bytes.fromhex(backdoor_key), key_type=key_type,
                                 block=sector * 4, count=4)
        if report['matched']:
            return key_type, report['blocks']
    return None


def read_card(uid, backdoor_key=None):
    """Fast read-only dump of all 64 blocks through the backdoor."""
    backdoor = backdoor_key or find_backdoor(uid)
    if backdoor is None:
        raise ValueError('SEN: no Fudan backdoor key authenticated; backdoor read unavailable')
    started = time.monotonic()
    blocks, errors, opened = [], [], []
    for sector in range(16):
        result = read_sector(uid, backdoor, sector)
        if result is None:
            blocks.extend([None] * 4)
            errors.extend([1] * 4)
            continue
        key_type, data = result
        opened.append((sector, 4 + key_type))
        blocks.extend(data)
        errors.extend([0] * 4)
    return {'backdoor_key': backdoor, 'blocks': blocks, 'block_errors': errors,
            'opened': opened, 'elapsed_s': time.monotonic() - started,
            'writes': 0, 'write_data_frames': 0}
