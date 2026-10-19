# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 NFClab contributors.
"""Specific M1 mailbox v5 helpers; no per-frame host transactions."""
import time
from swd import CLOCKS, ROOT, snapshot, snapshot_running, symbol, write_words_many
from transport import active

WORDS = 128
VERSION = 5
ERRORS = ['ok', 'argument', 'select', 'uid/card-type', 'rf', 'length', 'parity',
          'auth-answer', 'crc', 'dump-mismatch', 'nak', 'cleanup', 'reserved-12', 'restore']
# Every MCU batch mailbox; a submitted request keeps running even if the host stops.
MAILBOXES = ('m1', 'm1_bulk', 'm1_keys', 'bench', 'm1_recover')


def wait_idle(timeout=180, poll=0.5):
    """Wait until no MCU batch is pending or running.

    An interrupted host run leaves its last MCU batch running to completion, so a
    follow-up run must drain it before submitting anything.  Returns the names
    still busy when `timeout` expires.
    """
    deadline = time.monotonic() + timeout
    while True:
        busy = [name for name in MAILBOXES
                if any(snapshot_running(symbol(name), 4)[2:4])]
        if not busy or time.monotonic() >= deadline:
            return busy
        time.sleep(poll)

def write_allowed(block):
    return 0 <= block < 64

def references(dump_path, keys_path):
    dump, keys = dump_path.read_bytes(), keys_path.read_bytes()
    if len(dump) != 1024 or len(keys) != 192:
        raise ValueError('expected a 1K dump and 192-byte keys')
    for sector in range(16):
        trailer = dump[(sector * 4 + 3) * 16:(sector * 4 + 4) * 16]
        if (keys[sector * 6:sector * 6 + 6] != trailer[:6] or
                keys[(sector + 16) * 6:(sector + 17) * 6] != trailer[10:]):
            raise ValueError('key file does not match dump trailers')
    return dump, keys

def key_for(keys, block, key_type):
    offset = (key_type * 16 + block // 4) * 6
    return keys[offset:offset + 6]

def request(operation, block, key_type, key, uid, expected, payload=None, count=1, *, confirmed=False):
    if operation not in range(9) or not 0 <= block < 64 or not 1 <= count <= 1000:
        raise ValueError('invalid operation, block or count')
    if key_type not in (0, 1) or len(key) != 6 or len(expected) != 16:
        raise ValueError('invalid key or expected data')
    if operation == 7:
        if not confirmed:
            raise ValueError('Gen1a ERASE requires explicit user confirmation before submission')
        if count != 1 or block != 0 or payload is not None:
            raise ValueError('Gen1a ERASE requires count 1, block 0, no payload')
    if operation in (2, 3, 5):
        if not confirmed:
            raise ValueError('WRITE requires explicit user confirmation before submission')
        if payload is None or len(payload) != 16:
            raise ValueError('write payload must be exactly 16 bytes')
        if (operation in (2, 5) and count != 1) or (operation == 3 and count > 20):
            raise ValueError('write-once requires count 1; restored tests allow 1..20')
        if operation == 3 and payload == expected:
            raise ValueError('test payload must differ from original data')
    address = symbol('m1')
    words = snapshot_running(address, WORDS)
    if words[:2] != [0x4d31494f, VERSION]:
        raise RuntimeError('M1 firmware/ELF mismatch')
    if words[2] or words[3]:
        raise RuntimeError('M1 batch already pending/running')
    bulk = snapshot_running(symbol('m1_bulk'), 4)
    if bulk[2] or bulk[3]:
        raise RuntimeError('Read batch already pending/running')
    key_batch = snapshot_running(symbol('m1_keys'), 4)
    if key_batch[2] or key_batch[3]:
        raise RuntimeError('Key batch already pending/running')
    bench = snapshot_running(symbol('bench'), 13)
    if bench[2] or bench[3]:
        raise RuntimeError('Select benchmark already pending/running')
    recover = snapshot_running(symbol('m1_recover'), 4)
    if recover[2] or recover[3]:
        raise RuntimeError('Nonce capture already pending/running')
    config = [count, operation, block, key_type, *key, uid, *expected]
    segments = [(address + 16, config)]
    if payload is not None:
        segments.append((address + 79 * 4, list(payload)))
    segments.append((address + 8, [1]))
    write_words_many(segments)
    deadline = time.monotonic() + count * (0.4 if operation in (2, 3, 5) else 0.15) + 5
    cdc = active().name == 'cdc'
    time.sleep(0.005 if cdc else min(count * (0.22 if operation in (2, 3, 5) else 0.055) + 0.25, 55))
    while time.monotonic() < deadline:
        header = snapshot_running(address, 4)
        if not header[2] and not header[3]:
            return snapshot(address, WORDS)
        time.sleep(0.005 if cdc else 1)
    raise RuntimeError('M1 timeout; submitted MCU request may still be running')

def read_live(block, keys, uid, key_type=0):
    words = request(4, block, key_type, key_for(keys, block, key_type), uid, bytes(16))
    if words[31] != 1 or words[32] or words[36] or words[34] != 1:
        error = ERRORS[words[36]] if words[36] < len(ERRORS) else str(words[36])
        raise RuntimeError(f'block {block} read failed: {error}, RF {words[37]}')
    return bytes(words[56:72])


def read_gen1a(block, uid, *, unselected=False):
    """Backdoor read includes the full trailer, including both keys."""
    words = request(8 if unselected else 6, block, 0, bytes(6), uid, bytes(16))
    if words[31] != 1 or words[32] or words[36] or words[34] != 1:
        code = words[36]
        error = ERRORS[code] if code < len(ERRORS) else str(code)
        raise RuntimeError(f'Gen1a block {block} read failed: {error}, RF {words[37]}')
    return bytes(words[56:72])
