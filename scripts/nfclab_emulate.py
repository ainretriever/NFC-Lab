# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 NFClab contributors.
"""Foreground UID simulator with a firmware-enforced heartbeat lease."""
import time
from swd import symbol, snapshot_running, write_words

MAGIC = 0x55494453
FIELDS = ('magic version request busy active error uid_length uid0 uid1 uid2 uid3 '
          'heartbeat selected halts unsupported field_on field_off state irq '
          'lease_expired sequence clock_hz reserved0 reserved1').split()
ERRORS = {1: 'invalid UID (requires four bytes; first byte cannot be 88)',
          2: 'device busy with another NFC operation', 3: 'NFC SPI/restore failure'}


def state(address):
    values = snapshot_running(address, len(FIELDS))
    if values[:2] != [MAGIC, 1]:
        raise RuntimeError('UID simulator firmware/ELF mismatch; flash matching firmware')
    return dict(zip(FIELDS, values))


def submit(address, operation):
    before = state(address)
    if before['request'] or before['busy']:
        raise RuntimeError('UID simulator command already pending')
    write_words(address+8, [operation], halt=False)
    deadline = time.monotonic()+2
    while time.monotonic() < deadline:
        current = state(address)
        if not current['request'] and not current['busy'] and current['sequence'] != before['sequence']:
            if current['error']:
                raise RuntimeError(ERRORS.get(current['error'], 'UID simulator error'))
            return current
        time.sleep(.01)
    raise RuntimeError('UID simulator command timeout; heartbeat expiry will stop simulation')


def status_data(current):
    return dict(active=bool(current['active']), uid=''.join(f'{current[f"uid{i}"]:02X}' for i in range(4)),
                atqa='0400', sak=8, selected=current['selected'], halts=current['halts'],
                unsupported=current['unsupported'], field_on=current['field_on'],
                field_off=current['field_off'], lease_expired=bool(current['lease_expired']),
                error=current['error'])


def run(a, events, *, completed=None):
    try:
        address = symbol('uid_sim')
    except RuntimeError as error:
        raise RuntimeError('UID simulation requires updated firmware and matching ELF') from error
    current = state(address)
    if a.command == 'status':
        events.emit('uid_sim.status', **status_data(current))
        return 0
    if a.command == 'stop':
        if current['active'] or current['error'] == 3:
            current = submit(address, 2)
        events.emit('uid_sim.stopped', **status_data(current))
        return 0
    if a.uid[0] == 0x88:
        raise ValueError('UID beginning with 88 is a cascade marker, not a valid single-level UID')
    if current['active'] or current['request'] or current['busy']:
        raise RuntimeError('UID simulation already active; stop it first')
    heartbeat = (current['heartbeat']+1) & 0xffffffff
    write_words(address+24, [4, *a.uid], halt=False)
    write_words(address+44, [heartbeat], halt=False)
    owned = True  # Start may complete even if its response is lost.
    interrupted = False
    try:
        current = submit(address, 1)
        events.emit('uid_sim.started', **status_data(current), lease_ms=3000)
        started = time.monotonic()
        last_selected = current['selected']
        while a.duration is None or time.monotonic()-started < a.duration:
            if completed is not None and completed():
                break
            time.sleep(.2)
            heartbeat = (heartbeat+1) & 0xffffffff
            write_words(address+44, [heartbeat], halt=False)
            current = state(address)
            if not current['active'] or current['error']:
                raise RuntimeError('UID simulation stopped unexpectedly; inspect status')
            if current['selected'] != last_selected:
                events.emit('uid_sim.status', **status_data(current))
                last_selected = current['selected']
    except KeyboardInterrupt:
        interrupted = True
    finally:
        if owned:
            current = state(address)
            if current['active'] or current['request']:
                current = submit(address, 2)
            events.emit('uid_sim.stopped', **status_data(current), interrupted=interrupted)
    return 130 if interrupted else 0
