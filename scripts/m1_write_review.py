# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 NFClab contributors.
"""MIFARE Classic 1K write preview. Findings inform the user; never veto data.
Encoding and permission tables: NXP MF1S50YYX_V1, sections 8.6.3 and 8.7.
"""
import select
import os
import termios
import sys
import time

# C1C2C3 indexed as a 3-bit number. Permissions: read, write, increment, D/T/R.
DATA_ACCESS = (
    ('A/B', 'A/B', 'A/B', 'A/B'),
    ('A/B', 'none', 'none', 'A/B'),
    ('A/B', 'none', 'none', 'none'),
    ('B', 'B', 'none', 'none'),
    ('A/B', 'B', 'none', 'none'),
    ('B', 'none', 'none', 'none'),
    ('A/B', 'B', 'B', 'A/B'),
    ('none', 'none', 'none', 'none'),
)
# Trailer permissions: write Key A, write access bits, write Key B, readable B.
TRAILER_ACCESS = (
    ('A', 'none', 'A', True), ('A', 'A', 'A', True),
    ('none', 'none', 'none', True), ('B', 'B', 'B', False),
    ('B', 'none', 'B', False), ('none', 'B', 'none', False),
    ('none', 'none', 'none', False), ('none', 'none', 'none', False),
)


def access_conditions(payload):
    b6, b7, b8 = payload[6:9]
    positive = (b7 >> 4, b8 & 15, b8 >> 4)
    inverted = (b6 & 15, b6 >> 4, b7 & 15)
    errors = []
    for i, (value, inv) in enumerate(zip(positive, inverted), 1):
        if value ^ inv != 15:
            errors.append(f'C{i} complement mismatch: stored {inv:04b}, expected {value ^ 15:04b}')
    groups = tuple(((positive[0] >> i & 1) << 2) |
                   ((positive[1] >> i & 1) << 1) |
                   (positive[2] >> i & 1) for i in range(4))
    return errors, groups


def analyse_write(block, payload):
    if not 0 <= block < 64 or len(payload) != 16:
        raise ValueError('invalid 1K block or payload size')
    if block == 0:
        lines = ['[Note] Manufacturer block: data may change UID/manufacturer bytes; acceptance depends on card protocol.',
                 f'4-byte UID in new data: {payload[:4].hex().upper()}']
        bcc = payload[0] ^ payload[1] ^ payload[2] ^ payload[3]
        if payload[4] != bcc:
            lines.append(f'[Warning] For the 4-byte UID layout, BCC is {payload[4]:02X}, expected {bcc:02X}.')
        return lines
    if block % 4 != 3:
        return ['[Check] Data block; these 16 bytes are not sector access bits.']
    errors, groups = access_conditions(payload)
    lines = [f'Access bits: {payload[6:9].hex(" ").upper()}; GPB: {payload[9]:02X}(not required to be 69)']
    if errors:
        lines.extend('[Encoding error] ' + error for error in errors)
        lines.append('[Alert] Access bits and complements disagree; standard M1 chips may permanently lock the sector.')
        lines.append('Permissions below decode positive bits only; actual behavior with invalid encoding may differ.')
    else:
        lines.append('[Check] Access-bit complements match; encoding valid.')
    base = block - 3
    for i in range(3):
        read, write, inc, dtr = DATA_ACCESS[groups[i]]
        if base + i == 0:
            lines.append(f'block 0 / {groups[i]:03b}: read {read}; Standard cards cannot write the manufacturer block; clones follow their own protocol.')
        else:
            lines.append(f'block {base+i} / {groups[i]:03b}: read {read}; write {write}; '
                         f'increment {inc}; decrement/transfer/restore {dtr}')
        if groups[i] == 7:
            lines.append(f'[Warning] block {base+i} will prohibit all access listed above.')
    ka, acl, kb, readable_b = TRAILER_ACCESS[groups[3]]
    lines.append(f'Trailer {block} / {groups[3]:03b}: write Key A {ka}; write access bits {acl}; write Key B {kb}')
    if ka == acl == kb == 'none':
        lines.append('[Warning] Positive-bit decoding: trailer fields have no write permission.' if errors else
                     '[Warning] Encoding valid, but trailer fields will no longer be writable.')
    elif acl == 'none':
        lines.append('[Warning] Positive-bit decoding: access bits have no write permission.' if errors else
                     '[Warning] Encoding valid, but access bits will no longer be writable.')
    if readable_b:
        lines.append('[Note] Under this configuration, standard M1 Key B is readable and cannot authenticate.')
        if any('B' in DATA_ACCESS[group] for group in groups[:3]):
            lines.append('[Warning] Some data operations require Key B, but this trailer configuration prevents Key B authentication.')
    return lines


def confirm_write(block, payload, uid, *, test=False, count=1, restore=None, timeout=60, preview=False, key_type='A', plan=None):
    """Display the immutable plan, then wait for a human terminal response.
    No transport calls here. Cancellation/EOF/interrupt/timeout fail closed.
    Findings never suppress the WRITE choice.
    """
    print(f'Pending write: UID {uid:08X}; block {block}; Sector {block // 4}; authentication Key {key_type}', flush=True)
    print('Data: ' + payload.hex(' ').upper(), flush=True)
    for line in analyse_write(block, payload):
        print(line, flush=True)
    if plan is not None:
        for line in plan:
            print(line, flush=True)
    elif test:
        print(f'Test plan: perform {count} writes, readback, restoration and final readback.', flush=True)
        if restore is not None:
            print('Restore data: ' + restore.hex(' ').upper(), flush=True)
            for line in analyse_write(block, restore):
                print('Restore check: ' + line, flush=True)
        if block == 0 or block % 4 == 3:
            print('[Note] After changing UID/keys/permissions, old credentials may not restore the card.', flush=True)
    else:
        print('Plan: send full WRITE and report card ACK/NAK; no mandatory preread, readback or automatic restoration.', flush=True)
    print('The notes do not block writes or change data. WRITE has not been submitted.', flush=True)
    if preview:
        print('Preview finished: WRITE was not submitted.', flush=True)
        return False
    return confirm_submission(timeout)


def confirm_submission(timeout=60, *, details=None):
    """Shared terminal gate for single-block and whole-card plans."""
    if not sys.stdin.isatty():
        print('Cancelled: requires an interactive terminal; confirm after reviewing the prompt. Piped responses are not accepted.', flush=True)
        return False
    try:
        # Discard pretyped input: only a response entered after the prompt counts.
        fd = sys.stdin.fileno()
        termios.tcflush(fd, termios.TCIFLUSH)
        prompt = f'To continue, within {timeout:g} seconds type WRITE and press Enter'
        prompt += '; D shows full details' if details is not None else ''
        print(prompt+'; any other input cancels:', end=' ', flush=True)
        deadline = time.monotonic() + timeout
        response = bytearray()
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                print('\nConfirmation timed out; WRITE was not submitted.', flush=True)
                return False
            ready, _, _ = select.select([fd], [], [], remaining)
            if not ready:
                print('\nConfirmation timed out; WRITE was not submitted.', flush=True)
                return False
            chunk = os.read(fd, 256)
            if not chunk:
                print('\nEnd of input; WRITE was not submitted.', flush=True)
                return False
            response.extend(chunk)
            if len(response) > 256:
                print('\nCancelled; WRITE was not submitted.', flush=True)
                return False
            if b'\n' in response:
                answer = response.split(b'\n', 1)[0].strip()
                if details is not None and answer.upper() == b'D':
                    for line in details:
                        print(line, flush=True)
                    response.clear()
                    deadline = time.monotonic() + timeout
                    termios.tcflush(fd, termios.TCIFLUSH)
                    print(prompt+'; any other input cancels:', end=' ', flush=True)
                    continue
                if answer != b'WRITE':
                    print('Cancelled; WRITE was not submitted.', flush=True)
                    return False
                break
    except (EOFError, KeyboardInterrupt, OSError, termios.error):
        print('\nCancelled; WRITE was not submitted.', flush=True)
        return False
    print('Confirmed; submitting the data shown above.', flush=True)
    return True
