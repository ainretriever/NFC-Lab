# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 NFClab contributors.
"""Mailbox access helpers on top of the active transport.

`symbol()` resolves ELF symbols.  The read/write helpers address MCU SRAM over
whichever link `transport.active()` selected: the USB CDC channel when it is
present, otherwise ST-Link/SWD through OpenOCD.
"""
import struct
import subprocess
from functools import lru_cache

from transport import (CLOCKS, ROOT, TransportError, active, reset)  # noqa: F401

__all__ = ['ROOT', 'CLOCKS', 'TransportError', 'reset', 'symbol', 'read_bytes',
           'write_bytes', 'read_words', 'write_words', 'write_words_many',
           'snapshot', 'snapshot_running']


@lru_cache(maxsize=1)
def _symbol_table():
    nm = subprocess.check_output(['arm-none-eabi-nm', '-n', 'build/identity.elf'],
                                 cwd=ROOT, text=True)
    table = {}
    for line in nm.splitlines():
        parts = line.split()
        if len(parts) == 3:
            table.setdefault(parts[2], int(parts[0], 16))
    return table


def symbol(name):
    table = _symbol_table()
    if name not in table:
        raise RuntimeError(f'Missing ELF symbol {name!r}; build firmware first')
    return table[name]


def read_bytes(address, length, *, halt=True):
    return active().read_bytes(address, length, halt=halt)


def write_bytes(address, data, *, halt=True):
    return active().write_bytes(address, data, halt=halt)


def read_words(address, count, *, halt=True):
    return list(struct.unpack(f'<{count}I', read_bytes(address, count * 4, halt=halt)))


def write_words(address, values, *, halt=True):
    write_bytes(address, struct.pack(f'<{len(values)}I', *values), halt=halt)


def write_words_many(segments, *, halt=True):
    """Write several (address, values) ranges, batched per transport.

    `values` may be a list of 32-bit words or a bytes-like object.
    """
    packed = []
    for address, values in segments:
        if isinstance(values, (bytes, bytearray)):
            packed.append((address, bytes(values)))
        else:
            packed.append((address, struct.pack(f'<{len(values)}I', *values)))
    active().write_segments(packed, halt=halt)


def snapshot(address, count):
    """Halt, read, resume: use after a batch has finished."""
    return read_words(address, count, halt=True)


def snapshot_running(address, count):
    """Read without halting the core: use while RF work may be in flight."""
    return read_words(address, count, halt=False)
