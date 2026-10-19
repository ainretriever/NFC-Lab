# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 NFClab contributors.
"""Fixed bounded mailbox profiles for Magic and key-free initial nonce probes."""
import time
from m1_recover_host import RECORDS_WORD, VERSION
from swd import symbol, snapshot, snapshot_running, write_words_many
from transport import active


def request_info(uid, mode, count=1, key=None, key_type=0):
    if mode not in (4, 5, 6) or not 0 <= uid <= 0xffffffff or key_type not in (0, 1):
        raise ValueError('invalid info probe')
    if not 1 <= count <= 16 or (mode != 6 and count != 1):
        raise ValueError('invalid info count')
    if mode == 5 and (key is None or len(key) != 6):
        raise ValueError('Gen2 write-command probe requires a six-byte key')
    if key is not None and len(key) != 6:
        raise ValueError('invalid key')
    address = symbol('m1_recover')
    if snapshot_running(address, 2) != [0x4d314e43, VERSION]:
        raise RuntimeError('nonce firmware mismatch')
    for name in ('m1','m1_keys','m1_bulk','bench','m1_recover'):
        state = snapshot_running(symbol(name), 4)
        if state[2] or state[3]:
            raise RuntimeError(f'{name} busy')
    config = [count,uid,0,key_type,*(key or bytes(6)),0,0,mode]
    write_words_many([(address+16,config),(address+80,[0]),(address+8,[1])])
    deadline = time.monotonic()+10
    while time.monotonic()<deadline:
        header = snapshot_running(address, 20)
        if not header[2] and not header[3]:
            break
        time.sleep(.005 if active().name=='cdc' else .1)
    else:
        raise RuntimeError('info probe timeout; MCU may still be running')
    words = snapshot(address, RECORDS_WORD+count*6)
    stats = snapshot(symbol('m1'), 128)
    if stats[113] or (mode != 5 and stats[112]) or (mode == 5 and stats[112]>1):
        raise RuntimeError('unexpected card write in info probe')
    return dict(mode=mode,completed=words[17],error=words[18],
                values=[words[RECORDS_WORD+i*6] for i in range(count)],
                write_commands=stats[112],write_data_frames=stats[113],
                field_off=None if words[18]==1 else words[18]!=11)
