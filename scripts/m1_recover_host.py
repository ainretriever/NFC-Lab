# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 NFClab contributors.
"""Bounded, read-only nested capture mailbox."""
import time
from swd import snapshot, snapshot_running, symbol, write_words_many
from transport import active


RECORDS_WORD = 21          # header words before records[]
WORDS = RECORDS_WORD + 50 * 6
VERSION = 2


def capture(uid, source, key, target=None, count=16, depth=0, source_type=None, target_type=None, fast=False):
    """Collect nested nonces.

    `depth` is the number of nested source authentications performed before the
    target is probed.  Probing the same target at two depths gives two
    independent keystreams for the same key, which is what makes candidate-set
    intersection possible.  Records report the source nonce taken immediately
    before the probe, so the prediction distance is the same at every depth.

    `source_type` / `target_type` override the key type taken from the source and
    target index.  Types 0/1 are Key A/B; types 4/5 select the FM11RF08S backdoor
    opcodes 0x64/0x65, which is how the SEN evidence is collected (arm the
    session with a backdoor key, probe with the regular command).
    """
    # Fast mode is the firmware's profile 7: raw target evidence, an incomplete
    # response to abort target AUTH, then bounded recovery before re-selection.
    # The mailbox prefix is unchanged; only this mode permits up to 150 rows.
    profile=target is None
    if fast and (profile or depth or source_type not in (None,0,1) or target_type not in (None,0,1)):
        raise ValueError('fast capture requires a regular unknown-target slot at depth zero')
    if target is None:
        target=source
    if len(key)!=6 or not 0<=source<32 or not 0<=target<32 or not 1<=count<=(150 if fast else 50):
        raise ValueError('invalid capture arguments')
    if not 0 <= depth <= 3:
        raise ValueError('depth must be 0..3')
    if source_type is None: source_type=source%2
    if target_type is None: target_type=target%2
    if source_type not in (0,1,4,5) or target_type not in (0,1,4,5):
        raise ValueError('key types must be 0, 1, 4 or 5')
    address=symbol('m1_recover')
    initial=snapshot_running(address,20)
    if initial[:2]!=[0x4d314e43,VERSION]:
        raise RuntimeError('nonce firmware mismatch')
    for name in ('m1','m1_keys','m1_bulk','bench','m1_recover'):
        state=snapshot_running(symbol(name),4)
        if state[2] or state[3]:
            raise RuntimeError(f'{name} busy')
    config=[count,uid,source//2*4,source_type,*key,target//2*4,target_type,7 if fast else int(profile)]
    write_words_many([(address+16,config),(address+80,[depth]),(address+8,[1])])
    deadline=time.monotonic()+count*(.15+.12*depth)+10
    while time.monotonic()<deadline:
        header=snapshot_running(address,20)
        if not header[2] and not header[3]:
            break
        time.sleep(.005 if active().name == "cdc" else .1)
    else:
        raise RuntimeError('capture timeout; MCU may still be busy')
    words=snapshot(address,RECORDS_WORD+count*6)
    stats=snapshot(symbol('m1'),128)
    if stats[112] or stats[113]:
        raise RuntimeError('unexpected writes during capture')
    if fast and words[18]==1:
        raise RuntimeError('fast capture unsupported/rejected; update firmware or use --legacy-capture')
    if words[18] or words[17]!=count:
        raise RuntimeError(f'capture incomplete: {words[17]}/{count}, error {words[18]}')
    return {'uid':f'{uid:08x}','source':source,'target':target,'profile':profile,
            'count':count,'depth':depth,'fast':fast,'writes':stats[112],'write_data_frames':stats[113],
            'records':[dict(zip(('nt','encrypted','parity','plain','cycles','error'),
                               words[RECORDS_WORD+i*6:RECORDS_WORD+i*6+6])) for i in range(count)]}


def identify():
    address=symbol('m1_recover')
    for name in ('m1','m1_keys','m1_bulk','bench','m1_recover'):
        state=snapshot_running(symbol(name),4)
        if state[2] or state[3]:
            raise RuntimeError(f'{name} busy')
    initial=snapshot_running(address,20)
    if initial[:2]!=[0x4d314e43,VERSION]:
        raise RuntimeError('nonce firmware mismatch')
    write_words_many([(address+16,[0]),(address+64,[2]),(address+8,[1])])
    deadline=time.monotonic()+5
    while time.monotonic()<deadline:
        header=snapshot_running(address,20)
        if not header[2] and not header[3]:
            break
        time.sleep(.005 if active().name == "cdc" else .1)
    else:
        raise RuntimeError('identify timeout; MCU may still be busy')
    if header[18]:
        raise RuntimeError(f'card identification error {header[18]}')
    card=snapshot(symbol('card'),31)
    if card[9] not in (4,7,10) or card[20]!=8:
        raise RuntimeError('first Read supports Classic 1K only')
    uid=bytes(card[10:10+card[9]])
    if int.from_bytes(uid[-4:],'big')!=header[5]:
        raise RuntimeError('UID changed during identification')
    return {'uid':uid.hex(),'cuid':header[5], 'sak':card[20],'atqa':bytes(card[7:9]).hex()}


def probe_auth_read(uid, key, key_type=4, block=0, count=1):
    """Diagnostic AUTH 60/61/64/65 on one block, then READ `count` blocks.

    Requires the firmware's explicit profile=3 diagnostic mode and never issues
    a WRITE.  Key types 4/5 map to opcodes 0x64/0x65, which are the FM11RF08S
    backdoor key types, so this is also how a backdoor key is tested.  `count`
    blocks must stay inside one sector: authenticating once and reading the
    sector's four blocks is how a backdoored card is dumped without any key
    (Momentum's BackdoorReadSector).  A negative result alone does not identify
    the chip or prove a backdoor is absent.
    """
    if len(key) != 6 or key_type not in (0, 1, 4, 5) or not 0 <= uid <= 0xffffffff:
        raise ValueError('invalid diagnostic authentication arguments')
    if not 1 <= count <= 4:
        raise ValueError('diagnostic count must be 1..4 blocks')
    if not 0 <= block < 64 or block // 4 != (block + count - 1) // 4:
        raise ValueError('diagnostic blocks must lie inside one sector (0..63)')
    address = symbol('m1_recover')
    initial = snapshot_running(address, 20)
    if initial[:2] != [0x4d314e43, VERSION]:
        raise RuntimeError('nonce firmware mismatch')
    for name in ('m1', 'm1_keys', 'm1_bulk', 'bench', 'm1_recover'):
        if any(snapshot_running(symbol(name), 4)[2:4]):
            raise RuntimeError(f'{name} busy')
    config = [count, uid, block, key_type, *key, 0, 0, 3]
    write_words_many([(address + 16, config), (address + 8, [1])])
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        header = snapshot_running(address, 20)
        if not header[2] and not header[3]:
            break
        time.sleep(.01)
    else:
        raise RuntimeError('diagnostic timeout; MCU may still be busy')
    if header[18] == 1:
        raise RuntimeError('firmware lacks profile=3 diagnostic mode or rejected arguments')
    # records[] begins at RECORDS_WORD; word 0 of each record is the AUTH nonce
    # and words 1..4 are the 16 bytes read back from that block.
    words = snapshot(address + RECORDS_WORD * 4, count * 6)
    stats = snapshot(symbol('m1'), 128)
    if stats[112] or stats[113]:
        raise RuntimeError('unexpected writes during diagnostic')
    matched = header[17] == count and header[18] == 0
    blocks = [b''.join(x.to_bytes(4, 'big') for x in words[i*6+1:i*6+5]).hex()
              for i in range(count)] if matched else [None] * count
    return {'opcode': f'{0x60 + key_type:02x}', 'block': block, 'count': count,
            'matched': matched, 'error': header[18], 'stage': stats[35],
            'rf_error': stats[37], 'nonce': f'{words[0]:08x}' if matched else None,
            'data': blocks[0], 'blocks': blocks,
            'writes': stats[112], 'write_data_frames': stats[113]}


def probe_auth_read0(uid, key, key_type=4):
    """Block-0 wrapper kept for existing callers and docs."""
    result = probe_auth_read(uid, key, key_type=key_type, block=0)
    result['block0'] = result['data']
    return result
