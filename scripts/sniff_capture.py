#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 NFClab contributors.
"""Capture PA0/PA6 simultaneously through the passive sniff mailbox."""
import argparse
import json
import struct
import subprocess
import threading
import time
from pathlib import Path
from transport import CdcTransport, ROOT
from sniff_pm3 import read_block_data

FIELDS = ('magic version request busy enabled operation period count timeout_ms '
          'trigger_mask target sclk_high p2p_rx status clock_hz sample_hz buffer '
          'capacity valid oldest trigger_index elapsed_cycles dma_flags remaining '
          'op_before op_after aux_before aux_after transitions_miso transitions_irq '
          'sequence cleanup_error holdoff_ms first_edge_cycles').split()

PACKED_WORDS = tuple(struct.pack('<4H', *((((value >> (i*2)) & 1) |
                                        (((value >> (i*2+1)) & 1) << 6)) for i in range(4)))
                     for value in range(256))


def unpack_channels(payload, count):
    if len(payload) != (count+3)//4:
        raise ValueError('packed capture length mismatch')
    return b''.join(PACKED_WORDS[value] for value in payload)[:count*2]


def symbol(elf, name):
    table = subprocess.check_output(['arm-none-eabi-nm', '-n', str(elf)], text=True)
    for line in table.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[2] == name:
            return int(parts[0], 16)
    raise RuntimeError(f'{name} missing from {elf}')


def metadata(link, address):
    return dict(zip(FIELDS, struct.unpack('<34I', link.read_bytes(address, 136))))


def capture(link, elf, *, period=16, count=32768, timeout_ms=3000,
            target=1, sclk_high=1, p2p_rx=0x51, trigger_mask=0x40, selftest=False, holdoff_ms=0,
            address=None, on_submit=None, packed=False):
    started = time.monotonic()
    address = address if address is not None else symbol(elf, 'sniff')
    state = metadata(link, address)
    if state['magic'] != 0x534e4946 or state['version'] not in (2, 3):
        raise RuntimeError('sniff firmware/ELF mismatch')
    if state['request'] or state['busy']:
        raise RuntimeError('capture already pending/running')
    if packed is None:
        packed = state['version'] >= 3 and not selftest
    if packed and (state['version'] < 3 or selftest):
        raise ValueError('packed capture requires firmware v3 and receive mode')
    operation = 2 if packed else int(selftest)
    config = (1, operation, period, count, timeout_ms, trigger_mask,
              target, sclk_high, p2p_rx)
    link.write_bytes(address+16, struct.pack('<9I', *config))
    link.write_bytes(address+128, struct.pack('<I', holdoff_ms))
    request_started = time.monotonic()
    link.write_bytes(address+8, struct.pack('<I', 1))
    submitted = time.monotonic()
    if on_submit:
        on_submit()
    deadline = time.monotonic()+timeout_ms/1000+5
    while time.monotonic() < deadline:
        state = metadata(link, address)
        if not state['request'] and not state['busy']:
            break
        time.sleep(0.02)
    else:
        raise RuntimeError('capture completion timeout')
    n = state['valid']
    if n > state['capacity'] or state['capacity'] != 32768:
        raise RuntimeError('invalid capture length')
    observed = time.monotonic()
    payload_bytes = (n+3)//4 if packed else n*2
    raw = link.read_bytes(state['buffer'], payload_bytes) if n else b''
    if packed:
        raw = unpack_channels(raw, n)
    finished = time.monotonic()
    # Chronological ring order. Retain all GPIOA bits, including self-test PA5.
    cut = state['oldest']*2
    raw = raw[cut:]+raw[:cut]
    state['duration_us'] = n*state['period']*1e6/state['clock_hz']
    state['elapsed_us'] = state['elapsed_cycles']*1e6/state['clock_hz']
    state['host_capture_ms'] = (finished-started)*1000
    state['download_ms'] = (finished-observed)*1000
    state['payload_bytes'] = payload_bytes
    state['transfer_format'] = 'irq-miso2' if packed else 'gpioa16'
    state['submitted_monotonic'] = submitted
    state['request_started_monotonic'] = request_started
    state['completion_observed_monotonic'] = observed
    return state, raw


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--elf', type=Path, default=ROOT/'build/sniff.elf')
    p.add_argument('--port')
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--period', type=int, default=16, help='96MHz timer ticks/sample, 16..960')
    p.add_argument('--count', type=int, default=32768)
    p.add_argument('--timeout-ms', type=int, default=3000)
    p.add_argument('--target', type=int, choices=(0, 1), default=1)
    p.add_argument('--sclk-high', type=int, choices=(0, 1), default=1)
    p.add_argument('--p2p-rx', type=lambda s: int(s, 0), default=0x51)
    p.add_argument('--trigger-mask', type=lambda s: int(s, 0), default=0x40)
    p.add_argument('--selftest', action='store_true')
    p.add_argument('--packed', action='store_true', help='8x smaller IRQ/MISO transfer; firmware v3')
    p.add_argument('--holdoff-ms', type=int, default=0,
                   help='ignore first edge, wait this long, then trigger on next edge')
    p.add_argument('--pm3-port', help='run one read-only PM3 selection after arming')
    p.add_argument('--pm3-action', choices=('select', 'read'), default='select')
    p.add_argument('--block', type=int, default=16)
    p.add_argument('--key-type', choices=('A', 'B'), default='A')
    p.add_argument('--keys', type=Path, help='192-byte M1 1K key file for PM3 read')
    a = p.parse_args()
    if not (16 <= a.period <= 960 and 256 <= a.count <= 32768 and
            1 <= a.timeout_ms <= 10000 and 0 <= a.p2p_rx <= 255 and
            a.trigger_mask in (1, 0x40, 0x41) and 0 <= a.holdoff_ms <= 1000):
        p.error('invalid capture configuration')
    a.output.parent.mkdir(parents=True, exist_ok=True)
    pm3_command = 'hf 14a reader --skip; trace list -t 14a'
    key_hex = None
    if a.pm3_action == 'read':
        if not a.pm3_port or not a.keys or not 0 <= a.block < 64 or a.block % 4 == 3:
            p.error('read requires --pm3-port, --keys and a 1K data block')
        keys = a.keys.read_bytes()
        if len(keys) != 192:
            p.error('keys must contain 16 Key A followed by 16 Key B (192 bytes)')
        offset = (int(a.key_type == 'B')*16+a.block//4)*6
        key_hex = keys[offset:offset+6].hex()
        pm3_command = f'hf mf rdbl --blk {a.block} -{a.key_type.lower()} -k {key_hex}; trace list -t 14a'
    pm3_result = {}
    def run_pm3():
        try:
            time.sleep(0.5)
            result = subprocess.run(['proxmark3', '-p', a.pm3_port, '--incognito',
                                     '-c', pm3_command],
                                    text=True, capture_output=True, timeout=15)
            output = result.stdout+result.stderr
            if key_hex:
                output = output.replace(key_hex, '[known-key]').replace(key_hex.upper(), '[known-key]')
            pm3_result.update(returncode=result.returncode, output=output,
                              action=a.pm3_action, block=a.block if key_hex else None)
            if key_hex:
                pm3_result['data'] = read_block_data(output, a.block)
                pm3_result['read_ok'] = pm3_result['data'] is not None
        except Exception as error:
            pm3_result.update(error=str(error))
    worker = None
    link = CdcTransport(a.port)
    try:
        if a.pm3_port and not a.selftest:
            worker = threading.Thread(target=run_pm3)
            worker.start()
        state, raw = capture(link, a.elf, period=a.period, count=a.count,
                             timeout_ms=a.timeout_ms, target=a.target,
                             sclk_high=a.sclk_high, p2p_rx=a.p2p_rx,
                             trigger_mask=a.trigger_mask, selftest=a.selftest,
                             holdoff_ms=a.holdoff_ms, packed=a.packed)
    finally:
        link.close()
        if worker:
            worker.join()
    if pm3_result:
        state['pm3'] = pm3_result
        a.output.with_suffix('.pm3.txt').write_text(pm3_result.get('output', str(pm3_result)))
    a.output.with_suffix('.bin').write_bytes(raw)
    a.output.with_suffix('.json').write_text(json.dumps(state, indent=2)+'\n')
    print(json.dumps(state, indent=2))
    if state['status'] != 2 or (key_hex and not pm3_result.get('read_ok')):
        raise SystemExit(1)


if __name__ == '__main__':
    main()
