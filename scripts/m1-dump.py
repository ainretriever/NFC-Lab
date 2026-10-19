#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 NFClab contributors.
"""Read a sector or complete Classic 1K in one MCU request; never sends WRITE."""
import argparse
import json
import time
from pathlib import Path
from m1_host import CLOCKS, ERRORS
from swd import ROOT, snapshot, snapshot_running, symbol, write_words_many
from transport import active

WORDS = 1320

def read_batch(keys, uid, first=0, sectors=16, key_type=2, count=1, mode=0, spi_div=0, allow_partial=False):
    if len(keys) != 192 or not 0 <= first < 16 or not 1 <= sectors <= 16-first:
        raise ValueError('expected 192-byte keys and valid sector range')
    if key_type not in (0, 1, 2) or not 1 <= count <= 100:
        raise ValueError('invalid key type or count')
    if mode not in (0, 1) or not 0 <= spi_div <= 4:
        raise ValueError('invalid mode or SPI prescaler')
    address = symbol('m1_bulk')
    header = snapshot_running(address, 16)
    if header[:2] != [0x4d314255, 2] or header[2] or header[3]:
        raise RuntimeError('bulk firmware mismatch or request busy')
    for name, size in [('m1', 128), ('bench', 13), ('m1_keys', 32), ('m1_recover', 4)]:
        status = snapshot_running(symbol(name), size)
        if status[2] or status[3]:
            raise RuntimeError(f'{name} request busy')
    config = [first, sectors, count, key_type, uid]
    # m1_bulk.keys is uint32_t[192]: one key byte per word, not a packed blob.
    write_words_many([(address + 16, config),
                      (address + 64, list(keys)),
                      (address + 1312*4, [mode, spi_div]),
                      (address + 8, [1])])
    # Status polls must not halt the MCU during encrypted RF exchanges.
    deadline = time.monotonic() + count * sectors * 0.6 + 5
    # CDC status reads do not halt the MCU and are cheap enough for short polls.
    # Keep the existing coarse schedule for OpenOCD/SWD.
    cdc = active().name == "cdc"
    time.sleep(0.005 if cdc else min(count * (0.025 + sectors * 0.01) + 0.05, 50))
    while time.monotonic() < deadline:
        header = snapshot_running(address, 16)
        if not header[2] and not header[3]:
            words = snapshot(address, WORDS)
            raw = bytes(words[208:1232])
            valid = words[12] | words[13] << 32
            required = ((1 << (sectors*4))-1) << (first*4)
            if not allow_partial and (words[9] != count or words[10] or valid & required != required):
                code = words[10]
                raise RuntimeError(f'incomplete read: block {words[11]}, '
                                   f'{ERRORS[code] if code < len(ERRORS) else code}; '
                                   f'valid bitmap {valid:016x}; no dump exported')
            stats = snapshot(symbol('m1'), 128)
            if stats[112] or stats[113]:
                raise RuntimeError('Unexpected WRITE counters in read-only batch')
            hz = stats[52]
            if hz not in CLOCKS:
                raise RuntimeError('Unexpected MCU clock')
            ticks_ms = hz/1000
            spi_hz = snapshot(symbol('diag'), 26)[11]
            report = {'first_sector': first, 'sectors': sectors, 'count': count,
                      'error': words[10], 'block_errors': words[1232:1296],
                      'key_type': ['A','B','auto'][key_type], 'valid_bitmap': f'{valid:016x}',
                      'mcu_mean_ms': (words[14] | words[15]<<32)/ticks_ms/count,
                      'sector_ms_last': [x/ticks_ms for x in words[1296:1312]],
                      'mode': ['nested', 'reselect'][mode], 'spi_hz': spi_hz, 'clock_hz': hz,
                      'selects': words[1314], 'nested_auths': words[1315],
                      'recoveries': words[1316], 'mcu_min_ms': words[1317]/ticks_ms,
                      'mcu_max_ms': words[1318]/ticks_ms,
                      'auth_mean_ms': stats[47]/ticks_ms/stats[33] if stats[33] else None,
                      'read_mean_ms': stats[51]/ticks_ms/stats[34] if stats[34] else None,
                      'auth_ok': stats[33], 'read_ok': stats[34],
                      'auth_errors': stats[41], 'crc_errors': stats[42],
                      'parity_errors': stats[40], 'timeouts': stats[38],
                      'writes': stats[112], 'write_data_frames': stats[113]}
            return raw, report
        time.sleep(0.005 if cdc else 1)
    raise RuntimeError('bulk request timeout; MCU may still be running')

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--keys', type=Path, required=True)
    parser.add_argument('--uid', required=True, help='last four UID bytes, hex')
    parser.add_argument('--sector', type=int, help='read only sector 0..15; otherwise full 1K')
    parser.add_argument('--key-type', choices=['A','B','auto'], default='auto')
    parser.add_argument('--mode', choices=['nested', 'reselect'], default='nested')
    parser.add_argument('--spi-div', type=int, default=0, help='SPI ceiling 0..4: 8/4/2/1/0.5 MHz (actual rate depends on MCU clock)')
    parser.add_argument('--count', type=int, default=1, help='repeat on MCU (1..100)')
    parser.add_argument('--output', type=Path, required=True, help='new output directory')
    parser.add_argument('--reference', type=Path, help='optional 1024-byte reference for verification')
    args = parser.parse_args()
    keys = args.keys.read_bytes()
    if len(args.uid) != 8:
        parser.error('--uid requires eight hex digits')
    uid = int(args.uid, 16)
    if args.output.exists():
        parser.error('output directory already exists; choose a new directory')
    reference = args.reference.read_bytes() if args.reference else None
    if reference is not None and len(reference) != 1024:
        parser.error('reference must contain 1024 bytes')
    first, sectors = (0,16) if args.sector is None else (args.sector,1)
    raw, report = read_batch(keys, uid, first, sectors, ['A','B','auto'].index(args.key_type), args.count, ['nested','reselect'].index(args.mode), args.spi_div)
    completed = bytearray(raw)
    for sector in range(first, first+sectors):
        offset = (sector*4+3)*16
        completed[offset:offset+6] = keys[sector*6:sector*6+6]
        completed[offset+10:offset+16] = keys[(sector+16)*6:(sector+17)*6]
    start, end = first*64, (first+sectors)*64
    report['key_provenance'] = 'Both trailer keys supplied by key file, not recovered from RF'
    if reference is not None:
        # Compare raw data/ACL/GPB and keys supplied separately, never masked RF keys.
        mismatches = [block for block in range(first*4,(first+sectors)*4)
                      if completed[block*16:(block+1)*16] != reference[block*16:(block+1)*16]]
        report['reference_mismatches'] = mismatches
        if mismatches:
            raise RuntimeError(f'reference differs at blocks {mismatches}; no dump exported')
    args.output.mkdir(parents=True)
    (args.output/'raw.bin').write_bytes(raw[start:end])
    (args.output/'dump.bin').write_bytes(completed[start:end])
    (args.output/'report.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))

if __name__ == '__main__':
    main()
