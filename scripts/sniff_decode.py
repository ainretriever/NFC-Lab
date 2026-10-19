# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 NFClab contributors.
"""Experimental NFC-A 106k decoder for asynchronous PA6/PA0 captures.

Reader: modified Miller OOK on MISO. Tag: Manchester activity on IRQ.
This decoder requires clear subcarrier bursts, and reports
parity/CRC rather than silently accepting damaged frames. Encrypted traffic
is preserved as raw samples; Crypto1 decryption is outside this first version.
"""
import argparse
from array import array
import json
from pathlib import Path
import sys


def crc_a(data):
    crc = 0x6363
    for value in data:
        value ^= crc & 255
        value ^= (value << 4) & 255
        crc = ((crc >> 8) ^ (value << 8) ^ (value << 3) ^ (value >> 4)) & 65535
    return crc.to_bytes(2, 'little')


def edge_groups(samples, mask, gap):
    edges = [i for i in range(1, len(samples)) if (samples[i]^samples[i-1]) & mask]
    groups, group = [], []
    for i in edges:
        if group and i-group[-1] > gap:
            groups.append(group)
            group = []
        group.append(i)
    if group:
        groups.append(group)
    return groups


def bytes_with_parity(bits):
    data = bytes(sum(bits[i+j] << j for j in range(8))
                 for i in range(0, len(bits)-8, 9))
    parity = all(sum(bits[i:i+9]) % 2 == 1 for i in range(0, len(bits)-8, 9))
    return data, parity


def reader_frame(samples, group, period):
    falls = [i for i in group if not samples[i] & 64]
    if len(falls) < 2:
        return None
    widths = [group[k+1]-i for k, i in enumerate(group[:-1]) if not samples[i] & 64]
    # Reader OOK pauses are about a quarter bit. MISO can also carry very
    # short subcarrier glitches; their timing alone can mimic Miller symbols.
    if len(widths) != len(falls) or any(not period*0.15 <= width <= period*0.4 for width in widths):
        return None
    origin = falls[0]
    positions = [(i-origin)/period for i in falls]
    if any(abs(x*2-round(x*2)) > 0.25 for x in positions):
        return None
    pulses = {round(x*2) for x in positions[1:]}
    last = max(positions)
    candidates = [7] + [n for n in range(9, 8193, 9) if abs(n-last) <= 2]
    for n in candidates:
        used, bits, previous = set(), [], 0
        valid = True
        for i in range(n):
            early, middle = 2*(i+1), 2*(i+1)+1
            if middle in pulses and early not in pulses:
                bit = 1
                used.add(middle)
            elif early in pulses and middle not in pulses and previous == 0:
                bit = 0
                used.add(early)
            elif early not in pulses and middle not in pulses and previous == 1:
                bit = 0
            else:
                valid = False
                break
            bits.append(bit)
            previous = bit
        if not valid:
            continue
        if not previous:
            used.add(2*(n+1))  # EOF is an additional zero symbol.
        if pulses != used:
            continue
        if n == 7:
            data = bytes([sum(bit << i for i, bit in enumerate(bits))])
            parity = None
        else:
            data, parity = bytes_with_parity(bits)
        return dict(source='Rdr', start_sample=origin, end_sample=group[-1],
                    wire_bits=n, data=data.hex().upper(), parity_ok=parity,
                    parity_bits=bits[8::9] if n != 7 else [])
    return None


def tag_frame(samples, group, period):
    # A tag burst contains fast subcarrier transitions; reader OOK does not.
    if len(group) < 8 or sum(b-a < period/4 for a, b in zip(group, group[1:])) < 4:
        return None
    origin = group[0]
    # Comparator polarity can change with receiver state. SOF's second half
    # is unmodulated; infer its idle level instead of assuming active-high.
    quiet = samples[round(origin+period*0.65):round(origin+period*0.9)]
    if not quiet:
        return None
    idle = sum(bool(value & 1) for value in quiet) > len(quiet)/2
    n = round((group[-1]-origin)/period/9)*9
    if n < 9:
        return None
    bits, ambiguous = [], 0
    for i in range(n):
        activity = []
        for half in (0, 1):
            lo = round(origin+(i+1+half/2)*period+period*0.04)
            hi = round(origin+(i+1+(half+1)/2)*period-period*0.04)
            if hi > len(samples) or hi <= lo:
                return None
            activity.append(sum(bool(value & 1) != idle for value in samples[lo:hi])/(hi-lo))
        ambiguous += abs(activity[0]-activity[1]) < 0.15
        bits.append(int(activity[0] > activity[1]))
    data, parity = bytes_with_parity(bits)
    return dict(source='Tag', start_sample=origin, end_sample=group[-1],
                wire_bits=n, data=data.hex().upper(), parity_ok=parity,
                ambiguous_bits=ambiguous, parity_bits=bits[8::9])


def decode(samples, sample_hz, trigger_index=0):
    period = sample_hz*128/13560000
    if period < 28:
        raise ValueError('decoder requires at least 3 MS/s')
    frames = []
    for group in edge_groups(samples, 64, sample_hz*30e-6):
        frame = reader_frame(samples, group, period)
        if frame:
            frames.append(frame)
    reader_frames = frames[:]
    for group in edge_groups(samples, 1, sample_hz*30e-6):
        # IRQ also contains reader OOK; one-sample glitches must not turn a
        # successfully decoded reader burst into a duplicate tag response.
        if any(f['start_sample']-period/2 <= group[0] <= f['end_sample']+period/2
               for f in reader_frames):
            continue
        frame = tag_frame(samples, group, period)
        if frame:
            frames.append(frame)
    return annotate_frames(frames, sample_hz, trigger_index)


def annotate_frames(frames, sample_hz, trigger_index=0):
    """Apply plaintext/auth state to already demodulated wire frames."""
    frames.sort(key=lambda f: f['start_sample'])
    previous = None
    auth_phase = None
    encrypted = False
    for frame in frames:
        data = bytes.fromhex(frame['data'])
        if frame['source'] == 'Rdr' and frame['wire_bits'] == 7 and data in (b'\x26', b'\x52'):
            previous, auth_phase, encrypted = None, None, False
        frame['start_us'] = (frame['start_sample']-trigger_index)*1e6/sample_hz
        frame['crc_ok'] = None
        frame['encrypted'] = encrypted
        frame['wire_odd_parity_ok'] = frame['parity_ok']
        if auth_phase == 'nt' and frame['source'] == 'Tag' and len(data) == 4:
            frame['phase'] = 'nt'
            auth_phase = 'nr-ar'
            continue  # Nt has parity but no CRC.
        if auth_phase == 'nr-ar' and frame['source'] == 'Rdr' and len(data) == 8:
            encrypted = True
            frame['encrypted'] = True
            frame['phase'] = 'nr-ar'
            auth_phase = 'at'
        elif auth_phase == 'at' and frame['source'] == 'Tag' and len(data) == 4:
            frame['phase'] = 'at'
            auth_phase = 'data'
        elif encrypted:
            frame['phase'] = 'encrypted-command' if frame['source'] == 'Rdr' else 'encrypted-response'
        if encrypted:
            frame['parity_ok'] = None
            continue  # Keep ciphertext parity bits; no plaintext CRC judgement.
        if frame['source'] == 'Rdr':
            if len(data) >= 3:
                frame['crc_ok'] = crc_a(data[:-2]) == data[-2:]
            if len(data) == 4 and data[0] in (0x60, 0x61) and frame['crc_ok']:
                frame['phase'] = 'auth-a' if data[0] == 0x60 else 'auth-b'
                frame['block'] = data[1]
                auth_phase = 'nt'
            previous = data
        elif previous and len(previous) == 2 and previous[1] == 0x20 and len(data) == 5:
            frame['bcc_ok'] = data[0]^data[1]^data[2]^data[3] == data[4]
        elif len(data) >= 3:
            frame['crc_ok'] = crc_a(data[:-2]) == data[-2:]
    return frames


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('capture', type=Path, help='capture prefix, .bin, or .json')
    a = p.parse_args()
    meta = json.loads(a.capture.with_suffix('.json').read_text())
    samples = array('H')
    samples.frombytes(a.capture.with_suffix('.bin').read_bytes())
    if sys.byteorder != 'little':
        samples.byteswap()
    frames = decode(samples, meta['sample_hz'], meta['trigger_index'])
    a.capture.with_suffix('.frames.json').write_text(json.dumps(frames, indent=2)+'\n')
    print(json.dumps(frames, indent=2))


if __name__ == '__main__':
    main()
