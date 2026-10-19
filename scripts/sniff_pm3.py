# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 NFClab contributors.
"""Independent PM3 trace checks, including ciphertext wire parity."""
import re


def read_block_data(text, block):
    row = re.search(rf'(?m)^\[=\]\s+{block}\s+\|\s+((?:[0-9A-Fa-f]{{2}}\s+){{15}}[0-9A-Fa-f]{{2}})\s*\|', text)
    return ''.join(row[1].split()).upper() if row else None


def parse_trace(text):
    frames = []
    for match in re.finditer(r'(?m)^\s*(\d+)\s*\|\s*(\d+)\s*\|\s*(Rdr|Tag)\s*\|([^|]+)\|', text):
        field = match[4]
        tokens = re.findall(r'\b([0-9A-Fa-f]{2})(!)?', field)
        data = bytes(int(value, 16) for value, _ in tokens)
        short = '(7)' in field
        parity = [] if short else [(value.bit_count() % 2 ^ 1) ^ bool(bad)
                                   for value, (_, bad) in zip(data, tokens)]
        if ']' in field and parity:
            # PM3's CRC highlighting truncates the last byte's ! marker.
            # Use unhighlighted `trace list -t 14a` for complete parity checks.
            parity[-1] = None
        frames.append(dict(source=match[3], data=data.hex().upper(),
                           wire_bits=7 if short else len(data)*9, parity_bits=parity))
    return frames


def compare_with_pm3(frames, text):
    reference = parse_trace(text)
    return compare_frame_lists(frames, reference)


def compare_frame_lists(frames, reference):
    if not frames or len(frames) > len(reference):
        raise ValueError('incomplete or extra captured frames')
    for i, (frame, ref) in enumerate(zip(frames, reference)):
        for field in ('source', 'data', 'wire_bits'):
            if frame[field] != ref[field]:
                raise ValueError(f'frame {i}: {field} differs from PM3')
        if any(value is None for value in ref['parity_bits']):
            raise ValueError('PM3 highlighted CRC obscures parity; use trace list -t 14a')
        if frame['parity_bits'] != ref['parity_bits']:
            raise ValueError(f'frame {i}: wire parity differs from PM3')
        if frame.get('ambiguous_bits', 0):
            raise ValueError(f'frame {i}: ambiguous Manchester symbols')
    return dict(passed=True, captured_frames=len(frames), pm3_trace_frames=len(reference),
                ciphertext_and_wire_parity_match=True)


def verify_auth_read(frames, text, block, expected_data):
    if len(frames) < 12:
        raise ValueError('incomplete captured frames')
    comparison = compare_with_pm3(frames, text)
    auth = next((i for i, f in enumerate(frames) if f.get('phase') in ('auth-a', 'auth-b')), None)
    if auth is None or frames[auth].get('block') != block:
        raise ValueError('expected AUTH missing')
    phases = [f.get('phase') for f in frames[auth:auth+6]]
    if phases[1:] != ['nt', 'nr-ar', 'at', 'encrypted-command', 'encrypted-response']:
        raise ValueError('authentication/read sequence incomplete')
    if len(bytes.fromhex(frames[auth+5]['data'])) != 18:
        raise ValueError('expected encrypted 16-byte read response plus CRC')
    plaintext = read_block_data(text, block)
    if plaintext != expected_data.upper():
        raise ValueError('PM3 plaintext differs from saved reference block')
    return dict(**comparison,
                block=block, pm3_read_data=plaintext, reference_data_match=True,
                st_ciphertext_decrypted=False)


def compare_auth_with_pm3(frames, text):
    auth = next((i for i, f in enumerate(frames) if f.get('phase') in ('auth-a', 'auth-b')), None)
    if auth is None:
        raise ValueError('no initial AUTH to compare')
    end = auth+3  # AUTH, Nt, Nr/Ar; sufficient for mfkey32.
    if len(frames) > end and frames[end].get('phase') == 'at':
        end += 1
    if len(frames) < end:
        raise ValueError('incomplete authentication')
    reference = parse_trace(text)
    ref_auth = next((i for i, f in enumerate(reference)
                     if f['source'] == 'Rdr' and f['data'] == frames[auth]['data']), None)
    if ref_auth is None:
        raise ValueError('AUTH differs from PM3')
    def last_poll(stream, before):
        return next((i for i in range(before, -1, -1) if stream[i]['source'] == 'Rdr'
                     and stream[i]['wire_bits'] == 7 and stream[i]['data'] in ('26', '52')), 0)
    start = last_poll(frames, auth)
    ref_start = last_poll(reference, ref_auth)
    # PM3 clears unsuccessful SELECT retries from its trace. ST still sees
    # those physical polls: compare the successful selection + AUTH segment.
    result = compare_frame_lists(frames[start:end], reference[ref_start:ref_auth+(end-auth)])
    result['scope'] = 'authentication-only'
    result['total_captured_frames'] = len(frames)
    result['ignored_leading_capture_frames'] = start
    return result


def main():
    import argparse
    import json
    from pathlib import Path
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('capture', type=Path)
    p.add_argument('--block', type=int, default=16)
    p.add_argument('--dump', type=Path, required=True)
    a = p.parse_args()
    dump = a.dump.read_bytes()
    if len(dump) != 1024 or not 0 <= a.block < 64 or a.block % 4 == 3:
        p.error('requires a 1K dump and a data block')
    meta = json.loads(a.capture.with_suffix('.json').read_text())
    if meta['status'] != 2 or meta['cleanup_error'] or meta['dma_flags'] & 0x340:
        p.error('capture or DMA did not complete cleanly')
    frames = json.loads(a.capture.with_suffix('.frames.json').read_text())
    text = a.capture.with_suffix('.pm3.txt').read_text()
    result = verify_auth_read(frames, text, a.block,
                              dump[a.block*16:(a.block+1)*16].hex())
    a.capture.with_suffix('.verified.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
