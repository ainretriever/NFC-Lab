# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 NFClab contributors.
"""Export initial M1 authentication fields from decoded ST traces, without keys."""
import argparse
from itertools import combinations
import json
from pathlib import Path


def _clean(frame, source, length, *, plaintext=False, crc=False):
    return (frame['source'] == source and len(bytes.fromhex(frame['data'])) == length
            and frame['wire_bits'] == length*9 and not frame.get('ambiguous_bits', 0)
            and (not plaintext or frame.get('parity_ok') is True)
            and (not crc or frame.get('crc_ok') is True))


def extract_auth(frames, source='', rejections=None):
    records, cascades = [], []
    def reject(index, reason):
        if rejections is not None:
            rejections.append(dict(source=source, auth_frame=index, reason=reason))
    for i, frame in enumerate(frames):
        data = bytes.fromhex(frame['data'])
        if frame['source'] == 'Rdr' and frame['wire_bits'] == 7 and data in (b'\x26', b'\x52'):
            cascades = []  # Never associate a new session with an old UID.
        if not frame.get('encrypted') and _clean(frame, 'Rdr', 9, plaintext=True, crc=True):
            if data[0] in (0x93, 0x95, 0x97) and data[1] == 0x70:
                if data[0] == 0x93:
                    cascades = []
                expected = (0x93, 0x95, 0x97)[len(cascades)] if len(cascades) < 3 else None
                chunk = data[2:6]
                if data[0] != expected or chunk[0]^chunk[1]^chunk[2]^chunk[3] != data[6]:
                    cascades = []
                else:
                    cascades.append(chunk)
        if frame.get('encrypted') or frame['source'] != 'Rdr' or len(data) != 4 or data[0] not in (0x60, 0x61):
            continue
        if not _clean(frame, 'Rdr', 4, plaintext=True, crc=True):
            reject(i, 'bad-auth-framing-parity-or-crc')
            continue
        if not cascades or cascades[-1][0] == 0x88:
            reject(i, 'missing-complete-select')
            continue
        if any(chunk[0] != 0x88 for chunk in cascades[:-1]):
            reject(i, 'invalid-uid-cascade')
            continue
        uid = b''.join(chunk[1:] for chunk in cascades[:-1])+cascades[-1]
        following = frames[i+1:i+4]
        if len(following) < 2:
            reject(i, 'missing-nt-or-nr-ar')
            continue
        nt, nr_ar = following[:2]
        if not _clean(nt, 'Tag', 4, plaintext=True):
            reject(i, 'bad-or-missing-nt')
            continue
        if not _clean(nr_ar, 'Rdr', 8):
            reject(i, 'bad-or-missing-nr-ar')
            continue
        challenge = nr_ar['data']
        at = following[2] if len(following) > 2 and _clean(following[2], 'Tag', 4) else None
        if at is None:
            reject(i, 'missing-at-mfkey32-only')
        records.append(dict(uid=uid.hex().upper(), cuid=uid[-4:].hex().upper(),
                            block=data[1], sector=data[1]//4 if data[1]<128 else 32+(data[1]-128)//16,
                            key_type='A' if data[0] == 0x60 else 'B',
                            nt=nt['data'], nr_enc=challenge[:8], ar_enc=challenge[8:],
                            at_enc=at['data'] if at else None, source=source, auth_frame=i,
                            start_us=frame.get('start_us'),
                            parity_bits=dict(nt=nt['parity_bits'], nr_ar=nr_ar['parity_bits'],
                                             at=at['parity_bits'] if at else None)))
    return records


def solver_inputs(records):
    jobs = []
    for i, record in enumerate(records):
        if record['at_enc']:
            jobs.append(dict(tool='mfkey64', records=[i],
                             args=[record[f] for f in ('cuid', 'nt', 'nr_enc', 'ar_enc', 'at_enc')]))
    for (i, a), (j, b) in combinations(enumerate(records), 2):
        if any(a[f] != b[f] for f in ('uid', 'cuid', 'sector', 'key_type')):
            continue
        if (a['nt'], a['nr_enc'], a['ar_enc']) == (b['nt'], b['nr_enc'], b['ar_enc']):
            continue  # Repeated capture of the same exchange is not a second sample.
        if a['nt'] == b['nt']:
            if a['nr_enc'] == b['nr_enc']:
                continue
            args = [a['cuid'], a['nt'], a['nr_enc'], a['ar_enc'], b['nr_enc'], b['ar_enc']]
            tool = 'mfkey32'
        else:
            args = [a['cuid'], a['nt'], a['nr_enc'], a['ar_enc'], b['nt'], b['nr_enc'], b['ar_enc']]
            tool = 'mfkey32v2'
        jobs.append(dict(tool=tool, records=[i, j], args=args))
    return jobs


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('captures', type=Path, nargs='+', help='capture prefixes with .frames.json')
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    records = []
    for capture in a.captures:
        envelope = json.loads(capture.with_suffix('.json').read_text())
        meta = envelope.get('metadata', envelope)
        live = envelope.get('live', {})
        if live and (live.get('magic') != 0x53444d41 or any(live.get(k, 0) for k in ('overruns', 'queue_full', 'decoder_dropped'))):
            p.error(f'{capture}: MCU decode lost data')
        if meta['status'] != 2 or meta['cleanup_error'] or meta['dma_flags'] & 0x340:
            p.error(f'{capture}: incomplete capture or DMA error')
        frames = json.loads(capture.with_suffix('.frames.json').read_text())
        records.extend(extract_auth(frames, str(capture)))
    jobs = solver_inputs(records)
    result = dict(version=1, authentication='initial', byte_order='RF byte order, 32-bit hex big-endian',
                  records=records, solver_inputs=jobs)
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(result, indent=2)+'\n')
    print(f'Exported {len(records)} authentications, {len(jobs)} solver inputs to {a.output}')
    for job in jobs:
        print('build/'+job['tool']+' '+' '.join(job['args']))
    if not records:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
