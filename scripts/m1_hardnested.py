# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 NFClab contributors.
"""Independent hardnested evidence collection, bypassing dictionary and key reuse."""
import json
import os
from pathlib import Path
import time

from m1_keys_host import run_keys
from m1_recover_host import capture, identify
from m1_recovery import probe
from solvers.hardnested import inspect_nonces, pack_nonces, validate_record


def save_json(path, value):
    path = Path(path)
    temporary = path.with_suffix(path.suffix + '.tmp')
    with temporary.open('w') as stream:
        os.chmod(temporary, 0o600)
        json.dump(value, stream, indent=2)
        stream.write('\n')
    temporary.replace(path)


def authenticate(uid, block, key_type, key):
    report = run_keys([key], uid, block=block, key_type=key_type)
    if not report['complete'] or report['status'] != ['matched']:
        raise RuntimeError(f'full authentication failed at block {block} {"AB"[key_type]}')
    return report


def collect(output, *, source_block=0, source_type=0, source_key=bytes.fromhex('ffffffffffff'),
            target_block=4, target_type=0, samples=30000, progress=print, reducer=None, fast=True, on_progress=None):
    """Collect only unknown-target ciphertext. Save each completed batch first."""
    if any(not 0 <= b < 64 for b in (source_block, target_block)):
        raise ValueError('Classic 1K blocks must be 0..63')
    if source_type not in (0, 1) or target_type not in (0, 1) or len(source_key) != 6:
        raise ValueError('invalid key or key type')
    source, target = source_block // 4 * 2 + source_type, target_block // 4 * 2 + target_type
    if source == target:
        raise ValueError('source and target must be different sector/key slots')
    if not 2000 <= samples <= 1000000 or samples % 2:
        raise ValueError('samples must be even and between 2000 and 1000000')
    output = Path(output)
    started = time.monotonic()
    card = identify()
    progress(f"Card {card['uid'].upper()}: source sector {source//2} {'AB'[source_type]} -> "
             f"target sector {target//2} {'AB'[target_type]}")
    source_auth = authenticate(card['cuid'], source_block, source_type, source_key)
    # Characterise only the known source slot. No target key is used here.
    profile = capture(card['cuid'], source, source_key, count=16)
    classification = probe(profile['records'])
    save_json(output / 'profile.json', dict(capture=profile, probe=classification))
    progress(f"Source PRNG classification: {classification['class']}")
    records = []
    first_bytes_seen = set()
    staged, staged_ms = [], 0.0
    reductions = []
    if reducer is not None:
        reducer.start(card['cuid'])
        if on_progress and getattr(reducer, 'benchmark', None):
            on_progress('benchmark', benchmark=dict(reducer.benchmark))

    def receive(block=False):
        state = reducer.receive(block=block)
        if state is not None:
            reductions.append(state)
            with (output / 'reductions.jsonl').open('a') as stream:
                os.chmod(output / 'reductions.jsonl', 0o600)
                stream.write(json.dumps(state) + '\n')
            progress(f"Reduction {state['raw']} samples, {state['first_bytes']}/256 first bytes, "
                     f"estimated states={state['states']:.0f}, {state['reason']}")
            if on_progress:
                on_progress('reduce', samples=state['raw'], unique=state['unique'],
                            first_bytes=state['first_bytes'], estimated_states=state['states'],
                            stop=state['stop'], reason=state['reason'])
        return state

    summary = dict(schema_version=1, status='collecting', card=card,
                   source_block=source_block, source_type='AB'[source_type],
                   target_block=target_block, target_type='AB'[target_type],
                   requested_samples=samples, samples=0, source_auth=source_auth,
                   probe=classification, writes=0, write_data_frames=0,
                   fast_capture=fast, adaptive=reducer is not None, stop_reason='max-samples')
    save_json(output / 'capture.json', summary)
    if on_progress:
        on_progress('capture', samples=0, first_bytes=0)
    try:
        with (output / 'batches.jsonl').open('w') as log:
            os.chmod(output / 'batches.jsonl', 0o600)
            while len(records) < samples:
                batch_started = time.monotonic()
                batch = capture(card['cuid'], source, source_key, target=target,
                                count=min(150 if fast else 50, samples - len(records)), fast=fast)
                if (batch['uid'] != f"{card['cuid']:08x}" or batch['source'] != source
                        or batch['target'] != target or batch['profile']
                        or batch['count'] != len(batch['records'])
                        or batch['writes'] or batch['write_data_frames']):
                    raise RuntimeError('inconsistent capture batch or unexpected write counters')
                for record in batch['records']:
                    validate_record(record)
                log.write(json.dumps(batch) + '\n')
                log.flush()
                records.extend(batch['records'])
                summary['samples'] = len(records)
                first_bytes_seen.update(r['encrypted'] >> 24 for r in batch['records'])
                if on_progress:
                    on_progress('capture', samples=len(records), first_bytes=len(first_bytes_seen))
                if reducer is not None:
                    staged.extend(batch['records'])
                    staged_ms += (time.monotonic() - batch_started) * 1000
                    state = receive()
                    if state is None and reducer.pending and len(staged) >= 150:
                        state = receive(block=True)
                    if state is not None and state['stop']:
                        summary['stop_reason'] = state['reason']
                        break
                    if not reducer.pending and len(staged) >= 150:
                        reducer.submit(staged, staged_ms)
                        staged, staged_ms = [], 0.0
                if len(records) % 500 == 0 or len(records) == samples:
                    first = len({r['encrypted'] >> 24 for r in records})
                    progress(f"Captured {len(records)}/{samples}, first bytes {first}/256, "
                             f"{time.monotonic()-started:.1f}s")
                    save_json(output / 'capture.json', summary)
        if reducer is not None:
            if reducer.pending:
                state = receive(block=True)
                if state['stop']:
                    summary['stop_reason'] = state['reason']
            if staged:
                reducer.submit(staged, staged_ms)
                receive(block=True)
            summary['reduction'] = reducer.last_state
            summary['reduction_checks'] = len(reductions)
        summary['status'] = 'captured'
    except BaseException as error:
        summary['status'] = 'interrupted'
        summary['error'] = str(error) or type(error).__name__
        raise
    finally:
        # Preserve usable paired evidence even after host interruption.
        paired = records[:len(records) // 2 * 2]
        if paired:
            data = pack_nonces(card['cuid'], target_block, target_type, paired)
            (output / 'nonces.bin').write_bytes(data)
            os.chmod(output / 'nonces.bin', 0o600)
            summary['evidence'] = inspect_nonces(data)
        summary['elapsed_s'] = time.monotonic() - started
        save_json(output / 'capture.json', summary)
    return summary


def verify_result(result, *, expected=None):
    """Authenticate recovered key; expected answer is only compared afterward."""
    info = result['evidence']
    card = identify()
    if card['cuid'] != info['cuid']:
        raise RuntimeError('card changed before recovered-key verification')
    report = authenticate(card['cuid'], info['target_block'], 'AB'.index(info['target_type']),
                          bytes.fromhex(result['key']))
    result.update(verified=True, verification=report)
    if expected is not None:
        result['expected_match'] = result['key'] == expected.hex()
        if not result['expected_match']:
            raise RuntimeError('recovered key authenticated but differs from expected answer')
    return result
