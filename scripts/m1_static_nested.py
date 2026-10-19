# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 NFClab contributors.
"""PM3 static nested: calibrate two AUTH positions, exact nonce solve, RF check.

Reuses the existing read-only depth collector; no new firmware ABI or writes.
Reference: proxmark3 dd8bf6c, MifareStaticNested / mf_static_nested.
"""
import json
import os
import subprocess
import tempfile
import time

from m1_auth_timeout import calibrated_timeout, verify_with_fallback
from pathlib import Path

from m1_recover_host import capture
from m1_keys_host import dictionary, run_keys
from m1_nested_attempt import (OUTCOME_RECOVERED, OUTCOME_EXHAUSTED,
                               OUTCOME_INCONCLUSIVE, OUTCOME_UNSUPPORTED, progress)
from m1_recovery import SOLVER, SolverCandidateLimit

# The reference recovery32 state buffer contains at most 2^18 states.
STATIC_EXACT_MAX_CANDIDATES = 1 << 18


def save_trace(path, data):
    path.write_text(json.dumps(data, indent=2) + '\n')
    os.chmod(path, 0o600)


def calibration(profiles):
    """Both positions must have reproducible initial and decrypted nonces.

    Use each position's measured plaintext directly, including zero distance
    and non-PRNG static nonces. Never substitute the first position's distance
    for the second one. This is PM3's dist1/dist2 prediction in exact form.
    """
    positions = []
    for depth, profile in enumerate(profiles):
        records = profile['records']
        if len(records) < 2 or any(r.get('error') for r in records):
            raise ValueError('static nested calibration incomplete')
        pairs = {(r['nt'], r['plain']) for r in records}
        if len(pairs) != 1:
            raise ValueError('static nested nonce is not repeatable at this position')
        nt, plain = pairs.pop()
        positions.append(dict(depth=depth, source_nonce=nt, target_nonce=plain))
    if len(positions) != 2:
        raise ValueError('static nested requires two calibrated positions')
    return positions


def prepare(session, source, key, first):
    second = capture(session.card['cuid'], source, key, count=4, depth=1)
    if session.path is not None:
        save_trace(session.path/'profile-static-depth1.json', second)
    positions = calibration([first, second])
    plan = dict(path='static-nested', predicted=None, window=None, margin=0,
                reason=None, positions=positions, source_type=source % 2)
    # Use the short timeout only after the known entry key proves it works on
    # this card. Inconclusive candidate batches retry at the conservative NRT.
    timeout = calibrated_timeout(lambda value: run_keys(
        [key], session.card['cuid'], operation=1, repeat=3,
        block=source//2*4, key_type=source % 2, auth_timeout_us=value))

    plan['auth_timeout_us'] = timeout
    return plan


def solve_static(uid, traces, timeout=120, cap=STATIC_EXACT_MAX_CANDIDATES):
    if len(traces) < 2 or any(r.get('error') for r in traces):
        raise ValueError('static nested requires two valid calibrated traces')
    with tempfile.TemporaryDirectory(prefix='nfc-static-', dir='/tmp') as directory:
        path = Path(directory)/'traces.txt'
        path.write_text(''.join(f"{r['predicted_plain']:08x} {r['encrypted']:08x} {r['parity']:x}\n"
                                for r in traces))
        result = subprocess.run([str(SOLVER), 'static', uid, str(path), str(cap)],
                                capture_output=True, text=True, timeout=timeout)
    if result.returncode == 4:
        raise SolverCandidateLimit('static nested candidate cap reached')
    if result.returncode:
        raise RuntimeError(f'static nested solver failed ({result.returncode})')
    return list(dict.fromkeys(bytes.fromhex(k) for k in result.stdout.splitlines()))


def predicted_nonce(position, plan, target_type):
    plain = position['target_nonce']
    initial = plan['positions'][0]['source_nonce']
    # PM3's documented 009080A2 Key B exception (161/321 instead of 160/320).
    # Gate on the measured model, rather than applying it to every static card.
    if initial == 0x009080A2 and plan['source_type'] == 0 and target_type == 1:
        from m1_recovery import nonce_distance
        _, _, measured = nonce_distance(initial, plain)
        if measured == (position['depth'] + 1) * 160:
            output = subprocess.check_output([str(SOLVER), 'successor', f'{plain:08x}',
                                               '1', 'unused'], text=True)
            return int(output.strip(), 16)
    return plain


# A card that moved between calibration and probing (its source nonce no longer
# matches what prepare() measured) is worth re-measuring both positions once.
# A retry that changes nothing - same positions, same samples, same
# deterministic solve, same verification order - is deliberately absent: it
# would only repeat the same on-card verification work.
RECALIBRATIONS = 1


def capture_positions(session, source, key, target, plan, record):
    """Capture every calibrated position once; None when the card has moved.

    Guessing the target's plaintext nonce from a stale calibration would yield a
    keystream that can never match, so a drift is reported rather than guessed.
    """
    traces = []
    for position in plan['positions']:
        depth = position['depth']
        progress(session, 'capture', target, depth=depth, samples=2, method='static-nested')
        data = capture(session.card['cuid'], source, key, target=target, count=2, depth=depth)
        if any(r['nt'] != position['source_nonce'] for r in data['records']):
            return None
        for r in data['records']:
            r['predicted_plain'] = predicted_nonce(position, plan, target % 2)
        name = f"static-{target:02d}-{record['attempt']}-depth{depth}.json"
        if session.path is not None:
            save_trace(session.path/name, data)
        record['captures'].append(dict(depth=depth, trace=name))
        traces.extend(data['records'])
    return traces


def recalibrate(session, source, key, target):
    """Measure both positions again; None when the card is no longer stable."""
    session.event('recalibrate',
                  f'Target sector {target//2} {"AB"[target%2]}: Source nonce deviated; recalibrate both authentication positions')
    progress(session, 'recalibrate', target, method='static-nested')
    fresh = capture(session.card['cuid'], source, key, count=16)
    if session.path is not None:
        save_trace(session.path/'profile-recalibrated.json', fresh)
    try:
        return prepare(session, source, key, fresh)
    except ValueError as error:
        progress(session, 'unresolved', target, method='static-nested')
        session.event('unresolved', f'static nested recalibration failed: {error}; do not guess target plaintext')
        return None


def try_static_nested(session, source, key, target, plan):
    started = time.monotonic()
    recalibrations = 0
    attempt = 0
    while True:
        attempt += 1
        progress(session, 'start', target, attempt=attempt, method='static-nested')
        record = dict(target=target, attempt=attempt, rung='static-nested',
                      path='static-nested', captures=[], method='two-position-exact-nonce')
        traces = capture_positions(session, source, key, target, plan, record)
        if traces is None:
            record['error'] = 'source-nonce-drift'
            session.state['recovery_attempts'].append(record)
            session.save()
            if recalibrations >= RECALIBRATIONS:
                progress(session, 'unresolved', target, method='static-nested')
                session.event('unresolved', 'static nested source nonce deviated from calibration; do not guess target plaintext')
                return OUTCOME_UNSUPPORTED
            recalibrations += 1
            plan = recalibrate(session, source, key, target)
            if plan is None:
                return OUTCOME_UNSUPPORTED
            if session.state.get('recovery_path'):
                session.state['recovery_path']['positions'] = plan['positions']
            session.save()
            continue
        record['independent_keystreams'] = len({(r['predicted_plain'], r['encrypted']) for r in traces})
        progress(session, 'solve', target, method='static-nested')
        try:
            candidates = solve_static(f"{session.card['cuid']:08x}", traces)
        except SolverCandidateLimit:
            # A static keystream admits tens of thousands of consistent keys, so
            # the enumeration cap bounds cost, not correctness. Truncated output
            # is never accepted: record why, keep the samples, and leave the
            # target pending instead of reporting it unsolvable.
            record.update(candidate_count=None, error='candidate-limit')
            session.state['recovery_attempts'].append(record)
            session.save()
            progress(session, 'limit', target, method='static-nested')
            session.event('solver-limit',
                          f'Target sector {target//2} {"AB"[target%2]}: Static candidate limit reached; retaining samples')
            return OUTCOME_INCONCLUSIVE
        record['candidate_count'] = len(candidates)
        record.update(verified_candidates=0, verification_mcu_ms=0,
                      verification_host_ms=0, timing_us={}, verification_batches=[])
        session.state['recovery_attempts'].append(record)
        session.save()
        session.event('static-nested', f'Sector {target//2} {"AB"[target%2]}: Two-position solver returned {len(candidates)}  candidates')
        # Bounded batches keep progress and successful keys durable. Identical
        # keystreams retain candidates; only full RF authentication accepts one.
        for offset in range(0, len(candidates), 256):
            progress(session, 'verify', target, candidates=len(candidates), checked=offset,
                     method='static-nested')
            batch = candidates[offset:offset+256]
            report = verify_with_fallback(session, plan,
                lambda timeout: dictionary(batch, session.card['cuid'], 1 << target,
                                           auth_timeout_us=timeout), 'static-nested')
            record['verified_candidates'] += report['processed']
            record['verification_mcu_ms'] += report['mcu_ms']
            for batch_report in report['batches']:
                record['verification_host_ms'] += batch_report['host_elapsed_ms']
                for name, value in batch_report['timing_us'].items():
                    record['timing_us'][name] = record['timing_us'].get(name, 0) + value
            record['verification_batches'].append(dict(offset=offset, count=len(batch),
                processed=report['processed'], complete=report['complete'],
                found=report['all_found'], mcu_ms=report['mcu_ms'],
                auth_timeout_us=plan.get('auth_timeout_us', 4833)))
            added = session.accept_report(report, 'static-nested')
            progress(session, 'verify', target, candidates=len(candidates),
                     checked=offset + report['targets'][0]['checked'], method='static-nested')
            session.save()
            if added:
                record['elapsed_s'] = time.monotonic() - started
                session.save()
                progress(session, 'recovered', target, method='static-nested', elapsed_s=record['elapsed_s'])
                session.event('recovered', f'Target sector {target//2} {"AB"[target%2]} passed full authentication')
                session.advance(added)
                return OUTCOME_RECOVERED
        # Enumeration was complete and every candidate was checked on the card.
        progress(session, 'unresolved', target, method='static-nested')
        return OUTCOME_EXHAUSTED
