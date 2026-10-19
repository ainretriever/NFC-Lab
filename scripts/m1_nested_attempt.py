# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 NFClab contributors.
"""Mechanics of one nested recovery attempt against one target.

`m1_strategies` decides *what* to try (the ladder); this module decides *how* a
single nested attempt is carried out: where to search, how many samples to take,
when to bring in a second capture, and how to verify the result on the card.
"""
import json
import os
import time
from m1_keys_host import dictionary
from m1_recover_host import capture
from m1_recovery import (NESTED_MAX_CANDIDATES, STATIC_NESTED_MAX_CANDIDATES,
                         SolverCandidateLimit, solve)

__all__ = ['OUTCOME_RECOVERED', 'OUTCOME_EXHAUSTED', 'OUTCOME_INCONCLUSIVE',
           'OUTCOME_UNSUPPORTED', 'RETRY_WIDEN', 'INTERSECT_DEPTHS',
           'INTERSECT_ABOVE', 'attempt_windows', 'gather_candidates',
           'intersect_second_depth', 'try_nested']

OUTCOME_RECOVERED = 'recovered'
OUTCOME_EXHAUSTED = 'exhausted'        # solver produced nothing usable for this target
OUTCOME_INCONCLUSIVE = 'inconclusive'  # solver hit its candidate cap; try harder, don't retire
OUTCOME_UNSUPPORTED = 'unsupported'

# Widening applied to a bounded window on the retry attempt.  An exact
# prediction is never widened; see attempt_windows().
RETRY_WIDEN = 16
# Probing the same target at these nested depths yields independent keystreams.
INTERSECT_DEPTHS = (0, 1)
# Only pay for a second capture when one collection left a lot of candidates.
INTERSECT_ABOVE = 256


def progress(session, step, target, **details):
    callback = getattr(session, 'progress', None)
    if callback:
        callback('nested', step=step, sector=target//2, key_type='AB'[target%2], **details)


def attempt_windows(plan, attempt):
    """Where to search and how many samples to take on a given attempt.

    An exact prediction is retried at the *same* distance with more samples: the
    parity filter already rejects every wrong distance, so widening would only
    add wrong-distance candidates.  A bounded window is genuinely uncertain, so
    its retry does widen.
    """
    if plan['predicted'] is not None:
        lo = hi = plan['predicted']
        return lo, hi, (2 if attempt == 1 else 8)
    widen = 0 if attempt == 1 else RETRY_WIDEN
    lo = max(0, plan['window'][0] - widen)
    hi = min(65534, plan['window'][1] + widen)
    return lo, hi, 8


def gather_candidates(session, source, key, target, depth, count, lo, hi, cap, tag):
    """Capture the target at one nested depth and solve it."""
    progress(session, 'capture', target, samples=count, depth=depth)
    traces = capture(session.card['cuid'], source, key, target=target,
                     count=count, depth=depth)
    trace_name = f'nonce-{target:02d}-{tag}.json'
    if session.path is not None:
        trace_path = session.path / trace_name
        trace_path.write_text(json.dumps(traces, indent=2) + '\n')
        os.chmod(trace_path, 0o600)
    progress(session, 'solve', target)
    return trace_name, solve(traces, lo, hi, max_candidates=cap)


def intersect_second_depth(session, source, key, target, lo, hi, cap, attempt, record, first):
    """Narrow the candidate set with a second, independent capture.

    Returns the narrowed list, or `first` when the second capture is unusable or
    the intersection is empty: an empty intersection means the two depths
    disagree, which is a reason to fall back, not to abandon the target.
    """
    depth = INTERSECT_DEPTHS[1]
    try:
        name, second = gather_candidates(session, source, key, target, depth,
                                         8, lo, hi, cap, f'{attempt}-d{depth}')
    except SolverCandidateLimit:
        record['intersection'] = 'second-capture-hit-solver-limit'
        return first
    record['captures'].append({'depth': depth, 'trace': name,
                               'candidate_count': len(second)})
    second_set = set(second)
    common = [k for k in first if k in second_set]
    record['intersection_count'] = len(common)
    if not common:
        record['intersection'] = 'empty'
        return first
    record['intersection'] = 'narrowed'
    record['candidate_count'] = len(common)
    session.event('intersect',
                  f'Candidate intersection across two depths: {len(common)}  (single sample: {len(first)})')
    return common


def try_nested(session, source, key, target, plan, rung):
    """Capture, solve and verify one target.

    An exact prediction admits tens of thousands of candidates from a single
    keystream, which then have to be tried on the card one by one.  Probing the
    same target one step deeper in the nested chain gives a *second, independent*
    keystream for the same key, and the true key lies in the intersection of the
    two candidate sets.  That is how proxmark3's MifareStaticNested ends up with
    one candidate where a single collection gives tens of thousands.

    `rung` is the ladder rung; the provenance written into the session is
    `plan['path']`, selected by card class rather than distance-window width.
    """
    path = plan['path']
    started = time.monotonic()
    limited = False
    for attempt in (1, 2):
        lo, hi, sample_count = attempt_windows(plan, attempt)
        session.event('capture', f'Target sector {target//2} {"AB"[target%2]}, sample {attempt}/2')
        progress(session, 'start', target, attempt=attempt, method=path)
        record = {'target': target, 'attempt': attempt, 'rung': rung, 'path': path,
                  'predicted_distance': plan['predicted'], 'window': [lo, hi],
                  'sample_count': sample_count, 'captures': []}
        # A single predicted distance admits tens of thousands of candidates;
        # a bounded window admits few.
        cap = (STATIC_NESTED_MAX_CANDIDATES if plan['predicted'] is not None
               else NESTED_MAX_CANDIDATES)
        try:
            name, candidates = gather_candidates(session, source, key, target, 0,
                                                 sample_count, lo, hi, cap, f'{attempt}-d0')
        except SolverCandidateLimit:
            limited = True
            record.update(candidate_count=None, error='candidate-limit')
            session.state['recovery_attempts'].append(record)
            session.event('solver-limit', 'Candidate limit reached; retain samples for later retry')
            continue
        record['captures'].append({'depth': 0, 'trace': name,
                                   'candidate_count': len(candidates)})
        record['candidate_count'] = len(candidates)

        if plan['predicted'] is not None and len(candidates) > INTERSECT_ABOVE:
            candidates = intersect_second_depth(session, source, key, target, lo, hi,
                                                cap, attempt, record, candidates)
        session.state['recovery_attempts'].append(record)
        session.save()
        if not candidates:
            continue
        progress(session, 'verify', target, candidates=len(candidates), checked=0)
        report = dictionary(candidates, session.card['cuid'], 1 << target,
                            on_progress=lambda checked: progress(session, 'verify', target,
                                candidates=len(candidates), checked=checked))
        added = session.accept_report(report, path)
        if added:
            record['elapsed_s'] = time.monotonic() - started
            session.save()
            progress(session, 'recovered', target, elapsed_s=record['elapsed_s'])
            session.event('recovered', f'Target sector {target//2} {"AB"[target%2]} passed full authentication')
            session.advance(added)
            return OUTCOME_RECOVERED
    return OUTCOME_INCONCLUSIVE if limited else OUTCOME_EXHAUSTED
