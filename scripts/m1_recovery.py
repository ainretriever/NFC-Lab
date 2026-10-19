# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 NFClab contributors.
"""Nonce feature detection, recovery-path selection and nested solving.

The classification and selection helpers are pure functions over plain
dictionaries so they can be tested without hardware.  Only the distance helpers
and `solve` shell out to the host solver built from reference/proxmark3's
crapto1 core.
"""
import subprocess
import tempfile
from pathlib import Path
from swd import ROOT

SOLVER = ROOT / 'build/m1-nested'
# host/m1-nested.c refuses hi-lo > 256, so the window below must respect it.
MAX_DISTANCE_SPAN = 256
# Distances observed from a real card are tightly clustered; a wider spread
# means ordinary nested cannot bound the search and later algorithms apply.
BOUNDED_SPAN = 128
# Slack for a bounded window.  A fixed prediction gets no slack on purpose;
# see window_for().
BOUNDED_MARGIN = 2

# nonce class -> recovery path implemented today.
PATHS = {
    'fixed-distance': 'static-nested',
    'bounded-distance': 'nested',
}
UNSUPPORTED = ('insufficient', 'random-distance', 'static-plaintext')

# Candidate caps handed to the solver.  A bounded distance window admits few
# candidates; a single predicted distance admits tens of thousands, and the
# card-side verification stops at the first match, so a generous cap is fine.
NESTED_MAX_CANDIDATES = 1024
STATIC_NESTED_MAX_CANDIDATES = 65536


def nonce_distance(a, b):
    """Return (a_is_prng, b_is_prng, distance) using the host solver."""
    out = subprocess.check_output(
        [str(SOLVER), 'distance', f'{a:08x}', f'{b:08x}', 'unused'], text=True, timeout=5)
    weak_a, weak_b, distance = map(int, out.split())
    return bool(weak_a), bool(weak_b), distance


def nonce_distances(pairs):
    """Evaluate one calibration batch in one solver process and PRNG table."""
    if not 1 <= len(pairs) <= 50:
        raise ValueError('expected 1..50 nonce pairs')
    with tempfile.TemporaryDirectory(prefix='nfc-distances-', dir='/tmp') as directory:
        path = Path(directory) / 'pairs.txt'
        path.write_text(''.join(f'{a:08x} {b:08x}\n' for a, b in pairs))
        output = subprocess.check_output(
            [str(SOLVER), 'distances', str(path), 'unused', 'unused'],
            text=True, timeout=5)
    rows = [tuple(map(int, line.split())) for line in output.splitlines()]
    if len(rows) != len(pairs) or any(len(row) != 3 for row in rows):
        raise RuntimeError('incomplete nonce distance batch')
    return [(bool(a), bool(b), distance) for a, b, distance in rows]


# Card classes, mirroring proxmark3's up-front gating in `hf mf autopwn`
# (cmdhfmf.c:3360-3384: static nonce probe, then weak/hard PRNG, then
# static-encrypted nonce).  The class decides the whole recovery ladder.
PROBE_STATIC = 'static-nonce'
PROBE_STATIC_ENCRYPTED = 'static-encrypted'
PROBE_WEAK = 'weak'
PROBE_HARD = 'hard'
PROBE_INSUFFICIENT = 'insufficient'


def probe(records):
    """Characterise the card before choosing a strategy.

    proxmark3 takes this decision up front and uses it to gate every later
    branch, but samples once; we keep the same classes and sample 16 times so a
    single odd nonce cannot misroute the entire recovery.

    `records` is a profile capture: 'nt' is this AUTH's plaintext nonce, which
    is what both the static probe and the PRNG check look at.  `encrypted` is
    the raw ciphertext of the probed AUTH, which is what separates a static
    *plaintext* nonce from a static *encrypted* one.

    The order mirrors proxmark3's gating (cmdhfmf.c:3360-3384): static nonce
    first, then static encrypted nonce, then the PRNG class.  The static case
    must come first because a card whose plaintext nonce never changes also
    sends a constant ciphertext.
    """
    valid = [r for r in records if not r.get('error')]
    result = {'samples': len(valid), 'class': PROBE_INSUFFICIENT,
              'prng_valid': 0, 'prng_checked': 0, 'reason': None}
    if len(valid) < 2:
        result['reason'] = 'Insufficient samples to classify card'
        return result
    distinct_nt = len({r['nt'] for r in valid})
    if distinct_nt == 1:
        result['class'] = PROBE_STATIC
        result['reason'] = 'Plaintext nonce is fixed'
        return result
    # FM11RF08S: the card keeps sending the same ciphertext while its plaintext
    # nonce moves on, i.e. it re-encrypts with a stale keystream.  A normal card
    # cannot look like this: its ciphertext is f(plaintext, keystream) and both
    # change on every AUTH.  Requires a real profile capture, not synthetic
    # records without ciphertext.
    ciphertexts = {r.get('encrypted') for r in valid}
    if (len(valid) >= 4 and len(ciphertexts) == 1
            and all(isinstance(value, int) for value in ciphertexts)):
        result['class'] = PROBE_STATIC_ENCRYPTED
        result['reason'] = (f'Plaintext nonce has {distinct_nt}  distinct values, '
                            f'but encrypted nonce is fixed at {next(iter(ciphertexts)):08x}')
        return result
    # A self-pair reports the PRNG validity of that single nonce.
    checks = nonce_distances([(r['nt'], r['nt']) for r in valid])
    ok = sum(1 for prng_a, _, _ in checks if prng_a)
    result['prng_valid'] = ok
    result['prng_checked'] = len(checks)
    if ok * 2 >= len(checks):
        result['class'] = PROBE_WEAK
    else:
        result['class'] = PROBE_HARD
        result['reason'] = f'{len(checks) - ok}/{len(checks)} nonce is not a valid PRNG state'
    return result


def classify(records):
    """Classify a card's nonce behaviour from a profile capture.

    Each record carries 'nt' (this AUTH's plaintext Nt, decrypted with the
    known key) and 'plain' (the following nested AUTH's decrypted Nt).

    A repeating *initial* nonce does not make a card "static" on its own: a card
    may reseed its PRNG on every select, so the initial nonce repeats while the
    nested nonce still advances by a fixed distance.  What decides whether
    nested is usable is the distance between the two, computed here.  Measured
    example: `01200145` repeating, but the nested nonce is `7eef3586`, which is
    exactly `prng_successor(01200145, 160)` - so that card is an ordinary
    fixed-distance card, not an unsupported one.
    """
    valid = [r for r in records if not r.get('error')]
    result = {'samples': len(valid), 'class': 'insufficient', 'distances': [],
              'dmin': None, 'dmax': None, 'reason': None}
    if len(valid) < 2:
        result['reason'] = 'Insufficient calibration samples'
        return result
    distances = []
    for prng_a, prng_b, distance in nonce_distances([(r['nt'], r['plain']) for r in valid]):
        if not prng_a or not prng_b:
            result['class'] = 'random-distance'
            result['reason'] = 'nonce is not a valid PRNG state'
            return result
        distances.append(distance)
    result['distances'] = distances
    result['dmin'], result['dmax'] = min(distances), max(distances)
    span = result['dmax'] - result['dmin']
    if result['dmax'] == 0:
        # The nested nonce never advances past the initial one.  Distance 0
        # leaves no parity constraint for ordinary nested to filter on, so
        # window_for() cannot plan a search; the static-nested rung takes over
        # with independently measured positions instead.
        result['class'] = 'static-plaintext'
        result['reason'] = ('Nested nonce equals initial nonce (distance 0);'
                            ' ordinary nested has no usable constraints; use calibrated two-position static nested prediction')
    elif span == 0:
        result['class'] = 'fixed-distance'
    elif span <= BOUNDED_SPAN and span <= MAX_DISTANCE_SPAN:
        result['class'] = 'bounded-distance'
    else:
        result['class'] = 'random-distance'
        result['reason'] = f'Distance spread {span} exceeds ordinary nested search range'
    return result


def window_for(detection):
    """Decide the recovery path and how far to search.

    Returns a dict:
      path      - 'static-nested' / 'nested', or None when nothing applies
      predicted - the calibrated distance when the prediction is exact, else None
      window    - [lo, hi] handed to the solver
      margin    - slack around the prediction (0 when the prediction is exact)
      reason    - why no path applies

    A fixed distance is kept exact rather than padded.  The parity filter
    already pins it: measured on a laboratory card, searching 160..160 and 158..162
    both yield 32324 candidates, 159..159 yields none.  Padding therefore buys
    nothing, and widening the window on retry is actively harmful - 142..178
    triples the candidate list with wrong-distance noise.
    """
    if detection['class'] in UNSUPPORTED:
        return {'path': None, 'predicted': None, 'window': None, 'margin': None,
                'reason': detection.get('reason') or 'No applicable recovery path'}
    path = PATHS[detection['class']]
    if path == 'static-nested':
        predicted = detection['dmin']
        return {'path': path, 'predicted': predicted,
                'window': [predicted, predicted], 'margin': 0, 'reason': None}
    lo = max(0, detection['dmin'] - BOUNDED_MARGIN)
    hi = min(65534, detection['dmax'] + BOUNDED_MARGIN)
    if hi - lo > MAX_DISTANCE_SPAN:
        return {'path': None, 'predicted': None, 'window': None, 'margin': None,
                'reason': 'Distance search range exceeds solver limit'}
    return {'path': path, 'predicted': None, 'window': [lo, hi],
            'margin': BOUNDED_MARGIN, 'reason': None}


class SolverCandidateLimit(RuntimeError):
    """The solver reached its cap; a larger independent capture is needed."""


def solve(capture_data, lo, hi, timeout=120, max_candidates=NESTED_MAX_CANDIDATES):
    """Recover candidate keys from captured target nonces."""
    with tempfile.TemporaryDirectory(prefix='nfc-nested-', dir='/tmp') as directory:
        path = Path(directory) / 'traces.txt'
        path.write_text(''.join(f"{t['nt']:08x} {t['encrypted']:08x} {t['parity']:x}\n"
                                for t in capture_data['records']))
        result = subprocess.run([str(SOLVER), capture_data['uid'], str(lo), str(hi), str(path),
                                 str(max_candidates)],
                                capture_output=True, text=True, timeout=timeout)
    if result.returncode == 4:
        raise SolverCandidateLimit('nested solver candidate limit reached')
    if result.returncode:
        raise RuntimeError(f'nested solver failed ({result.returncode})')
    return list(dict.fromkeys(bytes.fromhex(line) for line in result.stdout.splitlines()))
