# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 NFClab contributors.
"""FM11RF08S static-encrypted-nonce (SEN) recovery, backdoor path.

Reference: proxmark3 dd8bf6c, HFMFSENRecover / fm11_generate_1nt_candidates
and MifareAcquireStaticEncryptedNonces. AUTH 0x64/0x65 yields the clear nonce;
regular nested AUTH yields its ciphertext and wire parity. recovery32 inverts
their XOR into candidates, filtered by seed16 pairing and verified on-card.
Read-only: no WRITE opcode.

See docs/m1-sen.md; the seed16 pairing lives in m1_sen_pair.py.
"""
import subprocess
import time

from m1_auth_timeout import calibrated_timeout, verify_with_fallback

from m1_keys_host import dictionary, run_keys
from m1_recover_host import capture
from m1_sen_backdoor import BACKDOOR_KEYS, find_backdoor, read_sector, read_card
from m1_nested_attempt import (OUTCOME_RECOVERED, OUTCOME_EXHAUSTED,
                               OUTCOME_INCONCLUSIVE, OUTCOME_UNSUPPORTED, progress)
from m1_recovery import SOLVER, SolverCandidateLimit
from m1_sen_pair import derive_partner, pair_candidates, seed16

__all__ = ['BACKDOOR_KEYS', 'DEFAULT_CAP', 'SenCandidateLimit', 'pm3_parity',
           'candidates', 'find_backdoor', 'collect_slot', 'collect_evidence',
           'enumerate_slot', 'seed16', 'pair_candidates', 'derive_partner',
           'read_sector', 'read_card',
           'prepare', 'try_sen']

# fm11_generate_1nt_candidates() stops at FM11RF08S_GENERATED_KEY_LIMIT = 1<<18.
DEFAULT_CAP = 1 << 18
# Verification batch size, same shape as the static-nested path.
BATCH = 256
# The same static nonce at two PRNG positions gives two independent keystreams
# for the same key, so their candidate lists intersect down to a handful.  This
# mirrors the static-nested double-depth trick; the backdoor session advances the
# card by one nested AUTH per depth, exactly like the regular path.
INTERSECT_DEPTHS = (0, 1)
# Intersect only when one collection alone leaves a lot of candidates.
INTERSECT_ABOVE = 64


class SenCandidateLimit(SolverCandidateLimit):
    """The enumeration cap was reached; truncated output is never accepted."""


def pm3_parity(raw_parity):
    """Map captured wire parity onto PM3's `par_enc` indexing.

    Our capture sets bit 0 for the first wire byte (the MSB of `nt_enc`), while
    PM3's parity bit `i` belongs to `nt` byte `i`, whose byte 0 is the LSB and
    therefore the *last* wire byte.  The two nibbles are bit-reversed.
    """
    value = raw_parity & 0xF
    return ((value & 1) << 3) | ((value & 2) << 1) | ((value >> 1) & 2) | ((value >> 3) & 1)


def candidates(uid, nt, enc, raw_parity, cap=DEFAULT_CAP, mask=1, timeout=120):
    """Candidate keys for one slot, from the clear nonce and its ciphertext.

    `mask` selects which parity bits are trusted and stays at PM3's single bit.
    Measuring 16 known key/slot samples of a laboratory card showed each wire byte's
    parity is consistent with keystream clock 39-8*i (PM3's ks2 bits 24..27 only
    fit byte 0), but enabling all four bits on real captures removed *no* wrong
    candidate at all -- the reader's parity for the lower wire bytes carries no
    extra information here -- so the wider mask only exists for experiments.
    """
    command = [str(SOLVER), 'sen', f'{uid:08x}', f'{nt:08x}', f'{enc:08x}',
               f'{pm3_parity(raw_parity):x}', str(cap)]
    if mask != 1:
        command.append(str(mask))
    result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    if result.returncode == 4:
        raise SenCandidateLimit('SEN candidate cap reached')
    if result.returncode:
        raise RuntimeError(f'SEN solver failed ({result.returncode})')
    return list(dict.fromkeys(bytes.fromhex(line) for line in result.stdout.splitlines()))


def nonce_is_valid(nt):
    """`validate_prng_nonce` through the solver: the clear nonce must be an LFSR16 state."""
    output = subprocess.check_output([str(SOLVER), 'distance', f'{nt:08x}', f'{nt:08x}',
                                      'unused'], text=True, timeout=5)
    return bool(int(output.split()[0]))


def collect_slot(uid, backdoor_key, sector, key_type, depth=0):
    """Return (nt, nt_enc, raw_parity) for one slot; ValueError when unstable.

    Both sessions must agree with themselves: the attack rests on the nested
    nonce being static, so an unstable reading means this is not a SEN card --
    or that the backdoor key is not the right one for this slot.  `depth` adds
    that many nested source AUTHs before the probe, which moves the plaintext
    nonce on while the key stays the same.
    """
    key = bytes.fromhex(backdoor_key)
    index = sector * 2 + key_type
    backdoor_type = 4 + key_type
    clear = capture(uid, index, key, count=2, depth=depth,
                    source_type=backdoor_type, target_type=backdoor_type)
    plains = {r['plain'] for r in clear['records']}
    if len(plains) != 1:
        raise ValueError(f'sector {sector} {"AB"[key_type]}: Unstable plaintext nonce in backdoor session')
    nt = plains.pop()
    if not nonce_is_valid(nt) or not nt:
        raise ValueError(f'sector {sector} {"AB"[key_type]}: Backdoor-decrypted nt={nt:08x} is not a valid PRNG state')
    regular = capture(uid, index, key, target=index, count=2, depth=depth,
                      source_type=backdoor_type, target_type=key_type)
    seen = {(r['encrypted'], r['parity']) for r in regular['records']}
    if len(seen) != 1:
        raise ValueError(f'sector {sector} {"AB"[key_type]}: Unstable ciphertext/parity under normal commands')
    enc, raw_parity = seen.pop()
    return nt, enc, raw_parity


def collect_evidence(uid, backdoor_key, sector, key_type, depths=INTERSECT_DEPTHS, *, on_position=None):
    """One (depth, nt, nt_enc, parity) record per requested PRNG position."""
    evidence = []
    for position, depth in enumerate(depths, 1):
        if on_position:
            on_position(position, len(depths), depth)
        evidence.append((depth,) + collect_slot(uid, backdoor_key, sector, key_type, depth=depth))
    return evidence


def enumerate_slot(uid, evidence, cap=DEFAULT_CAP):
    """Candidate lists per position, then their intersection when it helps.

    Returns (candidates, counts, narrowed).  An empty intersection means the two
    positions disagree (bad capture or a card that is not static), so the widest
    single list is kept instead of dropping the target.
    """
    lists = [candidates(uid, nt, enc, par, cap=cap) for _, nt, enc, par in evidence]
    counts = [len(entry) for entry in lists]
    if len(lists) < 2 or min(counts) <= INTERSECT_ABOVE:
        return lists[0], counts, False
    common = set(lists[0])
    for other in lists[1:]:
        common &= set(other)
    if not common:
        return lists[0], counts, False
    return [key for key in lists[0] if key in common], counts, True


def prepare(session, source, key):
    """Find a working backdoor key once for the whole run."""
    backdoor = find_backdoor(session.card['cuid'])
    if backdoor is None:
        raise ValueError('SEN: no Fudan backdoor key authenticated; known-key capture path required')
    timeout = calibrated_timeout(lambda value: run_keys(
        [key], session.card['cuid'], operation=1, repeat=3,
        block=source//2*4, key_type=source % 2, auth_timeout_us=value))

    return dict(path='sen', predicted=None, window=None, margin=0, reason=None,
                backdoor_key=backdoor,
                auth_timeout_us=timeout)


def try_sen(session, source, key, target, plan):
    """Collect, enumerate and verify one target over the backdoor path."""
    started = time.monotonic()
    backdoor = plan.get('backdoor_key')
    if not backdoor:
        progress(session, 'unresolved', target, method='sen')
        session.event('unresolved', 'SEN: no usable backdoor key; capture without a backdoor is not implemented')
        return OUTCOME_UNSUPPORTED
    sector, key_type = target // 2, target % 2
    progress(session, 'start', target, attempt=1, method='sen')
    record = dict(target=target, attempt=1, rung='sen', path='sen', captures=[],
                  method='backdoor-1nt', backdoor_key=backdoor)
    session.state['recovery_attempts'].append(record)
    try:
        evidence = collect_evidence(session.card['cuid'], backdoor, sector, key_type,
            on_position=lambda position, positions, depth: progress(session, 'capture', target,
                method='sen', position=position, positions=positions, depth=depth))
    except (ValueError, RuntimeError) as error:
        record['error'] = str(error)
        session.save()
        progress(session, 'unresolved', target, method='sen')
        session.event('unresolved', f'SEN capture failed: {error}')
        return OUTCOME_UNSUPPORTED
    record['evidence'] = [dict(depth=depth, nt=f'{nt:08x}', nt_enc=f'{enc:08x}',
                               wire_parity=f'{par:x}') for depth, nt, enc, par in evidence]
    record.update(nt=f'{evidence[0][1]:08x}', nt_enc=f'{evidence[0][2]:08x}',
                  wire_parity=f'{evidence[0][3]:x}')
    session.save()
    session.event('sen', f'Sector {sector} {"AB"[key_type]}: {len(evidence)} positions captured'
                         f'(nt={" ".join(f"{nt:08x}" for _, nt, _, _ in evidence)}), enumerating candidates')
    progress(session, 'solve', target, method='sen')
    try:
        found, counts, narrowed = enumerate_slot(session.card['cuid'], evidence)
    except SenCandidateLimit:
        record.update(candidate_count=None, error='candidate-limit')
        session.save()
        progress(session, 'limit', target, method='sen')
        session.event('solver-limit', f'Target sector {sector} {"AB"[key_type]}: Candidate limit reached; retaining evidence')
        return OUTCOME_INCONCLUSIVE
    record['candidate_counts'] = counts
    record['intersected'] = narrowed
    other_type = 1 - key_type
    other = None
    progress(session, 'pair', target, method='sen')
    try:
        other_evidence = collect_evidence(session.card['cuid'], backdoor, sector, other_type, depths=(0,))
        other_list, _, _ = enumerate_slot(session.card['cuid'], other_evidence)
        found, stats = pair_candidates(found, evidence[0][1], other_list, other_evidence[0][1])
        record['paired'] = stats
        other = (other_list, other_evidence[0][1])
        session.event('pair', f'Sector {sector} {"AB"[key_type]} paired with {"AB"[other_type]} slot for seed16 pairing, '
                              f'{stats["primary"]} -> {len(found)}  candidates'
                              f'(1+1 buckets {stats.get("singleton_buckets", 0)})')
    except (ValueError, RuntimeError, SenCandidateLimit) as error:
        record['paired'] = f'skipped: {error}'
        session.event('unresolved', f'Sector {sector} {"AB"[key_type]}: pairing skipped({error}), verify the original candidate list')
    record['candidate_count'] = len(found)
    record.update(verified_candidates=0, verification_batches=[])
    session.save()
    progress(session, 'verify', target, candidates=len(found), checked=0, method='sen')
    for offset in range(0, len(found), BATCH):
        batch = found[offset:offset + BATCH]
        report = verify_with_fallback(session, plan,
            lambda timeout: dictionary(batch, session.card['cuid'], 1 << target,
                                       auth_timeout_us=timeout), 'sen')
        record['verified_candidates'] += report['processed']
        record['verification_batches'].append(dict(offset=offset, count=len(batch),
                                                   processed=report['processed'],
                                                   found=report['all_found']))
        added = session.accept_report(report, 'sen')
        progress(session, 'verify', target, candidates=len(found),
                 checked=offset + report['targets'][0]['checked'], method='sen')
        session.save()
        if added:
            record['elapsed_s'] = time.monotonic() - started
            # A "1+1" bucket pins the counterpart key as well: the true partner
            # carries the recovered key's seed and must be in its enumerated
            # list, so a single match is provably it.  It is still put through
            # one real authentication before entering the key table.
            derived = []
            if other:
                candidate = derive_partner(added[0], other[0], evidence[0][1], other[1])
                if candidate:
                    progress(session, 'verify', target ^ 1, candidates=1, checked=0, method='sen')
                    report = verify_with_fallback(session, plan,
                        lambda timeout: dictionary([candidate], session.card['cuid'], 1 << (target ^ 1),
                                                   auth_timeout_us=timeout), 'sen-derived')
                    derived = session.accept_report(report, 'sen-derived')
                    progress(session, 'verify', target ^ 1, candidates=1,
                             checked=report['targets'][0]['checked'], method='sen')
                    if derived:
                        record['derived_partner'] = candidate.hex()
                        session.event('recovered',
                                      f'Sector {sector} {"AB"[1-key_type]} derived by seed16 pairing and authenticated')
            session.save()
            progress(session, 'recovered', target, method='sen', elapsed_s=record['elapsed_s'])
            session.event('recovered', f'Target sector {sector} {"AB"[key_type]} passed full authentication')
            session.advance(added + derived)
            return OUTCOME_RECOVERED
    record['elapsed_s'] = time.monotonic() - started
    session.save()
    progress(session, 'unresolved', target, method='sen')
    return OUTCOME_EXHAUSTED
