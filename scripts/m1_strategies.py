# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 NFClab contributors.
"""Recovery strategy ladder: which strategy applies, in what order, and when to escalate.

This is the "proxmark3 autopwn" half of the design: an explicit ordered ladder
per card class, with sticky escalation when a rung gives out.  The session state
machine, the reuse/read loop and persistence stay in `m1_read_session.py`; here
we only decide policy and drive one target at a time.

`run_recovery(session)` operates on a duck-typed session and uses exactly these
members, so the ladder can be tested with a fake session:

    session.card['cuid']        reader UID for the MCU
    session.pending()           bitmask of the 32 (sector, A/B) targets still unknown
    session.state               session dict, mutated in place
    session.path                session directory (traces and profile.json)
    session.event(phase, text)  record progress
    session.save()              persist the session dict
    session.accept_report(report, provenance) -> list of newly verified keys
    session.advance(new_keys)   cross-sector reuse plus reads

See docs/autopwn-gap.md for the source-grounded comparison this mirrors.
"""
import json

from m1_nested_attempt import (OUTCOME_EXHAUSTED, OUTCOME_INCONCLUSIVE,
                               OUTCOME_RECOVERED, OUTCOME_UNSUPPORTED, try_nested)
from m1_recover_host import capture
from m1_recovery import (PROBE_HARD, PROBE_INSUFFICIENT, PROBE_STATIC,
                         PROBE_STATIC_ENCRYPTED, PROBE_WEAK, SolverCandidateLimit,
                         classify, probe, window_for)

__all__ = ['RUNG_NESTED', 'RUNG_STATIC_NESTED', 'RUNG_HARDNESTED', 'RUNG_DARKSIDE',
           'RUNG_SEN', 'IMPLEMENTED', 'MISSING_REASON', 'LADDERS',
           'OPT_IN_RUNGS', 'NO_ENTRY_KEY',
           'OUTCOME_RECOVERED', 'OUTCOME_EXHAUSTED', 'OUTCOME_INCONCLUSIVE',
           'OUTCOME_UNSUPPORTED',
           'SolverCandidateLimit', 'ladder_for', 'Ladder', 'run_recovery', 'climb']

RUNG_STATIC_NESTED = 'static-nested'
RUNG_NESTED = 'nested'
RUNG_HARDNESTED = 'hardnested'
RUNG_DARKSIDE = 'darkside'
RUNG_SEN = 'sen'

# Rungs this firmware/host pair can actually run today.
#
# Nested handles dynamic weak PRNGs, with either an exact distance or a
# bounded search window. Static-nested handles static nonce cards using
# independently calibrated AUTH positions, including distance zero.
IMPLEMENTED = (RUNG_NESTED, RUNG_STATIC_NESTED, RUNG_SEN, RUNG_HARDNESTED)
MISSING_REASON = {
    RUNG_DARKSIDE: 'darkside requires explicit opt-in and is not implemented',
}
# Rungs that are never planned automatically.
#
# proxmark3's entry rung when no key is known is darkside, gated on a weak PRNG
# (cmdhfmf.c:3586).  We deliberately do not plan it: cards carrying that flaw are
# rare enough that it cannot even be tested here, and an untestable rung sitting
# in the default path only produces misleading progress.  A caller may opt in
# through `allow`; nothing implements it yet.
OPT_IN_RUNGS = (RUNG_DARKSIDE,)
# No authenticated key yet.  We cannot characterise the card in that state at
# all - our probe needs a known key to decrypt the nested nonce - so the entry
# ladder is a policy decision rather than a per-class table.
NO_ENTRY_KEY = 'No authenticated entry key; darkside is disabled by default (vulnerable cards are uncommon); cannot continue'

# Card class -> ordered rungs, mirroring cmdhfmf.c:3748-3867.
LADDERS = {
    PROBE_STATIC: (RUNG_STATIC_NESTED,),
    PROBE_WEAK: (RUNG_NESTED, RUNG_HARDNESTED),
    PROBE_HARD: (RUNG_HARDNESTED,),
    PROBE_STATIC_ENCRYPTED: (RUNG_SEN,),
    PROBE_INSUFFICIENT: (),
}


def ladder_for(probe_class=None, has_entry_key=True, allow=()):
    """Ordered rungs to try.

    With an entry key the class decides (LADDERS).  Without one the ladder is
    empty unless the caller opts into a rung through `allow`; only names listed
    in OPT_IN_RUNGS can be opted into, so a default run never wanders into an
    untested strategy.
    """
    if has_entry_key:
        return tuple(LADDERS.get(probe_class, ()))
    return tuple(r for r in OPT_IN_RUNGS if r in allow)


class Ladder:
    """Ordered rungs plus sticky escalation.

    proxmark3 retires nested for the whole card once it gives out
    (`nested_failed`, cmdhfmf.c:3815) instead of grinding every target.  We only
    retire a rung when something implemented remains after it: with no fallback
    implemented, retiring would silently abandon the remaining targets.
    """

    def __init__(self, rungs, implemented=IMPLEMENTED):
        self.rungs = tuple(rungs)
        self.implemented = tuple(implemented)
        self.retired = set()

    def active(self):
        return tuple(r for r in self.rungs if r not in self.retired)

    def runnable(self):
        return tuple(r for r in self.active() if r in self.implemented)

    def blocked_reason(self):
        """Why the first not-yet-runnable rung cannot run, for honest reporting."""
        for rung in self.active():
            if rung not in self.implemented:
                return MISSING_REASON.get(rung, f'Not implemented: {rung}')
        return None

    def has_implemented_fallback(self, rung):
        if rung not in self.rungs:
            return False
        for later in self.rungs[self.rungs.index(rung) + 1:]:
            if later in self.implemented:
                return True
        return False

    def record(self, rung, outcome):
        if outcome == OUTCOME_EXHAUSTED and self.has_implemented_fallback(rung):
            self.retired.add(rung)
        return self.active()


def run_recovery(session, allow=()):
    """Drive the whole recovery phase for `session`.

    `allow` opts into rungs excluded by default (OPT_IN_RUNGS); it only affects
    what happens when no key has been authenticated yet.
    """
    sources = [i for i, k in enumerate(session.state['keys']) if k['authenticated']]
    if not sources:
        ladder = Ladder(ladder_for(has_entry_key=False, allow=allow))
        reason = ladder.blocked_reason() or NO_ENTRY_KEY
        session.state['recovery_path'] = {
            'path': None, 'predicted_distance': None, 'window': None, 'margin': None,
            'probe': None, 'ladder': list(ladder.rungs),
            'implemented': list(ladder.runnable()), 'reason': reason,
        }
        session.save()
        session.event('recovery-unavailable', f'{reason}; retaining partial results')
        return

    source = sources[0]
    key = bytes.fromhex(session.state['keys'][source]['key'])
    session.event('calibrate', f'Using sector {source//2} {"AB"[source%2]} to calibrate nonce')
    cached = getattr(session, 'probe_profile', None)
    profile = (cached['data'] if cached and cached['source']==source and cached['key']==key.hex()
               else capture(session.card['cuid'], source, key, count=16))
    if session.path is not None:
        (session.path / 'profile.json').write_text(json.dumps(profile, indent=2) + '\n')

    detection = classify(profile['records'])
    characterisation = probe(profile['records'])
    session.state['nonce_profile'] = detection
    session.state['card_probe'] = characterisation

    ladder = Ladder(ladder_for(characterisation['class']))
    plan = window_for(detection)
    # An exact nonce-distance prediction is still ordinary nested on a
    # dynamic weak-PRNG card. Reserve static-nested for static nonce cards.
    if characterisation['class'] == PROBE_WEAK and plan['path'] is not None:
        plan = dict(plan, path=RUNG_NESTED)
    if characterisation['class'] == PROBE_STATIC:
        from m1_static_nested import prepare
        try:
            plan = prepare(session, source, key, profile)
        except ValueError as error:
            session.event('recovery-unavailable', str(error))
            return
    elif characterisation['class'] == PROBE_STATIC_ENCRYPTED:
        from m1_sen import prepare
        try:
            plan = prepare(session, source, key)
        except ValueError as error:
            session.event('recovery-unavailable', str(error))
            return
    if characterisation['class'] == PROBE_HARD or (plan['path'] is None and RUNG_HARDNESTED in ladder.runnable()):
        if RUNG_NESTED in ladder.rungs:
            ladder.record(RUNG_NESTED, OUTCOME_EXHAUSTED)
        plan = dict(path=RUNG_HARDNESTED, predicted=None, window=None, margin=None, reason=None)
    session.state['recovery_path'] = {
        'path': plan['path'], 'predicted_distance': plan['predicted'],
        'window': plan['window'], 'margin': plan['margin'], 'reason': plan['reason'],
        'probe': characterisation['class'],
        'ladder': list(ladder.rungs), 'implemented': list(ladder.runnable()),
    }
    if 'positions' in plan:
        session.state['recovery_path']['positions'] = plan['positions']
        session.state['recovery_path']['auth_timeout_us'] = plan['auth_timeout_us']
    if plan.get('backdoor_key'):
        session.state['recovery_path']['backdoor_key'] = plan['backdoor_key']
        session.state['recovery_path']['auth_timeout_us'] = plan['auth_timeout_us']
    session.save()
    callback = getattr(session, 'progress', None)
    if callback:
        callback('recovery-path', message=f"Recovery path    {plan['path'] or 'unavailable'}")

    if not ladder.runnable():
        missing = ladder.blocked_reason() or plan['reason'] or 'No applicable recovery path'
        session.event('recovery-unavailable',
                      f"Card class {characterisation['class']}: {missing}; retaining partial results")
        return
    if plan['path'] is None:
        session.event('recovery-unavailable',
                      f"Nonce class {detection['class']}: {plan['reason']}; retaining partial results")
        return

    where = ('Incremental nonce reduction and adaptive stopping' if plan['path']==RUNG_HARDNESTED else
             'Two authentication positions calibrated independently' if 'positions' in plan else
             f"Backdoor key {plan['backdoor_key']}" if plan.get('backdoor_key') else
             f"Predicted distance {plan['predicted']}" if plan['predicted'] is not None
             else f"Window {plan['window'][0]}..{plan['window'][1]}")
    session.event(plan['path'],
                  f"Card class {characterisation['class']}, nonce {detection['class']}"
                  f"({where}), recovering unknown targets")
    for target in range(32):
        if not session.pending() & (1 << target):
            continue
        climb(session, ladder, source, key, target, plan)


def climb(session, ladder, source, key, target, plan):
    """Try the ladder's runnable rungs against one target, escalation included."""
    for rung in ladder.runnable():
        if not session.pending() & (1 << target):
            return True  # reuse already filled it
        if rung == RUNG_STATIC_NESTED and 'positions' in plan:
            from m1_static_nested import try_static_nested
            outcome = try_static_nested(session, source, key, target, plan)
        elif rung == RUNG_HARDNESTED:
            from m1_hardnested_attempt import try_hardnested
            saved = session.state['recovery_path']
            if saved['path'] != rung:
                saved.setdefault('initial_path', saved['path'])
            saved.update(path=rung, active_rung=rung, predicted_distance=None, window=None, margin=None)
            outcome = try_hardnested(session, source, key, target, plan)
        elif rung == RUNG_SEN:
            from m1_sen import try_sen
            outcome = try_sen(session, source, key, target, plan)
        elif rung in (RUNG_NESTED, RUNG_STATIC_NESTED):
            outcome = try_nested(session, source, key, target, plan, rung)
        else:
            outcome = OUTCOME_UNSUPPORTED
        ladder.record(rung, outcome)
        if outcome == OUTCOME_RECOVERED:
            return True
    session.event('unresolved', f'targets {target} not recovered; continuing with other targets')
    return False
