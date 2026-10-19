# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 NFClab contributors.
"""One hardnested rung: persistent incremental solving, RF verification, reuse."""
from pathlib import Path
import tempfile
import time
import uuid

from m1_hardnested import collect, save_json
from m1_keys_host import dictionary
from m1_nested_attempt import OUTCOME_RECOVERED, OUTCOME_EXHAUSTED
from solvers.hardnested_stream import IncrementalSolver


def try_hardnested(session, source, key, target, plan=None):
    root = session.path
    if root is not None:
        root = Path(root) / 'hardnested'
    else:
        root = getattr(session, 'recovery_artifacts', None)
        if root is None:
            root = Path(tempfile.mkdtemp(prefix='nfclab-read-hardnested-'))
    output = Path(root) / f'target-{target:02d}-{uuid.uuid4().hex[:8]}'
    output.mkdir(parents=True, mode=0o700)
    started = time.monotonic()
    record = dict(target=target, rung='hardnested', path='hardnested',
                  artifacts=str(output.resolve()), status='running',
                  target_key_supplied=False, source_key_supplied_to_solver=False)
    session.state['recovery_attempts'].append(record)
    session.save()

    callback = getattr(session, 'progress', None)
    def stage(step, **details):
        if callback:
            callback('hardnested', step=step, sector=target//2,
                     key_type='AB'[target%2], method='hardnested', **details)

    def progress(message):
        session.event('hardnested', message)

    session.event('hardnested', f'Recovering sector {target//2} {"AB"[target%2]}')
    result = dict(status='running', verified=False)
    stage('start')
    try:
        with IncrementalSolver(output, cpus=getattr(session, 'solver_cpus', None)) as worker:
            capture = collect(output, source_block=source//2*4, source_type=source%2,
                              source_key=key, target_block=target//2*4,
                              target_type=target%2, progress=progress, reducer=worker, on_progress=stage)
            if capture['card'] != session.card:
                raise RuntimeError('card changed during hardnested capture')
            record.update(samples=capture['samples'], stop_reason=capture['stop_reason'],
                          capture_elapsed_s=capture['elapsed_s'])
            session.save()
            stage('solve', samples=capture['samples'], stop_reason=capture['stop_reason'])
            result.update(worker.finish(output / 'nonces.bin'))
        # A solver result is only a candidate until complete RF authentication.
        stage('verify', candidates=1, checked=0)
        report = dictionary([bytes.fromhex(result['key'])], session.card['cuid'], 1 << target)
        added = session.accept_report(report, 'hardnested')
        stage('verify', candidates=1, checked=report['targets'][0].get('checked', int(bool(added))))
        verified = session.state['keys'][target]['authenticated']
        result.update(verified=verified, verification=report,
                      status='complete' if verified else 'not-verified')
        record.update(status=result['status'], candidate_count=1,
                      solve_elapsed_s=result['elapsed_s'], verified=verified)
        save_json(output / 'result.json', result)
        session.save()
        if not verified:
            stage('unresolved')
            return OUTCOME_EXHAUSTED
        stage('recovered', elapsed_s=time.monotonic()-started)
        session.event('recovered', f'Hardnested sector {target//2} {"AB"[target%2]} passed full authentication')
        session.advance(added)
        return OUTCOME_RECOVERED
    except BaseException as error:
        record.update(status='interrupted' if isinstance(error, KeyboardInterrupt) else 'failed',
                      error=str(error) or type(error).__name__)
        result.update(status=record['status'], error=record['error'])
        save_json(output / 'result.json', result)
        raise
    finally:
        record['elapsed_s'] = time.monotonic() - started
        session.save()
