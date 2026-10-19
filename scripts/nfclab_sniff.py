# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 NFClab contributors.
"""Explicit windowed sniff adapter and offline solver; no continuous claim."""
from array import array
import json
from pathlib import Path
import re
import subprocess
import sys
from nfclab_cli import default_output
from sniff_session import Session, atomic_json
from transport import ROOT


def choose_job(state, target, method):
    priority = {'mfkey64': 0, 'mfkey32v2': 1, 'mfkey32': 2}
    choices = []
    for job in state['jobs']:
        if job['status'] != 'pending' or (method != 'auto' and job['tool'] != method):
            continue
        record = state['records'][job['records'][0]]
        if any(value is not None and str(record[field]).lower() != str(value).lower() for field, value in target.items()):
            continue
        choices.append(job)
    return min(choices, key=lambda j: priority[j['tool']]) if choices else None


def lock_target(records, target):
    for record in records:
        if all(v is None or str(record[k]).lower() == str(v).lower() for k, v in target.items()):
            return {k: record[k] for k in target}
    return None


def solve(session, job, events):
    executable = ROOT/'build'/job['tool']
    if not executable.is_file():
        raise ValueError(f'missing {executable}; run make host-mfkey')
    job['status'] = 'running'
    session.save()
    events.emit('solver.started', tool=job['tool'], records=job['records'])
    try:
        result = subprocess.run([str(executable), *job['args']], capture_output=True, text=True, timeout=30)
        found = re.findall(r'Found Key:\s*\[([0-9a-fA-F]{12})\]', result.stdout)
        job['status'] = 'candidate' if result.returncode == 0 and found else 'no-key'
        job['returncode'] = result.returncode
        record = session.state['records'][job['records'][0]]
        for key in found if job['status'] == 'candidate' else []:
            entry = dict(uid=record['uid'], cuid=record['cuid'], sector=record['sector'], key_type=record['key_type'], key=key.upper())
            if entry not in session.state['candidate_keys']:
                session.state['candidate_keys'].append(entry)
    except subprocess.TimeoutExpired:
        job['status'] = 'solver-timeout'
    finally:
        session.save()
        session.export()
    events.emit('solver.finished', tool=job['tool'], status=job['status'], candidates=session.state['candidate_keys'], verification='not performed')
    return 0 if job['status'] == 'candidate' else 1


def listen(a, link, events):
    from sniff_capture import capture, symbol
    from sniff_decode import decode
    from m1_host import wait_idle
    if wait_idle(timeout=0):
        raise RuntimeError('reader operation busy')
    path = a.resume or a.output or default_output(a.group, a.command)
    session = Session(path, resume=bool(a.resume))
    session.recover_pending()
    events.path = path/'events.jsonl'
    config = dict(command=a.command, method=getattr(a, 'method', None), uid=getattr(a, 'uid', None),
                  sector=getattr(a, 'sector', None), key_type=getattr(a, 'key_type', None))
    if a.resume and session.state.get('cli_config') != config:
        raise ValueError('resume sniff configuration differs')
    session.state['cli_config'] = config
    events.emit('session.started', path=str(path), coverage='windowed-with-gaps', continuous=False)
    address = symbol(a.elf or ROOT/'build/identity.elf', 'sniff')
    target = session.state.get('cli_target') or {k: config[k] for k in ('uid', 'sector', 'key_type')}
    locked = session.state.get('cli_target') is not None
    previous = None
    attempt = 0
    current = None
    try:
        while a.captures is None or attempt < a.captures:
            if a.command == 'recover' and locked:
                job = choose_job(session.state, target, a.method)
                if job:
                    events.emit('inputs.ready', target=target, tool=job['tool'])
                    # Each capture has already stopped DMA and completed RF cleanup.
                    events.emit('capture.stopped', cleanup_confirmed=True, coverage='windowed-with-gaps')
                    code = solve(session, job, events)
                    session.state['status'] = 'complete' if code == 0 else 'no-key'
                    return code
            prefix, current = session.reserve()
            meta, raw = capture(link, a.elf or ROOT/'build/identity.elf', address=address,
                                period=32, timeout_ms=a.timeout_ms, packed=None)
            if previous is not None:
                events.emit('capture.gap', lower_bound_ms=max(0, (meta['request_started_monotonic']-previous)*1000), total_unknown=True)
            previous = meta['completion_observed_monotonic']
            samples = array('H')
            samples.frombytes(raw)
            if sys.byteorder != 'little':
                samples.byteswap()
            frames = decode(samples, meta['sample_hz'], meta['trigger_index']) if meta['status'] == 2 else []
            atomic_json(prefix.with_suffix('.json'), meta)
            atomic_json(prefix.with_suffix('.frames.json'), frames)
            if frames or meta['status'] not in (2, 3):
                prefix.with_suffix('.bin').write_bytes(raw)
            session.ingest(current, meta, frames)
            session.export()
            for frame in frames:
                events.emit('frame.received', capture=current['index'], frame=frame)
            events.emit('capture.finished', window=current['index'], status=current['status'], records=len(session.state['records']))
            if current['status'] == 'capture-error':
                raise RuntimeError('capture or RF cleanup failed')
            if a.command == 'recover' and not locked:
                selected = lock_target(session.state['records'], target)
                if selected:
                    target, locked = selected, True
                    session.state['cli_target'] = target
                    session.save()
                    events.emit('target.locked', **target)
            attempt += 1
            # Check ready input before applying the capture-count limit.
            if a.command == 'recover' and locked and choose_job(session.state, target, a.method):
                continue
        # Last window may satisfy the input condition at the count boundary.
        job = choose_job(session.state, target, a.method) if a.command == 'recover' and locked else None
        if job:
            events.emit('inputs.ready', target=target, tool=job['tool'])
            events.emit('capture.stopped', cleanup_confirmed=True, coverage='windowed-with-gaps')
            code = solve(session, job, events)
            session.state['status'] = 'complete' if code == 0 else 'no-key'
            return code
        session.state['status'] = 'complete' if a.command == 'watch' else 'partial'
        return 0 if a.command == 'watch' else 4
    except BaseException:
        session.state['status'] = 'interrupted'
        if current and current['status'] == 'pending':
            current['status'] = 'interrupted'
        raise
    finally:
        session.save()
        session.export()
        events.emit('session.finished', status=session.state['status'], records=len(session.state['records']), path=str(path))


def session_command(a, events):
    state = json.loads((a.path/'session.json').read_text())
    if a.command == 'show':
        events.emit('session.info', path=str(a.path), state=state)
        return 0
    if state.get('mode') != 'repeated-windows-with-gaps':
        raise ValueError('session solve currently accepts sniff sessions only')
    session = Session(a.path, resume=True)
    session.recover_pending()
    events.path = a.path/'events.jsonl'
    code = 0
    for job in session.state['jobs']:
        if job['status'] == 'pending':
            code = max(code, solve(session, job, events))
    return code
