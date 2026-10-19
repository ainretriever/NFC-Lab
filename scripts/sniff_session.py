# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 NFClab contributors.
"""Durable accumulation and bounded pairing of independent sniff windows."""
import json
import os
from pathlib import Path
import re
import subprocess
import time
from sniff_mfkey import extract_auth, solver_inputs


def atomic_json(path, value):
    path = Path(path)
    temporary = path.with_name(path.name+'.tmp')
    with temporary.open('w') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def fingerprint(record):
    return tuple(record[f] for f in ('uid', 'cuid', 'sector', 'key_type', 'nt', 'nr_enc', 'ar_enc'))


def domain(record):
    return tuple(record[f] for f in ('uid', 'cuid', 'sector', 'key_type'))


class Session:
    def __init__(self, directory, *, resume=False, pair_depth=8):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.path = self.directory/'session.json'
        if self.path.exists():
            if not resume:
                raise ValueError('session exists; use --resume')
            self.state = json.loads(self.path.read_text())
            if self.state['version'] != 1:
                raise ValueError('unsupported session version')
        else:
            if resume:
                raise ValueError('no session to resume')
            if any(self.directory.iterdir()):
                raise ValueError('new session requires an empty output directory')
            self.state = dict(version=1, mode='repeated-windows-with-gaps', pair_depth=pair_depth,
                              attempts=[], records=[], jobs=[], candidate_keys=[],
                              duplicates=0, conflicts=0, rejections=[], status='ready')
        if not 1 <= self.state['pair_depth'] <= 64:
            raise ValueError('pair depth must be 1..64')
        self._indices = {fingerprint(r): i for i, r in enumerate(self.state['records'])}
        self._jobs = {(j['tool'], tuple(j['args'])) for j in self.state['jobs']}
        self.save()

    def save(self):
        atomic_json(self.path, self.state)

    def reserve(self):
        index = len(self.state['attempts'])+1
        prefix = self.directory/f'capture-{index:06d}'
        if any(prefix.with_suffix(suffix).exists() for suffix in ('.json', '.bin', '.frames.json')):
            raise ValueError('capture path collision')
        event = dict(index=index, prefix=prefix.name, status='pending',
                     started_unix=time.time())
        self.state['attempts'].append(event)
        self.state['status'] = 'running'
        self.save()
        return prefix, event

    def _add_job(self, job):
        identity = (job['tool'], tuple(job['args']))
        if identity not in self._jobs:
            self._jobs.add(identity)
            self.state['jobs'].append(dict(job, status='pending'))

    def _queue(self, index):
        records = self.state['records']
        r = records[index]
        for job in solver_inputs([r]):
            self._add_job(dict(job, records=[index]))
        previous = [i for i in range(index) if domain(records[i]) == domain(r)]
        for i in previous[-self.state['pair_depth']:]:
            for job in solver_inputs([records[i], r]):
                if len(job['records']) == 2:
                    self._add_job(dict(job, records=[i, index]))

    def add_records(self, records):
        added = 0
        for record in records:
            identity = fingerprint(record)
            if identity in self._indices:
                index = self._indices[identity]
                existing = self.state['records'][index]
                conflict = any(existing['parity_bits'][f] != record['parity_bits'][f]
                               for f in ('nt', 'nr_ar'))
                conflict |= bool(existing['at_enc'] and record['at_enc'] and
                                 (existing['at_enc'] != record['at_enc'] or
                                  existing['parity_bits']['at'] != record['parity_bits']['at']))
                if conflict:
                    self.state['conflicts'] += 1
                    self.state['rejections'].append(dict(source=record['source'], reason='duplicate-parity-or-at-conflict'))
                    continue
                self.state['duplicates'] += 1
                if not existing['at_enc'] and record['at_enc']:
                    existing['at_enc'] = record['at_enc']
                    existing['parity_bits']['at'] = record['parity_bits']['at']
                    existing['at_source'] = record['source']
                    self._queue(index)
                continue
            index = len(self.state['records'])
            self._indices[identity] = index
            self.state['records'].append(record)
            self._queue(index)
            added += 1
        return added

    def ingest(self, event, meta, frames):
        event.update(finished_unix=time.time(), firmware_status=meta['status'], frames=len(frames),
                     download_ms=meta.get('download_ms'), host_capture_ms=meta.get('host_capture_ms'),
                     dma_errors=meta['dma_flags'] & 0x340, cleanup_error=meta['cleanup_error'])
        if meta.get('analysis_error'):
            event.update(status='decode-error', reason=meta['analysis_error'], added=0)
        elif meta['status'] == 3 and not event['dma_errors'] and not event['cleanup_error']:
            event.update(status='idle-timeout', added=0)
        elif meta['status'] != 2 or event['dma_errors'] or event['cleanup_error']:
            event.update(status='capture-error', added=0)
        else:
            rejections = []
            records = extract_auth(frames, event['prefix'], rejections)
            self.state['rejections'].extend(rejections)
            event.update(status='captured' if records else 'no-auth',
                         added=self.add_records(records), authentications=len(records))
        self.save()

    def recover_pending(self):
        for event in self.state['attempts']:
            if event['status'] != 'pending':
                continue
            prefix = self.directory/event['prefix']
            try:
                meta = json.loads(prefix.with_suffix('.json').read_text())
                frames = json.loads(prefix.with_suffix('.frames.json').read_text())
                self.ingest(event, meta, frames)
                event['recovered_after_restart'] = True
            except (FileNotFoundError, json.JSONDecodeError):
                event.update(status='interrupted', added=0)
        for job in self.state['jobs']:
            if job['status'] == 'running':
                job['status'] = 'pending'
        self.save()

    def solve_pending(self, solver_directory, *, limit=8, timeout=30):
        attempted = 0
        for job in self.state['jobs']:
            if job['status'] != 'pending' or attempted >= limit:
                continue
            executable = Path(solver_directory)/job['tool']
            if not executable.is_file():
                raise ValueError(f'missing solver: {executable}; run make host-mfkey')
            job['status'] = 'running'
            self.save()
            attempted += 1
            try:
                result = subprocess.run([str(executable), *job['args']], capture_output=True,
                                        text=True, timeout=timeout)
                keys = re.findall(r'Found Key:\s*\[([0-9a-fA-F]{12})\]', result.stdout)
                job['status'] = 'candidate' if result.returncode == 0 and keys else 'no-key'
                job['returncode'] = result.returncode
                for key in keys if job['status'] == 'candidate' else []:
                    record = self.state['records'][job['records'][0]]
                    entry = dict(uid=record['uid'], cuid=record['cuid'], sector=record['sector'],
                                 key_type=record['key_type'], key=key.upper())
                    if entry not in self.state['candidate_keys']:
                        self.state['candidate_keys'].append(entry)
            except subprocess.TimeoutExpired:
                job['status'] = 'solver-timeout'
            self.save()

    def export(self):
        atomic_json(self.directory/'mfkey-inputs.json', dict(version=1,
                    records=self.state['records'], solver_inputs=self.state['jobs']))
        atomic_json(self.directory/'candidate-keys.json', self.state['candidate_keys'])
