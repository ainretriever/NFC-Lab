# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 NFClab contributors.
"""Persistent hardnested worker: incremental constraints, then same-state solving."""
import hashlib
import json
import math
import os
from pathlib import Path
import queue
import subprocess
import threading
import time

from solvers.hardnested import backend_paths, inspect_nonces, validate_record, resolve_cpus


class IncrementalSolver:
    """One bounded outstanding reduction; stdout drained concurrently to disk."""

    def __init__(self, output, *, solver=None, resources=None, cpus=None, timeout=600):
        cpus = resolve_cpus(cpus)
        options = {}
        if solver is not None:
            options['solver'] = solver
        if resources is not None:
            options['resources'] = resources
        backend, resources = backend_paths(**options)
        if not 1 <= cpus <= 256 or not math.isfinite(timeout) or timeout <= 0:
            raise ValueError('invalid stream worker limits')
        self.output, self.timeout = Path(output), timeout
        self.backend = backend
        self.started = time.monotonic()
        self.log_path = self.output / 'solver.log'
        self.log = self.log_path.open('w')
        os.chmod(self.log_path, 0o600)
        self.messages = queue.Queue()
        self.pending = False
        self.configured = False
        self.last_state = None
        self.benchmark = None
        self.keys = []
        argv = [str(backend), '--stream', str(resources), str(cpus), 'v1']
        try:
            self.process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                            stderr=subprocess.STDOUT, text=True, bufsize=1)
        except BaseException:
            self.log.close()
            raise
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()

    def _read(self):
        try:
            for line in self.process.stdout:
                self.log.write(line)
                self.log.flush()
                if line.startswith('NFCLAB_STATE='):
                    self.messages.put(json.loads(line.partition('=')[2]))
                if line.startswith('NFCLAB_KEY='):
                    self.keys.append(line.strip().partition('=')[2])
        except BaseException as error:
            self.messages.put(error)
        finally:
            self.messages.put('eof')

    def _message(self, block=True):
        try:
            message = self.messages.get(timeout=self.timeout if block else 0)
        except queue.Empty:
            if not block:
                return None
            raise subprocess.TimeoutExpired('hardnested stream', self.timeout) from None
        if isinstance(message, BaseException):
            raise RuntimeError(f'invalid stream response: {message}')
        if message == 'eof':
            raise RuntimeError(f'incremental worker exited; see {self.log_path}')
        return message

    def start(self, uid):
        if self.configured or not 0 <= uid <= 0xffffffff:
            raise ValueError('invalid or repeated stream configuration')
        ready = self._message()
        if not ready.get('ready'):
            raise RuntimeError('worker did not send readiness acknowledgement')
        if all(key in ready for key in ('rate', 'cpus', 'simd')):
            rate, cpus, simd = ready['rate'], ready['cpus'], ready['simd']
            if (not isinstance(rate, (int, float)) or not math.isfinite(rate) or rate <= 0
                    or not isinstance(cpus, int) or not 1 <= cpus <= 256
                    or simd not in ('AVX512', 'AVX2', 'AVX', 'SSE2', 'MMX', 'NEON', 'scalar')):
                raise RuntimeError('invalid hardnested benchmark acknowledgement')
            self.benchmark = dict(keys_per_second=rate, cpus=cpus, simd=simd)
        self.process.stdin.write(f'CUID {uid:08x}\n')
        self.process.stdin.flush()
        self.configured = True
        self.uid = uid
        return ready

    def submit(self, records, period_ms):
        if not self.configured or self.pending or not 1 <= len(records) <= 1000:
            raise RuntimeError('stream not configured, busy, or invalid batch')
        rows = [validate_record(record) for record in records]
        period_ms = max(1, min(3600000, round(period_ms)))
        payload = f'BATCH {len(rows)} {period_ms}\n'
        payload += ''.join(f'{nonce:08x} {parity:x}\n' for nonce, parity in rows)
        self.process.stdin.write(payload)
        self.process.stdin.flush()
        self.pending = True

    def receive(self, *, block=True):
        if not self.pending:
            return None
        state = self._message(block)
        if state is not None:
            required = ('raw', 'unique', 'first_bytes', 'states', 'stop', 'reason')
            if any(key not in state for key in required):
                raise RuntimeError('incomplete reduction acknowledgement')
            self.pending = False
            self.last_state = state
        return state

    def finish(self, path):
        if not self.configured or self.pending:
            raise RuntimeError('cannot finish an unconfigured or busy reducer')
        data = Path(path).read_bytes()
        info = inspect_nonces(data)
        if info['cuid'] != self.uid:
            raise RuntimeError('stream evidence identity does not match configured CUID')
        if not self.last_state or self.last_state['raw'] != info['samples']:
            raise RuntimeError('stream evidence count does not match saved evidence')
        if info['first_bytes'] != 256:
            raise RuntimeError('insufficient first-byte coverage; evidence retained')
        started = time.monotonic()
        self.process.stdin.write('FINISH\n')
        self.process.stdin.flush()
        self.process.stdin.close()
        try:
            self.process.wait(timeout=self.timeout)
        except (subprocess.TimeoutExpired, KeyboardInterrupt):
            self.close()
            raise
        self.reader.join(timeout=5)
        keys = set(self.keys)
        if self.process.returncode or len(keys) != 1 or any(
                len(k) != 12 or any(c not in '0123456789abcdef' for c in k) for k in keys):
            raise RuntimeError(f'incremental solver did not recover one key; see {self.log_path}')
        return dict(backend='nfclab-hardnested-pm3-core-stream', executable=str(self.backend),
                    key=keys.pop(), elapsed_s=time.monotonic() - started,
                    worker_elapsed_s=time.monotonic() - self.started,
                    log=str(self.log_path.resolve()), evidence=info,
                    evidence_sha256=hashlib.sha256(data).hexdigest(),
                    solver_sha256=hashlib.sha256(self.backend.read_bytes()).hexdigest(),
                    target_key_supplied=False, source_key_supplied=False)

    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
        self.reader.join(timeout=5)
        for stream in (self.process.stdin, self.process.stdout, self.log):
            if not stream.closed:
                stream.close()

    def __enter__(self):
        return self

    def __exit__(self, *unused):
        self.close()
