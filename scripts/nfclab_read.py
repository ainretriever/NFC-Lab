# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 NFClab contributors.
"""Scoped adapter around the existing recovery session; no duplicate algorithms."""
from m1_read_session import ReadSession
from sniff_session import atomic_json
import json
import time


class CliReadSession(ReadSession):
    def __init__(self, path, card, *, blocks, resume=False, builtin=None, events=None, auth_timeout_us=200, cpus=None):
        from solvers.hardnested import resolve_cpus
        self.solver_cpus = resolve_cpus(cpus)
        self.blocks = set(blocks)
        self.sectors = sorted({b//4 for b in blocks})
        self.events = events
        self._table_elapsed = {s: 0.0 for s in self.sectors}
        self._table_working = set()
        self._table_methods = {}
        self._table_activity = {}
        scope = dict(blocks=sorted(self.blocks), recovery_only=False)  # Retain saved read-session compatibility.
        if resume:
            from pathlib import Path
            saved = json.loads((Path(path)/'session.json').read_text())
            if saved.get('cli_scope') != scope:
                raise ValueError('resume scope differs from saved session')
        super().__init__(path, card, resume=resume, builtin=builtin,
                         auth_timeout_us=auth_timeout_us)
        self.state['cli_scope'] = scope
        self.state['solver_cpus'] = self.solver_cpus
        self.save()

    def event(self, phase, message):
        if not self.events:
            return super().event(phase, message)
        self.state['phase'] = phase
        self.state['events'].append(dict(phase=phase, message=message, time=time.time()))
        self.save()
        self.progress(phase, message=message, _note=True)

    def table_rows(self):
        """Describe only selected sectors; sources are ordered A then B."""
        names = {'common-dictionary': 'dictionary', 'user-dictionary': 'dictionary',
                 'builtin-dictionary': 'dictionary', 'provided-keys': 'provided',
                 'cached-keys': 'cached', 'uid-cache': 'cached', 'library-keys': 'library', 'key-reuse': 'reuse', 'readable-trailer': 'trailer',
                 'sen-derived': 'sen'}
        rows = []
        final = self.state['status'] != 'running'
        for sector in self.sectors:
            keys = self.state['keys'][sector*2:sector*2+2]
            sources = [(names.get(k['provenance'], k['provenance']) or '?')
                       if k['key'] else '-' for k in keys]
            source = '/'.join(sources)
            blocks = [b for b in self.blocks if b//4 == sector]
            complete = all(k['key'] for k in keys) and all(self.state['blocks'][b] is not None for b in blocks)
            status = ('complete' if complete else
                      'incomplete' if final else
                      'processing' if sector in self._table_working else 'pending')
            rows.append(dict(sector=sector, key_a=keys[0]['key'], key_b=keys[1]['key'],
                             source=source, status=status, elapsed_s=self._table_elapsed[sector],
                             activity=dict(self._table_activity.get(sector, {}))))
        return rows

    def progress(self, phase, **details):
        note = details.pop('_note', False)
        if details.get('step') == 'recovered' and 'sector' in details:
            self._table_elapsed[details['sector']] += details.get('elapsed_s', 0)
        dictionaries = ('provided-keys', 'cached-keys', 'uid-cache', 'library-keys', 'common-dictionary',
                        'user-dictionary', 'builtin-dictionary', 'key-reuse')
        if phase == 'hardnested' and details.get('step') == 'benchmark':
            pass  # CPU benchmark is header metadata, not a target stage.
        elif phase in dictionaries:
            self._table_working = ({s for s in self.sectors if self.pending() & (3 << (s*2))}
                                   if details.get('step') != 'complete' else set())
            for sector in self._table_working:
                self._table_methods[sector] = 'reuse' if phase == 'key-reuse' else 'dictionary'
        elif phase in ('nested', 'hardnested', 'sen', 'static-nested') and 'sector' in details:
            sector = details['sector']
            self._table_working = {sector} if details.get('step') not in ('recovered', 'limit', 'unresolved') else set()
            previous = self._table_methods.get(sector)
            self._table_methods[sector] = details.get('method') or (
                previous if phase == 'nested' and previous in ('nested', 'static-nested', 'sen') else phase)
            activity = dict(details, method=self._table_methods[sector])
            if activity['method'] == 'hardnested' and details.get('step') in ('capture', 'reduce'):
                prior = self._table_activity.get(sector, {})
                if (prior.get('method') == 'hardnested' and prior.get('step') == 'collect'
                        and prior.get('key_type') == details.get('key_type')):
                    activity = dict(prior, **activity)
                    # Reducer acknowledgements can lag behind RF capture.
                    for name in ('samples', 'first_bytes'):
                        activity[name] = max(prior.get(name, 0), details.get(name, 0))
                activity['step'] = 'collect'
                if details.get('step') == 'reduce':
                    activity['reduced_samples'] = details.get('samples', 0)
            self._table_activity[sector] = activity
        elif 'step' not in details and (
                phase in ('pair', 'sen', 'static-nested') or
                (phase == 'unresolved' and any(
                    self._table_activity.get(s, {}).get('step') == 'pair'
                    for s in self._table_working))):
            # Explanatory session notes are not stage transitions. In
            # particular, pairing notes must not erase pair before verify;
            # a throttled redraw could otherwise stay blank for an RF batch.
            pass
        elif phase == 'read':
            self._table_working = ({s for s in self.sectors
                if any(self.state['keys'][s*2+t]['authenticated'] for t in (0, 1))
                and any(self.state['blocks'][b] is None for b in self.blocks if b//4 == s)}
                if details.get('step') != 'complete' else set())
        elif note and phase not in ('finished', 'failed', 'interrupted', 'unresolved', 'recovery-unavailable'):
            # Logging a note must not end a structured recovery stage. This
            # also covers calibration/capture notes, not just solver notes.
            pass
        else:
            self._table_working = set()
        if self.events:
            known = sum(bool(self.state['keys'][s*2+t]['key']) for s in self.sectors for t in (0, 1))
            read = sum(self.state['blocks'][b] is not None for b in self.blocks)
            self.events.emit('operation.progress', operation='read', phase=phase,
                             blocks_read=read, blocks_total=len(self.blocks),
                             keys_known=known, keys_total=len(self.sectors)*2,
                             sectors=self.table_rows(), **details)

    def search(self, keys, provenance, *, targets=None):
        active = bool(keys and self.pending() & (targets if targets is not None else self.pending()))
        before = [k['key'] for k in self.state['keys']]
        started = time.monotonic()
        result = (super().search(keys, provenance) if targets is None else
                  super().search(keys, provenance, targets=targets))
        if active:
            elapsed = time.monotonic() - started
            for sector in self.sectors:
                if any(before[sector*2+t] != self.state['keys'][sector*2+t]['key'] for t in (0, 1)):
                    self._table_elapsed[sector] += elapsed
            self.progress(provenance, step='complete')
        return result

    def reuse_card(self, payload):
        # Group equal keys, but authenticate only their original sector/type slots.
        targets = {}
        for slot, key in enumerate(payload['keys']):
            if key['state'] == 'known' and self.pending() & (1 << slot):
                value = bytes.fromhex(key['value'])
                targets[value] = targets.get(value, 0) | (1 << slot)
        added = []
        for key, mask in targets.items():
            added.extend(self.search([key], 'uid-cache', targets=mask))
        self.advance(added)

    def pending(self):
        targets = sum(3 << (s*2) for s in self.sectors)
        return super().pending() & targets

    def read_available(self):
        before = self.state['blocks_read']
        self._read_available()
        if self.state['blocks_read'] != before:
            self.progress('read', step='complete')

    def _read_available(self):
        if self.blocks == set(range(64)):
            return super().read_available()
        self.refresh_trailers()
        from m1_host import read_live
        for sector in self.sectors:
            wanted = sorted(self.blocks & set(range(sector*4, sector*4+4)))
            if all(self.state['blocks'][b] is not None for b in wanted):
                continue
            known = [t for t in (0, 1) if self.state['keys'][sector*2+t]['authenticated']]
            if not known:
                continue
            if len(wanted) == 4:
                self.read_group([sector], 2 if len(known) == 2 else known[0])
            else:
                keys = self.sector_keys([sector])
                for block in wanted:
                    if self.state['blocks'][block] is not None:
                        continue
                    for t in known:
                        try:
                            raw = read_live(block, keys, self.card['cuid'], t)
                        except RuntimeError as error:
                            self.state['block_errors'][block] = str(error)
                        else:
                            self.state['blocks'][block] = raw.hex()
                            self.state['block_errors'][block] = None
                            if block % 4 == 3:
                                self.stale_trailers.discard(sector)
                                self.accept_trailer(sector)
                            break
                    self.save()

    def accept_trailer(self, sector):
        started = time.monotonic()
        added = super().accept_trailer(sector)
        if added:
            self._table_elapsed[sector] += time.monotonic() - started
        return added

    def finish(self):
        self.export()
        complete = not self.pending()
        complete = complete and all(self.state['blocks'][b] is not None for b in self.blocks)
        self.state['status'] = 'complete' if complete else 'partial'
        self.event('finished', self.state['status'])

    def export(self):
        super().export()
        if self.path is None:
            return
        atomic_json(self.path/'keys.json', dict(card=self.card, keys=self.state['keys']))
        atomic_json(self.path/'blocks.json', dict(card=self.card, scope=sorted(self.blocks),
                                                blocks=self.state['blocks'], errors=self.state['block_errors']))
