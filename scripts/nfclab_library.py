# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 NFClab contributors.
"""UID directories containing TOML metadata and Proxmark3 binary dumps."""
import json
import fcntl
from datetime import datetime
from zoneinfo import ZoneInfo
import os
from pathlib import Path
import re
import tomllib
import tempfile


def default_library():
    return Path(os.environ.get('NFCLAB_LIBRARY', 'library'))


def uid_name(uid):
    if not isinstance(uid, str) or not re.fullmatch(r'(?:[0-9a-fA-F]{8}|[0-9a-fA-F]{14}|[0-9a-fA-F]{20})', uid):
        raise ValueError('UID must be 4, 7 or 10 bytes of hex')
    return uid.upper()


DUMP_NAME = re.compile(r'dump(?:-([0-9]{3,}))?\.bin')


def dump_name(value):
    if not isinstance(value, str) or not DUMP_NAME.fullmatch(value):
        raise ValueError('invalid dump filename')
    return value


def toml_text(metadata):
    lines = []
    def table(values, path=(), header=None):
        if header:
            lines.append('\n'+header)
        for key, value in values.items():
            if isinstance(value, dict) or isinstance(value, list) and value and isinstance(value[0], dict):
                continue
            if isinstance(value, datetime):
                value = value.isoformat()
            lines.append(f'{json.dumps(key)} = {json.dumps(value, ensure_ascii=False)}')
        for key, value in values.items():
            child = path+(key,)
            label = '.'.join(json.dumps(part) for part in child)
            if isinstance(value, dict):
                table(value, child, '['+label+']')
            elif isinstance(value, list) and value and isinstance(value[0], dict):
                for entry in value:
                    table(entry, child, '[['+label+']]')
    table(metadata)
    return '\n'.join(lines)+'\n'


def write_metadata(directory, metadata):
    fd, temporary = tempfile.mkstemp(prefix='.card-', suffix='.tmp', dir=directory)
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(toml_text(metadata))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, directory/'card.toml')
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def decode_payload(raw, metadata):
    if len(raw) != 1024:
        raise ValueError('Classic 1K dump must contain 1024 bytes')
    missing_table = metadata.get('missing_keys', dict(keys=[]))
    if not isinstance(missing_table, dict) or 'keys' not in missing_table:
        raise ValueError('invalid missing_keys')
    missing = missing_table['keys']
    if not isinstance(missing, list) or any(not isinstance(k, str) or not re.fullmatch(r'(?:[0-9]|1[0-5])[AB]', k) for k in missing):
        raise ValueError('invalid missing_keys')
    block_table = metadata.get('missing_blocks', dict(blocks=[]))
    if not isinstance(block_table, dict) or 'blocks' not in block_table:
        raise ValueError('invalid missing_blocks')
    unknown_blocks = block_table['blocks']
    if not isinstance(unknown_blocks, list) or any(type(b) is not int or not 0 <= b < 64 for b in unknown_blocks):
        raise ValueError('invalid missing_blocks')
    slots = []
    for s in range(16):
        for t in (0, 1):
            offset = (s*4+3)*16 + (10 if t else 0)
            unknown = f'{s}{"AB"[t]}' in missing
            slots.append(dict(value=None if unknown else raw[offset:offset+6].hex(), state='unknown' if unknown else 'known'))
    return dict(blocks=[None if b in unknown_blocks else raw[b*16:(b+1)*16].hex() for b in range(64)], keys=slots)


def changes(before, after):
    blocks = []
    for b, (old, new) in enumerate(zip(before['blocks'], after['blocks'])):
        # Trailer key changes are reported separately; compare ACL/GPB bytes here.
        if b%4 == 3:
            old = old[12:20] if old is not None else None
            new = new[12:20] if new is not None else None
        if old != new:
            blocks.append(b)
    keys = [f'{i//2}{"AB"[i%2]}' for i, (old, new) in enumerate(zip(before['keys'], after['keys'])) if old != new]
    return dict(changed_blocks=blocks, changed_keys=keys)


class Library:
    def __init__(self, path=None):
        self.path = Path(path or default_library())
        self.index = {}
        self.scan()

    def scan(self):
        self.index = {}
        if self.path.exists():
            for directory in sorted(self.path.iterdir()):
                if directory.is_dir() and re.fullmatch(r'[0-9a-fA-F]{8}|[0-9a-fA-F]{14}|[0-9a-fA-F]{20}', directory.name):
                    uid = uid_name(directory.name)
                    if uid in self.index:
                        raise ValueError(f'duplicate UID directory: {uid}')
                    if (directory/'card.toml').exists():
                        self.index[uid] = self.load(directory)
        return self.index

    def load(self, directory, *, dump=None):
        with (directory/'card.toml').open('rb') as stream:
            metadata = tomllib.load(stream)
        uid = uid_name(directory.name)
        if uid_name(metadata.get('uid', uid)) != uid:
            raise ValueError(f'UID mismatch in {directory}')
        if 'versions' not in metadata:
            if 'current_dump' in metadata:
                raise ValueError('current_dump requires versions')
            # Adopt existing single-dump libraries without inventing a read time.
            version = dict(file='dump.bin', source='legacy')
            for key in ('missing_keys', 'missing_blocks'):
                if key in metadata:
                    version[key] = metadata.pop(key)
            metadata.update(current_dump='dump.bin', versions=[version])
        if 'missing_keys' in metadata or 'missing_blocks' in metadata:
            raise ValueError('missing_keys and missing_blocks belong to each version')
        versions = metadata['versions']
        if not isinstance(versions, list) or not versions or any(not isinstance(v, dict) for v in versions):
            raise ValueError('invalid versions')
        names = [dump_name(v.get('file')) for v in versions]
        if len(set(names)) != len(names):
            raise ValueError('duplicate version filename')
        current = dump_name(metadata.get('current_dump'))
        if current not in names:
            raise ValueError('current_dump is not a recorded version')
        selected = current if dump is None else dump_name(dump)
        if selected not in names:
            raise ValueError(f'version {selected} not found')
        version = versions[names.index(selected)]
        payload = decode_payload((directory/selected).read_bytes(), version)
        return dict(uid=uid, name=metadata.get('name', ''), metadata=metadata, payload=payload,
                    blocks_known=sum(b is not None for b in payload['blocks']),
                    keys_known=sum(k['state']=='known' for k in payload['keys']),
                    layout='classic-1k', path=str(directory), dump_file=selected)

    def card(self, uid, *, dump=None):
        uid = uid_name(uid)
        if uid not in self.index:
            raise ValueError(f'card {uid} not found')
        if dump is not None:
            return self.load(Path(self.index[uid]['path']), dump=dump)
        return self.index[uid]

    def keys(self, uid):
        slots = self.card(uid)['payload']['keys']
        if any(k['state'] != 'known' for k in slots):
            raise ValueError('selected card does not have all 32 known keys')
        return b''.join(bytes.fromhex(slots[s*2+t]['value']) for t in (0,1) for s in range(16))

    def known_keys(self, *, exclude_uid):
        exclude_uid = uid_name(exclude_uid)
        return list(dict.fromkeys(bytes.fromhex(key['value'])
            for uid, card in self.index.items() if uid != exclude_uid
            for key in card['payload']['keys'] if key['state'] == 'known'))

    def save(self, card, payload, *, fingerprint=None, inspection=None, name=None, source='read', parent_dump=None):
        uid = uid_name(card['uid'])
        if len(payload['blocks']) != 64 or len(payload['keys']) != 32:
            raise ValueError('Classic 1K requires 64 blocks and 32 keys')
        if source not in ('read', 'import', 'sim_write'):
            raise ValueError('invalid version source')
        if source == 'sim_write' and parent_dump is None:
            raise ValueError('sim_write requires the loaded parent_dump')
        if parent_dump is not None:
            dump_name(parent_dump)
        raw = bytearray()
        missing_blocks = []
        for b, value in enumerate(payload['blocks']):
            data = bytes.fromhex(value) if value is not None else bytes(16)
            if len(data) != 16:
                raise ValueError('block must contain 16 bytes')
            raw.extend(data)
            if value is None:
                missing_blocks.append(b)
        missing = []
        for s in range(16):
            for t in (0,1):
                key = payload['keys'][s*2+t]
                known = key['state']=='known' and key['value'] is not None
                data = bytes.fromhex(key['value']) if known else bytes(6)
                if len(data) != 6:
                    raise ValueError('key must contain 6 bytes')
                if not known:
                    missing.append(f'{s}{"AB"[t]}')
                offset = (s*4+3)*16+(10 if t else 0)
                raw[offset:offset+6] = data
        validity = {}
        if missing:
            validity['missing_keys'] = dict(keys=missing)
        if missing_blocks:
            validity['missing_blocks'] = dict(blocks=missing_blocks)
        normalized = decode_payload(bytes(raw), validity)
        directory = Path(self.index[uid]['path']) if uid in self.index else self.path/uid
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        # Lock the directory inode, so replacing card.toml does not replace the lock.
        lock = os.open(directory, os.O_RDONLY)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX)
            existing = self.load(directory) if (directory/'card.toml').exists() else None
            metadata = dict(existing['metadata']) if existing else dict(uid=uid, card_type='MIFARE Classic 1K')
            metadata.setdefault('name', '')
            versions = list(metadata.get('versions', []))
            current = metadata.get('current_dump')
            parent = parent_dump if parent_dump is not None else current
            before = self.load(directory, dump=parent) if parent is not None else None
            if source == 'sim_write' and (before is None or validity or before['blocks_known'] != 64 or before['keys_known'] != 32):
                raise ValueError('sim_write requires an existing parent and complete data and keys')
            # A failed/partial observation must not replace or merge an existing state.
            if existing and validity:
                self.index[uid] = existing
                return dict(path=str(directory), dump_file=current, parent_dump=current, status='incomplete', version_created=False,
                            changed_blocks=[], changed_keys=[])
            for key in ('atqa', 'sak'):
                if card.get(key) is not None:
                    metadata[key] = card[key]
            if name is not None:
                metadata['name'] = name
            if fingerprint:
                metadata['chip_fingerprint'] = fingerprint['label']
            if inspection:
                metadata['nonce_type'] = inspection.get('nonce', {}).get('nonce', 'unknown')
                metadata['prng'] = inspection.get('nonce', {}).get('prng', 'unknown')
                metadata['magic'] = inspection.get('magic', {}).get('label', 'unknown')
            now = datetime.now(ZoneInfo('Asia/Kuching')).isoformat(timespec='microseconds')
            difference = changes(before['payload'], normalized) if before else dict(changed_blocks=[], changed_keys=[])
            created = before is None or bool(difference['changed_blocks'] or difference['changed_keys'])
            if created:
                numbers = [int(match.group(1) or 0) for path in directory.iterdir()
                           if (match := DUMP_NAME.fullmatch(path.name))]
                numbers += [int(DUMP_NAME.fullmatch(v['file']).group(1) or 0) for v in versions]
                filename = f'dump-{max(numbers)+1:03d}.bin' if numbers else 'dump.bin'
                # Never truncate an existing version, including files not in the manifest.
                fd = os.open(directory/filename, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(raw)
                    stream.flush()
                    os.fsync(stream.fileno())
                # Ensure the BIN directory entry is durable before committing its manifest.
                os.fsync(lock)
                version = dict(file=filename, source=source, created_at=now, **validity)
                if parent is not None:
                    version.update(parent_dump=parent, **difference)
                versions.append(version)
                metadata.update(current_dump=filename, versions=versions)
            else:
                filename = current
            if source == 'read':
                metadata['last_seen_at'] = now
            write_metadata(directory, metadata)
            os.fsync(lock)
            self.index[uid] = self.load(directory)
            return dict(path=str(directory), dump_file=filename, parent_dump=parent, status='created' if created else 'unchanged',
                        version_created=created, **difference)
        finally:
            os.close(lock)

    def import_dump(self, uid, path, keys_known=False):
        raw = Path(path).read_bytes()
        if len(raw) != 1024:
            raise ValueError('Classic 1K dump must contain 1024 bytes')
        slots = [dict(value=raw[(s*4+3)*16+(10 if t else 0):(s*4+3)*16+(10 if t else 0)+6].hex() if keys_known else None,
                      state='known' if keys_known else 'unknown') for s in range(16) for t in (0,1)]
        return self.save(dict(uid=uid), dict(blocks=[raw[b*16:(b+1)*16].hex() for b in range(64)], keys=slots), source='import')


def session_content(state):
    slots = [dict(value=k['key'], state='known' if k['key'] and (k['authenticated'] or k['provenance']=='readable-trailer') else 'unknown') for k in state['keys']]
    return dict(blocks=state['blocks'], keys=slots)


def command(a, events):
    library = Library(a.library)
    if a.command == 'list':
        events.emit('library.cards', cards=[dict(
            uid=c['uid'], name=c['name'], card_type=c['metadata'].get('card_type', 'MIFARE Classic 1K'),
            versions=len(c['metadata']['versions']), blocks_known=c['blocks_known'], keys_known=c['keys_known'])
            for c in library.index.values()])
    elif a.command == 'show':
        events.emit('library.card', card=library.card(a.uid))
    elif a.command == 'import':
        result = library.import_dump(a.uid, a.path, a.keys_known)
        events.emit('library.imported', **result)
    return 0
