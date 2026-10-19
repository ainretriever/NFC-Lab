# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 NFClab contributors.
"""Adapters for retained Classic operations."""
import time
from nfclab_cli import default_output
from sniff_session import atomic_json


def key_file(path):
    data = path.read_bytes()
    if len(data) != 192:
        raise ValueError('keys must contain 192 bytes: 16 Key A then 16 Key B')
    return data


def fresh(a, events):
    path = a.output or default_output(a.group, a.command)
    path.mkdir(parents=True, exist_ok=False, mode=0o700)
    events.path = path/'events.jsonl'
    events.emit('session.started', path=str(path), operation=a.command)
    return path


def run(a, events):
    from m1_recover_host import identify
    card = identify()
    fingerprint = None
    inspection, probe_profile = None, None
    if a.group == 'tag' or a.command == 'read':
        from m1_fingerprint import detect
        supplied = key_file(a.keys) if getattr(a, 'keys', None) else None
        candidates = [supplied[:6], supplied[96:102]] if supplied else []
        if getattr(a, 'key', None):
            candidates.append(a.key)
        fingerprint = detect(card, candidates)
        from m1_inspection import inspect
        inspection, probe_profile = inspect(card, candidates,
                                           write_probe_type=int(getattr(a,'key_type','A')=='B'),
                                           allow_write_probe=not getattr(a,'no_write_probe',False),
                                           force_write_probe=getattr(a,'magic_write_probe',False))
    events.emit('tag.info', **card, supported_family='Classic 1K',
                **({'operation': 'read'} if a.command == 'read' else {}),
                **({'fingerprint': fingerprint, 'inspection': inspection} if fingerprint else {}))
    if a.group == 'tag' and a.command == 'info':
        return 0
    if a.command == 'auth':
        if a.uid and int.from_bytes(a.uid, 'big') != card['cuid']:
            raise ValueError('identified card does not match --uid')
        from m1_keys_host import run_keys
        result = run_keys([a.key], card['cuid'], block=a.block, key_type=int(a.key_type == 'B'))
        matched = result['complete'] and result['status'][0] == 'matched'
        events.emit('key.verified', uid=card['uid'], block=a.block, key_type=a.key_type, verified=matched, report=result)
        return 0 if matched else 1
    if a.command == 'dump':
        return dump(a, card, events)
    if a.command == 'read':
        return read(a, card, events, fingerprint=fingerprint, inspection=inspection, probe_profile=probe_profile)
    return keys(a, card, events)


def dump(a, card, events):
    from nfclab_library import Library
    from m1_read_session import dump_module
    from m1_write_review import access_conditions, TRAILER_ACCESS
    from nfclab_write import check_key
    path = a.output or default_output(a.group, a.command)
    if path.exists():
        raise ValueError('output already exists')
    library = Library(a.library)
    keys = library.keys(a.card) if getattr(a, 'card', None) else key_file(a.keys)
    raw, report = dump_module.read_batch(keys, card['cuid'], key_type=['A', 'B', 'auto'].index(a.key_type), allow_partial=True)
    valid = int(report['valid_bitmap'], 16)
    blocks = [raw[b*16:(b+1)*16].hex() if valid & (1<<b) else None for b in range(64)]
    slots = []
    for sector in range(16):
        for t in (0,1):
            key = keys[(t*16+sector)*6:(t*16+sector+1)*6]
            known = check_key(key, card['cuid'], sector*4, t)
            slots.append(dict(value=key.hex(), state='known' if known else 'unknown'))
        trailer = blocks[sector*4+3]
        if trailer and slots[sector*2]['state']=='known':
            data = bytes.fromhex(trailer)
            errors, groups = access_conditions(data)
            if not errors and TRAILER_ACCESS[groups[3]][3]:
                slots[sector*2+1] = dict(value=data[10:].hex(), state='known')
        events.emit('operation.progress', operation='dump', phase='verify-keys', sector=sector,
                    keys_checked=(sector+1)*2, blocks_read=sum(b is not None for b in blocks), blocks_total=64)
    # Dump is an explicit export; tag read is the formal library saving operation.
    exported = Library(path).save(card, dict(blocks=blocks, keys=slots))
    complete = valid == (1<<64)-1 and report['error']==0
    events.emit('operation.finished', operation='dump', status='complete' if complete else 'partial', path=exported['path'], dump_file=exported['dump_file'],
                blocks_read=sum(b is not None for b in blocks), keys_known=sum(k['state']=='known' for k in slots))
    return 0 if complete else 4


def read(a, card, events, fingerprint=None, inspection=None, probe_profile=None):
    from nfclab_library import Library, session_content
    from m1_read_session import BUILTIN
    from m1_keys_host import parse_dictionary
    from nfclab_read import CliReadSession
    started = time.monotonic()
    library = Library(a.library)
    dictionaries = [parse_dictionary(p) for p in a.dictionary]
    initial = key_file(a.keys) if a.keys else None
    blocks = [a.block] if getattr(a, 'block', None) is not None else list(range(a.sector*4,a.sector*4+4)) if a.sector is not None else list(range(64))
    path = a.resume or a.output
    session = CliReadSession(path, card, blocks=blocks, resume=bool(a.resume),
        builtin=BUILTIN if a.builtin_dictionary else None, events=events,
        auth_timeout_us=a.auth_timeout_us, cpus=a.cpus)
    session.probe_profile = probe_profile
    session.recovery_artifacts = path or library.path.parent/'recovery'/card['uid'].upper()
    if fingerprint:
        session.state['fingerprint'] = fingerprint
    if inspection:
        session.state['inspection'] = inspection
    session.save()
    if path:
        events.path = path/'events.jsonl'
    events.emit('session.started', operation='read', path=str(path or library.path), scope=blocks, sectors=session.table_rows())
    try:
        if not a.no_uid_cache and card['uid'].upper() in library.index:
            session.reuse_card(library.card(card['uid'])['payload'])
        if initial:
            session.advance(session.search([initial[i:i+6] for i in range(0,192,6)], 'provided-keys'))
        if a.cross_card_keys:
            state = session.run(dictionaries, cross_card_keys=library.known_keys(exclude_uid=card['uid']))
        else:
            state = session.run(dictionaries)
    except BaseException as error:
        session.state['status'] = 'interrupted' if isinstance(error, KeyboardInterrupt) else 'failed'
        session.export()
        raise
    saved = library.save(card, session_content(state), fingerprint=fingerprint, inspection=inspection)
    events.emit('operation.finished', operation='read', status=state['status'], uid=card['uid'].upper(),
        blocks_read=sum(state['blocks'][b] is not None for b in blocks), blocks_total=len(blocks),
        keys_known=sum(session_content(state)['keys'][s*2+t]['state']=='known' for s in session.sectors for t in (0,1)),
        keys_total=len(session.sectors)*2, elapsed_s=time.monotonic()-started, path=saved['path'],
        dump_file=saved['dump_file'], parent_dump=saved['parent_dump'], library_status=saved['status'], version_created=saved['version_created'],
        changed_blocks=saved['changed_blocks'], changed_keys=saved['changed_keys'],
        unread_sectors=[s for s in session.sectors if any(state['blocks'][b] is None for b in blocks if b//4==s)])
    return 0 if state['status']=='complete' else 4


def keys(a, card, events):
    from m1_keys_host import parse_dictionary, run_keys, dictionary
    candidates = a.key or parse_dictionary(a.dictionary, a.binary)
    path = fresh(a, events)
    if a.keys_command == 'check':
        result = run_keys(candidates, card['cuid'], block=a.block, key_type=int(a.key_type == 'B'))
        success = result['complete'] and any(s == 'matched' for s in result['status'])
    else:
        sectors = [a.sector] if a.sector is not None else range(16)
        types = (0, 1) if a.key_type == 'both' else (int(a.key_type == 'B'),)
        targets = sum(1 << (s*2+t) for s in sectors for t in types)
        result = dictionary(candidates, card['cuid'], targets)
        success = result['complete'] and result['all_found']
    atomic_json(path/'report.json', dict(card=card, **result))
    events.emit('operation.finished', report=result, path=str(path))
    return 0 if success else 4


def write(a, events):
    if getattr(a, 'write_wizard', False):
        from nfclab_write_wizard import wizard
        return wizard(a, events)
    if getattr(a, "card", None) is not None:
        from nfclab_write import card_write
        return card_write(a, events)
    return single_write(a, events)


def single_write(a, events):
    from m1_host import key_for, request, ERRORS
    from m1_write_review import analyse_write
    from nfclab_runtime import connection, reader_mode
    from m1_recover_host import identify
    if a.output and a.output.exists():
        raise ValueError('output already exists')
    card_type = getattr(a,'card_type',None) or 'standard'
    if card_type == 'gen1a':
        key = bytes(6)
    elif a.key is not None:
        key = a.key
    else:
        if getattr(a, 'target_card', None):
            from nfclab_library import Library
            target_keys = Library(a.library).keys(a.target_card)
        else:
            target_keys = key_file(a.keys)
        key = key_for(target_keys, a.block, int(a.key_type == 'B'))
    if a.preview:
        print(f"块 {a.block} · {card_type} · UID {a.uid.hex().upper() if a.uid else '自动识别'}")
        print('数据：'+a.data.hex(' ').upper())
        for line in analyse_write(a.block,a.data):
            if getattr(a,'verbose',False) or line.startswith(('[Warning]','[Alert]','[Encoding error]')):
                print(line)
        events.emit('write.preview',block=a.block,submitted=False)
        return 0
    with connection(a):
        reader_mode()
        if a.uid is None:
            a.uid = bytes.fromhex(identify()['uid'])
            if len(a.uid) != 4:
                raise ValueError('single-block write currently requires a 4-byte target UID')
        uid = int.from_bytes(a.uid, 'big')
        # The complete block command itself authorizes this submission.
        words = request(5 if card_type == 'gen1a' else 2,a.block,int(a.key_type=='B'),
                        key,uid,bytes(16),a.data,confirmed=True)
    result = dict(card_type=card_type,uid=a.uid.hex(),block=a.block,data=a.data.hex(),completed=words[31],
                  error=ERRORS[words[36]] if words[36]<len(ERRORS) else words[36],
                  acks=words[114],verification='card-ACK-only')
    if a.output:
        path = fresh(a, events)
        atomic_json(path/'report.json',result)
    events.emit('operation.finished',operation='write',**result)
    return 0 if words[31]==1 and not words[36] else 1
