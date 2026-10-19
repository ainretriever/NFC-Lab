# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 NFClab contributors.
"""Card write planning and verified execution; source and target keys differ."""
import os
import time
from nfclab_library import Library


def check_key(key, uid, block, key_type):
    from m1_keys_host import run_keys
    report = run_keys([key],uid,block=block,key_type=key_type)
    if not report['complete']:
        raise RuntimeError('inconclusive target key authentication')
    return report['status'][0]=='matched'


def plan_card(source, *, block=None, include_uid=False):
    if source['layout']!='classic-1k':
        raise ValueError('source layout is not supported')
    payload = source['payload']
    wanted = [block] if block is not None else list(range(0 if include_uid else 1,64))
    if 0 in wanted and len(bytes.fromhex(source['uid']))!=4:
        raise ValueError('manufacturer block copy currently supports 4-byte source UIDs only')
    writes = []
    for b in wanted:
        raw = payload['blocks'][b]
        if raw is None:
            raise ValueError(f'block {b} is unknown; select a smaller scope')
        data = bytearray.fromhex(raw)
        if b%4==3:
            slots=payload['keys'][b//4*2:b//4*2+2]
            if any(k['state']!='known' for k in slots):
                raise ValueError(f'sector {b//4} keys are incomplete')
            data[:6]=bytes.fromhex(slots[0]['value'])
            data[10:]=bytes.fromhex(slots[1]['value'])
        writes.append(dict(block=b,data=data.hex()))
    # For each sector, data first and trailer last; manufacturer block last overall.
    writes.sort(key=lambda w:(w['block']==0,w['block']//4,w['block']%4==3,w['block']))
    return dict(source_uid=source['uid'],source_dump=source.get('dump_file'),
                mode=source.get('write_mode','copy'),fill=source.get('fill'),
                scope=[w['block'] for w in writes],include_uid=0 in wanted,writes=writes)


def confirmation_lines(plan, target_uid):
    from m1_write_review import analyse_write
    label = (f"Generated reset: data {plan['fill']}, keys FF, default access bits" if plan.get('mode')=='reset'
             else f"Source card UID {plan['source_uid']} / {plan.get('source_dump') or 'dump'}")
    lines=[label,
           f'Target UID {target_uid.upper()}',f"Blocks: {len(plan['writes'])}; manufacturer block: {'included' if plan['include_uid'] else 'preserved'}",
           'Write data before trailers; manufacturer block last. Read back data and verify new keys.']
    for item in plan['writes']:
        if item['block']%4==3 or item['block']==0:
            lines.extend(analyse_write(item['block'],bytes.fromhex(item['data'])))
    return lines


def target_credentials(a):
    from nfclab_ops import key_file
    if a.keys or getattr(a, 'target_card', None):
        if getattr(a, 'target_card', None):
            slots=Library(a.library).card(a.target_card)['payload']['keys']
            return {s:{t:bytes.fromhex(slots[s*2+t]['value']) for t in (0,1)
                       if slots[s*2+t]['state']=='known'} for s in range(16)}
        else:
            keys=key_file(a.keys)
        return {s:{t:keys[(t*16+s)*6:(t*16+s+1)*6] for t in (0,1)} for s in range(16)}
    return {s:{int(a.key_type=='B'):a.key} for s in range(16)}


def preflight(plan, card, credentials, *, verified=None):
    """Authenticate supplied keys, read current ACL, and select a permitted key per block."""
    from m1_host import read_live
    from m1_write_review import access_conditions, DATA_ACCESS, TRAILER_ACCESS
    result, missing = {}, []
    for sector in sorted({w['block']//4 for w in plan['writes']}):
        cached=verified.get(sector) if verified is not None else None
        matched = cached['matched'] if cached is not None else [
            (t,k) for t,k in credentials.get(sector,{}).items()
            if check_key(k,card['cuid'],sector*4,t)]
        if not matched:
            missing.append(sector)
        else:
            packed=bytearray(192)
            for t,k in matched:
                packed[(t*16+sector)*6:(t*16+sector+1)*6]=k
            trailer=cached['trailer'] if cached is not None else None
            if trailer is None:
                for t,_ in matched:
                    try:
                        trailer=read_live(sector*4+3,bytes(packed),card['cuid'],t)
                        break
                    except RuntimeError:
                        continue
            if trailer is None:
                raise ValueError(f'Sector {sector}: cannot read access bits; no writes submitted.')
            errors,groups=access_conditions(trailer)
            if errors:
                raise ValueError(f'Sector {sector}: invalid access bits; no writes submitted.')
            if plan.get('mode')=='reset':
                current=dict(matched);readable=TRAILER_ACCESS[groups[3]][3]
                if (0 not in current or (readable and trailer[10:]!=credentials[sector].get(1))
                        or not readable and 1 not in current):
                    raise ValueError(f'Sector {sector}: library keys do not match; read the card again before erasing.')
            for item in plan['writes']:
                if item['block']//4 == sector:
                    b=item['block']
                    permissions=(TRAILER_ACCESS[groups[3]][:3] if b%4==3
                                 else (DATA_ACCESS[groups[b%4]][1],))
                    permitted=[(t,k) for t,k in matched
                               if not (t==1 and TRAILER_ACCESS[groups[3]][3])
                               and all('AB'[t] in p and p!='none' for p in permissions)]
                    if not permitted:
                        raise ValueError(f'Block {b}: current keys lack write permission; no writes submitted.')
                    result[b] = permitted[0]
    if missing:
        raise ValueError('Sectors '+', '.join(map(str,missing))+': current keys unavailable; read the card and update Card Library first.')
    return result


def execute_plan(plan, card, authenticated, *, card_type='standard', results=None, batch=True):
    if card_type=='gen1a' and batch:
        from m1_gen1a_batch import execute_batch
        return execute_batch(plan,card,{} if results is None else results)
    if card_type in ('gen2','standard') and batch:
        from m1_auth_write_batch import execute_batch
        return execute_batch(plan,card,authenticated,{} if results is None else results,card_type=card_type)
    from m1_host import request, read_live, read_gen1a, ERRORS
    from m1_recover_host import identify
    from m1_write_review import access_conditions, TRAILER_ACCESS
    results={} if results is None else results
    current=dict(card)
    new_sector_keys={}
    for item in plan['writes']:
        b=item['block'];data=bytes.fromhex(item['data'])
        results[str(b)]=dict(state='not-submitted',data=item['data'])
        try:
            t,key=(0,bytes(6)) if card_type=='gen1a' else authenticated[b]
            if card_type!='gen1a' and b==0 and 0 in new_sector_keys:
                # Sector 0 trailer was written earlier; old credentials are stale.
                candidates=new_sector_keys[0]
                found=[(kt,k) for kt,k in candidates.items() if check_key(k,current['cuid'],0,kt)]
                if not found:
                    raise RuntimeError('new sector-0 keys cannot authenticate manufacturer block')
                t,key=found[0]
            results[str(b)]['state']='submission-unknown'
            words=request(5 if card_type=='gen1a' else 2,b,t,key,current['cuid'],bytes(16),data,confirmed=True)
            if words[31]!=1 or words[36]:
                code=words[36]
                results[str(b)]['state']='write-failed'
                raise RuntimeError(f'block {b} write failed: {ERRORS[code] if code<len(ERRORS) else code}')
            results[str(b)]['state']='ack'
            if b==0:
                current=identify()
                if current['uid'].lower()!=data[:4].hex():
                    raise RuntimeError('target UID after write does not match planned UID')
            if card_type=='gen1a':
                if read_gen1a(b,current['cuid'])!=data:
                    raise RuntimeError(f'block {b} backdoor readback mismatch')
                results[str(b)].update(state='verified',verification='full-block-readback')
                continue
            if b%4==3:
                sector=b//4
                new_sector_keys[sector]={0:data[:6],1:data[10:]}
                errors,groups=access_conditions(data)
                verified={}
                for kt,k in new_sector_keys[sector].items():
                    if kt==1 and not errors and TRAILER_ACCESS[groups[3]][3]:
                        verified['B']='readable'
                    else:
                        verified['AB'[kt]]='authenticated' if check_key(k,current['cuid'],sector*4,kt) else 'unverified'
                # Read trailer with a working new key and compare access bits / readable B.
                packed=bytearray(192);trailer=None
                for kt,k in new_sector_keys[sector].items():
                    packed[(kt*16+sector)*6:(kt*16+sector+1)*6]=k
                for kt in (0,1):
                    if verified.get('AB'[kt])=='authenticated':
                        try:
                            trailer=read_live(b,bytes(packed),current['cuid'],kt)
                            break
                        except RuntimeError:
                            continue
                if trailer is None or trailer[6:10]!=data[6:10]:
                    raise RuntimeError(f'block {b} access bits could not be verified')
                if verified.get('B')=='readable':
                    if trailer[10:]!=data[10:]:
                        raise RuntimeError(f'block {b} readable Key B mismatch')
                    verified['B']='readback-match'
                results[str(b)].update(state='verified' if all(v!='unverified' for v in verified.values()) else 'unverified',keys=verified)
                if 'unverified' in verified.values():
                    raise RuntimeError(f'block {b} new key authentication failed')
            else:
                packed=bytearray(192)
                packed[(t*16+b//4)*6:(t*16+b//4+1)*6]=key
                if read_live(b,bytes(packed),current['cuid'],t)!=data:
                    raise RuntimeError(f'block {b} readback mismatch')
                results[str(b)]['state']='verified'
        except BaseException as error:
            results[str(b)]['error']=str(error)
            raise
    if card_type=='gen1a':
        # A final pass also detects later writes disturbing earlier blocks.
        for item in plan['writes']:
            b=item['block']
            try:
                if read_gen1a(b,current['cuid'])!=bytes.fromhex(item['data']):
                    raise RuntimeError(f'block {b} final readback mismatch')
            except BaseException as error:
                results[str(b)].update(state='unverified',error=str(error))
                raise
    return results,current


def card_write(a, events, *, confirmation=None, connection_context=None, source=None, factory_state=None, timings=None):
    from nfclab_runtime import connection, reader_mode
    from m1_recover_host import identify
    from m1_write_review import confirm_write
    if a.output and a.output.exists():
        raise ValueError('output already exists')
    if events.format == 'jsonl' and not a.preview:
        raise ValueError('interactive WRITE confirmation requires --format human')
    timings = {} if timings is None else timings
    source = Library(a.library).card(a.card) if source is None else source
    plan = plan_card(source, block=a.block, include_uid=a.include_uid)
    card_type = getattr(a,'card_type',None) or 'standard'
    if card_type=='standard' and plan['include_uid']:
        raise ValueError('Standard M1 preserves block 0; UID copy is not supported.')
    plan['card_type'] = card_type
    first = plan['writes'][0]
    lines = confirmation_lines(plan, a.uid.hex())
    lines.append('Gen1a backdoor: no authentication; verify all 16 bytes including keys.' if card_type=='gen1a' else 'Authenticated WRITE; verify data and new keys.')
    if a.preview:
        confirm_write(first['block'], bytes.fromhex(first['data']), int.from_bytes(a.uid,'big'),
                      preview=True, key_type=a.key_type, plan=lines)
        events.emit('write.preview', source_uid=source['uid'], plan=plan, submitted=False,
                    target_permissions='not checked offline')
        return 0
    with (connection_context if connection_context is not None else connection(a)):
        phase_started = time.monotonic()
        reader_mode()
        card = identify()
        if bytes.fromhex(card['uid']) != a.uid:
            raise ValueError('target card does not match --uid')
        if card_type=='gen1a':
            authenticated={}
        else:
            from m1_write_defaults import inspect_defaults,require_defaults,default_credentials,erase_credentials
            state=inspect_defaults(card) if factory_state is None else factory_state
            if state['uid']!=card['uid']:raise ValueError('target changed during default-key inspection')
            if plan.get('mode')=='reset':
                credentials=erase_credentials(card,Library(a.library),state)
            else:
                require_defaults(state)
                credentials=default_credentials()
            authenticated=preflight(plan,card,credentials,verified=state['verified'] if not state['nondefault'] else None)
        timings['preflight'] = time.monotonic() - phase_started
        if confirmation is None:
            from nfclab_write_wizard import review
            approved = review(plan,card,lines)
        else:
            approved = confirmation(plan,card,lines)
        if not approved:
            events.emit('write.cancelled', submitted=False)
            return 130
        if identify() != card:
            raise ValueError('target changed after confirmation; review a new plan')
        # Persist conservative intent before any MCU submission. A killed host
        # cannot know which blocks a still-running firmware batch has written.
        results={str(item['block']):dict(state='submission-unknown',data=item['data'])
                 for item in plan['writes']}
        if a.output:
            a.output.mkdir(mode=0o700, parents=True, exist_ok=False)
        def save_report(status, target_uid, error=None):
            if a.output:
                from sniff_session import atomic_json
                atomic_json(a.output/'report.json',dict(status=status,source_uid=source['uid'],
                    plan=plan,results=results,target_uid=target_uid,error=error,timings=timings))
                directory=os.open(a.output,os.O_RDONLY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
        save_report('running',card['uid'])
        try:
            phase_started = time.monotonic()
            results, after = execute_plan(plan, card, authenticated,card_type=card_type,results=results)
            timings['write_and_verify'] = time.monotonic() - phase_started
        except BaseException as error:
            save_report('partial', None, str(error))
            events.emit('write.partial', results=results, target_uid_after='unknown', error=str(error))
            raise
        save_report('complete',after['uid'])
    events.emit('operation.finished', operation='write', status='complete', source_uid=source['uid'],
                target_uid=after['uid'], blocks_written=len(results), verification='full-block-readback' if card_type=='gen1a' else 'readback-and-key-verification')
    return 0


def preflight_target(plan, card, credentials, card_type):
    if card_type!='gen1a':
        return preflight(plan,card,credentials)
    return {}
