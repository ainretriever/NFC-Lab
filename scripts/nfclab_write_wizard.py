# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 NFClab contributors.
"""Interactive whole-card writes; reset is a generated write source, not an erase opcode."""
from contextlib import nullcontext
from copy import copy
from contextvars import ContextVar
import sys
import os
import termios
import tty

from nfclab_library import Library
from nfclab_write import card_write, plan_card, confirmation_lines


_screen = ContextVar('write_screen', default=None)


def new_screen():
    """Replace each terminal menu while retaining target identity and warning."""
    from nfclab_render import terminal_color, write_header, write_warning
    if sys.stdout.isatty() and os.environ.get('TERM', '') != 'dumb':
        print('\033[2J\033[H', end='', flush=True)
    state = _screen.get()
    if state and state.get('card'):
        color = terminal_color(sys.stdout)
        print(write_header(state['card'], state.get('card_type'), color=color), flush=True)
        if state.get('warning'):
            print(write_warning(state['warning'], color=color), flush=True)


class Cancelled(Exception):
    pass


def ask(prompt):
    try:
        answer = input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        raise Cancelled() from None
    if answer.lower() == 'q' or answer == '\x1b':
        raise Cancelled()
    return answer


def choose(title, options, default=None):
    new_screen()
    print('\n'+title)
    for i, (label, _) in enumerate(options, 1):
        print(f'  {i}. {label}')
    print('  0. Cancel')
    while True:
        answer = ask(f'Select [{default}]: ' if default is not None else 'Select: ')
        if answer == '' and default is not None:
            answer = str(default)
        if answer == '0':
            raise Cancelled()
        if answer.isdigit() and 1 <= int(answer) <= len(options):
            return options[int(answer)-1][1]
        print('Enter a menu number, or q to cancel.')


def hex_value(prompt, length):
    new_screen()
    while True:
        try:
            value = bytes.fromhex(ask(prompt))
            if len(value) == length:
                return value
        except ValueError:
            pass
        print(f'Enter {length} bytes in hex, or q to cancel.')


def select_card(library, title, *, version=False):
    if not library.index:
        raise ValueError('Card Library is empty; read or import a source card, or choose Erase')
    options = [(f"{uid}  {c['name'] or '-'}  {c['blocks_known']}/64 blocks, {c['keys_known']}/32 keys", uid)
               for uid, c in library.index.items()]
    uid = choose(title, options)
    source = library.card(uid)
    versions = source['metadata']['versions']
    if version and len(versions) > 1:
        current = source['dump_file']
        files = [current]+[v['file'] for v in versions if v['file'] != current]
        selected = choose('Source version', [(f+(' (current)' if f==current else ''), f) for f in files], 1)
        source = library.card(uid, dump=selected)
    return source


def reset_source(uid):
    """Blank data and default trailers. Block 0 is excluded by the reset plan."""
    if len(bytes.fromhex(uid)) != 4:
        raise ValueError('whole-card write currently requires a 4-byte UID')
    blocks = [bytes(16).hex() for _ in range(64)]
    for sector in range(16):
        blocks[sector*4+3] = 'ffffffffffffff078069ffffffffffff'
    return dict(uid=uid, layout='classic-1k', dump_file=None,
                write_mode='reset', fill='00',
                payload=dict(blocks=blocks, keys=[dict(value='ffffffffffff',state='known') for _ in range(32)]))


def review(plan, card, lines, *, preview=False, instructions=()):
    from nfclab_render import write_plan
    new_screen()
    notes = list(dict.fromkeys(line for line in lines if line.startswith(('[Warning]','[Alert]','[Encoding error]'))))
    print('\n' + write_plan(plan, card, notes))
    for instruction in instructions:
        print(instruction, flush=True)
    if preview:
        print('Preview only: no device connected, no writes submitted.')
        return False
    details = [f"Block {w['block']:02d}: {w['data'].upper()}" for w in plan['writes']]+list(lines)
    return confirm_plan(details)


def confirm_plan(details):
    """One untimed Enter/Esc decision; restore terminal attributes on every exit."""
    if not sys.stdin.isatty():
        raise ValueError('Whole-card confirmation requires an interactive terminal')
    fd = sys.stdin.fileno()
    original = termios.tcgetattr(fd)
    try:
        tty.setcbreak(fd)
        while True:
            print('Enter to write | D for details | Esc to return',end=' ',flush=True)
            answer = os.read(fd,1)
            print()
            if answer in (b'\n',b'\r'):
                return True
            if answer in (b'd',b'D'):
                new_screen()
                for line in details:
                    print(line,flush=True)
                continue
            return False
    except KeyboardInterrupt:
        return False
    finally:
        termios.tcsetattr(fd,termios.TCSADRAIN,original)


def target_protocol(card, a=None, library=None, *, magic=True):
    from m1_write_detection import detect
    from m1_keys_host import COMMON_KEYS
    from nfclab_write import target_credentials
    if magic:
        protocol=detect(card)
        if protocol is not None:return protocol
    candidates=[]
    if a is not None and (a.key is not None or a.keys or a.target_card):
        candidates.extend((t,k) for t,k in target_credentials(a).get(0,{}).items())
    if library is not None and card['uid'].upper() in library.index:
        slots=library.card(card['uid'])['payload']['keys'][:2]
        candidates.extend((t,bytes.fromhex(k['value'])) for t,k in enumerate(slots) if k['state']=='known')
    candidates.extend((t,bytes.fromhex(k)) for t in (0,1) for k in COMMON_KEYS)
    return detect(card,candidates,magic=False)


class WizardEvents:
    def __init__(self, events):
        self.events = events
        self.format = events.format

    def emit(self, kind, **data):
        if getattr(self.events, 'verbose', False):
            return self.events.emit(kind, **data)
        if kind in ('write.preview','write.cancelled'):
            return
        if kind == 'write.partial':
            count = sum(r['state']=='verified' for r in data['results'].values())
            print(f"Write stopped: {count} blocks verified; {data['error']}",flush=True)
        elif kind == 'operation.finished':
            print(f"Write complete: {data['blocks_written']} blocks verified; target UID {data['target_uid'].upper()}", flush=True)
        else:
            self.events.emit(kind, **data)


def wizard(args, events):
    """Identify first online; preview stays offline. Collect only missing choices."""
    if events.format != 'human' or not sys.stdin.isatty():
        raise ValueError('Whole-card wizard requires an interactive terminal; use m1 write block for a single block')
    if args.output and args.output.exists():
        raise ValueError('output already exists')
    a = copy(args)
    library = Library(a.library)
    factory_state=None
    screen_state={}
    screen_token=_screen.set(screen_state)
    try:
        if getattr(a, 'phone', False):
            from nfclab_phone import phone_write
            return phone_write(a, events, library)
        from nfclab_runtime import connection, reader_mode
        from m1_recover_host import identify
        with nullcontext() if a.preview else connection(a):
            if a.preview:
                card = None
            else:
                reader_mode()
                card = identify()
                found = bytes.fromhex(card['uid'])
                if len(found) != 4:
                    raise ValueError('whole-card write currently requires a 4-byte target UID')
                if a.uid is not None and found != a.uid:
                    raise ValueError('target card does not match --uid')
                a.uid = found
                a.card_type = a.card_type or target_protocol(card,a,library)
                screen_state.update(card=card, card_type=a.card_type)
                new_screen()
                if a.card_type!='gen1a':
                    from m1_write_defaults import inspect_defaults,warning
                    factory_state=inspect_defaults(card)
                    if factory_state['nondefault']:
                        screen_state['warning']=warning(factory_state)
            mode = choose('M1 Write', [('Copy card','copy'),('Erase card','zero')])
            if not a.preview and factory_state is not None:
                from m1_write_defaults import require_defaults,erase_credentials
                if mode=='copy':require_defaults(factory_state)
                elif a.card_type is None:erase_credentials(card,library,factory_state)
                if a.card_type is None:raise ValueError('Cannot detect card type; specify --card-type')
            source = select_card(library,'Source card',version=True) if mode=='copy' else None
            if mode=='copy':
                if a.card_type=='standard':
                    if a.include_uid:
                        raise ValueError('Standard M1 preserves block 0; UID copy is not supported.')
                else:
                    a.include_uid = a.include_uid or choose('UID scope',[
                        ('Preserve target UID and manufacturer block',False),('Copy all blocks, including source UID',True)],1)
                plan_card(source,include_uid=a.include_uid)
            elif a.include_uid:
                raise ValueError('Erase preserves the manufacturer block; --include-uid requires a source card')
            if a.preview:
                a.card_type = a.card_type or choose('Target card type',[
                    ('Gen1a / UID','gen1a'),('Gen2 / CUID','gen2'),('Standard M1','standard')])
                a.uid = a.uid or hex_value('Target UID (8 hex digits, preview only): ',4)
                card = dict(uid=a.uid.hex(),cuid=int.from_bytes(a.uid,'big'))
                screen_state.update(card=card, card_type=a.card_type)
            if mode=='zero':
                source = reset_source(card['uid'])
            a.card = source['uid']
            if a.preview:
                plan = plan_card(source,include_uid=a.include_uid)
                plan['card_type'] = a.card_type
                review(plan,card,confirmation_lines(plan,card['uid']),preview=True)
                WizardEvents(events).emit('write.preview',plan=plan,submitted=False)
                return 0
            return card_write(a,WizardEvents(events),source=source,connection_context=nullcontext(),
                confirmation=review,factory_state=factory_state)
    except Cancelled:
        print('Cancelled.')
        WizardEvents(events).emit('write.cancelled',submitted=False)
        return 130
    finally:
        _screen.reset(screen_token)
