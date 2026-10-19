# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 NFClab contributors.
"""Guided UID handoff to a phone, followed by authenticated Classic writes."""
from contextlib import nullcontext
from types import SimpleNamespace
import select
import sys


def copy_completed():
    """Poll terminal input without blocking the simulator's heartbeat."""
    from nfclab_write_wizard import Cancelled
    if not select.select([sys.stdin], [], [], 0)[0]:
        return False
    answer = sys.stdin.readline()
    if not answer or answer.strip().lower() in ('q', '\x1b'):
        raise Cancelled()
    if not answer.strip():
        return True
    print('Press Enter when copied, or q then Enter to cancel.', flush=True)
    return False


def phone_write(a, events, library):
    from nfclab_write_wizard import select_card, review, WizardEvents
    from nfclab_write import plan_card, card_write, confirmation_lines
    from nfclab_runtime import connection, reader_mode
    from nfclab_emulate import run
    source = select_card(library, 'Source card for phone', version=True)
    uid = bytes.fromhex(source['uid'])
    if len(uid) != 4 or uid[0] == 0x88:
        raise ValueError('Phone workflow requires a 4-byte UID not beginning with 88')
    if a.uid is not None and a.uid != uid:
        raise ValueError('--uid must match the selected source UID')
    plan = plan_card(source)
    a.uid = uid
    a.card_type = 'standard'
    a.card = source['uid']
    if a.preview:
        plan['card_type'] = 'standard'
        review(plan, dict(uid=source['uid']), confirmation_lines(plan, source['uid']), preview=True)
        print('Phone workflow: simulate UID -> copy on phone -> stop simulation -> enable phone card -> write with readback and key verification.')
        return 0
    with connection(a):
        print('Copy this UID-only card on your phone. Press Enter when copied; q then Enter cancels.\n'
              'A selection event alone does not confirm copying.', flush=True)
        if run(SimpleNamespace(command='uid', uid=uid, duration=None), events,
               completed=copy_completed) != 0:
            return 130
        plan['card_type'] = 'standard'
        if not review(plan, dict(uid=source['uid']), confirmation_lines(plan, source['uid']),
                      instructions=('UID simulation stopped. Enable the copied card on your phone and place it on the antenna.',
                                    'Enter confirms this plan and starts checks, writing and verification.')):
            events.emit('write.cancelled', submitted=False)
            return 130
        reader_mode()
        timings = {}
        result = card_write(a, WizardEvents(events), source=source,
                          connection_context=nullcontext(), confirmation=lambda *_: True,
                          timings=timings)
        print('Timing: ' + ' | '.join(f'{name}: {seconds:.3f}s' for name, seconds in timings.items()), flush=True)
        return result
