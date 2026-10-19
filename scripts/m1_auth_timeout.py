# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 NFClab contributors.
"""Bounded authentication timeout tiers, shared by read-only recovery paths."""
AUTH_TIMEOUTS = (200, 400, 4833)


def next_timeout(current):
    return next((value for value in AUTH_TIMEOUTS if value > current), None)


def calibrated_timeout(check):
    """Choose the first tier passing all three known-key authentications."""
    for timeout in AUTH_TIMEOUTS:
        report = check(timeout)
        if report['complete'] and report['matched'] == 3:
            return timeout
    return AUTH_TIMEOUTS[-1]


def verify_with_fallback(session, plan, check, method):
    """Retry incomplete results only; transport exceptions propagate unchanged."""
    while True:
        timeout = plan.get('auth_timeout_us', AUTH_TIMEOUTS[-1])
        report = check(timeout)
        following = next_timeout(timeout)
        if report['complete'] or following is None:
            return report
        plan['auth_timeout_us'] = following
        if session.state.get('recovery_path'):
            session.state['recovery_path']['auth_timeout_us'] = following
        session.event('auth-timeout-fallback',
                      f'{timeout} us -> {following} us; retrying {method}')
