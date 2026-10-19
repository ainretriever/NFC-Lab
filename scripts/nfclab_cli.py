# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 NFClab contributors.
"""Unified CLI; argument parsing never opens hardware."""
import argparse
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo


def number(low, high):
    def parse(value):
        n = int(value)
        if not low <= n <= high:
            raise argparse.ArgumentTypeError(f'range is {low}..{high}')
        return n
    return parse


def hex_bytes(length):
    def parse(value):
        try:
            data = bytes.fromhex(value)
        except ValueError:
            raise argparse.ArgumentTypeError('invalid hexadecimal data') from None
        if len(data) != length:
            raise argparse.ArgumentTypeError(f'expected {length} bytes')
        return data
    return parse


def write_options(parser, *, block_mode=False):
    parser.add_argument('--card-type', choices=('standard','gen1a','gen2'),
                        help='write protocol (default: standard)' if block_mode else 'write protocol; wizard asks when omitted')
    parser.add_argument('--uid', type=hex_bytes(4), help='current target UID (otherwise identify automatically)' if block_mode else 'current target UID; wizard identifies it')
    parser.add_argument('--block', '--blk', type=number(0,63), required=block_mode)
    if not block_mode:
        parser.add_argument('--phone', '-p', action='store_true', help='interactive UID copy and standard M1 write to a phone')
        parser.add_argument('--card', help='copy a library UID without source selection')
        parser.add_argument('--include-uid', action='store_true', help='include manufacturer block; default preserves target UID')
    else:
        parser.set_defaults(card=None,include_uid=False)
    keys = parser.add_mutually_exclusive_group()
    keys.add_argument('--key', '-k', type=hex_bytes(6))
    keys.add_argument('--keys', type=Path)
    keys.add_argument('--target-card', help='library UID providing current target keys')
    parser.add_argument('--key-type', choices=('A','B'), default='A')
    parser.add_argument('--data', '-d', type=hex_bytes(16), required=block_mode)
    parser.add_argument('--preview', action='store_true', help='offline plan only; never opens device')
    parser.add_argument('--confirm-timeout', type=float, help=argparse.SUPPRESS)  # Legacy argument; no timeout now.
    parser.add_argument('--output', type=Path)


def build_parser():
    p = argparse.ArgumentParser(prog='nfclab', description='NFClab USB CDC CLI (Classic 1K)')
    p.add_argument('--device', help='NFClab CDC port')
    p.add_argument('--library', type=Path, help='Card Library directory (default: NFCLAB_LIBRARY or library)')
    p.add_argument('--elf', type=Path, help='temporary ABI compatibility: ELF matching flashed firmware')
    p.add_argument('--format', choices=('human', 'jsonl'), default='human')
    p.add_argument('--verbose', action='store_true', help='expand frame details')
    sub = p.add_subparsers(dest='group', required=True)
    tui = sub.add_parser('tui', help='interactive 80x24 terminal UI')
    tui.add_argument('--monochrome', action='store_true')
    emulate = sub.add_parser('emulate', help='hardware NFC-A UID-only simulation').add_subparsers(dest='command', required=True)
    uid_sim = emulate.add_parser('uid', help='simulate a 4-byte UID until Ctrl+C')
    uid_sim.add_argument('--uid', type=hex_bytes(4), required=True)
    uid_sim.add_argument('--duration', type=number(1, 86400), help='stop after this many seconds')
    emulate.add_parser('status')
    emulate.add_parser('stop')
    for name, commands in (('device', ('list', 'info')), ('tag', ('info',))):
        children = sub.add_parser(name).add_subparsers(dest='command', required=True)
        if name == 'tag':
            tag_commands = children
        for command in commands:
            cmd = children.add_parser(command)
            if name == 'tag':
                cmd.add_argument('--key', type=hex_bytes(6), help='known sector-0 authentication key')
                cmd.add_argument('--key-type', choices=('A','B'), default='A')
                probes = cmd.add_mutually_exclusive_group()
                probes.add_argument('--magic-write-probe', action='store_true',
                                    help='force Gen2 ACK probe even if Magic already identified (otherwise automatic)')
                probes.add_argument('--no-write-probe', action='store_true',
                                    help='strictly forbid WRITE commands; default Gen2 probe sends command only, never data')
    m1 = sub.add_parser('m1').add_subparsers(dest='command', required=True)
    auth = m1.add_parser('auth')
    auth.add_argument('--block', type=number(0, 63), required=True)
    auth.add_argument('--key', type=hex_bytes(6), required=True)
    auth.add_argument('--key-type', choices=('A', 'B'), default='A')
    auth.add_argument('--uid', type=hex_bytes(4), help='expected 4-byte UID, checked after identification')
    for name in ('read', 'dump'):
        cmd = m1.add_parser(name)
        cmd.add_argument('--output', type=Path)
        sources = cmd.add_mutually_exclusive_group(required=name == 'dump')
        sources.add_argument('--keys', type=Path)
        if name == 'dump':
            sources.add_argument('--card', help='use keys from a library UID')
        if name != 'dump':
            scope = cmd.add_mutually_exclusive_group()
            if name == 'read':
                scope.add_argument('--block', type=number(0, 63))
            scope.add_argument('--sector', type=number(0, 15))
            scope.add_argument('--all', action='store_true')
            cmd.add_argument('--dictionary', type=Path, action='append', default=[])
            cmd.add_argument('--builtin-dictionary', action='store_true')
            cmd.add_argument('--cross-card-keys', action='store_true',
                             help='try deduplicated known keys from other Library cards')
            cmd.add_argument('--no-uid-cache', action='store_true',
                             help='skip Library key acceleration for the current UID')
            cmd.add_argument('--cpus', type=number(1,256), help='hardnested threads (default: all available logical CPUs, max 256)')
            cmd.add_argument('--auth-timeout-us', type=number(200,4833), default=200,
                             help='dictionary/reuse timeout; automatic 200/400/4833 us fallback (default: 200 us)')
            resumes = cmd.add_mutually_exclusive_group()
            resumes.add_argument('--resume', type=Path)
            probes = cmd.add_mutually_exclusive_group()
            probes.add_argument('--magic-write-probe', action='store_true',
                                help='force Gen2 ACK probe even if Magic already identified (otherwise automatic)')
            probes.add_argument('--no-write-probe', action='store_true',
                                help='strictly forbid WRITE commands in read and info probes')
        else:
            cmd.add_argument('--key-type', choices=('A', 'B', 'auto'), default='auto')
    write = m1.add_parser('write', help='interactive whole-card writer; block for explicit single-block operations',
                          description='Run without a source/block to start the whole-card wizard. Use block for a single 16-byte write.')
    write_options(write)
    modes = write.add_subparsers(dest='write_mode')
    write_options(modes.add_parser('block', help='write exactly one 16-byte block'), block_mode=True)
    keys = m1.add_parser('keys').add_subparsers(dest='keys_command', required=True)
    for name in ('check', 'dictionary'):
        cmd = keys.add_parser(name)
        source = cmd.add_mutually_exclusive_group(required=True)
        source.add_argument('--key', type=hex_bytes(6), action='append')
        source.add_argument('--dictionary', type=Path)
        cmd.add_argument('--binary', action='store_true')
        cmd.add_argument('--key-type', choices=('A', 'B', 'both') if name == 'dictionary' else ('A', 'B'), default='both' if name == 'dictionary' else 'A')
        cmd.add_argument('--output', type=Path)
        if name == 'check':
            cmd.add_argument('--block', type=number(0, 63), required=True)
        else:
            cmd.add_argument('--sector', type=number(0, 15))
    sniff = sub.add_parser('sniff').add_subparsers(dest='command', required=True)
    for name in ('watch', 'recover'):
        cmd = sniff.add_parser(name, description='Windowed capture with gaps; continuous streaming is not yet supported')
        cmd.add_argument('--windowed', action='store_true', help='explicitly use current windowed firmware')
        cmd.add_argument('--output', type=Path)
        cmd.add_argument('--resume', type=Path)
        cmd.add_argument('--captures', type=number(1, 100000))
        cmd.add_argument('--timeout-ms', type=number(1, 3000), default=1000)
        if name == 'recover':
            cmd.add_argument('--method', choices=('auto', 'mfkey32', 'mfkey32v2', 'mfkey64'), default='auto')
            cmd.add_argument('--uid', help='full UID hex')
            cmd.add_argument('--sector', type=number(0, 39))
            cmd.add_argument('--key-type', choices=('A', 'B'))
    session = sub.add_parser('session').add_subparsers(dest='command', required=True)
    for name in ('show', 'solve'):
        cmd = session.add_parser(name)
        cmd.add_argument('path', type=Path)
    library = sub.add_parser('library').add_subparsers(dest='command', required=True)
    library.add_parser('list')
    show = library.add_parser('show')
    show.add_argument('uid')
    imp = library.add_parser('import')
    imp.add_argument('uid')
    imp.add_argument('path', type=Path)
    imp.add_argument('--keys-known', action='store_true', help='explicitly assert all trailer keys in the input are known')
    # Reuse the established Classic read arguments for the formal saving command.
    tag_commands.add_parser('read', parents=[m1.choices['read']], add_help=False, help='read and save to Card Library')
    return p


def default_output(group, command):
    stamp = datetime.now(ZoneInfo('Asia/Kuching')).strftime('%Y%m%d-%H%M%S-%f')
    return Path('build/sessions')/f'{group}-{command}-{stamp}'


def main(argv=None):
    p = build_parser()
    a = p.parse_args(argv)
    if a.group == 'tui':
        from nfclab_tui import launch
        return launch(a)
    if a.group == 'm1' and a.command == 'write':
        if getattr(a, 'phone', False) and (a.write_mode is not None or a.card or a.block is not None or a.data or a.include_uid or a.card_type not in (None, 'standard')):
            p.error('--phone requires the whole-card wizard and standard M1 protocol')
        a.write_wizard = a.write_mode is None and a.card is None and a.block is None and a.data is None
        if not a.write_wizard:
            a.card_type = a.card_type or 'standard'
            if a.card is not None and a.uid is None:
                p.error('explicit library copy requires --uid; use the wizard for automatic identification')
            if a.card is None and not (a.key or a.keys or a.target_card):
                if a.card_type == 'gen1a':
                    a.key = bytes(6)  # Backdoor never authenticates.
                else:
                    p.error('standard/Gen2 write requires --key, --keys or --target-card')
            if a.card is None and (a.block is None or a.data is None):
                p.error('single-block write requires --block and --data')
            if a.card is not None and a.data is not None:
                p.error('choose --card or --data')
            if a.include_uid and (a.card is None or a.block is not None):
                p.error('--include-uid requires a whole library card write')
    if getattr(a, 'resume', None) and getattr(a, 'output', None):
        p.error('choose --output or --resume')
    if a.group == 'sniff' and a.command == 'recover' and a.uid:
        try:
            uid = bytes.fromhex(a.uid)
            if len(uid) not in (4, 7, 10):
                raise ValueError()
            a.uid = uid.hex()
        except ValueError:
            p.error('--uid must be 4, 7 or 10 bytes of hex')
    from nfclab_runtime import execute
    return execute(a)
