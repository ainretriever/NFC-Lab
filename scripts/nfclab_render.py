# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 NFClab contributors.
"""Human-facing formatting, independent of hardware and operation logic."""


def terminal_color(stream):
    import os
    return stream.isatty() and 'NO_COLOR' not in os.environ and os.environ.get('TERM', '') != 'dumb'


def tag_info(data, *, color=False):
    uid = bytes.fromhex(data['uid']).hex(' ').upper()
    atqa = bytes.fromhex(data['atqa']).hex(' ').upper()
    family = data.get('supported_family')
    name = 'MIFARE Classic 1K' if family == 'Classic 1K' else family or 'Unknown'
    rows = [('UID', uid), ('ATQA', atqa), ('SAK', f"{data['sak']:02X}")]
    if data.get('fingerprint'):
        rows.append(('Fingerprint', data['fingerprint']['label']))
    info = data.get('inspection')
    if info:
        nonce = info['nonce']
        behavior, prng = nonce['nonce'], nonce['prng']
        nonce_text = behavior
        if prng in ('weak', 'hard', 'mixed'):
            nonce_text += f' ({prng} PRNG)'
        rows.extend([('Magic', info['magic']['label']), ('Nonce', nonce_text)])
        deep = info['magic'].get('gen2_diagnostic', {})
        if deep.get('status') in ('untested', 'unsupported', 'failed'):
            rows.append(('Gen2', deep['label']))
    # Fixed xterm-256 cube entries approximate bright VGA colors without
    # depending on the terminal theme's configurable first sixteen entries.
    def paint(text, index):
        return f'\033[38;5;{index}m{text}\033[0m' if color else text

    def value_color(label, value):
        if info:
            state = (info['magic'].get('status') if label == 'Magic' else
                     info['magic'].get('gen2_diagnostic', {}).get('status') if label == 'Gen2' else
                     info['nonce'].get('status') if label == 'Nonce' else None)
            if state == 'failed':
                return 203
        if label == 'UID' or (label == 'Magic' and info['magic'].get('status') == 'matched'):
            return 87
        if label == 'Nonce':
            if behavior in ('static', 'static-encrypted'):
                return 203
            if behavior == 'dynamic':
                return {'weak': 120, 'hard': 227}.get(prng)
        return None

    lines = [paint(name, 231)]
    for label, value in rows:
        index = value_color(label, value)
        lines.append(paint(f'{label:<11}', 145) + '  ' + (paint(value, index) if index else value))
    return '\n'.join(lines) + '\n'


def write_header(card, card_type, *, color=False):
    """Compact target identity using the Tag Info palette and alignment."""
    def paint(text, index):
        return f'\033[38;5;{index}m{text}\033[0m' if color else text

    magic = {'gen1a': 'Gen1a', 'gen2': 'Gen2', 'standard': 'none'}.get(card_type, 'Unknown')
    uid = bytes.fromhex(card['uid']).hex(' ').upper()
    rows = [('UID', uid, 87), ('Magic', magic, 87 if card_type in ('gen1a', 'gen2') else 227)]
    lines = [paint('MIFARE Classic 1K', 231)]
    for label, value, index in rows:
        lines.append(paint(f'{label:<11}', 145) + '  ' + paint(value, index))
    return '\n'.join(lines)


def write_warning(message, *, color=False):
    text = f"{'WARN':<11}  {message}"
    return f'\033[38;5;203m{text}\033[0m' if color else text


def write_plan(plan, card, notes=()):
    """Render a bounded ASCII grid, wrapping long source paths and notes."""
    from textwrap import wrap

    label_width, value_width = 8, 63
    inner_width = label_width + 3 + value_width
    border = '+' + '-' * (inner_width + 2) + '+'
    divider = '+' + '-' * (label_width + 2) + '+' + '-' * (value_width + 2) + '+'
    lines = [border, '| ' + 'Write plan'.ljust(inner_width) + ' |', divider]
    rows = []
    if plan.get('mode') == 'reset':
        rows.extend([('Erase', f"fill {plan['fill']}"),
                     ('Keys', 'Key A/B = FFFFFFFFFFFF'),
                     ('Access', 'Access bits/GPB = FF078069')])
    else:
        rows.append(('Source', f"{plan['source_uid']} / {plan.get('source_dump') or 'dump'}"))
    magic = {'gen1a': 'Gen1a', 'gen2': 'Gen2', 'standard': 'Standard M1'}.get(plan.get('card_type', 'standard'), 'Unknown')
    rows.extend([('Target', f"{card['uid'].upper()} / {magic}"),
                 ('Scope', f"{len(plan['writes'])} blocks"),
                 ('UID', 'Include UID; block 0 last' if plan['include_uid'] else 'Preserve UID and manufacturer block'),
                 ('Verify', 'Write data and sector trailers, then verify readback.')])
    rows.extend(('Warning', note) for note in notes)
    for label, value in rows:
        value = str(value).encode('ascii', 'backslashreplace').decode('ascii')
        for i, part in enumerate(wrap(value, value_width, break_on_hyphens=False) or ['']):
            lines.append(f"| {label if i == 0 else '':<{label_width}} | {part:<{value_width}} |")
    lines.append(divider)
    return '\n'.join(lines)


SOURCE_CODES = {'dictionary': 'D', 'common-dictionary': 'D', 'user-dictionary': 'D',
                'builtin-dictionary': 'D', 'hardnested': 'H', 'nested': 'N',
                'static-nested': 'S', 'sen': 'E', 'sen-derived': 'E', 'reuse': 'R', 'key-reuse': 'R',
                'provided': 'P', 'cached': 'C', 'library': 'L', 'trailer': 'T', '-': '-'}


def source_code(source):
    parts = source.split('/') if source else ['-', '-']
    # Older source labels used one name for a shared A/B source.
    if len(parts) == 1:
        parts *= 2
    return ''.join(SOURCE_CODES.get(part, '?') for part in parts)


def benchmark_line(benchmark):
    return f"{benchmark['cpus']}-thread {benchmark['simd']} {benchmark['keys_per_second']/1e6:.0f}Mkey/s"


def read_status(row):
    activity = row.get('activity', {})
    step = activity.get('step')
    if activity.get('method') in ('static-nested', 'sen', 'hardnested') and (
            row['status'] == 'processing' or (row['status'] != 'complete' and step in ('limit', 'unresolved'))):
        key_type = activity.get('key_type', '')
        label = {'start': 'start', 'capture': 'capture', 'solve': 'solve',
                 'verify': 'verify', 'pair': 'pair', 'reduce': 'reduce', 'recalibrate': 'recalibrate',
                 'limit': 'limit', 'unresolved': 'unresolved'}.get(step, 'working')
        if step == 'start' and activity.get('attempt', 1) > 1:
            label = f"retry {activity['attempt']}"
        elif step in ('collect', 'capture', 'reduce') and activity.get('method') == 'hardnested':
            label = 'collect'
            if 'samples' in activity:
                label += f" {activity['samples']}"
            if 'first_bytes' in activity:
                label += f" {activity['first_bytes']}/256"
            if 'estimated_states' in activity:
                label += f" ~{activity['estimated_states']:.3g}"
        elif step == 'capture' and 'position' in activity and 'positions' in activity:
            label += f" {activity['position']}/{activity['positions']}"
        elif step == 'capture' and 'depth' in activity:
            label += f" {activity['depth']+1}/2"
        elif step == 'verify' and 'checked' in activity and 'candidates' in activity:
            label += f" {activity['checked']}/{activity['candidates']}"
        return f'{key_type} {label}'.strip()
    if row['status'] == 'processing':
        return 'working'
    if row['status'] == 'complete':
        return f"done {row['elapsed_s']:.2f}s"
    return f"{row['elapsed_s']:.2f}s" if row['elapsed_s'] else ''


def read_header(data, *, color=False):
    """Two screen lines for reads; full evidence remains in tag info/verbose."""
    from textwrap import shorten
    def paint(text, index):
        return f'\033[38;5;{index}m{text}\033[0m' if color else text
    family = data.get('supported_family')
    name = 'MIFARE Classic 1K' if family == 'Classic 1K' else family or 'Unknown'
    uid = bytes.fromhex(data['uid']).hex(' ').upper()
    first = paint(name, 231) + '  UID ' + paint(uid, 87)
    fingerprint = (data.get('fingerprint') or {}).get('label', 'Unknown')
    info = data.get('inspection')
    if not info:
        return first + '\n' + shorten(fingerprint, width=78, placeholder='...')
    magic = info['magic']
    magic_text = 'Magic: none' if magic.get('status') == 'not_detected' else magic['label']
    magic_text = shorten(magic_text.replace(' / ', '/').replace(' (WRITE ACK)', ''), width=18, placeholder='...')
    nonce = info['nonce']
    behavior, prng = nonce['nonce'], nonce['prng']
    nonce_text = behavior + (f' ({prng} PRNG)' if prng in ('weak', 'hard', 'mixed') else '')
    nonce_text = shorten(nonce_text, width=36, placeholder='...')
    index = (203 if nonce.get('status') == 'failed' or behavior in ('static', 'static-encrypted') else
             {'weak': 120, 'hard': 227}.get(prng) if behavior == 'dynamic' else None)
    fingerprint = shorten(fingerprint, width=max(12, 78-len(magic_text)-len(nonce_text)-6), placeholder='...')
    return first + '\n' + ' | '.join([fingerprint, magic_text, paint(nonce_text, index) if index else nonce_text])




def fit_columns(text, width, *, tail=False):
    import unicodedata
    def size(c):
        return 0 if unicodedata.combining(c) else 2 if unicodedata.east_asian_width(c) in 'WF' else 1
    # Filesystem paths can contain wide characters or embedded control characters.
    text = ''.join(c if c.isprintable() else '?' for c in str(text))
    if sum(size(c) for c in text) <= width:
        return text
    result, used = [], 0
    for c in reversed(text) if tail else text:
        if used+size(c) > width-3:
            break
        result.append(c)
        used += size(c)
    return '...'+''.join(reversed(result)) if tail else ''.join(result)+'...'


def block_ranges(blocks):
    values = sorted(set(blocks))
    groups = []
    for value in values:
        if groups and value == groups[-1][1]+1:
            groups[-1][1] = value
        else:
            groups.append([value, value])
    return ', '.join(str(first) if first == last else f'{first}-{last}' for first, last in groups)


def library_cards(cards):
    import unicodedata
    def cell(value, width):
        value = fit_columns(value, width)
        columns = sum(0 if unicodedata.combining(c) else 2 if unicodedata.east_asian_width(c) in 'WF' else 1 for c in value)
        return value+' '*(width-columns)
    uid_width = max([8]+[len(card['uid']) for card in cards])
    lines = ['  '.join((cell('UID', uid_width), cell('TYPE', 9), cell('NAME', 20), 'STATUS'))]
    for card in cards:
        card_type = {'MIFARE Classic 1K':'MFC 1K'}.get(card['card_type'], card['card_type'])
        name = str(card.get('name') or '').strip() or '-'
        status = []
        if card['versions'] > 1:
            status.append(f"{card['versions']} versions")
        if card['blocks_known'] < 64 or card['keys_known'] < 32:
            status.append('Partial')
        lines.append('  '.join((cell(card['uid'], uid_width), cell(card_type, 9), cell(name, 20), ', '.join(status) or '-')))
    lines.extend(('', f"{len(cards)} {'card' if len(cards)==1 else 'cards'}"))
    return '\n'.join(lines)


def read_result_lines(data, width=78):
    """At most two footer lines; full differences and paths stay in TOML/JSONL."""
    status = data.get('library_status')
    lines = []
    label = 'Saved'
    if status == 'created':
        if data.get('parent_dump'):
            changes = [(title, values, summary) for title, values, summary in (
                ('Blocks', data.get('changed_blocks', []), block_ranges(data.get('changed_blocks', []))),
                ('Keys', data.get('changed_keys', []), ', '.join(data.get('changed_keys', [])))) if values]
            text = 'Changes: '+'  '.join(f'{title} [ {summary} ]' for title, _, summary in changes)
            if len(text) > width:
                text = 'Changes: '+'  '.join(f'{title} [ {len(values)} changed ]' for title, values, _ in changes)
            if changes:
                lines.append(text)
        else:
            lines.append('First saved version'+(' (partial)' if data.get('status') != 'complete' else ''))
        label = 'Saved version'
    elif status == 'unchanged':
        lines.append('Content unchanged')
        label = 'Current version'
    elif status == 'incomplete':
        lines.append('Comparison incomplete; existing version preserved')
        label = 'Current version'
    lines = [fit_columns(line, width) for line in lines]
    if data.get('path'):
        saved = data['path']
        if data.get('dump_file'):
            saved += '/'+data['dump_file']
        lines.append(label+': '+fit_columns(saved, width-len(label)-2, tail=True))
    return lines


class ReadView:
    """Compact progress; redraw fast steps instead of flooding the terminal."""
    LABELS = {'provided-keys': 'Checking supplied keys', 'cached-keys': 'Checking supplied keys',
              'common-dictionary': 'Checking common keys', 'user-dictionary': 'Checking user dictionary',
              'builtin-dictionary': 'Checking built-in dictionary', 'key-reuse': 'Checking key reuse'}

    def __init__(self, stream):
        self.stream = stream
        self.tty = stream.isatty()
        self.active = False
        self.last_update = 0
        self.method = 'nested'
        self.attempt = 1
        self.table = None
        self.table_height = 0
        self.table_live = False
        self.table_printed = False
        self.table_note = ''
        self.table_updated = 0
        self.benchmark = None

    def table_lines(self):
        header = f"{'Sec':<3}  {'Key A':<12}  {'Key B':<12}  {'Src':<3}  {'Status':<7}"
        lines = ([benchmark_line(self.benchmark)] if self.benchmark else []) + [header, '-' * len(header)]
        for row in self.table:
            key_a = row['key_a'].upper() if row['key_a'] else ''
            key_b = row['key_b'].upper() if row['key_b'] else ''
            elapsed = read_status(row)
            lines.append(f"{row['sector']:02d}   {key_a:<12}  {key_b:<12}  {source_code(row['source']):<3}  {elapsed:<7}")
        if self.table_note:
            lines.append(self.table_note[:78])
        return lines

    def draw_table(self, *, final=False):
        import time
        if self.table is None or (not self.table_live and not final):
            return
        now = time.monotonic()
        if not final and now - self.table_updated < .08:
            return
        lines = self.table_lines()
        # Always reserve one status line so warnings never change table height.
        if not self.table_note:
            lines.append('')
        if self.table_live:
            if self.table_height:
                print(f'\033[{self.table_height}A', end='', file=self.stream)
            print(''.join('\r\033[2K' + line + '\n' for line in lines), end='', file=self.stream, flush=True)
            self.table_height = len(lines)
        elif not self.table_printed:
            print('\n'.join(lines), file=self.stream, flush=True)
        self.table_printed = self.table_printed or final
        self.table_updated = now

    def clear(self):
        if self.active:
            print('\r\033[2K', end='', file=self.stream)
            self.active = False

    def update(self, text, *, final=False):
        import time
        now = time.monotonic()
        if self.tty:
            if not final and now-self.last_update < .12:
                return
            self.clear()
            print(text, end='\n' if final else '', file=self.stream, flush=True)
            self.active = not final
            self.last_update = now
        elif final:
            print(text, file=self.stream, flush=True)

    def render(self, kind, data):
        if kind == 'tag.info' and data.get('operation') == 'read':
            print(read_header(data, color=terminal_color(self.stream)), file=self.stream, flush=True)
            return True
        if kind == 'session.started' and data.get('operation') == 'read':
            scope = data['scope']
            if len(scope) == 64:
                label = 'Reading whole card'
            elif len(scope) == 1:
                label = f'Reading block {scope[0]}'
            else:
                label = f'Reading sector {scope[0]//4}'
            if 'sectors' not in data:
                print(label+'\n', file=self.stream, flush=True)
            if 'sectors' in data:
                import shutil
                import os
                self.table = data['sectors']
                size = shutil.get_terminal_size((80, 24))
                self.table_live = (self.tty and os.environ.get('TERM') != 'dumb'
                                   and size.columns >= 78 and size.lines >= len(self.table) + 5)
                self.draw_table()
            return True
        if data.get('operation') != 'read':
            if kind == 'error' or kind == 'session.interrupted':
                self.clear()
            if self.table is not None and kind in ('error', 'session.interrupted'):
                self.table = [dict(row, status='incomplete') if row['status'] != 'complete' else row
                              for row in self.table]
                if not self.table_printed:
                    self.draw_table(final=True)
                self.table_height = 0
            return False
        if kind == 'operation.progress':
            phase, step = data['phase'], data.get('step')
            if 'sectors' in data:
                if phase == 'hardnested' and step == 'benchmark':
                    self.benchmark = data['benchmark']
                self.table = data['sectors']
                if phase in ('unresolved', 'recovery-unavailable', 'auth-timeout-fallback'):
                    self.table_note = data['message']
                if phase != 'finished':
                    if step == 'benchmark':
                        self.table_updated = 0  # Insert directly below the card header.
                    self.draw_table(final=phase in ('failed', 'interrupted'))
                return True
            if phase in self.LABELS:
                status = 'complete' if step == 'complete' else 'in progress'
                self.update(f"{self.LABELS[phase]}...  {status} {data['keys_known']}/{data['keys_total']}", final=step == 'complete')
            elif phase == 'nested':
                # Session-level strategy notes share the phase with detailed
                # progress. They are saved in events; recovery-path already
                # supplies the compact human-facing announcement.
                if step is None:
                    return True
                if step == 'start':
                    self.method, self.attempt = data['method'], data['attempt']
                action = {'start': 'Preparing capture', 'capture': 'Capturing...', 'solve': 'Solving...',
                          'verify': 'Verifying...', 'recovered': 'Recovered'}[step]
                if step == 'verify' and 'checked' in data:
                    action += f" {data['checked']}/{data['candidates']}  candidates"
                if step == 'recovered' and 'elapsed_s' in data:
                    action += f" / {data['elapsed_s']:.2f} s"
                retry = f' / attempt {self.attempt}' if self.attempt > 1 else ''
                self.update(f"Recovering keys    {self.method} / Sector {data['sector']} / Key {data['key_type']}{retry} / {action}", final=step == 'recovered')
            elif phase == 'hardnested':
                if step is None:
                    self.update(data.get('message', 'Preparing hardnested'), final=True)
                else:
                    action = {'capture-reduce':'Capturing and reducing...', 'solve':'Solving...',
                              'verify':'Verifying...', 'recovered':'Recovered'}.get(step, step)
                    if step == 'recovered':
                        action += f" / {data['elapsed_s']:.2f} s"
                    self.update(f"Recovering keys    hardnested / Sector {data['sector']} / Key {data['key_type']} / {action}",
                                final=step in ('solve','recovered'))
            elif phase == 'read':
                self.update(f"Reading data    {data['blocks_read']}/{data['blocks_total']} Blocks")
            elif phase in ('unresolved', 'recovery-unavailable', 'auth-timeout-fallback'):
                self.update(data['message'], final=True)
            elif phase == 'recovery-path':
                self.update(data['message'], final=True)
            return True
        if kind == 'operation.finished':
            self.clear()
            footer = read_result_lines(data)
            if self.table is not None:
                status = 'Complete' if data['status'] == 'complete' else 'Incomplete'
                self.table_note = (f"{status} | Blocks {data['blocks_read']}/{data['blocks_total']}"
                                   f" | Keys {data['keys_known']}/{data['keys_total']}"
                                   f" | {data['elapsed_s']:.2f}s")
                self.draw_table(final=True)
                self.table_height = 0
                if footer:
                    print('\n'.join(footer), file=self.stream, flush=True)
                return True
            if self.table is not None and not self.table_printed:
                self.draw_table(final=True)
            self.table_height = 0
            status = 'Read complete' if data['status'] == 'complete' else 'Read incomplete'
            text = (f"\n{status}\nBlocks      {data['blocks_read']}/{data['blocks_total']}\n"
                    f"Keys    {data['keys_known']}/{data['keys_total']}\n"
                    f"Elapsed    {data['elapsed_s']:.2f} s\n")
            if data.get('unread_sectors'):
                text += 'Unread  Sector '+ ', '.join(map(str, data['unread_sectors']))+'\n'
            print(text+'\n'.join(footer), file=self.stream, flush=True)
            return True
        return False
