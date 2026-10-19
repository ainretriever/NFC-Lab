# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 NFClab contributors.
"""CLI connection lifetime, event output and compatibility checks."""
from contextlib import contextmanager, redirect_stdout
import fcntl
import glob
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid


class Events:
    def __init__(self, format, verbose=False):
        self.format, self.index = format, 0
        self.stream = sys.stdout
        self._path = None
        self.session_id = uuid.uuid4().hex
        self.verbose = verbose
        from nfclab_render import ReadView
        self.read_view = ReadView(self.stream)

    @property
    def path(self):
        return self._path

    @path.setter
    def path(self, value):
        self._path = value
        if value and value.exists():
            for line in value.read_text().splitlines():
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                self.index = max(self.index, event['event_id'])
                self.session_id = event.get('session_id', self.session_id)

    def emit(self, kind, **data):
        self.index += 1
        event = dict(schema_version=1, session_id=self.session_id, event_id=self.index, host_time=time.time(), type=kind, **data)
        line = json.dumps(event, ensure_ascii=False)
        if self.path:
            with self.path.open('a') as stream:
                stream.write(line+'\n')
        if self.format == 'human' and not self.verbose and self.read_view.render(kind, data):
            return
        if self.format == 'human' and not self.verbose and kind == 'operation.finished' and data.get('operation')=='write' and 'block' in data:
            text = f"块 {data['block']} · " + ('写入 ACK' if data.get('completed')==1 and data.get('error')=='ok' else f"写入失败：{data.get('error')}")
        elif self.format == 'human' and kind == 'library.cards':
            from nfclab_render import library_cards
            text = library_cards(data['cards'])
        elif self.format == 'human' and kind == 'tag.info':
            from nfclab_render import tag_info, terminal_color
            text = tag_info(data, color=terminal_color(self.stream))
        elif self.format == 'human' and kind.startswith('uid_sim.'):
            uid = bytes.fromhex(data['uid']).hex(' ').upper()
            if kind == 'uid_sim.started':
                text = f'UID simulation started: {uid} | Ctrl+C to stop'
            elif kind == 'uid_sim.stopped':
                text = f'UID simulation stopped | selections: {data["selected"]}'
            else:
                label = 'active' if data['active'] else 'stopped'
                text = f'UID simulation {label}: {uid} | selections: {data["selected"]}'
                if data['lease_expired']:
                    text += ' | stopped automatically: heartbeat lease expired'
        elif self.format == 'human' and kind == 'frame.received' and not self.verbose:
            frame = data['frame']
            text = f"[{data['capture']}] {frame['source']:3}  {frame.get('phase', 'frame'):18} {frame['data']}"
        else:
            text = line if self.format == 'jsonl' else f'[{kind}] {json.dumps(data, ensure_ascii=False)}'
        print(text, file=self.stream, flush=True)


def ports():
    # Never select PM3 just because it is another ttyACM device.
    return sorted({str(Path(p).resolve()) for p in glob.glob('/dev/serial/by-id/usb-*NFClab*')})


@contextmanager
def connection(a):
    import transport
    import swd
    found = ports()
    port = a.device or os.environ.get('NFCLAB_CDC_PORT')
    if not port:
        if len(found) != 1:
            raise transport.TransportError(f'expected one NFClab device, found {len(found)}; use --device')
        port = found[0]
    lock_id = hashlib.sha256(os.path.realpath(port).encode()).hexdigest()[:20]
    lock = open(f'/tmp/nfclab-{os.getuid()}-{lock_id}.lock', 'a')
    previous = {k: os.environ.get(k) for k in ('NFCLAB_TRANSPORT', 'NFCLAB_CDC_PORT')}
    try:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise transport.TransportError('NFClab device is in use by another CLI') from None
        os.environ['NFCLAB_TRANSPORT'], os.environ['NFCLAB_CDC_PORT'] = 'cdc', port
        transport.reset()
        if a.elf:
            output = subprocess.check_output(['arm-none-eabi-nm', '-n', str(a.elf)], text=True)
            table = {fields[2]: int(fields[0], 16) for line in output.splitlines() if len(fields := line.split()) == 3}
            swd._symbol_table.cache_clear()
            original = swd._symbol_table
            swd._symbol_table = lambda: table
        else:
            original = None
        try:
            link = transport.active()
            # Kernel exclusivity prevents new serial clients opening this port.
            import termios
            fcntl.ioctl(link.fd, termios.TIOCEXCL)
            yield link
        finally:
            if transport._active is not None:
                try:
                    import termios
                    fcntl.ioctl(transport._active.fd, termios.TIOCNXCL)
                except OSError:
                    pass
            transport.reset()
            if original:
                swd._symbol_table = original
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        lock.close()


def reader_mode():
    """Require idle ABI then enable the retained reader dispatcher."""
    from swd import snapshot_running, symbol, write_words
    from m1_host import wait_idle
    try:
        uid_address = symbol('uid_sim')
    except RuntimeError:
        uid_address = None  # Older reader-only firmware remains supported.
    if uid_address is not None:
        uid_state = snapshot_running(uid_address, 6)
        if uid_state[:2] != [0x55494453, 1]:
            raise RuntimeError('UID simulator ABI mismatch; use matching firmware/ELF')
        if any(uid_state[2:5]):
            raise RuntimeError('UID simulation is active; stop it before reader operations')
        if uid_state[5] == 3:
            raise RuntimeError('UID simulator NFC error; retry emulate stop or reset the device')
    if wait_idle(timeout=0):
        raise RuntimeError('MCU operation is busy; no request submitted')
    address = symbol('sniff')
    state = snapshot_running(address, 4)
    if state[:2] not in ([0x534e4946, 2], [0x534e4946, 3]):
        raise RuntimeError('sniff ABI mismatch; use an ELF matching flashed firmware')
    if state[2] or state[3]:
        raise RuntimeError('sniff capture busy')
    from m1_host import VERSION
    if snapshot_running(symbol('m1'), 2) != [0x4d31494f, VERSION]:
        raise RuntimeError('M1 ABI mismatch; use an ELF matching flashed firmware')
    write_words(address+16, [0], halt=False)


def execute(a):
    from transport import TransportError
    events = Events(a.format, a.verbose)
    try:
        # Legacy progress is diagnostic; structured events are emitted separately.
        with redirect_stdout(sys.stderr):
            if a.group == 'device' and a.command == 'list':
                events.emit('devices', ports=ports())
                return 0
            if a.group == 'library':
                from nfclab_library import command
                return command(a, events)
            if a.group == 'session':
                from nfclab_sniff import session_command
                return session_command(a, events)
            if a.group == 'sniff' and not a.windowed:
                raise TransportError('continuous sniff is not supported by current firmware; use --windowed explicitly')
            if a.group == 'm1' and a.command == 'write':
                from nfclab_ops import write
                # Confirmation/preview occurs before opening a connection.
                return write(a, events)
            with connection(a) as link:
                if a.group == 'emulate':
                    from nfclab_emulate import run
                    return run(a, events)
                if a.group == 'device':
                    events.emit('device.info', port=link.port, info=link.info, abi_discovery='ELF compatibility bridge', continuous_sniff=False)
                    return 0
                if a.group == 'sniff':
                    from nfclab_sniff import listen
                    return listen(a, link, events)
                reader_mode()
                from nfclab_ops import run
                return run(a, events)
    except KeyboardInterrupt:
        events.emit('session.interrupted', device_stop_confirmed=False)
        return 130
    except TransportError as error:
        events.emit('error', message=str(error))
        return 3
    except (ValueError, FileNotFoundError) as error:
        events.emit('error', message=str(error))
        return 2
    except (OSError, RuntimeError) as error:
        events.emit('error', message=str(error))
        return 1
