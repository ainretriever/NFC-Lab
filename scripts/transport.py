# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 NFClab contributors.
"""Transport to the MCU mailbox RAM.

Two implementations share one small byte-oriented interface:

  * `CdcTransport`     - framed protocol over the USB CDC link (fast, default)
  * `OpenOcdTransport` - ST-Link/SWD through OpenOCD (debug fallback)

Every existing mailbox helper only needs read/write access to SRAM, so the same
host code drives either link.  Select explicitly with `NFCLAB_TRANSPORT=cdc|swd`
and `NFCLAB_CDC_PORT=/dev/ttyACM0`; the default prefers CDC and falls back to SWD.
"""
import binascii
import glob
import os
import re
import select
import struct
import subprocess
import tempfile
import termios
import time
import tty
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Accepted MCU core clocks. 96 MHz is the HSE25/PLLN192 build that also yields
# the 48 MHz USB clock; 100 MHz was the pre-USB HSI build.
CLOCKS = (16000000, 96000000, 100000000)

# Must match firmware/usb_proto.inc.
OP_ECHO = 0x01
OP_INFO = 0x02
OP_READ_MEM = 0x10
OP_WRITE_MEM = 0x11
USB_MAX_PAYLOAD = 8192
FRAME_HEADER = 8
FRAME_TRAILER = 2
MAX_XFER_BYTES = USB_MAX_PAYLOAD - FRAME_HEADER

# Below this size a plain mdw/mww burst beats writing a temporary image.
BULK_THRESHOLD = 256


class TransportError(RuntimeError):
    pass


def _frame(opcode, seq, payload):
    """Encode one protocol frame, including the pad byte the firmware expects."""
    data = b'NF' + bytes((1, opcode, seq, 0)) + struct.pack('<H', len(payload)) + payload
    data += struct.pack('<H', binascii.crc_hqx(data, 0xffff))
    if len(data) % 64 == 0:
        data += b'\0'
    return data


class CdcTransport:
    name = 'cdc'

    def __init__(self, port=None):
        self.port = port or find_cdc_port()
        if not self.port:
            raise TransportError('no CDC port found')
        self.fd = os.open(self.port, os.O_RDWR | os.O_NOCTTY)
        try:
            tty.setraw(self.fd)
            attrs = termios.tcgetattr(self.fd)
            attrs[4] = attrs[5] = termios.B115200
            termios.tcsetattr(self.fd, termios.TCSANOW, attrs)
            termios.tcflush(self.fd, termios.TCIOFLUSH)
        except Exception:
            os.close(self.fd)
            raise
        self.seq = 0
        try:
            self.info = self._info()
        except Exception:
            os.close(self.fd)
            raise

    def close(self):
        try:
            os.close(self.fd)
        except OSError:
            pass

    def _write_all(self, data, deadline):
        offset = 0
        while offset < len(data):
            remaining = deadline - time.monotonic()
            # select returns (readable, writable, exceptional): the fd is in wlist.
            if remaining <= 0 or not select.select([], [self.fd], [], remaining)[1]:
                raise TransportError('CDC write timeout')
            offset += os.write(self.fd, data[offset:])

    def _exchange(self, opcode, payload, timeout=120.0):
        seq = self.seq & 0xff
        self.seq = (self.seq + 1) & 0xff
        deadline = time.monotonic() + timeout
        self._write_all(_frame(opcode, seq, payload), deadline)
        response = bytearray()
        want = None
        while want is None or len(response) < want:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([self.fd], [], [], remaining)[0]:
                raise TransportError(f'CDC timeout: op={opcode} seq={seq} got={len(response)}')
            chunk = os.read(self.fd, 4096)
            if not chunk:
                continue
            response.extend(chunk)
            if want is None and len(response) >= FRAME_HEADER:
                if response[:2] != b'NF' or response[2] != 1:
                    raise TransportError(f'CDC framing lost: {bytes(response[:8])!r}')
                length = struct.unpack_from('<H', response, 6)[0]
                if length > USB_MAX_PAYLOAD:
                    raise TransportError(f'CDC oversized frame: {length}')
                want = FRAME_HEADER + FRAME_TRAILER + length
                if want % 64 == 0:
                    want += 1
        length = struct.unpack_from('<H', response, 6)[0]
        if response[3] != opcode or response[4] != seq:
            raise TransportError(f'CDC reply mismatch: want op={opcode} seq={seq}, '
                                 f'got op={response[3]} seq={response[4]}')
        crc = struct.unpack_from('<H', response, FRAME_HEADER + length)[0]
        if binascii.crc_hqx(bytes(response[:FRAME_HEADER + length]), 0xffff) != crc:
            raise TransportError('CDC reply CRC mismatch')
        return bytes(response[FRAME_HEADER:FRAME_HEADER + length])

    def _info(self):
        payload = self._exchange(OP_INFO, b'', timeout=5)
        if len(payload) != 12:
            raise TransportError(f'short INFO reply: {len(payload)}')
        return {'protocol': payload[0], 'state': payload[2],
                'clock_hz': struct.unpack_from('<I', payload, 4)[0],
                'clock_src': payload[8]}

    def read_bytes(self, address, length, *, halt=True):
        out = bytearray()
        while length:
            n = min(length, MAX_XFER_BYTES)
            reply = self._exchange(OP_READ_MEM, struct.pack('<II', address, n))
            if len(reply) != n:
                raise TransportError(f'short READ_MEM reply: {len(reply)} != {n}')
            out += reply
            address += n
            length -= n
        return bytes(out)

    def write_bytes(self, address, data, *, halt=True):
        offset = 0
        while offset < len(data):
            n = min(len(data) - offset, MAX_XFER_BYTES)
            reply = self._exchange(OP_WRITE_MEM,
                                   struct.pack('<II', address + offset, n) + data[offset:offset + n])
            if len(reply) != 4 or struct.unpack('<I', reply)[0] != n:
                raise TransportError('WRITE_MEM was not confirmed')
            offset += n

    def write_segments(self, segments, *, halt=True):
        for address, data in segments:
            self.write_bytes(address, data, halt=halt)


class OpenOcdTransport:
    name = 'swd'

    def _run(self, commands, halt):
        control = ['-c', 'halt', '-c', 'wait_halt 2000'] if halt else []
        finish = ['-c', 'resume'] if halt else []
        result = subprocess.run(['openocd', '-f', 'interface/stlink.cfg', '-f',
                                 'target/stm32f4x.cfg', '-c', 'adapter speed 1000',
                                 '-c', 'init', *control, '-c', commands, *finish,
                                 '-c', 'shutdown'],
                                cwd=ROOT, text=True, capture_output=True, timeout=60)
        if result.returncode:
            # Commands may contain key material: do not echo the command string.
            raise TransportError('OpenOCD failed:\n' + result.stdout + result.stderr)
        words = []
        for line in (result.stdout + result.stderr).splitlines():
            match = re.match(r'^0x[0-9a-fA-F]+:\s+(.+)$', line)
            if match:
                words.extend(int(value, 16) for value in match[1].split())
        return words

    def read_bytes(self, address, length, *, halt=True):
        if length >= BULK_THRESHOLD or length % 4:
            with tempfile.TemporaryDirectory(prefix='nfc-dump-', dir='/tmp') as directory:
                path = Path(directory) / 'memory.bin'
                self._run(f'dump_image {path} 0x{address:x} {length}', halt)
                data = path.read_bytes()
        else:
            count = length // 4
            words = self._run(f'mdw 0x{address:x} {count}', halt)
            if len(words) != count:
                raise TransportError('Incomplete SWD read')
            data = struct.pack(f'<{count}I', *words)
        if len(data) != length:
            raise TransportError(f'Incomplete read: {len(data)} != {length}')
        return data

    def write_bytes(self, address, data, *, halt=True):
        if len(data) >= BULK_THRESHOLD or len(data) % 4:
            with tempfile.TemporaryDirectory(prefix='nfc-load-', dir='/tmp') as directory:
                path = Path(directory) / 'memory.bin'
                path.write_bytes(data)
                self._run(f'load_image {path} 0x{address:x} bin', halt)
        else:
            words = struct.unpack(f'<{len(data)//4}I', data)
            commands = '; '.join(f'mww 0x{address + i*4:x} {value}'
                                 for i, value in enumerate(words))
            self._run(commands, halt)

    def write_segments(self, segments, *, halt=True):
        """Write several disjoint ranges in ONE OpenOCD invocation.

        A mailbox submit sets a header, a config block and a request flag at
        different addresses; issuing them as separate runs costs ~190 ms each.
        """
        commands = []
        with tempfile.TemporaryDirectory(prefix='nfc-load-', dir='/tmp') as directory:
            for index, (address, data) in enumerate(segments):
                if len(data) >= BULK_THRESHOLD or len(data) % 4:
                    path = Path(directory) / f'segment{index}.bin'
                    path.write_bytes(data)
                    commands.append(f'load_image {path} 0x{address:x} bin')
                else:
                    words = struct.unpack(f'<{len(data)//4}I', data)
                    commands.extend(f'mww 0x{address + i*4:x} {value}'
                                    for i, value in enumerate(words))
            if commands:
                self._run('; '.join(commands), halt)


def find_cdc_port():
    override = os.environ.get('NFCLAB_CDC_PORT')
    if override:
        return override
    for pattern in ('/dev/serial/by-id/usb-NFCl*', '/dev/ttyACM*'):
        matches = sorted(glob.glob(pattern))
        if matches:
            return matches[0]
    return None


_active = None


def active():
    """Return the process-wide transport, choosing CDC when it answers."""
    global _active
    if _active is not None:
        return _active
    choice = os.environ.get('NFCLAB_TRANSPORT', 'auto').lower()
    if choice not in ('auto', 'cdc', 'swd'):
        raise TransportError(f'unknown NFCLAB_TRANSPORT={choice!r}')
    if choice in ('auto', 'cdc'):
        port = find_cdc_port()
        if port:
            try:
                _active = CdcTransport(port)
                return _active
            except (TransportError, OSError) as error:
                if choice == 'cdc':
                    raise
                print(f'CDC unavailable ({error}); falling back to SWD', flush=True)
    _active = OpenOcdTransport()
    return _active


def reset():
    """Drop the cached transport; the next active() call reconnects."""
    global _active
    if _active is not None:
        close = getattr(_active, 'close', None)
        if close:
            close()
    _active = None
