# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 NFClab contributors.
"""Single device worker with persistent CDC ownership and UI event delivery."""
from contextlib import ExitStack, nullcontext
import queue
import threading
from nfclab_cli import build_parser


class Stopped(KeyboardInterrupt):
    pass


class TaskEvents:
    format = 'human'
    path = None

    def __init__(self, worker):
        self.worker = worker

    def emit(self, kind, **data):
        # Cancel only at host boundaries; never claim the MCU stopped mid-batch.
        if self.worker.stop_requested.is_set() and kind not in ('operation.finished','write.cancelled'):
            raise Stopped('Stop requested; last MCU batch returned')
        self.worker.output.put(dict(type=kind, **data))


class DeviceWorker:
    def __init__(self, config):
        self.config = config
        self.commands = queue.Queue()
        self.output = queue.Queue()
        self.stop_requested = threading.Event()
        self.confirm_reply = queue.Queue()
        self.lock = threading.Lock()
        self.active = False
        self.connected = False
        self.closed = False
        self.thread = threading.Thread(target=self._loop, name='nfclab-device', daemon=True)
        self.thread.start()

    def submit(self, operation, **options):
        with self.lock:
            if self.active or self.closed:
                raise ValueError('device task already active or worker closed')
            self.active = True
            self.stop_requested.clear()
            while not self.confirm_reply.empty():
                self.confirm_reply.get_nowait()
            self.commands.put((operation,options))

    def stop(self):
        self.stop_requested.set()

    def confirm(self, accepted):
        self.confirm_reply.put(bool(accepted))

    def close(self):
        self.stop()
        self.closed = True
        self.commands.put(('shutdown',{}))

    def _connect(self, stack):
        from nfclab_runtime import connection
        if not self.connected:
            link = stack.enter_context(connection(self.config))
            self.connected = True
            self.output.put(dict(type='device.connected',port=link.port))

    def _args(self, words):
        args = build_parser().parse_args(words)
        args.library, args.device, args.elf = self.config.library, self.config.device, self.config.elf
        return args

    def _confirm(self, plan, card, lines):
        self.output.put(dict(type='write.confirmation',plan=plan,card=card,lines=lines))
        while not self.stop_requested.is_set():
            try:
                return self.confirm_reply.get(timeout=.2)
            except queue.Empty:
                pass
        return False

    def _operate(self, operation, options):
        from nfclab_runtime import reader_mode
        from nfclab_ops import run
        from nfclab_write import card_write
        from m1_recover_host import identify
        reader_mode()
        events = TaskEvents(self)
        if operation == 'info':
            return run(self._args(['tag','info','--no-write-probe']), events)
        if operation == 'read':
            words=['tag','read','--no-write-probe']
            return run(self._args(words),events)
        if operation == 'dump':
            words=['m1','dump']
            if options.get('card'):
                words+=['--card',str(options['card'])]
            else:
                from nfclab_ops import dump
                args=self._args(['m1','dump','--card','00000000'])
                args.card=None
                class KeyPreset:
                    def read_bytes(self):
                        return bytes.fromhex(options['key'])*32
                args.keys=KeyPreset()
                return dump(args,identify(),events)
            return run(self._args(words),events)
        if operation == 'write':
            card=identify()
            self.output.put(dict(type='tag.info',**card))
            if len(bytes.fromhex(card['uid']))!=4:
                raise ValueError('library card write currently requires a 4-byte target UID')
            words=['m1','write','--card',str(options['card']),'--uid',card['uid']]
            words+=['--card-type',options.get('card_type','standard')]
            if options.get('card_type')=='gen1a':
                pass
            elif options.get('target_card'):
                words+=['--target-card',str(options['target_card'])]
            else:
                words+=['--key',options.get('key','ffffffffffff')]
            if options.get('include_uid'):
                words+=['--include-uid']
            return card_write(self._args(words),events,confirmation=self._confirm,connection_context=nullcontext())
        raise ValueError('unknown device operation')

    def _loop(self):
        from transport import TransportError
        stack=ExitStack()
        try:
            try:
                self._connect(stack)
            except Exception as error:
                self.output.put(dict(type='device.disconnected',message=str(error)))
            while True:
                operation,options=self.commands.get()
                if operation=='shutdown':
                    break
                code=1
                try:
                    if operation=='reconnect':
                        stack.close();self.connected=False
                        self._connect(stack);code=0
                    else:
                        self._connect(stack)
                        code=self._operate(operation,options)
                except KeyboardInterrupt as error:
                    code=130
                    self.output.put(dict(type='task.stopped',message=str(error) or 'Stopped at batch boundary'))
                except Exception as error:
                    self.output.put(dict(type='task.error',message=str(error)))
                    if isinstance(error,(TransportError,OSError)):
                        stack.close();self.connected=False
                        self.output.put(dict(type='device.disconnected',message=str(error)))
                finally:
                    with self.lock:
                        self.active=False
                    self.output.put(dict(type='task.finished',operation=operation,code=code))
        finally:
            stack.close()
            self.connected=False
            self.output.put(dict(type='worker.closed'))
