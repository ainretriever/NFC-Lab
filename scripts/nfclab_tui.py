# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 NFClab contributors.
"""Card Library/device TUI. All core actions use arrows, Enter and Escape."""
from dataclasses import dataclass
from datetime import datetime
import curses
import os
from pathlib import Path
import queue
import sys
import time
import textwrap
import unicodedata
from nfclab_library import Library, default_library
from nfclab_tasks import DeviceWorker


def width(text):
    return sum(0 if unicodedata.combining(c) else 2 if unicodedata.east_asian_width(c) in 'WF' else 1 for c in str(text))


def clip(text, limit):
    result=''
    for c in str(text):
        if width(result+c)>limit:
            break
        result+=c
    return result


def stamp(milliseconds):
    return datetime.fromtimestamp(milliseconds/1000).astimezone().strftime('%m-%d %H:%M:%S')


@dataclass
class Page:
    title: str
    lines: list
    options: list


class App:
    def __init__(self, config, worker=None):
        self.config=config
        self.config.library=Path(config.library or default_library()).resolve()
        self.worker=worker or DeviceWorker(config)
        self.page=None
        self.back=[]
        self.selected=0
        self.message='Ready'
        self.device='Connecting...'
        self.color_mode='monochrome' if config.monochrome else 'auto'
        self.running=False
        self.exiting=False
        self.closed=False
        self.latest_events=[]
        self.result=None
        self.current_operation=None
        self.dump_options=None
        self.last_dump_card=None
        self.confirmation=None
        self.key_editor=None
        self.home(reset=True)

    def show(self, page, *, remember=True):
        if remember and self.page:
            self.back.append((self.page,self.selected))
        self.page,self.selected=page,0

    def go_back(self):
        if self.confirmation:
            self.reply_write(False)
        elif self.key_editor:
            self.key_editor=None
            self.go_back()
        elif self.back:
            self.page,self.selected=self.back.pop()
            if self.page.title=='Current task':
                self.task_page()
        else:
            self.request_exit()

    def home(self, reset=False):
        if reset:
            self.back=[]
        self.show(Page('NFClab', ['Select a function'],[
            ('Tag info   View information only',lambda:self.start('info')),
            ('Read       Recover and save card',self.read_menu),
            ('Dump       Read using selected keys',self.dump_menu),
            ('Write      Select a library card',lambda:self.cards('write')),
            ('Library    Browse cards',lambda:self.cards('browse')),
            ('Settings   Display and device',self.settings),
            ('Exit',self.request_exit)]),remember=not reset)

    def text(self, title, lines, actions=None, index=0, remember=True):
        # Content paging avoids pushing all details off a small terminal.
        lines=[part for line in lines for part in (textwrap.wrap(str(line),56) or [''])]
        chunks=[lines[i:i+10] for i in range(0,len(lines),10)] or [[]]
        options=[]
        if index>0:
            options.append(('Previous page',lambda:self.text(title,lines,actions,index-1,remember=False)))
        if index+1<len(chunks):
            options.append(('Next page',lambda:self.text(title,lines,actions,index+1,remember=False)))
        options.extend(actions or [])
        options.append(('Back',self.go_back))
        self.show(Page(f'{title} / {index+1} of {len(chunks)}',chunks[index],options),remember=remember)

    def fail(self,error):
        self.message=str(error)
        self.text('Error',[str(error)])

    def read_menu(self):
        self.show(Page('Read', ['Recover keys and save the current UID to Card Library'], [
            ('Start whole-card Read', lambda:self.start('read')), ('Back',self.go_back)]))

    def dump_menu(self):
        self.show(Page('Dump / Key source', ['Read fresh blocks using known keys'], [
            ('Select keys from library',lambda:self.cards('dump')),
            ('Manual key or preset',self.dump_presets),('Back',self.go_back)]))

    def dump_presets(self):
        self.show(Page('Dump / Presets',['Apply a single key to all sectors'],[
            ('All FFFFFFFFFFFF',lambda:self.choose_dump(key='ffffffffffff')),
            ('All 000000000000',lambda:self.choose_dump(key='000000000000')),
            ('Edit a hexadecimal key',lambda:self.edit_key(self.choose_dump)),('Back',self.go_back)]))

    def edit_key(self, callback):
        self.key_editor=dict(value=list('ffffffffffff'),position=0,callback=callback)
        self.show(Page('Key editor',['Left/Right: choose digit; Up/Down: change digit','Enter: use key; Esc: cancel'],[]))

    def choose_dump(self, **options):
        self.dump_options=options
        label=f"Card {options['card']}" if options.get('card') else 'Key '+options['key'].upper()
        self.show(Page('Dump / Ready',[label,'Hold the target card on the antenna'],[
            ('Start Dump',lambda:self.start('dump',**self.dump_options)),('Back',self.go_back)]))

    def cards(self, mode):
        library = Library(self.config.library)
        options=[]
        for uid, card in library.index.items():
            if mode in ('dump','target') and card['keys_known'] != 32:
                continue
            def action(uid=uid):
                if mode=='dump':self.choose_dump(card=uid)
                elif mode=='target':self.write_mode(target_card=uid)
                elif mode=='write':self.select_write(uid)
                else:self.card(uid)
            options.append((f"{uid}  {card['name']}  K {card['keys_known']}/32", action))
        self.show(Page('Card Library', ['Select a UID'], options+[('Back',self.go_back)]))

    def card(self, uid):
        card = Library(self.config.library).card(uid)
        self.show(Page(f'Card {uid}', [card['name'],
            f"Blocks {card['blocks_known']}/64   Known keys {card['keys_known']}/32",
            f"Current: {card['dump_file']} / Versions: {len(card['metadata']['versions'])}"], [
            ('Block data',lambda:self.blocks(uid)),('Keys',lambda:self.keys(uid)),
            ('Write this card',lambda:self.select_write(uid)),('Back',self.go_back)]))

    def blocks(self,uid,sector=0,remember=True):
        s = Library(self.config.library).card(uid)
        lines=[]
        for b in range(sector*4,sector*4+4):
            value=s['payload']['blocks'][b]
            lines.append(f"Block {b:02}: "+(bytes.fromhex(value).hex(' ').upper() if value else '<unknown>'))
        lines.append('Dump bytes include known trailer keys')
        self.show(Page(f'Card {uid} / Sector {sector}',lines,[
            ('Previous sector',lambda:self.blocks(uid,(sector-1)%16,remember=False)),
            ('Next sector',lambda:self.blocks(uid,(sector+1)%16,remember=False)),('Back',self.go_back)]),remember=remember)

    def keys(self,uid,sector=0,remember=True):
        s = Library(self.config.library).card(uid)
        lines=[]
        for t in (0,1):
            key=s['payload']['keys'][sector*2+t]
            lines.append(f"Sector {sector} / Key {'AB'[t]}: {(key['value'] or '<unknown>').upper()} / {key['state']}")
        self.show(Page(f'Card {uid} / Keys',lines,[
            ('Previous sector',lambda:self.keys(uid,(sector-1)%16,remember=False)),
            ('Next sector',lambda:self.keys(uid,(sector+1)%16,remember=False)),('Back',self.go_back)]),remember=remember)

    def select_write(self,uid):
        self.write_source=uid
        s = Library(self.config.library).card(uid)
        self.show(Page('Write / Target credentials',[f"Source card {uid} / {s['uid']}",
            'These credentials authenticate the CURRENT target card'],[
            ('Gen1a / UID backdoor (no key)',lambda:self.write_mode(card_type='gen1a')),
            ('Try source card keys',lambda:self.write_mode(target_card=uid)),
            ('Select target keys from library',lambda:self.cards('target')),
            ('All FFFFFFFFFFFF',lambda:self.write_mode(key='ffffffffffff')),
            ('All 000000000000',lambda:self.write_mode(key='000000000000')),
            ('Edit target key',lambda:self.edit_key(self.write_mode)),('Back',self.go_back)]))

    def write_mode(self,**credentials):
        self.show(Page('Write / Mode',[f'Source card {self.write_source}','Target will be identified and preflighted before confirmation'],[
            ('Copy data and keys; keep target UID',lambda:self.start('write',card=self.write_source,**credentials)),
            ('Full copy including UID',lambda:self.start('write',card=self.write_source,include_uid=True,**credentials)),
            ('Back',self.go_back)]))

    def start(self,operation,**options):
        if self.worker.active or self.running:
            self.text('Device busy',['One hardware task at a time'],[('View current task',self.task_page)])
            return
        self.result=None;self.latest_events=[];self.confirmation=None
        self.worker.submit(operation,**options)
        self.current_operation=operation;self.running=True;self.message='Task started'
        self.task_page()

    def task_page(self):
        lines=[f'Task: {self.current_operation}',self.message]
        tag=next((e for e in reversed(self.latest_events) if e['type']=='tag.info'),None)
        if tag:
            lines.append('Card UID: '+tag['uid'].upper())
        if not self.running and self.result:
            if 'blocks_read' in self.result:
                lines.append(f"Blocks {self.result['blocks_read']} / Known keys {self.result['keys_known']}")
            if self.result.get('path'):
                lines.append(self.result['path'])
            if self.result.get('dump_file'):
                lines.append('Dump: '+self.result['dump_file'])
            if self.result.get('library_status'):
                lines.append('Library: '+self.result['library_status'])
        progress=next((e for e in reversed(self.latest_events) if e['type']=='operation.progress'),None)
        if progress and (self.running or not self.result):
            if 'blocks_read' in progress:
                lines.append(f"Blocks {progress['blocks_read']}/{progress.get('blocks_total',64)} / Keys {progress.get('keys_known',progress.get('keys_checked','-'))}")
            if self.current_operation=='write':
                lines.append(f"Verified {progress.get('verified',0)}/{progress.get('total','-')} / Block {progress.get('block','-')}")
            lines.append('Phase: '+str(progress.get('phase',progress.get('step','working'))))
            if 'candidates' in progress:
                lines.append(f"Candidates checked {progress.get('checked',0)}/{progress['candidates']}")
        options=[]
        if self.running:
            options=[('Request stop after current MCU batch',self.stop),('Browse library',lambda:self.cards('browse')),
                     ('Main menu (task keeps running)',self.home)]
        else:
            if self.result and self.result.get('uid'):
                options.append(('View saved card',lambda:self.card(self.result['uid'])))
            if self.current_operation=='dump' and self.dump_options:
                options.append(('Read again with selected keys',lambda:self.start('dump',**self.dump_options)))
            if self.current_operation=='read':
                options.append(('Read another card',lambda:self.start('read')))
            options.append(('Main menu',lambda:self.home(reset=True)))
        self.show(Page('Current task',lines,options),remember=False)

    def stop(self):
        self.worker.stop();self.message='Stop requested; waiting for current MCU batch to return'
        self.task_page()

    def write_confirm(self,event,index=0,details=False):
        self.confirmation=event
        if details:
            source_lines=event['lines']
        else:
            trailers=sum(w['block']%4==3 for w in event['plan'].get('writes',[]))
            warnings=list(dict.fromkeys(line for line in event['lines']
                                       if line.startswith(('[Warning]','[Alert]','[Encoding error]'))))
            source_lines=event['lines'][:4]+[
                f'Sector trailers: {trailers}; keys and access bits included',
                ('Gen1a backdoor write; full key/data readback' if event['plan'].get('card_type')=='gen1a' else
                 'Target keys authenticated')]+warnings
        lines=[part for line in source_lines for part in (textwrap.wrap(line,56) or [''])]
        chunks=[lines[i:i+9] for i in range(0,len(lines),9)] or [[]]
        options=[('Back / cancel write',lambda:self.reply_write(False))]
        if index>0:
            options.append(('Previous plan page',lambda:self.write_confirm(event,index-1,details)))
        if index+1<len(chunks):
            options.append(('Next plan page',lambda:self.write_confirm(event,index+1,details)))
        if details:
            options.append(('Return to confirmation summary',lambda:self.write_confirm(event)))
        else:
            options.append(('View full block/permission plan',lambda:self.write_confirm(event,details=True)))
            if index+1==len(chunks):
                options.append(('Confirm write to this target',lambda:self.reply_write(True)))
        title='Write plan details' if details else 'Write confirmation'
        self.show(Page(f'{title} / {index+1} of {len(chunks)}',
                       chunks[index]+['Esc cancels; no WRITE has been submitted'],options),remember=False)

    def reply_write(self,accepted):
        self.confirmation=None
        self.worker.confirm(accepted)
        self.message='Writing confirmed plan' if accepted else 'Write cancelled'
        self.task_page()

    def settings(self):
        self.show(Page('Settings',[f'Display: {self.color_mode}',f'Library: {self.config.library}'],[
            ('Automatic color',lambda:self.set_color('auto')),('Color',lambda:self.set_color('color')),
            ('Monochrome',lambda:self.set_color('monochrome')),('Reconnect device',lambda:self.start('reconnect')),
            ('View current task',self.task_page),('Back',self.go_back)]))

    def set_color(self,mode):
        self.color_mode=mode;self.settings()

    def request_exit(self):
        self.show(Page('Exit',['Stop active tasks and release USB before exiting'],[
            ('Return to application',self.go_back),('Stop and exit',self.exit)]))

    def exit(self):
        self.exiting=True;self.worker.close();self.message='Waiting for worker / current MCU batch'
        self.show(Page('Exiting',[self.message],[('Waiting for device shutdown',lambda:None)]),remember=False)

    def poll(self):
        while True:
            try:event=self.worker.output.get_nowait()
            except queue.Empty:break
            kind=event['type']
            self.latest_events.append(event);self.latest_events=self.latest_events[-100:]
            if kind=='device.connected':self.device='Connected: '+event['port']
            elif kind=='device.disconnected':self.device='Disconnected: '+event['message']
            elif kind=='write.confirmation':self.write_confirm(event)
            elif kind=='task.error':self.message=event['message']
            elif kind=='task.stopped':self.message=event['message']
            elif kind=='operation.finished':
                self.result=event;self.message='Result: '+event.get('status','finished')
            elif kind=='task.finished':
                self.running=False
                if event['code']==0 and not self.result:self.message='Task complete'
                if event['code']==130:self.message='Stopped or cancelled; available progress saved'
                elif event['code'] not in (0,4) and not self.message:self.message='Task failed'
                if self.current_operation=='info' and event['code']==0:
                    tag=next(e for e in reversed(self.latest_events) if e['type']=='tag.info')
                    from nfclab_render import tag_info
                    self.text('Tag info',tag_info(tag).splitlines(),[('Identify again',lambda:self.start('info'))])
                elif self.page.title=='Current task':self.task_page()
            elif kind=='worker.closed':self.closed=True
        if self.page.title=='Current task' and self.running and not self.confirmation:
            # Refresh progress without changing which action the user selected.
            selected=self.selected;self.task_page();self.selected=min(selected,len(self.page.options)-1)

    def handle(self,key):
        if self.exiting:return
        if self.key_editor:
            editor=self.key_editor
            if key in ('left','right'):editor['position']=(editor['position']+(-1 if key=='left' else 1))%12
            elif key in ('up','down'):
                pos=editor['position'];digits='0123456789abcdef'
                editor['value'][pos]=digits[(digits.index(editor['value'][pos])+(1 if key=='up' else -1))%16]
            elif key=='enter':
                callback=editor['callback'];value=''.join(editor['value']);self.key_editor=None;callback(key=value)
            elif key=='escape':self.go_back()
            return
        if key=='up':self.selected=max(0,self.selected-1)
        elif key=='down':self.selected=min(len(self.page.options)-1,self.selected+1)
        elif key=='escape':
            if self.page.title=='Current task' and self.running:
                self.show(Page('Task actions',['Esc does not stop the device'],[
                    ('Continue viewing',self.task_page),('Request stop',self.stop),('Main menu',self.home)]))
            else:self.go_back()
        elif key=='enter' and self.page.options:
            self.page.options[self.selected][1]()

    def render(self,columns=80,rows=24):
        lines=list(self.page.lines)
        if self.key_editor:
            value=''.join(self.key_editor['value']).upper()
            lines+=['Key: '+value,'     '+' '*self.key_editor['position']+'^']
        body=lines+['']+[('> ' if i==self.selected else '  ')+label for i,(label,_) in enumerate(self.page.options)]
        focus=len(lines)+1+self.selected;capacity=rows-6
        start=max(0,focus-capacity+1)
        canvas=[self.page.title,self.device,'-'*columns]+body[start:start+capacity]
        canvas+=['']*(rows-3-len(canvas))
        canvas+=['-'*columns,self.message,'Up/Down: select  Enter: open/confirm  Esc: back']
        return [clip(line,columns)+' '*(columns-width(clip(line,columns))) for line in canvas]


def screen(stdscr,app):
    curses.curs_set(0);stdscr.keypad(True);stdscr.timeout(100)
    colors=curses.has_colors()
    if colors:
        curses.start_color();curses.use_default_colors()
        curses.init_pair(1,curses.COLOR_CYAN,-1)
        curses.init_pair(2,curses.COLOR_GREEN,-1)
        curses.init_pair(3,curses.COLOR_YELLOW,-1)
    keys={curses.KEY_UP:'up',curses.KEY_DOWN:'down',curses.KEY_LEFT:'left',curses.KEY_RIGHT:'right',10:'enter',13:'enter',curses.KEY_ENTER:'enter',27:'escape'}
    while not app.closed:
        app.poll();stdscr.erase();height,columns=stdscr.getmaxyx()
        if height<20 or columns<60:
            canvas=['Terminal must be at least 60x20','Recommended: 80x24','Esc: stop and exit']
            top=left=0
        else:
            rows,cols=min(height,24),min(columns,80)
            canvas=app.render(cols,rows);top,left=(height-rows)//2,(columns-cols)//2
        use_color=colors and app.color_mode!='monochrome' and (app.color_mode=='color' or not os.environ.get('NO_COLOR'))
        for y,line in enumerate(canvas[:height]):
            attr=curses.A_REVERSE if line.startswith('> ') else curses.A_NORMAL
            if use_color and y==0:attr=curses.color_pair(1)|curses.A_BOLD
            elif use_color and y==1:attr=curses.color_pair(2 if app.worker.connected else 3)
            try:stdscr.addstr(top+y,left,clip(line,max(0,columns-left)),attr)
            except curses.error:pass
        stdscr.refresh()
        key=stdscr.getch()
        try:
            if height<20 or columns<60:
                if key==27:app.exit()
            elif key in keys:app.handle(keys[key])
        except Exception as error:app.fail(error)


def launch(config):
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        print('TUI requires an interactive terminal',file=sys.stderr)
        return 2
    app=None
    try:
        app=App(config)
        curses.wrapper(screen,app)
        return 0
    except (OSError,ValueError,curses.error) as error:
        print(str(error),file=sys.stderr);return 1
    finally:
        if app:
            app.worker.close()
            # A device task can be completing a long MCU batch. Keep ownership
            # until it reaches a host boundary; never abandon an active write.
            while app.worker.thread.is_alive():
                app.worker.thread.join(.2)
