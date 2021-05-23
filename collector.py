import json
import os
import threading
import time
from watchdog.observers import Observer

from config import Config, State, Outputs
from parsers import RegexParser
from loghandler import LogHandler

config_file = "loganalyser.config"
state_file = "loganalyser.state"
output_file = "loganalyser.output"


class LogObserver:
    def __init__(self):
        self._observer = Observer()
        self._lock = threading.Lock()
        self._event_handlers = dict()

    def add(self, filepath, pos, parsers, inode, device, ctime, output, name):
        directory = os.path.dirname(filepath)
        if directory not in self._event_handlers:
            self._event_handlers[directory] = LogHandler()

        self._event_handlers[directory].add_file(filepath, pos, parsers, inode, device, ctime, output, name)

    def start(self):
        for dir in self._event_handlers:
            self._observer.schedule(self._event_handlers[dir], dir, recursive=False)
        print('starting')
        self._observer.start()

    def stop(self):
        self._observer.stop()

    def join(self):
        self._observer.join()

    def dump_state(self):
        print('dump_state')
        state = []
        for eh in self._event_handlers.values():
            state += eh.dump_state()
        with open(state_file, 'w') as outfile:
            json.dump(state, outfile)

    def flush_output(self):
        for eh in self._event_handlers.values():
            eh.flush_output()


if __name__ == '__main__':
    path = "/var/log/auth.log"
    path1 = "/home/harm/test.log"
    path2 = "/home/harm/test1.log"

    config = Config()
    state = State()
    output = Outputs()
    config.parse_config(config_file)
    state.parse_state(state_file)
    output.parse_outputs(output_file)

    observer = LogObserver()
    for fl in config.get_files():
        pos = state.pos(fl)
        file_id = state.id(fl)
        filt = config.get_filter(fl)
        name = config.get_name(fl)
        out = output.get_output(config.get_output(fl))

        res = []
        for x in filt:
            res.append(RegexParser(x['regex'], x['emit'], x['transform']))

        observer.add(fl, pos, res, file_id[0], file_id[1], file_id[2], out, name)

    observer.start()
    try:
        while True:
            observer.dump_state()
            observer.flush_output()
            time.sleep(10)
    finally:
        print('finale')
        # print(event_handler1.dump_state())
        observer.stop()
        observer.join()
        observer.dump_state()
        observer.flush_output()
