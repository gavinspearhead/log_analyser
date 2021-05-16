import json
import os
import time
import logging
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
        self._event_handlers = dict()

    def add(self, filepath, pos, parsers, inode, device, ctime, output):
        directory = os.path.dirname(filepath)
        if directory not in self._event_handlers:
            self._event_handlers[directory] = LogHandler()

        self._event_handlers[directory].add_file(filepath, pos, parsers, inode, device, ctime, output)

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


if __name__ == '__main__':
    # logging.basicConfig(level=logging.INFO,
    #                     format='%(asctime)s - %(message)s',
    #                     datefmt='%Y-%m-%d %H:%M:%S')
    # path = sys.argv[1] if len(sys.argv) > 1 else '.'
    # path1 = "/var/log/auth.log"
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
        id = state.id(fl)
        filt = config.get_filter(fl)
        out = output.get_output(config.get_output(fl))

        # exit()
        res = []
        for x in filt:
            res.append(RegexParser(x['regex'], x['emit']))

        observer.add(fl, pos, res, id[0], id[1], id[2], out)


    # dir1 = os.path.dirname(path1)
    # # event_handler = LoggingEventHandler()
    # event_handler1 = LogHandler()
    #
    # event_handler1.add_file(path1, 0, [RegexParser(r'(oo2)', "Parsed: {0}")])
    # event_handler1.add_file(path2, 0, [RegexParser(r'(foo).*(bar)', "Parsed: {0} and {1}")])
    # print(event_handler1.dump_state())
    #
    # observer = Observer()
    # # observer.schedule(event_handler, path, recursive=False)
    # observer.schedule(event_handler1, dir1, recursive=False)
    # observer.start();
    # observer.add(path, 0, [RegexParser(r'Accepted password for (\w+) from (\d+\.\d+\.\d+\.\d+) port (\d+) (\w+)',
    #                                    "Parsed: Logged in {0} {1} {2} {3}"),
    #                        RegexParser(
    #                            r'Failed password for (invalid user)? ?(\w+) from (\d+\.\d+\.\d+\.\d+) port (\d+) (\w+)',
    #                            "Parsed: Failed {0} {1} {2} {3} {4}")
    #                        ])
    # observer.add(path1, 0, [RegexParser(r'(oo2)', "Parsed: {0}")])
    # observer.add(path2, 0, [RegexParser(r'(foo).*(bar)', "Parsed: {0} and {1}")])

    observer.start()
    try:
        while True:
            time.sleep(1)
            # print(event_handler1.dump_state())
    finally:
        print('finale')
        # print(event_handler1.dump_state())
        observer.dump_state()
        observer.stop()
        observer.join()
