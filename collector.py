import argparse
import json
import os
import threading
import time
from watchdog.observers import Observer
import logging

from config import Config, State, Outputs
from parsers import RegexParser
from loghandler import LogHandler

config_file_name = "loganalyser.config"
state_file_name = "loganalyser.state"
output_file_name = "loganalyser.output"

VERSION = "0.1"
LOG_LEVEL = logging.DEBUG
STATE_DUMP_TIMEOUT = 10


class LogObserver:
    def __init__(self, state_file):
        self._observer = Observer()
        self._lock = threading.Lock()
        self._event_handlers = dict()
        self._state_file = state_file
        self._cleanup_threat = None

    def add(self, filepath, pos, parsers, inode, device, output, name, retention):
        directory = os.path.dirname(filepath)
        if directory not in self._event_handlers:
            self._event_handlers[directory] = LogHandler()

        self._event_handlers[directory].add_file(filepath, pos, parsers, inode, device, output, name, retention)

    def start(self):
        logging.info('Starting log collector version {}'.format(VERSION))
        for directory in self._event_handlers:
            self._observer.schedule(self._event_handlers[directory], directory, recursive=False)
        self._observer.start()
        self.start_cleanup_threat()

    def stop(self):
        logging.info('Stopping log collector')
        self._observer.stop()

    def join(self):
        self._observer.join()
        self._cleanup_threat.join()

    def dump_state(self):
        logging.debug('dump_state')
        state = []
        for eh in self._event_handlers.values():
            state += eh.dump_state()
        try:
            with open(self._state_file, 'w') as outfile:
                json.dump(state, outfile)
        except OSError as e:
            print("Cannot write file {}".format(self._state_file))

    def flush_output(self):
        logging.debug('flushing output')
        for eh in self._event_handlers.values():
            eh.flush_output()

    def cleanup(self):
        for eh in self._event_handlers.values():
            eh.cleanup()
        time.sleep(60*60) # 1 hour

    def start_cleanup_threat(self):
        logging.debug("starting cleanup thread")
        self._cleanup_threat = threading.Thread(target=self.cleanup)
        self._cleanup_threat.start()


if __name__ == '__main__':
    logging.basicConfig(level=LOG_LEVEL)
    parser = argparse.ArgumentParser(description="RSS update daemon")
    parser.add_argument("-c", '--config', help="Config File Directory", default="", metavar="FILE")
    # path = "/var/log/auth.log"
    # path1 = "/home/harm/test.log"
    # path2 = "/home/harm/test1.log"
    args = parser.parse_args()
    config_path = ''
    if args.config:
        config_path = args.config
    config_file = os.path.join(config_path, config_file_name)
    state_file = os.path.join(config_path, state_file_name)
    output_file = os.path.join(config_path, output_file_name)
    config = Config()
    state = State()
    output = Outputs()
    config.parse_config(config_file)
    state.parse_state(state_file)
    output.parse_outputs(output_file)
    args = parser.parse_args()
    observer = LogObserver(state_file)

    for fl in config.get_files():
        pos = state.pos(fl)
        inode, dev = state.id(fl)
        filters = config.get_filter(fl)
        name = config.get_name(fl)
        retention = config.get_retention(fl)
        out = output.get_output(config.get_output(fl))

        res = []
        for x in filters:
            res.append(RegexParser(x['regex'], x['emit'], x['transform']))

        observer.add(fl, pos, res, inode, dev, out, name, retention)

    observer.start()
    try:
        while True:
            observer.dump_state()
            observer.flush_output()
            time.sleep(STATE_DUMP_TIMEOUT)
    finally:
        logging.debug('finale')
        # print(event_handler1.dump_state())
        observer.stop()
        observer.join()
        observer.dump_state()
        observer.flush_output()
