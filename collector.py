import argparse
import json
import os
import threading
import time
import logging
import local_ip
import traceback

from watchdog.observers import Observer
from output import factory, Outputs
from config import Config
from state import State
from notify import Notify
from parsers import RegexParser
from loghandler import LogHandler
from util import pid_running
from log_analyser_version import VERSION, PROG_NAME_COLLECTOR

config_file_name: str = "loganalyser.config"
state_file_name: str = "loganalyser.state"
output_file_name: str = "loganalyser.output"
notify_file_name: str = "loganalyser.notify"
ip_range_file_name: str = "loganalyser.ip_ranges"
pid_file_name: str = "loganalyser.pid"

pid_path: str = '/tmp/'

LOG_LEVEL = logging.INFO
STATE_DUMP_TIMEOUT: int = 15
CLEANUP_INTERVAL: int = 60 * 60  # 1 hour


class LogObserver:
    def __init__(self, state_file_handle:str) -> None:
        self._observer = Observer()
        self._lock = threading.Lock()
        self._event_handlers = {}
        self._state_file = state_file_handle
        self._cleanup_threat = None

    def add(self, filepath: str, file_pos: int, parsers, file_inode: int, device: int, output_type, name,
            retention: int) -> None:
        directory = os.path.dirname(filepath)
        if directory not in self._event_handlers:
            self._event_handlers[directory] = LogHandler()

        self._event_handlers[directory].add_file(filepath, file_pos, parsers, file_inode, device, output_type, name,
                                                 retention)

    def start(self) -> None:
        logging.info('Starting log collector log_analyser_version.py {}'.format(VERSION))
        for directory in self._event_handlers:
            self._observer.schedule(self._event_handlers[directory], directory, recursive=False)
        self._observer.start()
        self._start_cleanup_threat()

    def stop(self) -> None:
        logging.info('Stopping log collector')
        self._observer.stop()

    def join(self) -> None:
        logging.debug('Joining log collector')
        self._observer.join()
        logging.debug('joining cleanup thread')
        # self._cleanup_threat.join()
        logging.debug('done')

    def dump_state(self) -> None:
        logging.debug('dump_state')
        current_state = []
        for eh in self._event_handlers.values():
            current_state += eh.dump_state()
        try:
            logging.debug(json.dumps(current_state))
            with open(self._state_file, 'w') as outfile:
                json.dump(current_state, outfile)
        except OSError as exc:
            logging.warning("Cannot write file {}: {}".format(self._state_file, str(exc)))

    def flush_output(self) -> None:
        logging.debug('flushing output')
        for eh in self._event_handlers.values():
            eh.flush_output()

    def _cleanup(self) -> None:
        while True:
            logging.debug("Cleaning up")
            for eh in self._event_handlers.values():
                eh.cleanup()
            time.sleep(CLEANUP_INTERVAL)

    def _start_cleanup_threat(self) -> None:
        logging.debug("starting cleanup thread")
        self._cleanup_threat = threading.Thread(target=self._cleanup)
        self._cleanup_threat.daemon = True
        self._cleanup_threat.start()


if __name__ == '__main__':
    try:
        state_dump_timeout: int = STATE_DUMP_TIMEOUT
        parser = argparse.ArgumentParser(description=PROG_NAME_COLLECTOR)
        parser.add_argument("-v", '--version', help="Print Version information", action='store_true')
        parser.add_argument("-D", '--debug', help="Debug mode", action='store_true')
        parser.add_argument("-c", '--config', help="Config File Directory", default="", metavar="FILE")
        parser.add_argument("-p", '--pid', help="PID File Directory", default="", metavar="FILE")
        parser.add_argument("-d", '--dump_state_timeout', help="Timeout between periods dumping state", type=int,
                            default=STATE_DUMP_TIMEOUT, metavar="SECONDS")
        args = parser.parse_args()
        config_path: str = ''
        if args.version:
            print("{} {}".format(PROG_NAME_COLLECTOR, VERSION))
            exit(0)
        if args.config:
            config_path = args.config
        if args.dump_state_timeout:
            state_dump_timeout = args.dump_state_timeout
        if args.debug:
            LOG_LEVEL = logging.DEBUG
        if args.pid:
            pid_path = args.pid

        logging.basicConfig(level=LOG_LEVEL)
        pid_file: str = os.path.join(pid_path, pid_file_name)

        config_file = os.path.join(config_path, config_file_name)
        state_file = os.path.join(config_path, state_file_name)
        output_file = os.path.join(config_path, output_file_name)
        notify_file = os.path.join(config_path, notify_file_name)
        local_ip_file = os.path.join(config_path, ip_range_file_name)

        config = Config()
        state = State()
        output = Outputs()
        notify = Notify()

        notify.parse_notify(notify_file)
        config.parse_config(config_file)
        state.parse_state(state_file)
        output.parse_outputs(output_file)
        observer = LogObserver(state_file)

        local_ip.load_local_address(local_ip_file)
        if os.path.isfile(pid_file):
            if pid_running(pid_file):
                print("File already running")
                exit()
            else:
                os.unlink(pid_file)
        try:
            for fl in config.get_files():
                pos = state.pos(fl)
                inode, dev = state.id(fl)
                filters = config.get_filter(fl)
                log_name = config.get_name(fl)
                retention_time = config.get_retention(fl)
                out = output.get_output(config.get_output(fl))

                res = []
                output_conn = factory(out)(out)
                output_conn.connect()
                for x in filters:
                    # print(x)
                    res.append(
                        RegexParser(x['regex'], x['emit'], x['transform'], x['notify'], notify, output_conn, log_name))

                observer.add(fl, pos, res, inode, dev, out, log_name, retention_time)

            with open(pid_file, 'w') as f:
                pid = str(os.getpid())
                f.write(pid)
            observer.start()
            while True:
                observer.dump_state()
                observer.flush_output()
                time.sleep(STATE_DUMP_TIMEOUT)
        except KeyboardInterrupt as e:
            logging.debug(e)
            pass
        finally:
            logging.debug('finale')
            observer.stop()
            observer.join()
            observer.dump_state()
            observer.flush_output()
            logging.debug('removing PID file')
            os.unlink(pid_file)
    except Exception as e:
        traceback.print_exc()
        logging.info(str(e))
        exit()
