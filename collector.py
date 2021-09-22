import argparse
import json
import os
import threading
import time
import logging
import local_ip

from watchdog.observers import Observer
from output import factory, Outputs
from config import Config
from state import State
from notify import Notify
from parsers import RegexParser
from loghandler import LogHandler

config_file_name = "loganalyser.config"
state_file_name = "loganalyser.state"
output_file_name = "loganalyser.output"
notify_file_name = "loganalyser.notify"
ip_range_file_name = "loganalyser.ip_ranges"
pid_file_name = "loganalyser.pid"

pid_path = '/tmp/'

VERSION = "0.2"
LOG_LEVEL = logging.INFO
STATE_DUMP_TIMEOUT = 15


class LogObserver:
    def __init__(self, state_file_handle):
        self._observer = Observer()
        self._lock = threading.Lock()
        self._event_handlers = {}
        self._state_file = state_file_handle
        self._cleanup_threat = None

    def add(self, filepath, file_pos, parsers, file_inode, device, output_type, name, retention):
        directory = os.path.dirname(filepath)
        if directory not in self._event_handlers:
            self._event_handlers[directory] = LogHandler()

        self._event_handlers[directory].add_file(filepath, file_pos, parsers, file_inode, device, output_type, name,
                                                 retention)

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
        logging.debug('Joining log collector')
        self._observer.join()
        logging.debug('joining cleanup thread')
        # self._cleanup_threat.join()
        logging.debug('done')

    def dump_state(self):
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

    def flush_output(self):
        logging.debug('flushing output')
        for eh in self._event_handlers.values():
            eh.flush_output()

    def cleanup(self):
        for eh in self._event_handlers.values():
            eh.cleanup()
        time.sleep(60 * 60)  # 1 hour

    def start_cleanup_threat(self):
        logging.debug("starting cleanup thread")
        self._cleanup_threat = threading.Thread(target=self.cleanup)
        self._cleanup_threat.daemon = True
        self._cleanup_threat.start()


def pid_running(pid_filename):
    try:
        with open(pid_filename, "r") as fn:
            s = int(fn.readline().strip())
            if s > 0:
                os.kill(s, 0)
                return True
    except (ValueError, FileNotFoundError, OSError):
        return False
    except PermissionError:
        return True
    return False


if __name__ == '__main__':
    try:
        state_dump_timeout = STATE_DUMP_TIMEOUT
        parser = argparse.ArgumentParser(description="Log Collector")
        parser.add_argument("-D", '--debug', help="Debug mode", action='store_true')
        parser.add_argument("-c", '--config', help="Config File Directory", default="", metavar="FILE")
        parser.add_argument("-d", '--dump_state_timeout', help="Timeout between periods dumping state", type=int,
                            default=STATE_DUMP_TIMEOUT, metavar="SECONDS")
        args = parser.parse_args()
        config_path = ''
        if args.config:
            config_path = args.config
        if args.dump_state_timeout:
            state_dump_timeout = args.dump_state_timeout
        if args.debug:
            LOG_LEVEL = logging.DEBUG

        logging.basicConfig(level=LOG_LEVEL)
        pid_file = os.path.join(pid_path, pid_file_name)

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
                # print(out)
                output_conn = factory(out)(out)
                output_conn.connect()
                # print(output_conn)
                for x in filters:
                    res.append(RegexParser(x['regex'], x['emit'], x['transform'], x['notify'], notify, output_conn))

                observer.add(fl, pos, res, inode, dev, out, log_name, retention_time)

            with open(pid_file, 'w') as f:
                pid = str(os.getpid())
                f.write(pid)
            observer.start()
            while True:
                observer.dump_state()
                observer.flush_output()
                time.sleep(STATE_DUMP_TIMEOUT)
        except KeyboardInterrupt:
            pass
        finally:
            logging.debug('finale')
            # print(event_handler1.dump_state())
            observer.stop()
            observer.join()
            # print('done')
            observer.dump_state()
            observer.flush_output()
            logging.debug('removing PID file')
            os.unlink(pid_file)
    except Exception as e:
        logging.info(str(e))
        exit()
