import json
import os
import threading
import time
import logging

from watchdog.observers import Observer
from log_analyser_version import get_version
from loghandler import LogHandler


class LogObserver:
    STATE_DUMP_TIMEOUT: int = 15

    def __init__(self, state_file_handle: str, cleanup_interval: int, state_dump_timeout=STATE_DUMP_TIMEOUT,
                 notify_cleanup_handler=None) -> None:
        self._observer = Observer()
        self._lock = threading.Lock()
        self._event_handlers = {}
        self._state_file: str = state_file_handle
        self._cleanup_threat = None
        self._cleanup_interval: int = cleanup_interval
        self._state_dump_timeout: int = state_dump_timeout
        self._notify_cleanup_handler = notify_cleanup_handler

    def add(self, filepath: str, file_pos: int, parsers, file_inode: int, device: int, output_conn, name,
            retention: int) -> None:
        directory: str = os.path.dirname(filepath)
        if directory not in self._event_handlers:
            self._event_handlers[directory] = LogHandler()

        self._event_handlers[directory].add_file(filepath, file_pos, parsers, file_inode, device, output_conn, name,
                                                 retention)

    def start(self) -> None:
        logging.info('Starting log collector log_analyser_version.py {}'.format(get_version()))
        for directory in self._event_handlers:
            self._observer.schedule(self._event_handlers[directory], directory, recursive=False)
        self._observer.start()
        self._start_cleanup_threat()
        while True:
            self.dump_state()
            self.flush_output()
            time.sleep(self._state_dump_timeout)

    def stop(self) -> None:
        logging.info('Stopping log collector')
        self._observer.stop()

    def join(self) -> None:
        logging.debug('Joining log collector')
        self._observer.join()
        logging.debug('joining cleanup thread')
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
        logging.debug('Flushing output')
        for eh in self._event_handlers.values():
            eh.flush_output()

    def _cleanup(self) -> None:
        while True:
            logging.debug("Cleaning up Log Handler")
            for eh in self._event_handlers.values():
                eh.cleanup()
            logging.debug("Cleaning up Notifiers")
            if self._notify_cleanup_handler is not None:
                self._notify_cleanup_handler()
            time.sleep(self._cleanup_interval)

    def _start_cleanup_threat(self) -> None:
        logging.debug("Starting cleanup thread")
        self._cleanup_threat = threading.Thread(target=self._cleanup)
        self._cleanup_threat.daemon = True
        self._cleanup_threat.start()
