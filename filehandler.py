import logging
import os
import threading
# import traceback

from watchdog.events import FileModifiedEvent

from outputters.output_abstract import AbstractOutput
from parsers import LogParser
from typing import Any, Optional, Dict, List


class FileHandler:
    def __init__(self, filename: str, pos: int, parsers: List, inode: int, dev: int, output_conn: AbstractOutput,
                 name: str, retention: int) -> None:
        self._pos: int = pos
        self._lock = threading.Lock()
        self._path: str = filename
        self._name: str = name
        self._retention: int = retention
        self._file = None
        self._inode: int = -1
        self._dev: int = -1
        self._output_engine: AbstractOutput = output_conn
        self._line: str = ''
        self._parsers: List[LogParser] = parsers
        self._open_file(inode, dev)

    def __str__(self) -> str:
        return "path: {}, pos: {},  output: {}, name: {}".format(
            self._path, self._pos, self._output_engine.name, self._name)

    def flush_output(self) -> None:
        if self._output_engine is not None:
            self._output_engine.commit()

    def _open_file(self, inode: Optional[int] = None, dev: Optional[int] = None) -> None:
        logging.debug("Opening file: {} as {}".format(self._path, self._name))
        self._line = ''
        try:
            stat_info = os.stat(self._path)
            self._inode = stat_info.st_ino
            self._dev = stat_info.st_dev
            self._file = open(self._path, "r")
            if inode != self._inode or dev != self._dev:
                # we got the same file as before
                # otherwise we start reading at 0, file may have been truncated or rotated
                self._pos = 0
            logging.debug("Starting at {}".format(self._pos))
            self._file.seek(self._pos)
            self._read_contents()
        except (OSError, PermissionError):
            logging.info('Cannot open file: {}'.format(self._path))
            self._file = None
            self._inode = -1
            self._dev = -1

    def cleanup(self) -> None:
        if self._output_engine is None:
            raise ValueError("Output engine not initialised")
        self._output_engine.cleanup(self._name, self._retention)

    def dump_state(self) -> Dict[str, Any]:
        with self._lock:
            _pos = self._pos
        return {"pos": _pos, "path": self._path, 'inode': self._inode, 'device': self._dev}

    def _match_line(self, line: str) -> None:
        if self._output_engine is None:
            raise ValueError("output engine not initialised")
        for p in self._parsers:
            m = p.match(line)
            if m:
                self._output_engine.write(p.emit(m, self._name))
                p.notify(m, self._name)

    def _process_line(self, line: str) -> bool:
        logging.debug(line)
        self._line += line
        if line[-1:] != "\n":
            return False
        line = self._line
        self._line = ''
        self._match_line(line)
        return True

    def _read_contents(self) -> None:
        if self._file is None:
            raise ValueError("File not initialised")
        while True:
            try:
                line = self._file.readline()
            except ValueError:
                line = ''
            if not line:
                break
            if self._process_line(line):
                with self._lock:
                    self._pos = self._file.tell()

    def on_modified(self, event: FileModifiedEvent) -> None:
        if not event.is_directory and self._path == event.src_path:
            self._read_contents()

    def on_deleted(self, event: FileModifiedEvent) -> None:
        if not event.is_directory and self._path == event.src_path:
            self._read_contents()
            if self._file is not None:
                self._file.close()
            self._open_file(self._inode, self._dev)

    def on_moved(self, event: FileModifiedEvent) -> None:
        if not event.is_directory and self._path == event.src_path:
            self._read_contents()
            if self._file is not None:
                self._file.close()
            self._open_file(self._inode, self._dev)

    def on_created(self, event: FileModifiedEvent) -> None:
        if not event.is_directory and self._path == event.src_path:
            self._open_file(self._inode, self._dev)
            self._read_contents()

    def on_closed(self, event: FileModifiedEvent) -> None:
        if not event.is_directory and self._path == event.src_path:
            self._read_contents()
