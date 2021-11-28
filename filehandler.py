import logging
import os
import threading
import traceback
import typing
import output

from watchdog.events import FileModifiedEvent
from parsers import LogParser


class FileHandler:
    def __init__(self, filename: str, pos: int, parsers: typing.List, inode: int, dev: int, output_type:str, name: str,
                 retention: int) -> None:
        self._pos: int = pos
        self._lock = threading.Lock()
        self._path: str = filename
        self._name: str = name
        self._retention: int = retention
        self._file = None
        self._inode: int = -1
        self._dev: int = -1
        self._output = output_type
        self._output_engine = None
        self._line: str = ""
        self._parsers: typing.List[LogParser] = parsers
        self._open_output()
        self._open_file(inode, dev)

    def __str__(self) -> str:
        return "path: {}, pos: {},  output: {}, name: {}".format(self._path, self._pos, self._output, self._name)

    def _open_output(self) -> None:
        logging.debug("Opening output")
        self._output_engine = output.factory(self._output)(self._output)
        # print(self._output_engine)
        self._output_engine.connect()

    def flush_output(self) -> None:
        if self._output_engine is not None:
            self._output_engine.commit()

    def _open_file(self, inode: typing.Optional[int] = None, dev: typing.Optional[int] = None) -> None:
        logging.debug("Opening file: {}".format(self._file))
        self._line = ''
        try:
            stat_info = os.stat(self._path)
            self._inode = stat_info.st_ino
            self._dev = stat_info.st_dev
            # print(self._dev, self._inode)
            self._file = open(self._path, "r")
            if inode != self._inode or dev != self._dev:
                # we got the same file as before
                # otherwise we start reading at 0, file may have been truncated or rotated
                self._pos = 0
            logging.debug("Starting at {}".format(self._pos))
            self._file.seek(self._pos)
            # print(self._path, "starting at :", self._file.tell())
            self._read_contents()
        except OSError as e:
            # traceback.print_exc()
            self._file = None
            self._inode = None
            self._dev = None

    def cleanup(self) -> None:
        if self._output_engine is None:
            raise ValueError("output engine not initialised")
        self._output_engine.cleanup(self._name, self._retention)

    def dump_state(self) -> typing.Dict[str, typing.Any]:
        with self._lock:
            _pos = self._pos
        # print("aoaouo", {"pos": _pos, "path": self._path, 'inode': self._inode, 'device': self._dev})
        return {"pos": _pos, "path": self._path, 'inode': self._inode, 'device': self._dev}

    # def add_parser(self, parser):
    #     self._parsers.append(parser)

    def _match_line(self, line: str) -> None:
        if self._output_engine is None:
            raise ValueError("output engine not initialised")
        for p in self._parsers:
            m = p.match(line)
            if m:
                # print(self._output_engine)
                self._output_engine.write(p.emit(m, self._name))
                # print(self._name)
                p.notify(m, self._name)

    def _process_line(self, line: str) -> bool:
        logging.debug(line)
        if line[-1:] == "\n":
            line = self._line + line
            self._line = ''
            self._match_line(line)
            return True
        else:
            self._line += line
            return False

    def _read_contents(self) -> None:
        if self._file is None:
            raise ValueError("File not initialised")
        while True:
            line = self._file.readline()
            # print(line)
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
            # print('deleted', event)
            self._read_contents()
            if self._file is not None:
                self._file.close()
            self._open_file(self._inode, self._dev)

    def on_moved(self, event: FileModifiedEvent) -> None:
        if not event.is_directory and self._path == event.src_path:
            # print('moved', event)
            self._read_contents()
            if self._file is not None:
                self._file.close()
            self._open_file(self._inode, self._dev)

    def on_created(self, event: FileModifiedEvent) -> None:
        if not event.is_directory and self._path == event.src_path:
            # print("created", event)
            self._open_file(self._inode, self._dev)
            self._read_contents()

    def on_closed(self, event: FileModifiedEvent) -> None:
        if not event.is_directory and self._path == event.src_path:
            # print("closed", event)
            self._read_contents()
