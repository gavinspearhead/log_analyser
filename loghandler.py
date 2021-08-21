import os
import threading
import output
import logging

from watchdog.events import FileSystemEventHandler


class LogHandler(FileSystemEventHandler):
    def __init__(self):
        super().__init__()
        self._file_list = dict()

    def dump_state(self):
        states = []
        for files in self._file_list.values():
            states.append(files.dump_state())
        return states

    def cleanup(self):
        for files in self._file_list.values():
            files.cleanup()

    def flush_output(self):
        for files in self._file_list.values():
            files.flush_output()

    def add_file(self, filename, pos=0, parsers=None, inode=None, dev=None, output_type=None, name=None,
                 retention=None):
        self._file_list[filename] = FileHandler(filename, pos, parsers, inode, dev, output_type, name, retention)

    def match(self, event):
        for filename in self._file_list:
            if not event.is_directory and filename == event.src_path:
                return self._file_list[filename]
        return None

    def on_deleted(self, event):
        try:
            self.match(event).on_deleted(event)
        except AttributeError as e:
            logging.debug(str(e))
            # print("error deletion", e, event, self)
            pass

    def on_modified(self, event):
        try:
            self.match(event).on_modified(event)
        except AttributeError as e:
            logging.debug(str(e))
            # print("error modified", e, event, self)
            pass

    def on_moved(self, event):
        try:
            self.match(event).on_moved(event)
        except AttributeError as e:
            logging.debug(str(e))
            # print("error moved", e, event)
            pass

    def on_created(self, event):
        try:
            self.match(event).on_created(event)
        except AttributeError as e:
            logging.debug(str(e))
            # print("error created", e, event)
            pass

    def on_closed(self, event):
        try:
            self.match(event).on_closed(event)
        except AttributeError as e:
            logging.debug(str(e))
            # print("error closed", e, event)
            pass


class FileHandler:
    def __init__(self, filename, pos=0, parsers=None, inode=None, dev=None, output_type=None, name=None, retention=0):
        self._pos = pos
        self._lock = threading.Lock()
        self._path = filename
        self._name = name
        self._retention = retention
        self._file = None
        self._inode = None
        self._dev = None
        self._output = output_type
        self._output_engine = None
        self._line = ""
        self._parsers = parsers
        self._open_output()
        self._open_file(inode, dev)

    def __str__(self):
        return "path: {}, pos: {},  output: {}, name: {}".format(self._path, self._pos, self._output, self._name)

    def _open_output(self):
        logging.debug("Opening output")
        self._output_engine = output.factory(self._output)(self._output)
        # print(self._output_engine)
        self._output_engine.connect()

    def flush_output(self):
        if self._output_engine is not None:
            self._output_engine.commit()

    def _open_file(self, inode=None, dev=None):
        logging.debug("Opening file: {}".format(self._file))
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
            # print(self._path, "starting at :", self._file.tell())
            self._read_contents()
        except FileNotFoundError:
            self._file = None
            self._inode = None
            self._dev = None

    def cleanup(self):
        self._output_engine.cleanup(self._name, self._retention)

    def dump_state(self):
        self._lock.acquire()
        _pos = self._pos
        self._lock.release()
        state = {"pos": _pos, "path": self._path, 'inode': self._inode, 'device': self._dev}
        return state

    def add_parser(self, parser):
        self._parsers.append(parser)

    def _match_line(self, line):
        for p in self._parsers:
            m = p.match(line)
            if m:
                # print(self._output_engine)
                self._output_engine.write(p.emit(m, self._name))
                p.notify(m, self._name)

    def _process_line(self, line):
        logging.debug(line)
        if line[-1:] == "\n":
            line = self._line + line
            self._line = ''
            self._match_line(line)
            return True
        else:
            self._line += line
            return False

    def _read_contents(self):
        while True:
            line = self._file.readline()
            # print(line)
            if not line:
                break
            if self._process_line(line):
                self._lock.acquire()
                self._pos = self._file.tell()
                # print(self._pos)
                self._lock.release()

    def on_modified(self, event):
        if not event.is_directory and self._path == event.src_path:
            # print('modified', event)
            self._read_contents()

    def on_deleted(self, event):
        if not event.is_directory and self._path == event.src_path:
            # print('deleted', event)
            self._read_contents()
            self._file.close()
            self._open_file(self._inode, self._dev)

    def on_moved(self, event):
        if not event.is_directory and self._path == event.src_path:
            # print('moved', event)
            self._read_contents()
            self._file.close()
            self._open_file(self._inode, self._dev)

    def on_created(self, event):
        if not event.is_directory and self._path == event.src_path:
            # print("created", event)
            self._open_file(self._inode, self._dev)
            self._read_contents()

    def on_closed(self, event):
        if not event.is_directory and self._path == event.src_path:
            # print("closed", event)
            self._read_contents()
