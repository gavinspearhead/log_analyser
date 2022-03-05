import logging

from watchdog.events import FileSystemEventHandler, FileModifiedEvent
from filehandler import FileHandler
from typing import List, Optional


class LogHandler(FileSystemEventHandler):
    def __init__(self) -> None:
        super().__init__()
        self._file_list = {}

    def dump_state(self) -> List:
        states: List = []
        for files in self._file_list.values():
            states.append(files.dump_state())
        return states

    def cleanup(self) -> None:
        for files in self._file_list.values():
            files.cleanup()

    def flush_output(self) -> None:
        for files in self._file_list.values():
            files.flush_output()

    def add_file(self, filename: str, pos: int = 0, parsers=None, inode: Optional[int] = None,
                 dev: Optional[int] = None, output_conn=None, name: Optional[str] = None,
                 retention: Optional[int] = None) -> None:
        self._file_list[filename] = FileHandler(filename, pos, parsers, inode, dev, output_conn, name, retention)

    def match(self, event: FileModifiedEvent) -> FileHandler:
        try:
            for filename in self._file_list:
                if not event.is_directory and filename == event.src_path:
                    return self._file_list[filename]
        except AttributeError as e:
            logging.debug(str(e))
        raise ValueError('Not found')

    def on_deleted(self, event: FileModifiedEvent) -> None:
        try:
            self.match(event).on_deleted(event)
        except ValueError:
            pass
        except AttributeError as e:
            logging.debug(str(e))

    def on_modified(self, event: FileModifiedEvent) -> None:
        try:
            self.match(event).on_modified(event)
        except ValueError:
            pass
        except AttributeError as e:
            logging.debug(str(e))

    def on_moved(self, event: FileModifiedEvent) -> None:
        try:
            self.match(event).on_moved(event)
        except ValueError:
            pass
        except AttributeError as e:
            logging.debug(str(e))

    def on_created(self, event: FileModifiedEvent) -> None:
        try:
            self.match(event).on_created(event)
        except ValueError:
            pass
        except AttributeError as e:
            logging.debug(str(e))

    def on_closed(self, event: FileModifiedEvent) -> None:
        try:
            self.match(event).on_closed(event)
        except ValueError:
            pass
        except AttributeError as e:
            logging.debug(str(e))
