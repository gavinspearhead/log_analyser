import typing
import logging

from watchdog.events import FileSystemEventHandler, FileModifiedEvent
from filehandler import FileHandler


class LogHandler(FileSystemEventHandler):
    def __init__(self) -> None:
        super().__init__()
        self._file_list = {}

    def dump_state(self) -> typing.List:
        states = []
        for files in self._file_list.values():
            states.append(files.dump_state())
        return states

    def cleanup(self) -> None:
        for files in self._file_list.values():
            files.cleanup()

    def flush_output(self) -> None:
        for files in self._file_list.values():
            files.flush_output()

    def add_file(self, filename: str, pos: int = 0, parsers=None, inode: typing.Optional[int] = None,
                 dev: typing.Optional[int] = None, output_type=None,
                 name: typing.Optional[str] = None, retention: typing.Optional[int] = None) -> None:
        self._file_list[filename] = FileHandler(filename, pos, parsers, inode, dev, output_type, name, retention)

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
            # print("error deletion", e, event, self)

    def on_modified(self, event: FileModifiedEvent) -> None:
        try:
            self.match(event).on_modified(event)
        except ValueError:
            pass
        except AttributeError as e:
            logging.debug(str(e))
            # traceback.print_exc()
            # print("error modified", e, event, self)

    def on_moved(self, event: FileModifiedEvent) -> None:
        try:
            self.match(event).on_moved(event)
        except ValueError:
            pass
        except AttributeError as e:
            logging.debug(str(e))
            # print("error moved", e, event)

    def on_created(self, event: FileModifiedEvent) -> None:
        try:
            self.match(event).on_created(event)
        except ValueError:
            pass
        except AttributeError as e:
            logging.debug(str(e))
            # print("error created", e, event)

    def on_closed(self, event: FileModifiedEvent) -> None:
        try:
            self.match(event).on_closed(event)
        except ValueError:
            pass
        except AttributeError as e:
            logging.debug(str(e))
            # print("error closed", e, event)
