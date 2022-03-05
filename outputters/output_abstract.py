import logging
import threading
from abc import ABC
from typing import Dict, Any, List
from config_checker import Config_Checker


class AbstractOutput(ABC):
    _config_items = {
        'buffer_size': Config_Checker.OPTIONAL,
        'name': Config_Checker.MANDATORY,
        'type': Config_Checker.MANDATORY
    }
    DEFAULT_BUFFER_SIZE = 1

    def __init__(self, config: Dict[str, Any]) -> None:
        logging.debug("Configuring output {} of type {}".format(config['name'], config['type']))
        Config_Checker.config_validate(self._config_items, config)
        self._name: str = config['name']
        self._type: str = config['type']
        self._buffer_size: int = config.get('buffer_size', self.DEFAULT_BUFFER_SIZE)
        self._buffer: List[Dict[str, Any]] = []
        self._lock = threading.Lock()

    @property
    def type(self) -> str:
        return self._type

    @property
    def name(self) -> str:
        return self._name

    def write(self, data: Dict[str, Any]) -> None:
        with self._lock:
            self._buffer.append(data)
            buf_len = self.size()
        if buf_len > self._buffer_size:
            self.commit()
        pass

    def empty(self) -> bool:
        return len(self._buffer) == 0

    def size(self) -> int:
        return len(self._buffer)

    def clear_buffer(self) -> None:
        self._buffer = []

    def buffer(self):
        for elem in self._buffer:
            yield elem

    def commit(self) -> None:
        raise NotImplemented("commit")

    def connect(self) -> None:
        raise NotImplemented("connect")

    def cleanup(self, name: str, retention: int) -> None:
        pass

    def count(self, condition: Dict[str, Any]) -> int:
        return -1

    def is_new(self, source: str, field: str, value: str) -> bool:
        return True

    def __hash__(self):
        return hash(self._name + self._type)
