import json
from typing import Dict, Any
from output import AbstractOutput


class StdOutput(AbstractOutput):
    def __init__(self, config: Dict[str, str]) -> None:
        super().__init__(config)
        self._indent: str = config.get('indent', None)
        self._sort_keys: bool = config.get('sort_keys', False)
        if type(self._indent) == str and self._indent.lower() in ['none', 'false' 'off', 'no']:
            self._indent = None

    def commit(self) -> None:
        if self.empty():
            return
        with self._lock:
            for data in self.buffer():
                print(json.dumps(data, sort_keys=self._sort_keys, default=str, indent=self._indent))
            self.clear_buffer()

    def connect(self) -> None:
        pass
