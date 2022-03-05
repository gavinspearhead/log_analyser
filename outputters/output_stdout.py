import json
from typing import Dict, Any
from output import AbstractOutput


class StdOutput(AbstractOutput):
    def __init__(self, config: Dict[str, str]) -> None:
        super().__init__(config)

    def commit(self) -> None:
        if self.empty():
            return
        with self._lock:
            for data in self.buffer():
                print(json.dumps(data))
            self.clear_buffer()

    def connect(self) -> None:
        pass
