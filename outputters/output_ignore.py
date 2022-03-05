from typing import Dict, Any
from output import AbstractOutput


class IgnoreOutput(AbstractOutput):
    def __init__(self, config: Dict[str, str]) -> None:
        super().__init__(config)

    def write(self, data: Dict[str, Any]) -> None:
        pass

    def commit(self) -> None:
        pass

    def connect(self) -> None:
        pass

