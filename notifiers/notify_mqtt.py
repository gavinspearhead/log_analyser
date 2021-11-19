from typing import Dict
from notifiers import notify_handler


class Notify_mqtt(notify_handler.Notify_handler):
    def __init__(self, config: Dict[str, str]):
        super().__init__(config)

    def send_msg(self, msg: str, limit_type: str) -> None:
        raise NotImplementedError
