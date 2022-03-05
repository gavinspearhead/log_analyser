import os
from notifiers import notify_handler
from pathlib import Path
from typing import Dict


class Notify_signal(notify_handler.Notify_handler):
    def __init__(self, config: Dict[str, str]):
        super().__init__(config)

        self._phone_number: str = config.get('phone_number', None)
        self._command_path: str = config.get('command_path', None)
        self._note_to_self: bool = config.get('note_to_self', False)
        if self._command_path is None:
            raise ValueError("Command for Signal missing")
        if self._note_to_self is False and (self._phone_number == "" or self._phone_number is None):
            raise ValueError("Phone number for Signal missing")
        if not Path(self._command_path).is_file():
            raise ValueError("Command for Signal not found")

    def send_msg(self, msg: str, limit_type: str) -> None:
        if self.check_rate_limit(limit_type):
            return

        if self._phone_number is not None and self._phone_number != "":
            cmd: str = "{} send -u {} -m {}".format(self._command_path, self._phone_number, msg)
        elif self._note_to_self:
            cmd = "{} send --note-to-self -m '{}'".format(self._command_path, msg)
        else:
            raise ValueError("Parameters for Signal: phone_number or note_to_self")
        os.system(cmd)
