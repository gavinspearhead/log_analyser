import socket
from typing import Dict
from notifiers import notify_handler


class Notify_udp(notify_handler.Notify_handler):
    def __init__(self, config: Dict[str, str]):
        super().__init__(config)
        self._port: int = int(config.get('port', "0"))
        self._host: str = config.get('host', "")
        self._format: str = config.get("format", 'text')
        if not (0 < self._port < 65536):
            raise ValueError("Invalid port number {}".format(self._port))
        if self._host == "":
            raise ValueError("Host missing")
        if self._format not in ['text', 'json']:
            raise ValueError("Invalid format: {}".format(self._format))
        if self._format not in ('json', 'text'):
            raise ValueError("Invalid format {}".format(self._format))
        self._socket = socket.socket(type=socket.SOCK_DGRAM)

    def _disconnect(self):
        if self._socket is not None:
            self._socket.close()

    def send_msg(self, msg: str, limit_type: str) -> None:
        if self.check_rate_limit(limit_type):
            return
        try:
            if self._socket is None:
                raise ValueError("No socket created")
            self._socket.sendto(bytes(msg, encoding='utf8'), (self._host, self._port))
        except Exception as e:
            raise ValueError(e)

    def get_format(self):
        return self._format
