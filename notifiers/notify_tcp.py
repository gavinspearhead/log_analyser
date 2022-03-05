import socket
from typing import Dict
from notifiers import notify_handler


class Notify_tcp(notify_handler.Notify_handler):
    def __init__(self, config: Dict[str, str]):
        super().__init__(config)
        self._port: int = int(config.get('port', "0"))
        if not (0 < self._port < 65536):
            raise ValueError("Invalid port number {}".format(self._port))
        self._host: str = config.get('host', "")
        self._format: str = config.get("format", 'text')
        if not self.validate_format(self._format):
            raise ValueError("Invalid format {}".format(self._format))
        self._socket = None

    def _connect(self):
        self._socket = socket.socket()
        self._socket.connect((self._host, self._port))

    def _disconnect(self):
        if self._socket is not None:
            self._socket.shutdown(socket.SHUT_RDWR)
            self._socket.close()

    def send_msg(self, msg: str, limit_type: str) -> None:
        if self.check_rate_limit(limit_type):
            return
        try:
            if self._socket is None:
                raise ValueError("No socket created")
            self._socket.send(bytes(msg, encoding='utf8'))
        except Exception:
            try:
                self._connect()
                self._socket.send(bytes(msg, encoding='utf8'))
            except Exception:
                raise ValueError("Cannot send message on TCP connection")

    def get_format(self):
        return self._format
