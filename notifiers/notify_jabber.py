import xmpp
from typing import Dict
from notifiers import notify_handler


class Notify_jabber(notify_handler.Notify_handler):
    def __init__(self, config: Dict[str, str]) -> None:
        super().__init__(config)
        self._jabber_id: str = config.get('jabber_id', "")
        self._send_to: str = config.get('to_address', "")
        self._password: str = config.get('password', "")

    def send_msg(self, msg: str, limit_type: str) -> None:
        if self.check_rate_limit(limit_type):
            return
        jid = xmpp.protocol.JID(self._jabber_id)
        connection = xmpp.Client(server=jid.getDomain())
        connection.connect()
        connection.auth(user=jid.getNode(), password=self._password, resource=jid.getResource())
        connection.send(xmpp.protocol.Message(to=self._send_to, body=msg))
        raise NotImplementedError
