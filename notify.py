import logging
import json
from typing import Dict, Optional, Any, Type, List

from notifiers.notify_http import Notify_http
from notifiers.notify_jabber import Notify_jabber
from notifiers.notify_mail import Notify_mail
from notifiers.notify_mongo import Notify_mongo
from notifiers.notify_mqtt import Notify_mqtt
from notifiers.notify_signal import Notify_signal
from notifiers.notify_syslog import Notify_syslog
from notifiers import notify_handler
from notifiers.notify_tcp import Notify_tcp
from notifiers.notify_telegram import Notify_telegram
from notifiers.notify_udp import Notify_udp


class Notify:
    _notifiers = {
        'telegram': Notify_telegram,
        'signal': Notify_signal,
        'mail': Notify_mail,
        'jabber': Notify_jabber,
        'tcp': Notify_tcp,
        'udp': Notify_udp,
        'mqtt': Notify_mqtt,
        'http': Notify_http,
        'syslog': Notify_syslog,
        'mongo': Notify_mongo,
    }

    def __init__(self) -> None:
        self._notify: List[Dict[str, Any]] = []

    def get_notify(self, name: str) -> Optional[Dict[str, Any]]:
        for i in self._notify:
            if i['name'] == name:
                return i
        return None

    def _factory(self, notify_type: str) -> Type[notify_handler.Notify_handler]:
        if notify_type in self._notifiers:
            return self._notifiers[notify_type]
        else:
            raise ValueError("Unknown notify type: {}".format(notify_type))

    def parse_notify(self, filename: str) -> None:
        with open(filename, "r") as infile:
            notify = json.load(infile)
        r_config = []
        for config_element in notify:
            tmp = {
                'type': config_element['type'],
                'name': config_element['name'],
                'config': config_element
            }
            tmp['handler'] = self._factory(tmp['type'])(config_element)
            r_config.append(tmp)

        self._notify = r_config

    def send(self, notify_type: str, msg: str, limit_type: str) -> None:
        for i in self._notify:
            try:
                if notify_type == i['type']:
                    i['handler'].send(msg, limit_type)
            except Exception as e:
                logging.info("Notifying failed: {}".format(str(e)))

    def cleanup(self) -> None:
        for notifier in self._notify:
            notifier['handler'].cleanup()
