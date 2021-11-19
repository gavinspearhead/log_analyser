import logging

import json
from typing import Dict, Optional, Any, Type, List
from notifiers import notify_syslog
from notifiers import notify_http
from notifiers import notify_telegram
from notifiers import notify_signal
from notifiers import notify_mqtt
from notifiers import notify_udp
from notifiers import notify_tcp
from notifiers import notify_jabber
from notifiers import notify_mail
from notifiers import notify_handler


class Notify:
    _notifiers = {
        'telegram': notify_telegram.Notify_telegram,
        'signal': notify_signal.Notify_signal,
        'mail': notify_mail.Notify_mail,
        'jabber': notify_jabber.Notify_jabber,
        'tcp': notify_tcp.Notify_tcp,
        'udp': notify_udp.Notify_udp,
        'mqtt': notify_mqtt.Notify_mqtt,
        'http': notify_http.Notify_http,
        'syslog': notify_syslog.Notify_syslog,
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
                'name': config_element['name']
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
