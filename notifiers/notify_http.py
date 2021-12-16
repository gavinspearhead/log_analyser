import logging
import requests
from typing import Dict
from notifiers import notify_handler


class Notify_http(notify_handler.Notify_handler):
    def __init__(self, config: Dict[str, str]) -> None:
        super().__init__(config)
        self._method: str = str(config.get('method', "GET")).upper()
        if self._method not in ['GET', 'POST']:
            raise ValueError("Invalid HTTP method")
        self._url: str = config.get('url', "")
        if self._url == "":
            raise ValueError("URL needed")

    def send_msg(self, msg: str, limit_type: str) -> None:
        if self.check_rate_limit(limit_type):
            return
        if self._method == "GET":
            try:
                requests.get("{}{}".format(self._url, msg))
            except (requests.ConnectionError, requests.HTTPError) as e:
                logging.error(e)
                raise ValueError

        elif self._method == "POST":
            try:
                requests.post(url=self._url, json=msg)
            except (requests.ConnectionError, requests.HTTPError) as e:
                logging.error(e)
                raise ValueError
        else:
            raise NotImplementedError

    def get_format(self):
        if self._method == "POST":
            return "json"
        else:
            return 'text'
