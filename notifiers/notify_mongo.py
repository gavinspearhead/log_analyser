import json
from typing import Dict

import dateutil.parser

from log_analyser_version import PROG_NAME_COLLECTOR
from notifiers import notify_handler
from output import MongoConnector


class Notify_mongo(notify_handler.Notify_handler):
    def __init__(self, config: Dict[str, str]):
        super().__init__(config)
        self._ident = PROG_NAME_COLLECTOR
        mc = MongoConnector(config)
        self._collection = mc.get_collection()

    def send_msg(self, msg: str, limit_type: str) -> None:
        t = json.loads(msg)
        t['timestamp'] = dateutil.parser.isoparse(t['timestamp'])
        print(t)
        self._collection.insert_one(t)

    def get_format(self)->str:
        return "json"
