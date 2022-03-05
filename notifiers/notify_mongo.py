import datetime
import json
import logging
import dateutil.parser
from typing import Dict
from config_checker import Config_Checker
from notifiers import notify_handler
from outputters.output_mongo import MongoConnector


class Notify_mongo(notify_handler.Notify_handler):
    _config_items = {'retention': Config_Checker.OPTIONAL}

    def __init__(self, config: Dict[str, str]):
        super().__init__(config)
        Config_Checker.config_validate(self._config_items, config)
        mc = MongoConnector(config)
        self._collection = mc.get_collection()
        self._retention: int = config.get('retention', 0)

    def send_msg(self, msg: str, limit_type: str) -> None:
        t = json.loads(msg)
        t['timestamp'] = dateutil.parser.isoparse(t['timestamp'])
        self._collection.insert_one(t)

    def get_format(self) -> str:
        return "json"

    def cleanup(self) -> None:
        logging.debug("Cleaning up mongo")
        if self._retention == 0:
            return
        upper_limit = datetime.datetime.now() - datetime.timedelta(days=self._retention)
        self._collection.delete_many({"$and": [{"timestamp": {"$lte": upper_limit}}]})
