import datetime
import logging

from pymongo import MongoClient, collection
from typing import Dict, Any, Optional
from config_checker import Config_Checker
import outputters.output_abstract

import matches


class MongoConnector:
    _config_items = {
        'hostname': Config_Checker.MANDATORY,
        'port': Config_Checker.MANDATORY,
        'password': Config_Checker.MANDATORY,
        'username': Config_Checker.MANDATORY,
        'auth_db': Config_Checker.MANDATORY,
        'database': Config_Checker.MANDATORY,
        'collection': Config_Checker.MANDATORY,
    }

    def __init__(self, config: Dict[str, str]) -> None:
        Config_Checker.config_validate(self._config_items, config)
        self._config = config
        hostname = self._config['hostname'] if self._config['hostname'] != "" else None
        port = self._config['port'] if self._config['port'] != "" else None
        if 'username' in self._config and 'password' in self._config and \
                (self._config['username'] != '' and self._config['password'] != ''):
            self._mongo = MongoClient(username=self._config['username'], password=self._config['password'],
                                      authSource=self._config['auth_db'], host=hostname, port=port)
        else:
            self._mongo = MongoClient(host=hostname, port=port)
        self._db = self._mongo[self._config['database']]
        self._collection = self._db[self._config['collection']]

    def get_collection(self) -> collection.Collection:
        return self._collection


class MongoOutput(outputters.output_abstract.AbstractOutput):
    _config_items = {'buffer_size': Config_Checker.OPTIONAL, 'name': Config_Checker.MANDATORY}

    def __init__(self, config: Dict[str, Any]) -> None:
        super().__init__(config)
        Config_Checker.config_validate(self._config_items, config)
        self._config = config
        self._mongo = None
        self._db: Optional[MongoConnector] = None
        self._collection: Optional[collection] = None

    def commit(self) -> None:
        if self.empty():
            return
        try:
            if self._db is None or self._collection is None:
                raise ValueError('Not connected to Database')
            with self._lock:
                self._collection.insert_many(self.buffer())
                self.clear_buffer()
        except Exception as e:
            logging.warning(str(e))
            self.connect()

    def connect(self) -> None:
        self._db = MongoConnector(self._config)
        self._collection = self._db.get_collection()

    def cleanup(self, name: str, retention: int) -> None:
        if self._db is None or self._collection is None:
            raise ValueError('Not connected to Database')
        upper_limit = datetime.datetime.now() - datetime.timedelta(days=retention)
        self._collection.delete_many({"$and": [{"name": name}, {"timestamp": {"$lte": upper_limit}}]})

    def count(self, condition: Dict[str, Any]) -> int:
        if self._db is None or self._collection is None:
            raise ValueError('Not connected to Database')
        return int(self._collection.count_documents(condition))

    def is_new(self, source: str, field: str, value: str) -> bool:
        return matches.is_new(self, source, field, value)