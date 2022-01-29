import datetime
import json
import logging
import threading
import pymongo
from abc import ABC
from pymongo import MongoClient, collection
from typing import List, Dict, Optional, Any, Type

from config_checker import Config_Checker


class Outputs:
    def __init__(self) -> None:
        self._outputs: List[Dict[str, str]] = []

    def parse_outputs(self, filename: str) -> None:
        with open(filename, "r") as infile:
            outputs = json.load(infile)
        self._outputs = outputs

    def get_output(self, name: str) -> Optional[Dict[str, str]]:
        for i in self._outputs:
            if i['name'] == name:
                return i
        return None


class AbstractOutput(ABC):
    _config_items = {
        'buffer_size': Config_Checker.OPTIONAL,
        'name': Config_Checker.MANDATORY,
        'type': Config_Checker.MANDATORY
    }
    DEFAULT_BUFFER_SIZE = 1

    def __init__(self, config: Dict[str, Any]) -> None:
        logging.debug("Configuring output {}".format(config['name']))
        Config_Checker.config_validate(self._config_items, config)
        self._name: str = config['name']
        self._buffer_size: int = config.get('buffer_size', self.DEFAULT_BUFFER_SIZE)
        self._buffer: List[Dict[str, Any]] = []
        self._lock = threading.Lock()

    def write(self, data: Dict[str, Any]) -> None:
        with self._lock:
            self._buffer.append(data)
            buf_len = self.size()
        if buf_len > self._buffer_size:
            self.commit()
        pass

    def empty(self) -> bool:
        return len(self._buffer) == 0

    def size(self) -> int:
        return len(self._buffer)

    def clear_buffer(self):
        self._buffer = []

    def buffer(self):
        for elem in self._buffer:
            yield elem

    def commit(self) -> None:
        raise NotImplemented("commit")

    def connect(self) -> None:
        raise NotImplemented("connect")

    def cleanup(self, name: str, retention: int) -> None:
        pass


class IgnoreOutput(AbstractOutput):
    def __init__(self, config: Dict[str, str]) -> None:
        super().__init__(config)

    def write(self, data: Dict[str, Any]) -> None:
        pass

    def commit(self) -> None:
        pass

    def connect(self) -> None:
        pass

    def count(self, condition: Dict[str, Any]) -> int:
        return -1


class StdOutput(AbstractOutput):
    def __init__(self, config: Dict[str, str]) -> None:
        super().__init__(config)

    def commit(self) -> None:
        if self.empty():
            return
        with self._lock:
            for data in self.buffer():
                print(json.dumps(data))
            self.clear_buffer()

    def connect(self) -> None:
        pass

    def count(self, condition: Dict[str, Any]) -> int:
        return -1


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

    def get_collection(self) -> pymongo.collection.Collection:
        return self._collection


class MongoOutput(AbstractOutput):
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


def factory(config: Dict[str, str]) -> Type[AbstractOutput]:
    if config['type'] == 'stdout':
        return StdOutput
    elif config['type'] == 'mongo':
        return MongoOutput
    elif config['type'] == 'ignore':
        return IgnoreOutput
    raise NotImplemented(config['type'])
