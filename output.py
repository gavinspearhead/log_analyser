import datetime
import json
import logging
import threading
import typing
from abc import ABC

import pymongo
from pymongo import MongoClient, collection


class Outputs:
    def __init__(self) -> None:
        self._outputs: typing.List[typing.Dict[str, str]] = []

    def parse_outputs(self, filename: str) -> None:
        with open(filename, "r") as infile:
            outputs = json.load(infile)
        self._outputs = outputs

    def get_output(self, name: str) -> typing.Optional[typing.Dict[str, str]]:
        for i in self._outputs:
            if i['name'] == name:
                return i
        return None


class AbstractOutput(ABC):
    DEFAULT_BUFFER_SIZE = 1

    def __init__(self, config: typing.Dict[str, typing.Any]) -> None:
        logging.debug("Configuring output {}".format(config['name']))
        self._name: str = config['name']
        self._buffer_size: int = config['buffer_size'] if 'buffer_size' in config else self.DEFAULT_BUFFER_SIZE
        self._buffer: typing.List[typing.Dict[str, typing.Any]] = []
        self._lock = threading.Lock()

    def write(self, data: typing.Dict[str, typing.Any]) -> None:
        # print(len(self._buffer), self._buffer_size)
        with self._lock:
            self._buffer.append(data)
            buf_len = len(self._buffer)
        if buf_len > self._buffer_size:
            self.commit()
        pass

    def commit(self) -> None:
        raise NotImplemented("commit")

    def connect(self) -> None:
        raise NotImplemented("connect")

    def cleanup(self, name: str, retention: int) -> None:
        pass


class IgnoreOutput(AbstractOutput):
    def __init__(self, config: typing.Dict[str, str]) -> None:
        super().__init__(config)

    def write(self, data: typing.Dict[str, typing.Any]) -> None:
        pass

    def commit(self) -> None:
        pass

    def connect(self) -> None:
        pass

    def count(self, condition: typing.Dict[str, typing.Any]) -> int:
        return -1


class StdOutput(AbstractOutput):
    def __init__(self, config: typing.Dict[str, str]) -> None:
        super().__init__(config)

    def commit(self) -> None:
        if len(self._buffer) == 0:
            return
        with self._lock:
            for data in self._buffer:
                print(json.dumps(data))
            self._buffer = []

    def connect(self) -> None:
        pass

    def count(self, condition: typing.Dict[str, typing.Any]) -> int:
        return -1


class MongoConnector:
    def __init__(self, config: typing.Dict[str, str]) -> None:
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
    def __init__(self, config: typing.Dict[str, typing.Any]) -> None:
        super().__init__(config)
        self._config = config
        self._mongo = None
        self._db: typing.Optional[MongoConnector] = None
        self._collection: typing.Optional[collection] = None

    def commit(self) -> None:
        if len(self._buffer) == 0:
            return
        try:
            if self._db is None or self._collection is None:
                raise ValueError('Not connected to Database')
            with self._lock:
                self._collection.insert_many(self._buffer)
                self._buffer = []
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

    def count(self, condition: typing.Dict[str, typing.Any]) -> int:
        if self._db is None or self._collection is None:
            raise ValueError('Not connected to Database')
        return int(self._collection.count_documents(condition))


def factory(config: typing.Dict[str, str]) -> typing.Type[AbstractOutput]:
    if config['type'] == 'stdout':
        return StdOutput
    elif config['type'] == 'mongo':
        return MongoOutput
    elif config['type'] == 'ignore':
        return IgnoreOutput
    raise NotImplemented(config['type'])
