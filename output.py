import datetime
import json
import logging
import threading
from abc import ABC

from pymongo import MongoClient


class Outputs:

    def __init__(self):
        self._outputs = []

    def parse_outputs(self, filename):
        with open(filename, "r") as infile:
            outputs = json.load(infile)
        self._outputs = outputs

    def get_output(self, name):
        for i in self._outputs:
            if i['name'] == name:
                return i
        return None


class AbstractOutput(ABC):
    DEFAULT_BUFFER_SIZE = 1

    def __init__(self, config):
        logging.debug("Configuring output {}".format(config['name']))
        self._name = config['name']
        self._buffer_size = config['buffer_size'] if 'buffer_size' in config else self.DEFAULT_BUFFER_SIZE
        self._buffer = []
        self._lock = threading.Lock()

    def write(self, data):
        # print(len(self._buffer), self._buffer_size)
        with self._lock:
            self._buffer.append(data)
            buf_len = len(self._buffer)
        if buf_len > self._buffer_size:
            self.commit()
        pass

    def commit(self):
        raise NotImplemented("commit")

    def connect(self):
        raise NotImplemented("connect")

    def cleanup(self, name, retention):
        pass


class IgnoreOutput(AbstractOutput):
    def __init__(self, config):
        super().__init__(config)

    def write(self, data):
        pass

    def commit(self):
        pass

    def connect(self):
        pass

    def count(self, condition):
        return -1


class StdOutput(AbstractOutput):
    def __init__(self, config):
        super().__init__(config)

    def commit(self):
        if len(self._buffer) == 0:
            return
        try:
            self._lock.acquire()
            for data in self._buffer:
                print(json.dumps(data))
            self._buffer = []
        finally:
            self._lock.release()

    def connect(self):
        pass

    def count(self, condition):
        return -1


class MongoConnector:
    def __init__(self, config):
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

    def get_collection(self):
        return self._collection


class MongoOutput(AbstractOutput):
    def __init__(self, config):
        super().__init__(config)
        self._config = config
        self._mongo = None
        self._db = None
        self._collection = None

    def commit(self):
        if len(self._buffer) == 0:
            return
        try:
            with self._lock:
                self._collection.insert_many(self._buffer)
                self._buffer = []
        except Exception as e:
            logging.warning(str(e))
            self.connect()

    def connect(self):
        self._db = MongoConnector(self._config)
        self._collection = self._db.get_collection()

    def cleanup(self, name, retention):
        upper_limit = datetime.datetime.now() - datetime.timedelta(days=retention)
        self._collection.delete_many({"$and": [{"name": name}, {"timestamp": {"$lte": upper_limit}}]})

    def count(self, condition):
        return self._collection.count(condition)


def factory(config):
    if config['type'] == 'stdout':
        return StdOutput
    elif config['type'] == 'mongo':
        return MongoOutput
    elif config['type'] == 'ignore':
        return IgnoreOutput
    else:
        raise NotImplemented(config['type'])
