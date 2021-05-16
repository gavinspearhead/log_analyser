import json
from abc import abstractmethod

from pymongo import MongoClient


class AbstractOutput:

    def __init__(self, config):
        self._name = config['name']

    def write(self, data):
        pass

    def connect(self):
        pass


class StdOutput(AbstractOutput):
    def __init__(self, config):
        super().__init__(config)

    def write(self, data):
        print(json.dumps(data))

    def connect(self):
        pass


class MongoOutput(AbstractOutput):
    def __init__(self, config):
        super().__init__(config)
        self._mongo = MongoClient()
        self._db = self._mongo[config['database']]
        self._collection = self._db[config['collection']]

    def write(self, data):
        self._collection.insert_one(data)

    def connect(self):
        pass


def factory(config):
    if config['type'] == 'stdout':
        return StdOutput
    elif config['type'] == 'mongo':
        return MongoOutput
    else:
        raise NotImplemented(config['type'])