import json
import threading

from pymongo import MongoClient


class AbstractOutput:
    DEFAULT_BUFFER_SIZE = 1

    def __init__(self, config):
        self._name = config['name']
        self._buffer_size = config['buffer_size'] if 'buffer_size' in config else self.DEFAULT_BUFFER_SIZE
        self._buffer = []
        self._lock = threading.Lock()

    def write(self, data):
        # print(len(self._buffer), self._buffer_size)
        try:
            self._lock.acquire()
            self._buffer.append(data)
            buf_len = len(self._buffer)
        finally:
            self._lock.release()
        if buf_len > self._buffer_size:
            self.commit()
        pass

    def commit(self):
        raise NotImplemented("connect")

    def connect(self):
        raise NotImplemented("connect")


class StdOutput(AbstractOutput):
    def __init__(self, config):
        super().__init__(config)

    # def write(self, data):

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


class MongoConnector:
    def __init__(self, config):
        self._config = config
        if 'username' in self._config and 'password'  in self._config and \
                (self._config['username'] != '' and self._config['password'] != ''):
            self._mongo = MongoClient(username=self._config['username'], password=self._config['password'],
                                      authSource=self._config['auth_db'])
        else:
            self._mongo = MongoClient()
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

    # def write(self, data):
    #     self._collection.insert_one(data)

    def commit(self):
        # print('commiting')
        if len(self._buffer) == 0:
            return
        try:
            self._lock.acquire()
            self._collection.insert_many(self._buffer)
            self._buffer = []
            # self._lock.release()
        except Exception as e:
            print(e)
            self.connect()
        finally:
            self._lock.release()

    def connect(self):
        self._db = MongoConnector(self._config)
        self._collection = self._db.get_collection()


def factory(config):
    if config['type'] == 'stdout':
        return StdOutput
    elif config['type'] == 'mongo':
        return MongoOutput
    else:
        raise NotImplemented(config['type'])
