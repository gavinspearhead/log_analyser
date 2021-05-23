import json


# State
# [
# {
#     'pos': 168273,
#     'path': '/var/log/auth.log',
#     'inode': 24249580,
#     'device': 64769,
#     'ctime': 1621087741.3265584
# }
# ]

class State:
    def __init__(self):
        self._state = None

    def parse_state(self, filename):
        with open(filename, "r") as infile:
            state = json.load(infile)
        r_state = []
        for s in state:
            try:
                for i in ['pos', 'path', 'inode', 'device', 'ctime']:
                    if i not in s:
                        raise ValueError('Unknown parameter {}'.format(i))
                    # else:
                    #     print(i, s[i])
                r_state.append(s)
            except ValueError as e:
                print(e)
                pass
        self._state = r_state

    def pos(self, path):
        for fl in self._state:
            if fl['path'] == path:
                return fl['pos']

    def id(self, path):
        for fl in self._state:
            if fl['path'] == path:
                return fl['inode'], fl['device'], fl['ctime']
        return None, None, None


# print(parse_state("loganalyser.state"))


# Config
# {
#     #     'path': '/var/log/auth.log',
#     'filter': [
#         {'regex': 'Accepted password for (\w+) from (\d+\.\d+\.\d+\.\d+) port (\d+) (\w+)',
#          'emit': [{
#              'username': "{0}"},
#              {'ip_address': "{1}"},
#              {'port': "{2}"},
#              {'protocol': "{3}"}
#          ]
#          }
#     ]
#
# }

class Config:
    def __init__(self):
        self._config = None

    def parse_config(self, filename):
        with open(filename, "r") as infile:
            config = json.load(infile)
        r_config = []
        for s in config:
            tmp = dict()
            tmp['path'] = s['path']
            tmp['name'] = s['name']
            tmp['output'] = s['output']
            tmp['filter'] = []
            for t in s['filter']:
                filter = dict()
                filter['regex'] = t['regex']
                filter['emit'] = t['emit']
                filter['transform'] = t['transform'] if 'transform' in t else dict()
                tmp['filter'].append(filter)
            r_config.append(tmp)

        self._config = r_config

    def get_name(self, filename):
        for i in self._config:
            if i['path'] == filename:
                return i['name']
        return None

    def get_filter(self, filename):
        for i in self._config:
            if i['path'] == filename:
                return i['filter']
        return None

    def _check_filename(self, filename):
        for i in self._config:
            if i['path'] == filename:
                return True
        return False

    def get_files(self):
        for i in self._config:
            yield i['path']

    def get_output(self, filename):
        for i in self._config:
            if i['path'] == filename:
                return i['output']
        return None


# Output config

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


if __name__ == '__main__':
    c = Config()
    s = State()
    s.parse_state('loganalyser.state')
    print(s.pos('/var/log/auth.log'))
    print(s.id('/var/log/auth.log'))
    c.parse_config('loganalyser.config')
    print(c.get_filter('/var/log/auth.log'))
    print(c.get_files())
