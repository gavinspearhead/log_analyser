import json
import logging

import telegram_send


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
        # print('pasreSstate')
        # print(filename)
        try:
            with open(filename, "r") as infile:
                state = json.load(infile)
        except FileNotFoundError:
            state = []
        r_state = []
        for state_entry in state:
            try:
                for parameter in ['pos', 'path', 'inode', 'device']:
                    if parameter not in state_entry:
                        raise ValueError('Unknown parameter {}'.format(parameter))
                    # else:
                    #     print(i, s[i])
                r_state.append(state_entry)
            except ValueError as e:
                logging.warning(str(e))
                pass
        self._state = r_state
        # print(self._state)

    def pos(self, path):
        for fl in self._state:
            if fl['path'] == path:
                return fl['pos']

    def id(self, path):
        for fl in self._state:
            if fl['path'] == path:
                return fl['inode'], fl['device']
        return None, None


class Notify_handler:
    def __init__(self, config):
        self._config = config

    def send_msg(self, msg):
        raise NotImplementedError


class Notify_signal(Notify_handler):
    def __init__(self, config):
        super().__init__(config)


class Notify_mail(Notify_handler):
    def __init__(self, config):
        super().__init__(config)


class Notify_telegram(Notify_handler):
    def __init__(self, config):
        super().__init__(config)

    def send_msg(self, msg):
        telegram_send.send(messages=[msg])


class Notify:
    def __init__(self):
        self._notify = None

    def get_notify(self, name):
        for i in self._notify:
            if i['name'] == name:
                return i
        return None

    @staticmethod
    def _factory(notify_type):
        if notify_type == 'telegram':
            return Notify_telegram
        elif notify_type == 'signal':
            return Notify_signal;
        elif notify_type == 'mail':
            return Notify_mail

    def parse_notify(self, filename):
        with open(filename, "r") as infile:
            notify = json.load(infile)
        r_config = []
        for config_element in notify:
            tmp = dict()
            tmp['type'] = config_element['type']
            tmp['name'] = config_element['name']
            tmp['handler'] = self._factory(tmp['type'])(config_element)
            r_config.append(tmp)

        self._notify = r_config
        # print(self._notify)

    def send(self, notify_type, msg):
        for i in self._notify:
            if notify_type == i['type']:
                i['handler'].send(msg)


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
        for config_element in config:
            tmp = dict()
            tmp['path'] = config_element['path']
            tmp['name'] = config_element['name']
            tmp['output'] = config_element['output']
            tmp['retention'] = config_element['retention'] if 'retention' in config_element else None
            tmp['filter'] = []
            for t in config_element['filter']:
                filter = dict()
                filter['regex'] = t['regex']
                filter['emit'] = t['emit']
                filter['transform'] = t['transform'] if 'transform' in t else dict()
                filter['notify'] = dict()
                if 'notify' in t and 'condition' in t['notify'] and 'name' in t['notify']:
                    # print(t['notify'])
                    notify = dict()
                    # print('//aoeua', t['notify'])
                    notify['condition'] = t['notify']['condition']
                    notify['name'] = t['notify']['name']
                    filter['notify'] = notify
                tmp['filter'].append(filter)
            r_config.append(tmp)
        self._config = r_config

    def get_retention(self, filename):
        for i in self._config:
            if i['path'] == filename:
                return i['retention']

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
