import json


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
            if 'path' not in config_element or 'name' not in config_element or 'output' not in config_element:
                continue
            tmp = {
                'path': config_element['path'],
                'name': config_element['name'],
                'output': config_element['output'],
                'retention': config_element['retention'] if 'retention' in config_element else None, 'filter': []
            }
            for t in config_element['filter']:
                if 'regex' in t and 'emit' in t:
                    log_filter = {
                        'regex': t['regex'],
                        'emit': t['emit'],
                        'transform': t['transform'] if 'transform' in t else {}, 'notify': {}
                    }
                    if 'notify' in t and 'condition' in t['notify'] and 'name' in t['notify']:
                        notify = {
                            'condition': t['notify']['condition'],
                            'name': t['notify']['name']
                        }
                        log_filter['notify'] = notify
                    tmp['filter'].append(log_filter)
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
