import json
# from pprint import pprint
from typing import Iterator, Optional, List, Dict, Any

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
from config_checker import Config_Checker


class Config:

    _config_items = {
        'path': Config_Checker.OPTIONAL,
        'name': Config_Checker.MANDATORY,
        'output': Config_Checker.MANDATORY,
        'retention': Config_Checker.OPTIONAL,
        'filter': {
            "regex": Config_Checker.MANDATORY,
            "emit": Config_Checker.MANDATORY,
            "transform": Config_Checker.OPTIONAL,
            "notify": {
                "condition": Config_Checker.MANDATORY,
                "name": Config_Checker.MANDATORY
            }
        }
    }

    def __init__(self) -> None:
        self._config: List[Dict[str, Any]] = []

    def parse_config(self, filename: str) -> None:
        with open(filename, "r") as infile:
            config = json.load(infile)
        # Config_Checker.config_validate(self._config_items, config)
        r_config: List = []
        for config_element in config:
            if 'path' not in config_element or 'name' not in config_element or 'output' not in config_element \
                    or 'filter' not in config_element:
                continue
            tmp = {
                'path': config_element['path'],
                'name': config_element['name'],
                'output': config_element['output'],
                'retention': config_element.get('retention', None),
                'filter': []
            }
            for t in config_element['filter']:
                if 'regex' in t and 'emit' in t:
                    log_filter = {
                        'regex': t['regex'],
                        'emit': t['emit'],
                        'transform': t.get('transform', {}),
                        'notify': {}
                    }
                    if 'notify' in t:
                        log_filter['notify'] = []
                        for notifier in t['notify']:
                            if 'condition' in notifier and 'name' in notifier:
                                notify = {
                                    'condition': notifier['condition'],
                                    'name': notifier['name']
                                }
                                log_filter['notify'].append(notify)
                    tmp['filter'].append(log_filter)
            r_config.append(tmp)
        self._config = r_config

    def get_retention(self, filename: str) -> Optional[int]:
        for i in self._config:
            if i['path'] == filename:
                return int(i['retention'])
        return None

    def get_name(self, filename: str) -> Optional[str]:
        for i in self._config:
            if i['path'] == filename:
                return str(i['name'])
        return None

    def get_filter(self, filename: str) -> Optional[List[Dict[str, Any]]]:
        for i in self._config:
            if i['path'] == filename:
                return i['filter']
        return None

    def _check_filename(self, filename: str) -> bool:
        for i in self._config:
            if i['path'] == filename:
                return True
        return False

    def get_files(self) -> Iterator[str]:
        for i in self._config:
            yield str(i['path'])

    def get_output(self, filename: str) -> Optional[str]:
        for i in self._config:
            if i['path'] == filename:
                return str(i['output'])
        return None
