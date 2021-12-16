import json
import logging
from typing import Union, Dict, Optional, List, Tuple

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
    def __init__(self) -> None:
        self._state: List[Dict[str, Union[str, int]]] = []

    def parse_state(self, filename: str) -> None:
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
        self._state = r_state

    def pos(self, path: str) -> Optional[int]:
        for fl in self._state:
            if fl['path'] == path:
                return int(fl['pos'])
        return None

    def id(self, path: str) -> Tuple[Optional[int], Optional[int]]:
        for fl in self._state:
            # print(fl)
            if fl['path'] == path and fl['inode'] is not None and fl['device'] is not None:
                return int(fl['inode']), int(fl['device'])
        return None, None
