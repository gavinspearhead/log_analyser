import json
import logging

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
