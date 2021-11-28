import datetime
import ipaddress
import json
import logging
import operator
import re
import typing
from pprint import pprint

import dateutil.parser
from util import load_data_set
from time_parsers import parse_apache_timestamp, parse_syslog_timestamp

from abc import ABC
from dateutil.tz import tzoffset
from matches import is_new
from local_ip import is_local_address

from typing import Union, Dict, Optional, List, Tuple

data_conversion = load_data_set()


class LogParser(ABC):
    def __init__(self) -> None:
        pass

    def match(self, line: str):
        raise NotImplemented

    def emit(self, matches, name: str):
        raise NotImplemented

    def notify(self, matches, name: str):
        raise NotImplemented


class RegexParser(LogParser):
    _patterns = {
        "IP": ('(?:\\d+\\.\\d+\\.\\d+\\.\\d+)|(?:(?:[a-fA-F0-9]{0,4}:){0,7}(?:[a-fA-F0-9]{0,4}))', str),
        "IP4": ('\\d+\\.\\d+\\.\\d+\\.\\d+', str),
        "IP6": ('[a-fA-F0-9]{0,4}:){0,7}(?:[a-fA-F0-9]{0,4})', str),
        'NUM': ('[+-]?\\d+', int),
        'ALNUM': ('[a-zA-Z0-9]+', str),
        'FLOAT': ('[+-]?\\d*.?\\d+(?e[+-]?\\d+)', float),
        'ALPHA': ('[a-zA-Z]+', str),
        'STR': ('\\S+', str),
        'SPACE': ('\\s+', str),
        'NAME': ('[-a-zA-Z0-9_]+', str),
        'VERSION': ('\\d+[.]\\d+', str),
        "WORD": ('\\w+', str),
        'HEX': ('[A-Fa-f0-9]+', str),
        'TIME': ('\\d{1,2}[:.]\\d{1,2}(?:[:.]\\d{1,2}(?:[.]\\d+)?)?', str),
        'AUTH_DATE': ('[a-zA-Z]+ \\d{1,2}', str),
        'APACHE_TIMESTAMP': ('\\[\\d+/[a-zA-Z]+/\\d+:\\d+:\\d+:\\d+\\s[+-]?\\d+]', parse_apache_timestamp),
        'SYSLOG_TIMESTAMP': ('[A-Za-z]+\\s+\\d+\\s+\\d+:\\d+:\\d+', parse_syslog_timestamp),
        'ISOTIME': (
            '\\d{4}-[01]\\d-[0-3]\\dT[0-2]\\d:[0-5]\\d:[0-5]\\d(?:\\.\\d+)?(?:[+-][0-2]\\d:[0-5]\\d|Z)?', str),
        'DATE': ('\\d{4}-[01]\\d-[0-3]\\dT[0-2]\\d', str),
        '%': ('%', str)
    }

    def __init__(self, reg_ex: str, format_str: typing.Dict[str, str], transform: typing.Dict[str, str], notify,
                 notifiers, output, log_name) -> None:
        super().__init__()
        self._pattern, self._filters = self.parse_regexp(reg_ex)
        # print(self._pattern)
        self._compiled_pattern = re.compile(self._pattern)
        self._format_str = format_str
        self._transform = transform
        self._notify = notify
        self._notifiers = notifiers
        self._output = output
        self._logname = log_name

    def __str__(self) -> str:
        return "{} : {}".format(self._pattern, self._format_str)

    def _find_pattern(self, pattern: str) -> Tuple[str, object]:
        if pattern in self._patterns:
            return self._patterns[pattern]
        raise ValueError("Pattern not found {}".format(pattern))

    @staticmethod
    def _parse_pattern(line: str) -> Tuple[str, str, str, int]:
        pos: int = 0
        start: int = pos
        colon_count: int = 0
        parts: List[str] = ["", "", ""]
        while True:
            try:
                if line[pos] == ')':
                    parts[colon_count] = line[start:pos]
                    return parts[0], parts[1], parts[2], pos + 1
                elif line[pos] == ':':
                    parts[colon_count] = line[start:pos]
                    start = pos + 1
                    colon_count += 1
                    if colon_count > 2:
                        raise ValueError('too many colons')
                pos += 1
            except IndexError:
                raise ValueError('missing closing parenthesis')

    def parse_regexp(self, line: str) -> typing.Tuple[str, typing.Dict]:
        # "foo (%BAR:name:param)
        pos: int = 0
        out: str = ""
        filters: typing.Dict = {}
        index: int = 0
        while pos < len(line):
            try:
                if line[pos:pos + 2] == "(%":
                    pattern, name, params, total_length = self._parse_pattern(line[pos + 2:])
                    if name == '':
                        name = "__{}".format(index)
                    s, tp = self._find_pattern(pattern)
                    filters[name] = (index, tp)
                    index += 1
                    out += '({})'.format(s)
                    pos += total_length + 2
                else:
                    out += line[pos]
                    pos += 1
            except IndexError as e:
                logging.info('error {}'.format(e))
        # print(out, filters)
        return out, filters

    def match(self, line: str) -> typing.List[str]:
        res = self._compiled_pattern.search(line)
        # print(line, res)
        if res is None:
            return []
        return list(res.groups())

    def emit(self, matches, name):
        res = {}
        values = {}
        for idx, val in self._filters.items():
            try:
                values[idx] = val[1](matches[val[0]])
            except TypeError:
                logging.info('Error: {} is not a {}'.format(matches[val[0]], val[1]))

        for idx, val in self._format_str.items():
            try:
                val = self.parameter_expand(val)
                rv = val.format(**values)
                res[idx] = self._transform_value(rv, idx)
            except KeyError:
                continue
        res['name'] = name
        # print(res)
        return res

    def notify(self, matches, name: str):
        res = self.emit(matches, name)
        # print(self._notify)
        for notifier in self._notify:
            if notifier != {}:
                if self._match_notify_conditions(res, notifier['condition']):
                    try:
                        notifier = self._notifiers.get_notify(notifier['name'])
                        formatting = notifier['handler'].get_format()
                        if formatting == "text":
                            msg = "".join(["{}: {}\n".format(x, y) for x, y in res.items()])
                        elif formatting == "json":
                            msg = json.dumps({x: str(y) for x, y in res.items()})
                        else:
                            raise ValueError("Unknown format {}".format(formatting))

                        notifier['handler'].send_msg(msg, self._logname)
                        # self._notifiers.get_notify(self._notify['name'])['handler'].send_msg(text, self._logname)
                    except (KeyError, ValueError) as e:
                        logging.warning("Can't send message: {}".format(str(e)))
        return None

    @staticmethod
    def _compare(element: str, clause) -> bool:
        # print(element, clause)
        if element.startswith("<="):
            val = element[2:]
            op = operator.le
        elif element.startswith(">="):
            val = element[2:]
            op = operator.ge
        elif element.startswith(">"):
            val = element[1:]
            op = operator.gt
        elif element.startswith("<"):
            op = operator.lt
            val = element[1:]
        elif element.startswith("="):
            val = element[1:]
            op = operator.eq
        elif element.startswith("!"):
            val = element[1:]
            op = operator.ne
        else:
            raise ValueError("Unknown operator")
        try:
            val = val.strip()
            v = ipaddress.ip_address(val)
            c = ipaddress.ip_network(clause)
            if op == operator.ne:
                return v not in c
            elif op == operator.eq:
                return v in c
            else:
                raise ValueError("can't compare ipaddress")
        except ValueError:
            pass
        if (type(val) == int or val.isnumeric()) and (type(clause) == int or clause.isnumeric()):
            return op(int(clause), int(val))
        else:
            return op(clause, val)

    def _match_notify_conditions(self, matches, conditions) -> typing.Optional[bool]:
        # print(matches)
        # print(conditions)
        res = False
        for condition in conditions:
            # print('cond', condition)
            res2 = len(condition) > 0
            for clause in condition:
                # print('claus1e', clause)
                if clause in matches:
                    # print('clause', clause, matches[clause], condition[clause])
                    if type(condition[clause]) != list:
                        condition[clause] = [condition[clause]]
                    for elem in condition[clause]:
                        # print('clause', clause, matches[clause], elem)
                        if elem == 'new':
                            # print('is_new')
                            if is_new(self._output, matches['name'], clause, matches[clause]):
                                # print('new ', clause)
                                res2 = res2 and True
                            else:
                                res2 = False
                        elif elem == 'all' or elem == 'any':
                            res2 = res2 and True
                        elif elem == 'local':
                            try:
                                res2 = res2 and is_local_address(matches[clause])
                            except ValueError:
                                # only for IP addresses
                                res2 = False
                        elif elem == 'nonlocal':
                            try:
                                res2 = res2 and not is_local_address(matches[clause])
                            except ValueError:
                                # only for IP addresses
                                res2 = False
                        elif elem[0] in "=!<>":
                            # print(self._compare(elem, matches[clause]))
                            res2 = res2 and self._compare(elem, matches[clause])
                        else:
                            res2 = False
                        # print(res, res2)
            res = res or res2
            if res:
                # matches['notify'] = "{} {}".format(matches[clause], clause)
                # print(matches['notify'])
                return True
        # print(res)
        return None

    def _transform_value(self, rv, idx):
        if idx in self._transform:
            if self._transform[idx] == 'date':
                # print(rv)
                return dateutil.parser.isoparse(rv)
            elif self._transform[idx] == 'int':
                return int(rv)
            elif self._transform[idx] == 'str':
                return str(rv)
            elif self._transform[idx] == 'float':
                return float(rv)
            elif self._transform[idx] == 'bool':
                if rv.lower() == 'true':
                    return True
                elif rv.lower() == 'false':
                    return False
                else:
                    raise ValueError("Unknown value {}".format(rv))
            else:
                raise ValueError("Unknown transform {}".format(self._transform[idx]))
        return rv

    @staticmethod
    def parameter_expand(val):
        matches = re.findall(r"([$]\w+)", val)
        for m in matches:
            val = val.replace(m, data_conversion.get(m, '-'))
        return val


if __name__ == "__main__":
    r = RegexParser('', None, None, None, None, None, None)

    rs = {'hostname': 'mercenary', 'ip_address': '2001:984:47bf:1:36a3:bf3c:d751:500b', 'unknown': '-', 'username': '-',
          'timestamp': datetime.datetime(2021, 9, 23, 18, 19, 33, tzinfo=tzoffset(None, 7200)), 'http_command': 'GET',
          'path': '/cds/loginscreen.php', 'protocol': 'HTTP', 'protocol_version': '1.1', 'code': '200', 'size': 892,
          'name': 'apache_access'}
    conds = [{'ip_address': ['new', "local"]}]  # , {'username': 'new'}]

    xx = r._match_notify_conditions(rs, conds)
    print(xx)
