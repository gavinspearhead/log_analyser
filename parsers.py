import ipaddress
import json
import logging
import operator
import re
import dateutil.parser
from datetime import datetime

from matches import address_in_prefix
from outputters.output_abstract import AbstractOutput
from util import DataSet, dns_translate, get_flag
from time_parsers import parse_apache_timestamp, parse_syslog_timestamp, parse_iso_timestamp
from abc import ABC
from dateutil.tz import tzoffset
from local_ip import is_local_address
from typing import List, Tuple, Dict, Union, Any

data_conversion = DataSet()


class LogParser(ABC):
    def __init__(self) -> None:
        pass

    def match(self, line: str):
        raise NotImplemented

    def emit(self, matches: List[str], name: str):
        raise NotImplemented

    def notify(self, output_dict, name: str):
        raise NotImplemented


class RegexParser(LogParser):
    _ip4_regex = '\\d+\\.\\d+\\.\\d+\\.\\d+'
    _ip6_regex = '(?:[a-fA-F0-9]{0,4}:){0,7}(?:[a-fA-F0-9]{0,4})'
    _patterns = {
        "IP": ('(?:' + _ip4_regex + ')|(?:' + _ip6_regex + ')', str),
        "IP4": (_ip4_regex, str),
        "IP6": (_ip6_regex, str),
        'NUM': ('[+-]?\\d+', int),
        'ALNUM': ('[a-zA-Z0-9]+', str),
        'HOST': ('(?:[-a-zA-Z0-9.]+)|(?:' + _ip4_regex + ')|(?:' + _ip6_regex + ')', str),
        'FLOAT': ('[+-]?\\d*.?\\d+(?:e[+-]?\\d+)', float),
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
            '\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(?:\\.\\d+)?(?:Z|[+-]\\d{2}:\\d{2})',
#            '\\d{4}-?[01]\\d-?[0-3]\\dT[0-2]\\d:?[0-5]\\d:?[0-5]\\d(?:\\.\\d+)?(?:[+-][0-2]\\d(:?[0-5]\\d)?|Z|z)?',
            parse_iso_timestamp),
        'DATE': ('\\d{4}-[01]\\d-[0-3]\\dT[0-2]\\d', str),
        '%': ('%', str)
    }

    def __init__(self, reg_ex: str, format_str: Dict[str, str], transform: Dict[str, str], notify,
                 notifiers, output: AbstractOutput, log_name) -> None:
        super().__init__()
        self._pattern, self._filters = self.parse_regexp(reg_ex)
        # print(self._pattern)
        self._compiled_pattern = re.compile(self._pattern)
        self._format_str: Dict[str, str] = format_str
        self._transform: Dict[str, str] = transform
        self._notify = notify
        self._notifiers = notifiers
        self._output: AbstractOutput = output
        self._log_name: str = log_name

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

    def parse_regexp(self, line: str) -> Tuple[str, Dict]:
        #print(line)
        pos: int = 0
        out: str = ""
        filters: Dict = {}
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
        return out, filters

    def match(self, line: str) -> List[str]:
        res = self._compiled_pattern.search(line)
        if res is None:
            return []
        #print(res.groups())
        return list(res.groups())

    def emit(self, matches: List[str], name: str) -> Dict[str, Union[datetime, int, str, float, bool]]:
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
        #print(res)
        return res

    def notify(self, output_dict: List[str], name: str) -> None:
        # res = self.emit(matches, name)
        for notifier in self._notify:
            if notifier != {}:
                if self._match_notify_conditions(output_dict, notifier['condition']):
                    try:
                        notifier = self._notifiers.get_notify(notifier['name'])
                        handler = notifier['handler']
                        if handler.do_convert_dns() and 'remote_host' not in output_dict:
                            rv = dns_translate(output_dict['ip_address'])
                            if rv:
                                output_dict['remote_host'] = rv
                        if handler.do_find_country() and 'country' not in output_dict:
                            country_code, country_name = get_flag(output_dict['ip_address'])
                            if country_name != '':
                                output_dict['country'] = "{} ({})".format(country_name, country_code)
                        formatting = handler.format
                        if formatting == "text":
                            msg = "".join(["{}: {}\n".format(x, y) for x, y in output_dict.items()])
                        elif formatting == "json":
                            msg = json.dumps({x: str(y) for x, y in output_dict.items()})
                        else:
                            raise ValueError("Unknown format {}".format(formatting))

                        handler.send_msg(msg, self._log_name)
                    except (KeyError, ValueError) as e:
                        logging.warning("Can't send message: {}".format(str(e)))
        return None

    @staticmethod
    def _get_operator(element: str) -> Tuple[str, Any]:
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
            raise ValueError("Unknown operator: {}".format(element))
        return val, op

    def _compare(self, element: str, clause: Union[str, int]) -> bool:
        val, op = self._get_operator(element)
        try:
            val = val.strip()
            v = ipaddress.ip_address(val)
            c = ipaddress.ip_network(clause)
            if op == operator.ne:
                return v not in c
            elif op == operator.eq:
                return v in c
            else:
                raise ValueError("Can't compare ipaddress")
        except ValueError:
            # not an IP address
            pass
        if (type(val) == int or val.isnumeric()) and (type(clause) == int or clause.isnumeric()):
            return op(int(clause), int(val))
        else:
            return op(clause, val)

    @staticmethod
    def _compare_regex(elem: str, clause: Union[str, int]) -> bool:
        return re.match(elem[1:], str(clause)) is not None

    def _match_condition(self, elem: str, name: str, clause: str, matched_clause: str, res2: bool) -> bool:
        if type(elem) == dict:
            for k, v in elem.items():
                if k.lower() == 'in':
                    if type(v) == list:
                        v = [str(t) for t in v]
                        res2 = res2 and matched_clause in v
                    elif address_in_prefix(matched_clause, v):
                        res2 = res2 and True
                    else:
                        logging.info("in expects a list or an IP address range")
                        res2 = False
                else:
                    logging.info("Unknown operator {}".format(k))
        elif elem == 'new':
            if self._output.is_new(name, clause, matched_clause):
                res2 = res2 and True
            else:
                res2 = False
        elif elem == 'all' or elem == 'any':
            res2 = res2 and True
        elif elem == 'local':
            try:
                res2 = res2 and is_local_address(matched_clause)
            except ValueError:
                # only for IP addresses
                res2 = False
        elif elem == 'nonlocal':
            try:
                res2 = res2 and not is_local_address(matched_clause)
            except ValueError:
                # only for IP addresses
                res2 = False
        elif elem[0] in "=!<>":
            res2 = res2 and self._compare(elem, matched_clause)
        elif elem[0] in "~":
            res2 = res2 and self._compare_regex(elem, matched_clause)
        else:
            res2 = False
        return res2

    def _match_notify_conditions(self, matches: Dict[str, str], conditions: List[Dict[str, List[str]]]) -> bool:
        res: bool = False
        for condition in conditions:
            res2 = len(condition) > 0
            for clause in condition:
                if clause in matches:
                    if type(condition[clause]) != list:
                        condition[clause] = [condition[clause]]
                    for elem in condition[clause]:
                        res2 = self._match_condition(elem, matches['name'], clause, matches[clause], res2)
            res = res or res2
            if res:
                return True
        return False

    def _transform_value(self, rv: str, idx: str) -> Union[datetime, int, str, float, bool]:
        if idx in self._transform:
            if self._transform[idx] == 'date':
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
    def parameter_expand(val: str) -> str:
        matches = re.findall(r"([$]\w+)", val)
        for m in matches:
            val = val.replace(m, data_conversion.get(m, '-'))
        # print(val)
        return val


if __name__ == "__main__":
    r = RegexParser('', None, None, None, None, None, None)

    rs = {'hostname': 'mercenary', 'ip_address': '2001:984:47bf:1:36a3:bf3c:d751:500b', 'unknown': '-', 'username': '-',
          'timestamp': datetime.datetime(2021, 9, 23, 18, 19, 33, tzinfo=tzoffset(None, 7200)), 'http_command': 'GET',
          'path': '/cds/loginscreen.php', 'protocol': 'HTTP', 'protocol_version': '1.1', 'code': '200', 'size': 892,
          'name': 'apache_access'}
    conds = [{'ip_address': ['new', "local"]}]  # , {'username': 'new'}]

    xx = r._match_notify_conditions(rs, conds)
    # print(xx)
