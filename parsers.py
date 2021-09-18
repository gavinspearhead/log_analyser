import datetime
import logging
import re
import time
import socket

import dateutil.parser
import netifaces as ni

from matches import is_new
from local_ip import is_local_address


class LogParser:
    def __init__(self):
        pass

    def match(self, line):
        raise NotImplemented

    def emit(self, matches, name):
        raise NotImplemented

    def notify(self, matches, name):
        raise NotImplemented


class TimestampParsers:
    months = {"jan": 1, "feb": 2, 'mar': 3, 'apr': 4, 'may': 5, 'jun': 6, 'jul': 7, 'aug': 8, 'sep': 9, 'oct': 10,
              'nov': 11, 'dec': 12}

    def __init__(self):
        self._apache_pattern = re.compile(r'\[(\d+)/([a-zA-Z]+)/(\d+):(\d+):(\d+):(\d+)\s([+-]?\d+)]')
        self._syslog_pattern = re.compile(r'([A-Za-z]+)\s+(\d+)\s+(\d+):(\d+):(\d+)')

    def parse_syslog_timestamp(self, time_str):
        matches = self._syslog_pattern.search(time_str)
        try:
            x = matches.groups()
            day = int(x[1])
            mnt = x[0].lower()
            # print(mn)
            if mnt in self.months:
                mon = self.months[mnt]
                # print(mon)
            else:
                raise ValueError("Unknown month: {}".format(mnt))
            year = datetime.datetime.now().year
            hour = int(x[2])
            mn = int(x[3])
            sec = int(x[4])
            tz = time.strftime("%z", time.localtime())
            # print(year, mon, day, hour, mn, sec, tz)
            time_str = "{:04d}-{:02d}-{:02d}T{:02d}:{:02d}:{:02d}{:s}".format(year, mon, day, hour, mn, sec, tz)
            # print(time_str)
        except Exception as e:
            logging.info("Invalid Date {} {}".format(time_str, e))
            return ""
        return time_str

    def parse_apache_timestamp(self, time_str):
        matches = self._apache_pattern.search(time_str)
        x = matches.groups()
        try:
            day = int(x[0])
            mnt = x[1].lower()
            # print(mn)
            if mnt in self.months:
                mon = self.months[mnt]
            else:
                raise ValueError("Unknown month: {}".format(mnt))
                # print(mon)
            year = int(x[2])
            hour = int(x[3])
            mn = int(x[4])
            sec = int(x[5])
            tz = int(x[6])
            # print(year, mon, day, hour, mn, sec, tz)
            time_str = "{:04d}-{:02d}-{:02d}T{:02d}:{:02d}:{:02d}{:+05d}".format(year, mon, day, hour, mn, sec, tz)
        except Exception as e:
            logging.info("Invalid Date {}".format(e))
            return ""
        return time_str


_P = TimestampParsers()
parse_apache_timestamp = _P.parse_apache_timestamp
parse_syslog_timestamp = _P.parse_syslog_timestamp


def get_own_ip(ip_version=4):
    interfaces = ni.interfaces()
    address = None
    for i in interfaces:
        if i != "lo":
            try:
                if ip_version == 4:
                    address = ni.ifaddresses(i)[ni.AF_INET][0]['addr']
                elif ip_version == 6:
                    address = ni.ifaddresses(i)[ni.AF_INET6][0]['addr']
                else:
                    raise KeyError
                break
            except KeyError:
                pass
    return address


def load_data_set():
    r = dict()
    r['$fqdn'] = socket.getfqdn()
    r['$hostname'] = socket.gethostname().lower()
    r['$host_ip'] = get_own_ip(4)
    r['$host_ipv6'] = get_own_ip(6)
    return r


data_conversion = load_data_set()


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

    def __init__(self, reg_ex: str, format_str, transform, notify, notifiers, output):
        super().__init__()
        self._pattern, self._filters = self.parse_regexp(reg_ex)
        # print(self._pattern)
        self._compiled_pattern = re.compile(self._pattern)
        self._format_str = format_str
        self._transform = transform
        self._notify = notify
        self._notifiers = notifiers
        self._output = output

    def __str__(self):
        return "{} : {}".format(self._pattern, self._format_str)

    def _find_pattern(self, pattern):
        if pattern in self._patterns:
            return self._patterns[pattern]
        raise ValueError("Pattern not found {}".format(pattern))

    @staticmethod
    def _parse_pattern(line):
        pos = 0
        start = pos
        colon_count = 0
        parts = ["", "", ""]
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

    def parse_regexp(self, line):
        # "foo (%BAR:name:param)
        pos = 0
        out = ""
        filters = dict()
        index = 0
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

    def match(self, line):
        res = self._compiled_pattern.search(line)
        # print(line, res)
        if res is None:
            return False
        return list(res.groups())

    @staticmethod
    def _guess_type(rv):
        try:
            return dateutil.parser.isoparse(rv)
        except ValueError:
            pass

        if rv.isnumeric():
            return int(rv)
        elif rv.lower() == 'true':
            return True
        elif rv.lower() == 'false':
            return False
        return rv

    def emit(self, matches, name):
        res = dict()
        values = dict()
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

    def notify(self, matches, name):
        res = self.emit(matches, name)
        if self._notify != {}:
            if self._match_notify_conditions(res, self._notify['condition']):
                try:
                    text = "".join(["{}: {}\n".format(x, y) for x, y in res.items()])
                    self._notifiers.get_notify(self._notify['name'])['handler'].send_msg(text)
                except (KeyError, ValueError) as e:
                    logging.warning("Can't send message: {}".format(str(e)))
        return None

    def _match_notify_conditions(self, matches, conditions):
        # print(matches)
        # print(conditions)
        res = False
        for condition in conditions:
            # print('cond', condition)
            res2 = len(condition) > 0
            for clause in condition:
                # print('claus1e', clause)
                if clause in matches:
                    # print('clause', clause, matches[clause])
                    if condition[clause] == 'new':
                        # print('is_new')
                        if is_new(self._output, matches['name'], clause, matches[clause]):
                            # print('new ', clause)
                            res2 = res2 and True
                        else:
                            res2 = False
                    elif condition[clause] == 'all' or condition[clause] == 'any':
                        res2 = res2 and True
                    elif condition[clause] == 'local':
                        try:
                            res2 = res2 and is_local_address(matches[clause])
                        except ValueError:
                            # only for IP addresses
                            res2 = False
                    elif condition[clause] == 'nonlocal':
                        try:
                            res2 = res2 and not is_local_address(matches[clause])
                        except ValueError:
                            # only for IP addresses
                            res2 = False
                    else:
                        res2 = False
            res = res or res2
            if res:
                matches['notify'] = "{} {}".format(matches[clause], clause)
                return matches
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
