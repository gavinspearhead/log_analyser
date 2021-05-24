import datetime
import re
import time
import dateutil.parser


class LogParser:
    def __init__(self):
        pass

    def match(self, line):
        raise NotImplemented

    def emit(self, matches, name):
        raise NotImplemented


class TimestampParsers:
    months = {"jan": 1, "feb": 2, 'mar': 3, 'apr': 4, 'may': 5, 'jun': 6, 'jul': 7, 'aug': 8, 'sep': 9, 'oct': 10,
              'nov': 11, 'dec': 12}

    def __init__(self):
        self._apache_pattern = re.compile(r'\[(\d+)/([a-zA-Z]+)/(\d+):(\d+):(\d+):(\d+)\s([+-]?\d+)]')
        self._syslog_pattern = re.compile(r'([A-Za-z]+)\s(\d+)\s(\d+):(\d+):(\d+)')

    def parse_syslog_timestamp(self, timestr):
        matches = self._syslog_pattern.search(timestr)
        try:
            x = matches.groups()
            day = int(x[1])
            mn = x[0].lower()
            # print(mn)
            if mn in self.months:
                mon = self.months[mn]
                # print(mon)
            year = datetime.datetime.now().year
            hour = int(x[2])
            mn = int(x[3])
            sec = int(x[4])
            tz = time.strftime("%z", time.localtime())
            # print(year, mon, day, hour, mn, sec, tz)
            timestr = "{:04d}-{:02d}-{:02d}T{:02d}:{:02d}:{:02d}{:s}".format(year, mon, day, hour, mn, sec, tz)
            # print(timestr)
        except Exception as e:
            print("Invalid Date", e)
            return ""
        return timestr

    def parse_apache_timestamp(self, timestr):
        matches = self._apache_pattern.search(timestr)
        x = matches.groups()
        try:
            day = int(x[0])
            mn = x[1].lower()
            # print(mn)
            if mn in self.months:
                mon = self.months[mn]
                # print(mon)
            year = int(x[2])
            hour = int(x[3])
            mn = int(x[4])
            sec = int(x[5])
            tz = int(x[6])
            # print(year, mon, day, hour, mn, sec, tz)
            timestr = "{:04d}-{:02d}-{:02d}T{:02d}:{:02d}:{:02d}{:+05d}".format(year, mon, day, hour, mn, sec, tz)
            # print(timestr)
        except Exception as e:
            print("Invalid Date", e)
            return ""
        return timestr


_P = TimestampParsers()
parse_apache_timestamp = _P.parse_apache_timestamp
parse_syslog_timestamp = _P.parse_syslog_timestamp


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
        'SYSLOG_TIMESTAMP': ('[A-Za-z]+\\s\\d+\\s\\d+:\\d+:\\d+', parse_syslog_timestamp),
        'ISOTIME': (
            '\\d{4}-[01]\\d-[0-3]\\dT[0-2]\\d:[0-5]\\d:[0-5]\\d(?:\\.\\d+)?(?:[+-][0-2]\\d:[0-5]\\d|Z)?', str),
        'DATE': ('\\d{4}-[01]\\d-[0-3]\\dT[0-2]\\d', str),
        '%': ('%', str)
    }

    def __init__(self, reg_ex: str, format_str, transform):
        super().__init__()
        self._pattern, self._filters = self.parse_regexp(reg_ex)
        self._compiled_pattern = re.compile(self._pattern)
        self._format_str = format_str
        self._transform = transform

    def __str__(self):
        return self._pattern + " : " + self._format_str

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
                    out += '(' + s + ')'
                    pos += total_length + 2
                else:
                    out += line[pos]
                    pos += 1
            except IndexError:
                print('error')
        # print(out, filters)
        return out, filters

    def match(self, line):
        x = self._compiled_pattern.search(line)
        if x is None:
            return False
        return list(x.groups())

    def _guess_type(self, rv):
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
        vals = dict()
        for idx, val in self._filters.items():
            try:
                v = val[1](matches[val[0]])
                vals[idx] = v
            except TypeError:
                print('Error: {} is not a {}'.format(matches[val[0]], val[1]))

        for idx, val in self._format_str.items():
            try:
                rv = val.format(**vals)
                res[idx] = self._transform_value(rv, idx)
            except KeyError:
                continue
        res['name'] = name
        return res

    def _transform_value(self, rv, idx):
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


if __name__ == '__main__':
    # c = RegexParser("(%TIME)", "XX {0} YY")
    # x = c.match("10:34:23.a12343 oeauoeu")
    # print(x, )
    # x = c.match("[15/May/2021:23:45:15 +0200]")
    # print(x, )
    c = RegexParser("foo (%TIME:freddy) (%ALNUM:host) (%ISOTIME:date) (%IP4) bar", {
        'test': "{freddy} ",
        "test1": " {host} at",
        'test3': "{date} {__3}"})
    s = "foo 12:34:45 foobar 2021-06-12T12:23:45+03:00 12.34.56.78 bar"
    m = c.match(s)
    print(c.emit(m, 'foo'))
    # print(o, f)
    # res = re.search(o, s)
    # print(res)
    # print(res.groups())
