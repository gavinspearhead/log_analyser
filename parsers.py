import json
import re


class LogParser:
    def __init__(self):
        pass

    def match(self, line):
        raise NotImplemented

    def emit(self):
        raise NotImplemented


class RegexParser(LogParser):
    def __init__(self, reg_ex: str, format_str: str):
        super().__init__()
        self._pattern = self._convert(reg_ex)
        self._compiled_pattern = re.compile(self._pattern)
        self._format_str = format_str

    def __str__(self):
        return self._pattern + " : " + self._format_str

    def match(self, line):
        # print(self._pattern, self._format_str, line)
        x = self._compiled_pattern.search(line)
        # print(',,', x)
        if x is None:
            return False
        return list(x.groups())

    def _convert(self, pattern):
        # print(pattern)
        patterns = {
            "IP": '(?:\\d+\\.\\d+\\.\\d+\\.\\d+)|(?:(?:[a-fA-F0-9]{0,4}:){0,7}(?:[a-fA-F0-9]{0,4}))',
            "IP4": '\\d+\\.\\d+\\.\\d+\\.\\d+',
            "IP6": '[a-fA-F0-9]{0,4}:){0,7}(?:[a-fA-F0-9]{0,4})',
            'NUM': '\\d+',
            'ALNUM': '[a-zA-Z0-9]+',
            'ALPHA': '[a-zA-Z]+',
            'STR': '\\S+',
            'NAME': '[-a-zA-Z0-9_]+',
            "WORD": '\\w+',
            'HEX': '[A-Fa-f0-9]+',
            'TIME': '\\d{1,2}[:.]\\d{1,2}(?:[:.]\\d{1,2}(?:[.]\\d+)?)?',
            '%': '%'
        }
        for pat, val in patterns.items():
            # print(pat, val)
            pattern = pattern.replace('%' + pat, '(?:' + val + ')')
        print('x', pattern)
        return pattern

    def emit(self, matches):
        # print(self._format_str, matches)
        res = dict()

        for idx, val in self._format_str.items():
            res[idx] = val.format(*matches)
        return res
        # return self._format_str.format(*matches)

if __name__ == '__main__':
    c = RegexParser("(%TIME)", "XX {0} YY")
    x=c.match("10:34:23.a12343 oeauoeu")
    print(x,)
    x=c.match("[15/May/2021:23:45:15 +0200]")
    print(x,)
