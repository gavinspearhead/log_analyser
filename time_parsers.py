import re
import time
import logging
import datetime
import dateutil.parser
# import typing
from traceback import print_exc
from typing import Dict, Pattern, Match, Optional, Sequence


class TimestampParsers:
    _months: Dict[str, int] = {"jan": 1, "feb": 2, 'mar': 3, 'apr': 4, 'may': 5, 'jun': 6, 'jul': 7, 'aug': 8,
                               'sep': 9, 'oct': 10, 'nov': 11, 'dec': 12}

    def __init__(self) -> None:
        self._apache_pattern: Pattern[str] = re.compile(r'\[(\d+)/([a-zA-Z]+)/(\d+):(\d+):(\d+):(\d+)\s([+-]?\d+)]')
        self._syslog_pattern: Pattern[str] = re.compile(r'([A-Za-z]+)\s+(\d+)\s+(\d+):(\d+):(\d+)')

    def parse_syslog_timestamp(self, time_str: str) -> str:
        matches: Optional[Match[str]] = self._syslog_pattern.search(time_str)
        try:
            if matches is None:
                raise ValueError("Not found: {}".format(time_str))
            x: Sequence = matches.groups()
            if x is None:
                raise ValueError("Not found: {}".format(time_str))
            day: int = int(x[1])
            mnt: str = x[0].lower()
            # print(mn)
            if mnt in self._months:
                mon: int = self._months[mnt]
                # print(mon)
            else:
                raise ValueError("Unknown month: {}".format(mnt))
            year: int = datetime.datetime.now().year
            hour: int = int(x[2])
            mn: int = int(x[3])
            sec: int = int(x[4])
            tz: str = time.strftime("%z", time.localtime())
            # print(year, mon, day, hour, mn, sec, tz)
            time_out_str: str = "{:04d}-{:02d}-{:02d}T{:02d}:{:02d}:{:02d}{:s}".format(year, mon, day, hour, mn, sec,
                                                                                       tz)

            dateutil.parser.isoparse(time_out_str)
            # print(time_str)
        except ValueError as e:
            print_exc()
            logging.info("Invalid Syslog Date {} {}".format(time_str, e))
            return ""
        return time_out_str

    def parse_apache_timestamp(self, time_str: str) -> str:
        matches: Optional[Match[str]] = self._apache_pattern.search(time_str)
        try:
            if matches is None:
                raise ValueError("Not found: {}".format(time_str))
            x = matches.groups()
            if x is None:
                raise ValueError("Not found: {}".format(time_str))
            day: int = int(x[0])
            mnt: str = x[1].lower()
            # print(mn)
            if mnt in self._months:
                mon: int = self._months[mnt]
            else:
                raise ValueError("Unknown month: {}".format(mnt))
                # print(mon)
            year: int = int(x[2])
            hour: int = int(x[3])
            mn: int = int(x[4])
            sec: int = int(x[5])
            tz: int = int(x[6])
            # print(year, mon, day, hour, mn, sec, tz)
            time_out_str = "{:04d}-{:02d}-{:02d}T{:02d}:{:02d}:{:02d}{:+05d}".format(year, mon, day, hour, mn, sec, tz)
            dateutil.parser.isoparse(time_out_str)
        except ValueError as e:
            logging.info("Invalid Apache Date {} {}".format(time_str, e))
            return ""
        return time_out_str

    def parse_iso_timestamp(self, time_str):
        try:
            dateutil.parser.isoparse(time_str)
        except ValueError as e:
            logging.info("Invalid ISO Date {} {}".format(time_str, e))
            return ""

        return time_str


_P = TimestampParsers()
parse_apache_timestamp = _P.parse_apache_timestamp
parse_syslog_timestamp = _P.parse_syslog_timestamp
parse_iso_timestamp = _P.parse_iso_timestamp

if __name__ == "__main__":
    print('j', parse_syslog_timestamp("Dec 1 23:17:58 "))
    print('y', parse_apache_timestamp("[04/Dec/2021:00:41:47 +0100]"))
    print('x', parse_iso_timestamp("2021-12-04T03:41:47z"))
