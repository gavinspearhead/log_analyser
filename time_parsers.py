import re
import time
import logging
import datetime


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
