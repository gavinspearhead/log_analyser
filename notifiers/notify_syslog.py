import syslog
from syslog import LOG_EMERG, LOG_ALERT, LOG_CRIT, LOG_ERR, LOG_WARNING, LOG_NOTICE, LOG_INFO, LOG_DEBUG, LOG_KERN, \
    LOG_LOCAL2, LOG_LOCAL3, LOG_LOCAL4, LOG_LOCAL5, LOG_LOCAL6, LOG_USER, LOG_MAIL, LOG_DAEMON, LOG_AUTH, LOG_LPR, \
    LOG_NEWS, LOG_UUCP, LOG_CRON, LOG_SYSLOG, LOG_LOCAL0, LOG_LOCAL7, LOG_AUTHPRIV, LOG_LOCAL1

from typing import Dict

from log_analyser_version import PROG_NAME_COLLECTOR
from notifiers import notify_handler


class Notify_syslog(notify_handler.Notify_handler):
    _priorities = {
        "EMERG": LOG_EMERG,
        "ALERT": LOG_ALERT,
        "CRIT": LOG_CRIT,
        "ERR": LOG_ERR,
        "WARNING": LOG_WARNING,
        "NOTICE": LOG_NOTICE,
        "INFO": LOG_INFO,
        "DEBUG": LOG_DEBUG
    }

    _facilities = {
        "KERN": LOG_KERN,
        "USER": LOG_USER,
        "MAIL": LOG_MAIL,
        "DAEMON": LOG_DAEMON,
        "AUTH": LOG_AUTH,
        "LPR": LOG_LPR,
        "NEWS": LOG_NEWS,
        "UUCP": LOG_UUCP,
        "CRON": LOG_CRON,
        "SYSLOG": LOG_SYSLOG,
        "LOCAL0": LOG_LOCAL0,
        "LOCAL1": LOG_LOCAL1,
        "LOCAL2": LOG_LOCAL2,
        "LOCAL3": LOG_LOCAL3,
        "LOCAL4": LOG_LOCAL4,
        "LOCAL5": LOG_LOCAL5,
        "LOCAL6": LOG_LOCAL6,
        "LOCAL7": LOG_LOCAL7,
        "AUTHPRIV": LOG_AUTHPRIV
    }

    def __init__(self, config: Dict[str, str]):
        super().__init__(config)
        self._facility = None
        self._priority = None
        self._ident = PROG_NAME_COLLECTOR

        priority = str(config.get('priority', "")).upper()
        if priority in self._priorities:
            self._priority = self._priorities[priority]
        else:
            raise ValueError("Unknown facility: {}".format(priority))
        facility = str(config.get('facility', "")).upper()
        if facility in self._facilities:
            self._facility = self._facilities[facility]
        else:
            raise ValueError("Unknown facility: {}".format(facility))
        ident = str(config.get('ident', ""))
        if ident != "":
            self._ident = ident

    def send_msg(self, msg: str, limit_type: str) -> None:
        if self.check_rate_limit(limit_type):
            return
        syslog.openlog(ident=self._ident, facility=self._facility, logoption=syslog.LOG_PID)
        syslog.syslog(self._priority, msg)
        syslog.closelog()

