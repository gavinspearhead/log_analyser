from typing import Dict, Any
import time

from config_checker import Config_Checker


class Notify_handler:
    _config_items = {
        'limit': Config_Checker.OPTIONAL,
        'resolve_ip': Config_Checker.OPTIONAL,
    }
    _valid_formats = ['text', 'json']  # might add CSV, YAML, XML,

    def __init__(self, config: Dict[str, Any]) -> None:
        Config_Checker.config_validate(self._config_items, config)
        self._config: Dict[str, str] = config
        self._limit: int = int(config.get('limit', 0))  # rate limit
        self._last_time: Dict[str, int] = {}
        self._convert_dns = config.get('resolve_ip', False)
        self._find_country = config.get('find_country', False)

    def do_find_country(self) -> bool:
        return self._find_country

    def do_convert_dns(self) -> bool:
        return self._convert_dns

    def check_rate_limit(self, limit_type: str) -> bool:
        if self._limit == 0:
            return False
        now: int = int(time.time())
        rv: bool = limit_type in self._last_time and now - self._last_time[limit_type] < self._limit
        if not rv:
            self._last_time[limit_type] = now
        return rv

    def send_msg(self, msg: str, limit_type: str) -> None:
        raise NotImplementedError

    @property
    def format(self) -> str:
        return self.get_format()

    def get_format(self) -> str:
        return 'text'

    def cleanup(self) -> None:
        pass

    def validate_format(self, notify_format):
        return notify_format in self._valid_formats
