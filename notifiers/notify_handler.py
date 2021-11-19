from typing import Dict, Any
import time


class Notify_handler:
    def __init__(self, config: Dict[str, Any]) -> None:
        self._config: Dict[str, str] = config
        self._limit: int = int(config.get('limit', 0))  # rate limit
        self._last_time: Dict[str, int] = {}

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

    def get_format(self) -> str:
        return 'text'
