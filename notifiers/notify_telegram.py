from typing import Dict, List, Optional
import telegram_send



from notifiers import notify_handler


class Notify_telegram(notify_handler.Notify_handler):
    def __init__(self, config: Dict[str, str]) -> None:
        super().__init__(config)
        self._config_path: Optional[str] = config.get('config_path', None)
        self._subject: str = config.get('subject', "")

    def send_msg(self, msg: str, limit_type: str) -> None:
        if self.check_rate_limit(limit_type):
            return
        messages: List[str] = ["{}:\n\n{}".format(self._subject, msg)]
        telegram_send.send(messages=messages, conf=self._config_path)
