from typing import Dict
import smtplib
import ssl
from notifiers import notify_handler


class Notify_mail(notify_handler.Notify_handler):

    def __init__(self, config: Dict[str, str]) -> None:
        super().__init__(config)
        self._smtp_server: str = config.get('smtp_host', "")
        self._smtp_port: int = int(config.get('smtp_port', 25))
        self._mail_from: str = config.get('from_address', "")
        self._mail_to: str = config.get('to_address', "")
        self._password: str = config.get('password', "")
        self._subject: str = config.get('subject', "Log Notification")
        if self._mail_to == "":
            raise ValueError("Missing mail to address")
        if self._mail_from == "":
            raise ValueError("Missing mail from address")
        if self._smtp_server == "":
            raise ValueError("Missing mail server")

    def send_msg(self, msg: str, limit_type: str) -> None:
        if self.check_rate_limit(limit_type):
            return
        context: ssl.SSLContext = ssl.create_default_context()
        try:
            with smtplib.SMTP_SSL(self._smtp_server, self._smtp_port, context=context) as server:
                if self._password != '':
                    server.login(self._mail_from, self._password)
                message = "Subject: {}\n\n{}".format(self._subject, msg)
                server.sendmail(self._mail_from, self._mail_to, message)
        except smtplib.SMTPException as e:
            raise ValueError(e)
