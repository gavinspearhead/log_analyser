import logging
import smtplib
import ssl

import xmpp

import telegram_send
import json


class Notify_handler:
    def __init__(self, config):
        self._config = config

    def send_msg(self, msg):
        raise NotImplementedError


class Notify_signal(Notify_handler):
    def __init__(self, config):
        super().__init__(config)

    def send_msg(self, msg):
        raise NotImplementedError


class Notify_mail(Notify_handler):

    def __init__(self, config):
        super().__init__(config)
        self._smtp_server = config.get('smtp_host', "")
        self._smtp_port = config.get('smtp_port', "")
        self._mail_from = config.get('from_address', "")
        self._mail_to = config.get('to_address', "")
        self._password = config.get('password', "")
        self._subject = config.get('subject', "Log Notification")

    def send_msg(self, msg):
        context = ssl.create_default_context()
        try:
            with smtplib.SMTP_SSL(self._smtp_server, self._smtp_port, context=context) as server:
                if self._password != '':
                    server.login(self._mail_from, self._password)
                message = "Subject: {}\n\n{}".format(self._subject, msg)
                print(message)
                server.sendmail(self._mail_from, self._mail_to, message)
        except smtplib.SMTPException as e:
            raise ValueError(e)


class Notify_telegram(Notify_handler):
    def __init__(self, config):
        super().__init__(config)

    def send_msg(self, msg):
        telegram_send.send(messages=[msg])


class Notify:
    def __init__(self):
        self._notify = None

    def get_notify(self, name):
        for i in self._notify:
            if i['name'] == name:
                return i
        return None

    @staticmethod
    def _factory(notify_type):
        if notify_type == 'telegram':
            return Notify_telegram
        elif notify_type == 'signal':
            return Notify_signal
        elif notify_type == 'mail':
            return Notify_mail
        elif notify_type == 'jabber':
            return Notify_jabber
        else:
            raise ValueError("Unknown notify type: {}".format(notify_type))

    def parse_notify(self, filename):
        with open(filename, "r") as infile:
            notify = json.load(infile)
        r_config = []
        for config_element in notify:
            tmp = dict()
            tmp['type'] = config_element['type']
            tmp['name'] = config_element['name']
            tmp['handler'] = self._factory(tmp['type'])(config_element)
            r_config.append(tmp)

        self._notify = r_config
        # print(self._notify)

    def send(self, notify_type, msg):
        for i in self._notify:
            try:
                if notify_type == i['type']:
                    i['handler'].send(msg)
            except Exception as e:
                logging.info("Notifying failed: {}".format(str(e)))


class Notify_jabber(Notify_handler):
    def __init__(self, config):
        super().__init__(config)
        self._jabber_id = config.get('jabber_id', "")
        self._send_to = config.get('to_address', "")
        self._password = config.get('password', "")

    def send_msg(self, msg):
        jid = xmpp.protocol.JID(self._jabber_id)
        connection = xmpp.Client(server=jid.getDomain())
        connection.connect()
        connection.auth(user=jid.getNode(), password=self._password, resource=jid.getResource())
        connection.send(xmpp.protocol.Message(to=self._send_to, body=msg))
        raise NotImplementedError
