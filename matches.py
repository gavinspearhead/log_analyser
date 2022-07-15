import functools
import logging
from typing import Any, Tuple, Dict
from outputters.output_abstract import AbstractOutput


def false_only_cache(fn):
    cache: Dict[int, bool] = {}

    @functools.wraps(fn)
    def wrapper(*args: Tuple[Any, ...], **kwargs: Dict[str, Any]) -> bool:
        key = hash(args + tuple(sorted(kwargs.items())))
        if key in cache:
            return cache[key]
        result: bool = fn(*args, **kwargs)
        if not result:
            cache[key] = result
        return result

    return wrapper


def _is_new(col: AbstractOutput, value: str, field: str, name: str) -> bool:
    res = (0 == col.count({field: value, "name": name}))
    return res


def apache_is_new_ipaddress(col: AbstractOutput, value: str) -> bool:
    return 0 == col.count({"ip_address": value, "name": "apache_access"})


def apache_is_new_username(col: AbstractOutput, value: str) -> bool:
    return 0 == col.count({"username": value, "name": "apache_access"})


def ssh_is_new_ipaddress(col: AbstractOutput, value: str) -> bool:
    return 0 == col.count({"ip_address": value, "name": "auth_ssh"})


def nntp_is_new_dest_address(col: AbstractOutput, value: str) -> bool:
    return 0 == col.count({"dest_address": value, "name": "nntp_proxy"})


def nntp_is_new_ipaddress(col: AbstractOutput, value: str) -> bool:
    return 0 == col.count({"ip_address": value, "name": "nntp_proxy"})


def ssh_is_new_username(col: AbstractOutput, value: str) -> bool:
    return 0 == col.count({"username": value, "name": "auth_ssh"})


def apache_is_new(col: AbstractOutput, field: str, value: str) -> bool:
    if field == 'ip_address':
        return apache_is_new_ipaddress(col, value)
    elif field == 'username':
        return apache_is_new_username(col, value)
    else:
        logging.info('Unknown field {}:'.format(field))
        return False


def ssh_is_new(col: AbstractOutput, field: str, value: str) -> bool:
    if field == 'ip_address':
        return ssh_is_new_ipaddress(col, value)
    elif field == 'username':
        return ssh_is_new_username(col, value)
    else:
        logging.info('Unknown field {}:'.format(field))
        return False


def nntp_is_new(col: AbstractOutput, field: str, value: str) -> bool:
    if field == 'ip_address':
        return _is_new(col, value, 'ip_address', 'nntp_proxy')
    elif field == 'dest_address':
        return _is_new(col, value, 'dest_address', 'nntp_proxy')
    else:
        logging.info('Unknown field {}:'.format(field))
        return False


@false_only_cache
def is_new(col: AbstractOutput, source: str, field: str, value: str) -> bool:
    if source == "auth_ssh":
        return ssh_is_new(col, field, value)
    elif source == 'apache_access':
        return apache_is_new(col, field, value)
    elif source == 'nntp_proxy':
        return nntp_is_new(col, field, value)
    else:
        logging.info('Unknown source {}:'.format(source))
        return False
