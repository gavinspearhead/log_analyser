import functools
import logging
import ipaddress
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
    res: bool = (0 == col.count({field: value, "name": name}))
    return res


def apache_is_new(col: AbstractOutput, field: str, value: str) -> bool:
    if field in ['ip_address', 'username']:
        return _is_new(col, value, field, 'apache_access')
    else:
        logging.info('Unknown field {}:'.format(field))
        return False


def ssh_is_new(col: AbstractOutput, field: str, value: str) -> bool:
    if field in ['ip_address', 'username']:
        return _is_new(col, value, field, 'auth_ssh')
    else:
        logging.info('Unknown field {}:'.format(field))
        return False


def nntp_is_new(col: AbstractOutput, field: str, value: str) -> bool:
    if field in ['ip_address', 'dest_address']:
        return _is_new(col, value, field, 'nntp_proxy')
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


def address_in_prefix(address,prefix):
    try:
        return ipaddress.ip_address(address) in ipaddress.ip_network(prefix)
    except Exception:
        return False

