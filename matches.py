import functools
from typing import Any, Tuple, Dict
from output import MongoOutput


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


def apache_is_new_ipaddress(col: MongoOutput, value: str) -> bool:
    return col.count({"ip_address": value, "name": "apache_access"}) == 0


def apache_is_new_username(col: MongoOutput, value: str) -> bool:
    return 0 == col.count({"username": value, "name": "apache_access"})


def ssh_is_new_ipaddress(col: MongoOutput, value: str) -> bool:
    return 0 == col.count({"ip_address": value, "name": "auth_ssh"})


def ssh_is_new_username(col: MongoOutput, value: str) -> bool:
    return col.count({"username": value, "name": "auth_ssh"}) == 0


def apache_is_new(col: MongoOutput, field: str, value: str) -> bool:
    if field == 'ip_address':
        return apache_is_new_ipaddress(col, value)
    elif field == 'username':
        return apache_is_new_username(col, value)
    else:
        return False


def ssh_is_new(col: MongoOutput, field: str, value: str) -> bool:
    if field == 'ip_address':
        return ssh_is_new_ipaddress(col, value)
    elif field == 'username':
        return ssh_is_new_username(col, value)
    else:
        return False


@false_only_cache
def is_new(col: MongoOutput, source: str, field: str, value: str) -> bool:
    if source == "auth_ssh":
        return ssh_is_new(col, field, value)
    elif source == 'apache_access':
        return apache_is_new(col, field, value)
    else:
        return False
