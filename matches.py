import functools


def false_only_cache(fn):
    cache = {}

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        key = args + tuple(sorted(kwargs.items()))
        if key in cache:
            return cache[key]
        result = fn(*args, **kwargs)
        if not result:
            cache[key] = result
        return result
    return wrapper


def apache_is_new_ipaddress(col, value):
    return 0 == col.count({"ip_address": value, "name": "apache_access"})


def apache_is_new_username(col, value):
    return 0 == col.count({"username": value, "name": "apache_access"})


def ssh_is_new_ipaddress(col, value):
    return 0 == col.count({"ip_address": value, "name": "auth_ssh"})


# @false_only_cache
def ssh_is_new_username(col, value):
    return col.count({"username": value, "name": "auth_ssh"}) == 0


def apache_is_new(col, field, value):
    if field == 'ip_address':
        return apache_is_new_ipaddress(col, value)
    elif field == 'username':
        return apache_is_new_username(col, value)
    else:
        return False


def ssh_is_new(col, field, value):
    if field == 'ip_address':
        return ssh_is_new_ipaddress(col, value)
    elif field == 'username':
        return ssh_is_new_username(col, value)
    else:
        return False


@false_only_cache
def is_new(col, source, field, value):
    if source == "auth_ssh":
        return ssh_is_new(col, field, value)
    elif source == 'apache_access':
        return apache_is_new(col, field, value)
    else:
        return False
