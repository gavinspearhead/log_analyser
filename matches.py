from output import MongoConnector


def apache_is_new_ipaddress(col, value):
    return col.count({"ip_address": value, "name": "apache_access"}) == 0


def apache_is_new_username(col, value):
    return col.count({"username": value, "name": "apache_access"}) == 0


def ssh_is_new_ipaddress(col, value):
    x = col.count({"ip_address": value, "name": "auth_ssh"})
    # print('count', x)
    return x == 0


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


def is_new(col, source, field, value):
    # print('GAR  ', col)
    # print("IS_NWU", source, field, value)
    if source == "auth_ssh":
        x = ssh_is_new(col, field, value)
    elif source == 'apache_access':
        x = apache_is_new(col, field, value)
    else:
        x = False
    # print('RESNEW', x)
    return x
