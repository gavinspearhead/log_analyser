import datetime
import os.path
import re
import sys
import pymongo
import pytz
import tzlocal

from typing import List, Dict, Any, Optional, Tuple, Union
from functions import match_ip_address, get_mongo_connection, format_time, get_period_mask
from data_set import Data_set

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def get_search_mask_ssh(search: str) -> Optional[Dict[str, Any]]:
    s = match_ip_address(search)
    if s is not None:
        return s
    return {"username": {"$regex": re.escape(search)}}


def get_ssh_user_time_data(search: str, mask: Dict[str, Any], raw: bool, time_mask: str,
                           intervals: List[Union[int, str, Tuple[int, int]]]) -> Data_set:
    local_tz: str = str(tzlocal.get_localzone())
    col = get_mongo_connection()
    search_q = get_search_mask_ssh(search)
    orig_time_mask = time_mask.capitalize()
    if time_mask == 'day':
        time_mask = 'dayOfMonth'
    res = col.aggregate(
        [{"$match": {"$and": [{"name": "auth_ssh"}, mask, search_q]}},
         {"$group": {"_id": {"username": "$username", "type": "$type",
                             "time": {"$" + time_mask: {"date": "$timestamp", "timezone": local_tz}},
                             "month": {"$month": {"date": "$timestamp", "timezone": local_tz}},
                             },
                     "total": {"$sum": 1},
                     "ips": {"$addToSet": "$ip_address"},
                     "hosts": {"$addToSet": "$host"},
                     'hour': {"$addToSet": {"$hour": {"date": "$timestamp", "timezone": local_tz}}},
                     # 'month': {"$addToSet": {"$month": {"date": "$timestamp", "timezone": local_tz}}}
                     }},
         {"$sort": {'_id.month': 1, '_id.time': 1, "total": -1}}
         ])
    data = Data_set('username', 'time', 'total')
    data.set_keys([orig_time_mask, 'Username', 'Type', 'Total', 'IPs', 'Hosts'])
    if raw:
        data.prepare_time_output(time_mask, intervals,
                                 {'time': None, 'username': "", 'type': None, 'total': 0, 'ips': ""})
    for x in res:
        time_str = format_time(time_mask, x['_id']['month'], x['hour'][0], x['_id']['time'])
        row = {
            "time": time_str,
            'username': x['_id']['username'],
            'type': x['_id']['type'],
            'total': x['total'],
            'ips': ", ".join(x['ips']),
            'hosts': ", ".join(x['hosts'])}
        data.add_data_row(row)
    return data


def get_ssh_user_data(search: str, mask: Dict[str, Any]) -> Data_set:
    local_tz: str = str(tzlocal.get_localzone())
    col = get_mongo_connection()
    search_q = get_search_mask_ssh(search)
    q = [{"$match": {"$and": [{"name": "auth_ssh"}, mask, search_q]}},
         {"$group": {"_id": {"username": "$username", "type": "$type"}, "total": {"$sum": 1},
                     "hosts": {"$addToSet": "$host"},
                     "ips": {"$addToSet": "$ip_address"},
                     "times": {"$addToSet": {"$dateToString": {"date": "$timestamp", "timezone": local_tz,
                                                               "format": "%Y-%m-%dT%H:%M:%S"}}}}},
         {"$sort": {"total": -1}}
         ]
    data = Data_set('type', 'username', 'count')
    data.set_keys(['Username', 'Type', 'Count', 'IPs', "Hosts", "Timestamps"])
    res = col.aggregate(q)
    for x in res:
        row = {
            'username': x['_id']['username'],
            'type': x['_id']['type'],
            'count': x['total'],
            'ips': ", ".join(sorted(x['ips'])),
            'hosts': ", ".join(x['hosts']),
            'times': ", ".join(sorted(x['times']))
        }
        data.add_data_row(row)
    return data


def get_ssh_ip_data(search: str, mask: Dict[str, Any], name: str) -> Data_set:
    col = get_mongo_connection()
    search_q = get_search_mask_ssh(search)
    res = col.aggregate(
        [{"$match": {"$and": [{"name": "auth_ssh"}, mask, search_q]}},
         {"$group": {"_id": {"ip_address": "$ip_address", "type": "$type"}, "total": {"$sum": 1},
                     "users": {"$addToSet": "$username"},
                     "hosts": {"$addToSet": "$host"}}},
         {"$sort": {"total": -1}}
         ])
    data = Data_set('type', 'prefix' if name == 'ip_prefixes' else 'ip_address', 'count')
    for x in res:
        ip_address = x['_id']['ip_address']
        row = {
            'ip_address': ip_address,
            'count': x['total'],
            'type': x['_id']['type'],
            'users': ", ".join(sorted(x['users'])),
            'hosts': ", ".join(sorted(x['hosts']))
        }
        data.add_data_row(row)
    if name == 'ip_prefixes':
        data.set_keys(['IP Prefixes', 'Count', 'Type', 'Users', 'Hosts'])
        data.merge_prefixes(['count'], ['users', 'hosts'], ['type'])
    else:
        data.set_keys(['IP Addresses', 'Count', 'Type', 'Users', 'Hosts'], )
    return data


def get_ssh_time_ips_data(search: str, mask: Dict[str, Any], raw: bool, time_mask: str,
                          intervals: List[Union[int, str, Tuple[int, int]]]) -> Data_set:
    local_tz: str = str(tzlocal.get_localzone())
    col = get_mongo_connection()
    search_q = get_search_mask_ssh(search)
    orig_time_mask = time_mask.capitalize()
    if time_mask == 'day':
        time_mask = 'dayOfMonth'

    res = col.aggregate(
        [{"$match": {"$and": [{"name": "auth_ssh"}, mask, search_q]}},
         {"$group": {"_id": {"ip_address": "$ip_address", "type": "$type",
                             "time": {"$" + time_mask: {"date": "$timestamp", "timezone": local_tz}},
                             "month": {"$month": {"date": "$timestamp", "timezone": local_tz}},
                             },
                     "total": {"$sum": 1},
                     "usernames": {"$addToSet": "$username"},
                     "hosts": {"$addToSet": "$host"},
                     'hour': {"$addToSet": {"$hour": {"date": "$timestamp", "timezone": local_tz}}},
                     'month': {"$addToSet": {"$month": {"date": "$timestamp", "timezone": local_tz}}}}},
         {"$sort": {'_id.month': 1, '_id.time': 1, "total": -1}}
         ])
    data = Data_set('ip_address', 'time', 'total')
    data.set_keys([orig_time_mask, 'IP Addresses', 'Type', 'Total', 'Usernames', 'Hosts'])
    if raw:
        data.prepare_time_output(time_mask, intervals,
                                 {'time': None, 'ip_address': "", 'type': None, 'total': 0, 'users': ""})
    for x in res:
        time_str = format_time(time_mask, x['_id']['month'], x['hour'][0], x['_id']['time'])
        row = {
            'time': time_str,
            'ip_address': x['_id']['ip_address'],
            'type': x['_id']['type'],
            'total': x['total'],
            'users': ", ".join(sorted(x['usernames'])),
            'hosts': ", ".join(sorted(x['hosts']))
        }
        data.add_data_row(row)
    return data


def get_ssh_new_ips_data(search: str, mask: Dict[str, Any], start_time: datetime.datetime) -> Data_set:
    col: pymongo.collection.Collection = get_mongo_connection()
    search_q = get_search_mask_ssh(search)
    ips: Dict[str, Tuple[int, datetime.datetime]] = {}
    res = col.aggregate(
        [{"$match": {"$and": [{"name": "auth_ssh"}, {"type": "connect"}]}},
         {"$group": {"_id": {"ip_address": "$ip_address"}, "total": {"$sum": 1},
                     "oldest": {"$min": "$timestamp"}}},
         {"$sort": {"total": -1}}
         ])
    for x in res:
        ip: str = x['_id']['ip_address']
        if ip not in ips:
            ips[ip] = (x['total'], pytz.UTC.localize(x['oldest']))
    res = col.aggregate(
        [{"$match": {"$and": [{"name": "auth_ssh"}, {"type": "connect"}, mask, search_q]}},
         {"$group": {
             "_id": {"ip_address": "$ip_address"},
             "total": {"$sum": 1},
             'types': {"$addToSet": "$type"},
             'hosts': {"$addToSet": "$host"}}},
         {"$sort": {"total": -1}}
         ])
    new_ips: Dict[str, Tuple[int, str, str]] = {}
    for x in res:
        ip1: str = x['_id']['ip_address']
        ts: int = x['total']
        ty: str = ", ".join(x['types'])
        th: str = ", ".join(x['hosts'])

        if ip1 not in ips or (ips[ip1][0] < (2 * ts)) or ips[ip1][1] >= start_time:
            if ip1 not in new_ips:
                new_ips[ip1] = (ts, ty, th)

    data = Data_set()
    data.set_keys(['IP address', 'Count', 'Types', 'Hosts'])
    for ip2 in new_ips:
        data.add_data_row({
            'ip_address': ip2,
            'count': new_ips[ip2][0],
            'types': new_ips[ip2][1],
            'hosts': new_ips[ip2][2]
        })
    return data


def get_ssh_new_user_data(search: str, mask: Dict[str, Any], start_time: datetime.datetime) -> Data_set:
    col = get_mongo_connection()
    search_q = get_search_mask_ssh(search)
    users: Dict[str, Dict[str, Tuple[int, datetime.datetime]]] = {}
    res = col.aggregate(
        [{"$match": {"$and": [{"name": "auth_ssh"}, {"type": "connect"}]}},
         {"$group": {"_id": {"username": "$username", "ip_address": "$ip_address"}, "total": {"$sum": 1},
                     "oldest": {"$min": "$timestamp"}}},
         {"$sort": {"total": -1}}
         ])
    for x in res:
        username: str = x['_id']['username']
        ip: str = x['_id']['ip_address']
        total: int = x['total']
        oldest = pytz.UTC.localize(x['oldest'])
        if username not in users:
            users[username] = {}
        users[username][ip] = (total, oldest)
    res = col.aggregate(
        [{"$match": {"$and": [{"name": "auth_ssh"}, {"type": "connect"}, mask, search_q]}},
         {"$group": {
             "_id": {"username": "$username", "ip_address": "$ip_address"},
             "total": {"$sum": 1},
             'hosts': {"$addToSet": "$host"},
             'types': {"$addToSet": "$type"}}},
         {"$sort": {"total": -1}}
         ])
    new_users: Dict[str, Dict[str, Tuple[int, str, str]]] = {}
    for x in res:
        u1: str = x['_id']['username']
        ip1: str = x['_id']['ip_address']
        ts: int = x['total']
        ty: str = ", ".join(x['types'])
        th: str = ", ".join(x['hosts'])

        if u1 not in users or ip1 not in users[u1] or (users[u1][ip1][0] < (2 * ts)) or users[u1][ip1][1] >= start_time:
            if u1 not in new_users:
                new_users[u1] = {}
            new_users[u1][ip1] = (ts, ty, th)

    data = Data_set()
    data.set_keys(['Username', 'IP address', 'Count', 'Types', 'Hosts'])
    for u2 in new_users:
        for ip2 in new_users[u2]:
            data.add_data_row({
                'username': u2,
                'ip_address': ip2,
                'count': new_users[u2][ip2][0],
                'types': new_users[u2][ip2][1],
                'hosts': new_users[u2][ip2][2]
            })
    return data


def get_ssh_data(name: str, period: str, search: str, raw: bool = False, to_time: Optional[str] = None,
                 from_time: Optional[str] = None, host: str = "*") -> Data_set:
    local_tz: str = str(tzlocal.get_localzone())
    mask_range = get_period_mask(period, to_time, from_time, pytz.timezone(local_tz))
    time_mask = mask_range[2]
    intervals = mask_range[3]
    mask: Dict[str, Any] = {"$and": [{"timestamp": {"$gte": mask_range[0]}}, {"timestamp": {"$lte": mask_range[1]}}]}
    if host not in ["*", '']:
        mask['$and'].append({"hostname": {"$regex": host, "$options": "i"}})
    if name == 'users':
        data = get_ssh_user_data(search, mask)
    elif name == 'time_users':
        data = get_ssh_user_time_data(search, mask, raw, time_mask, intervals)
    elif name == 'time_ips':
        data = get_ssh_time_ips_data(search, mask, raw, time_mask, intervals)
    elif name == 'ip_addresses' or name == 'ip_prefixes':
        data = get_ssh_ip_data(search, mask, name)
    elif name == 'new_ips':
        data = get_ssh_new_ips_data(search, mask, mask_range[0])
    elif name == 'new_users':
        data = get_ssh_new_user_data(search, mask, mask_range[0])
    else:
        raise ValueError(name)
    return data
