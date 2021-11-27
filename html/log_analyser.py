#!/usr/bin/python3
import argparse
import datetime
import ipaddress
import json
import logging
import os.path
import re
import sys
from traceback import print_exc

import dns.resolver
import pymongo
import dateutil.parser
import geoip2.database
import geoip2.errors
import pytz
import tzlocal
import whois

from typing import List, Dict, Any, Optional, Tuple, Union
from flask import Flask, render_template, request, make_response
from humanfriendly import format_size
from natsort import natsorted
from copy import deepcopy

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from output import MongoConnector, Outputs
from log_analyser_version import VERSION, PROG_NAME_WEB

output_file_name: str = "loganalyser.output"
config_path: str = os.path.dirname(__file__)
app = Flask(__name__)
geoip2_db = geoip2.database.Reader(os.path.join(os.path.dirname(__file__), 'data/GeoLite2-Country.mmdb'))

dashboard_data_types: Dict[str, Tuple[str, str, str]] = {
    "ssh_users": ("ssh", "users", "SSH - Users"),
    "ssh_time_users": ("ssh", "time_users", "SSH - Users per Time"),
    "ssh_time_ips": ("ssh", "time_ips", "SSH - IPs per time"),
    "ssh_ip_addresses": ("ssh", "ip_addresses", "SSH - IP Addresses"),
    "ssh_ip_prefixes": ("ssh", "ip_prefixes", "SSH - IP Prefixes"),
    "apache_ip_addresses": ("apache", "ip_addresses", "Apache - IP Addresses"),
    "apache_ip_prefixes": ("apache", "ip_prefixes", "Apache - IP Prefixes"),
    "apache_time_ips": ("apache", "time_ips", "Apache - IPs per Time"),
    "apache_codes": ("apache", "codes", "Apache - Response codes"),
    "apache_method": ("apache", "method", "Apache - HTTP Methods"),
    "apache_protocol": ("apache", "protocol", "Apache - Protocols"),
    "apache_size_ip": ("apache", "size_ip", "Apache - Volume per IP"),
    "apache_size_prefix": ("apache", "size_prefix", "Apache - Volume per IP Prefix"),
    "apache_size_user": ("apache", "size_user", "Apache - Volume per User"),
}

main_data_titles = {
    'ssh': "SSH",
    'apache': 'Apache'
}

main_data_types: Dict[str, Dict[str, Tuple[str, str, str]]] = {
    'ssh': {
        "ssh_users": ("ssh", "users", "Users"),
        "ssh_new_users": ("ssh", "new_users", "SSH New Users"),
        "ssh_time_users": ("ssh", "time_users", "Users per Time"),
        "ssh_time_ips": ("ssh", "time_ips", "IPs per Time"),
        "ssh_ip_addresses": ("ssh", "ip_addresses", "IP Addresses"),
        "ssh_ip_prefixes": ("ssh", "ip_prefixes", "IP Prefixes"),
        "ssh_new_ips": ("ssh", "new_ips", "New IP Addresses"),
    },
    "apache": {
        "apache_ip_addresses": ("apache", "ip_addresses", "IP Addresses"),
        "apache_ip_prefixes": ("apache", "ip_prefixes", "IP Prefixes"),
        "apache_new_ips": ("apache", "new_ips", "New IP Addresses"),
        "apache_time_ips": ("apache", "time_ips", "IPs per Time"),
        "apache_codes": ("apache", "codes", "Response Codes"),
        "apache_method": ("apache", "method", "HTTP Methods"),
        "apache_protocol": ("apache", "protocol", "Protocols and Versions"),
        "apache_urls": ("apache", "urls", "URLs"),
        "apache_time_urls": ("apache", "time_urls", "URLs per Time"),
        "apache_size_ip": ("apache", "size_ip", "Volume per IP"),
        "apache_size_prefix": ("apache", "size_prefix", "Volume per IP Prefix"),
        "apache_size_user": ("apache", "size_user", "Volume per User"),
    }
}

enabled_data_types: Dict[str, Dict[str, Tuple[str, str, str]]] = {}
for x in dashboard_data_types:
    enabled_data_types[x] = True


class Data_set:
    def __init__(self, field1: Optional[str], field2: Optional[str], field3: Optional[str]):
        self._field1: Optional[str] = field1
        self._field2: Optional[str] = field2
        self._field3: Optional[str] = field3
        self._data: List[Dict[str, Union[int, str]]] = []
        self._keys: List[str] = []
        self._raw_keys: List[str] = []

    def set_keys(self, keys: List[str]) -> None:
        self._keys = keys

    @property
    def raw_keys(self) -> List[str]:
        return self.get_raw_keys()

    def get_raw_keys(self) -> List[str]:
        return self._raw_keys

    @property
    def keys(self):
        return self.get_keys()

    def get_keys(self) -> List[str]:
        return self._keys

    def add_data_row(self, row: Dict[str, Union[int, str]]) -> None:
        self._data.append(row)

    @property
    def raw_data(self) -> Dict[str, Dict[str, Union[int, str]]]:
        return self._get_raw_data()

    def _get_raw_data(self) -> Dict[str, Dict[str, Union[int, str]]]:
        if self._field1 is None or self._field3 is None:
            raise ValueError("Can't get raw data")
        rv, self._raw_keys = self._get_raw_data_internal()
        return rv

    @property
    def data(self) -> List[Dict[str, Union[int, str]]]:
        return self._get_data()

    def _get_data(self) -> List[Dict[str, Union[int, str]]]:
        return self._data

    def merge_prefixes(self, sum_list: List[str], join_list: List[str], hash_list: Optional[List[str]] = None) -> None:
        rv2: Dict[str, Dict[str, Union[str, int]]] = {}

        for x in self._data:
            prefix: Optional[str] = get_prefix(str(x['ip_address']))
            if prefix is None:
                prefix = str(x['ip_address'])
            key = prefix
            if hash_list is not None:
                key = str(prefix) + str(hash(str([x[y] for y in hash_list])))
            if key in rv2:
                for z in sum_list:
                    rv2[key][z] += x[z]
                for y in join_list:
                    rv2[key][y] = join_str_list(rv2[key][y], x[y])
            else:
                rv2[key] = {}
                rv2[key]['prefix'] = prefix
                rv2[key].update(x)
                del rv2[key]['ip_address']
        self._data = list(rv2.values())

    def format_size(self, field: str) -> None:
        for x in self._data:
            if field in x:
                x[field] = format_size(x[field])

    def prepare_time_output(self, time_mask: str, intervals: List[Union[int, str, Tuple[int, int]]],
                            template: Dict[str, Union[Optional[str], int]]) -> None:
        t: str = ""
        for i in intervals:
            if type(i) == int or type(i) == str:
                t = '{}'.format(i)
            elif type(i) == tuple:
                if time_mask == 'minute':
                    f_str = "{:02}:{:02}"
                elif time_mask == 'dayOfMonth' or time_mask == 'week':
                    f_str = "{:02}-{:02}"
                else:
                    f_str = "{}{}"
                t = f_str.format(i[0], i[1])
            else:
                raise TypeError('invalid time value')
            template['time'] = t
            self._data.append(deepcopy(template))

    def _get_raw_data_internal(self) -> Tuple[Dict[str, Dict[str, Union[str, int]]], List[str]]:
        field1_values: List[str] = natsorted(list(set([x[self._field1] for x in self._data])))
        field2_values: List[str] = []
        if self._field2 is not None:
            field2_values = natsorted(list(set([x[self._field2] for x in self._data])))
        data_set: Dict[str, Dict[str, Union[str, int]]] = {}
        for t in field1_values:
            data_set[t] = {}
            if self._field2 is not None:
                for u in field2_values:
                    data_set[t][u] = 0
        for x in self._data:
            if self._field2 is not None:
                data_set[x[self._field1]][x[self._field2]] += x[self._field3]
            else:
                data_set[x[self._field1]] = x[self._field3]

        rv = data_set
        keys: List[str] = list(field1_values)
        return rv, keys


def get_prefix(ip_address: str) -> Optional[str]:
    try:
        r = geoip2_db.country(ip_address)
        network_address = ipaddress.ip_interface("{}/{}".format(ip_address, r.traits._prefix_len))
        return str(network_address.network)
    except geoip2.errors.AddressNotFoundError:
        return None


def get_mongo_connection() -> pymongo.collection.Collection:
    output = Outputs()
    output.parse_outputs(os.path.join(config_path, '..', output_file_name))
    config = output.get_output('mongo')
    if config is None:
        raise ValueError("Configuration error: No Monge configured")
    mc = MongoConnector(config)
    col: pymongo.collection.Collection = mc.get_collection()
    return col


def get_period_mask(period: str, to_time: Optional[str] = None, from_time: Optional[str] = None,
                    tz: pytz.BaseTzInfo = pytz.UTC) -> Tuple[
                    datetime.datetime, datetime.datetime, str, Union[List[int], List[Tuple[int, int]]]]:
    now = datetime.datetime.now(tz)
    intervals: Union[List[int], List[Tuple[int, int]]] = []
    if period == 'today':
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        today_end = now.replace(hour=23, minute=59, second=59, microsecond=999999)
        intervals = list(range(0, 24))
        return today_start, today_end, 'hour', intervals
    elif period == 'hour':
        today_start = now - datetime.timedelta(hours=1)
        today_end = now
        intervals = list([((today_start + datetime.timedelta(minutes=x)).hour,
                           (today_start + datetime.timedelta(minutes=x)).minute)
                          for x in range(60)])
        return today_start, today_end, 'minute', intervals
    elif period == 'yesterday':
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0) - datetime.timedelta(days=1)
        today_end = now.replace(hour=23, minute=59, second=59, microsecond=0) - datetime.timedelta(days=1)
        intervals = list(range(0, 24))
        return today_start, today_end, 'hour', intervals
    elif period == 'week':
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0) - datetime.timedelta(weeks=1)
        today_end = now.replace(hour=23, minute=59, second=59, microsecond=0)
        intervals = list(
            [((today_start + datetime.timedelta(days=x)).month, (today_start + datetime.timedelta(days=x)).day) for x in
             range(8)])
        return today_start, today_end, 'day', intervals
    elif period == 'month':
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0) - datetime.timedelta(days=31)
        today_end = now.replace(hour=23, minute=59, second=59, microsecond=0)
        intervals = list(
            [((today_start + datetime.timedelta(days=x)).month, (today_start + datetime.timedelta(days=x)).day) for x in
             range(31)])
        return today_start, today_end, 'day', intervals
    elif period == 'custom':
        if from_time is None or to_time is None:
            raise ValueError("Invalid time format")
        today_start = (dateutil.parser.isoparse(from_time).astimezone(pytz.UTC))
        today_end = (dateutil.parser.isoparse(to_time).astimezone(pytz.UTC))
        t_delta: int = int((today_end - today_start).total_seconds())
        if t_delta <= 1:
            t_delta = 1
        if t_delta <= 60:
            p = 'second'
            intervals = list([(today_start + datetime.timedelta(seconds=x)).second for x in range(t_delta)])
        elif t_delta <= 3600:
            t = t_delta // 60
            p = 'minute'
            intervals = list([(today_start + datetime.timedelta(seconds=60 * x)).minute for x in range(t)])
        elif t_delta <= 24 * 3600:
            t = t_delta // 3600
            p = 'hour'
            intervals = list([(today_start + datetime.timedelta(seconds=3600 * x)).hour for x in range(t)])
        elif t_delta <= 7 * 24 * 3600:
            p = 'week'
            t = t_delta // (3600 * 24)
            try:
                intervals = list([(today_start + datetime.timedelta(seconds=3600 * 24 * x)).day for x in range(t)])
            except TypeError as e:
                raise e
        else:
            t = t_delta // (3600 * 24 * 28)
            p = 'month'
            intervals = list(
                [(today_start + datetime.timedelta(seconds=3600 * 24 * 28 * x)).isocalendar()[1] for x in range(t)])
        return today_start, today_end, p, intervals
    else:
        raise ValueError("Unknown period {}".format(period))


def match_ip_address(search: str) -> Optional[Dict[str, Any]]:
    try:
        ipaddress.ip_address(search)
        return {"ip_address": search}
    except ValueError:
        pass

    try:
        t_search = search.replace("*", "1", 2)
        ipaddress.IPv4Address(t_search)
        t_search = search.replace(".", "[.]", 2)
        t_search = t_search.replace("*", ".*", 2)
        return {"ip_address": {"$regex": t_search}}
    except ValueError:
        pass

    try:
        t_search = search.replace("*", "1", 2)
        ipaddress.IPv6Address(t_search)
        t_search = search.replace(".", "[.]", 2)
        t_search = t_search.replace("*", ".*", 2)
        return {"ip_address": {"$regex": t_search}}
    except ValueError:
        pass
    return None


def get_search_mask_ssh(search: str) -> Optional[Dict[str, Any]]:
    s = match_ip_address(search)
    if s is not None:
        return s
    return {"username": {"$regex": re.escape(search)}}


def get_search_mask_apache(search: str) -> Dict[str, Any]:
    s = match_ip_address(search)
    if s is not None:
        return s
    if search.isnumeric():
        return {"code": search}
    return {"path": {"$regex": re.escape(search)}}


def format_time(time_mask: str, month: int, hour: int, time_val: int) -> str:
    if time_mask == 'dayOfMonth' or time_mask == 'week':
        time_str: str = "{:02}-{:02}".format(month, time_val)
    elif time_mask == 'minute':
        time_str = "{:02}:{:02}".format(hour, time_val)
    else:
        time_str = "{}".format(time_val)
    return time_str


def get_ssh_user_time_data(search: str, mask: Dict[str, Any], raw: bool, time_mask: str,
                           intervals: List[Union[int, str, Tuple[int, int]]]) -> Data_set:
    local_tz: str = str(tzlocal.get_localzone())
    col = get_mongo_connection()
    search_q = get_search_mask_ssh(search)
    if time_mask == 'day':
        time_mask = 'dayOfMonth'
    res = col.aggregate(
        [{"$match": {"$and": [{"name": "auth_ssh"}, mask, search_q]}},
         {"$group": {"_id": {"username": "$username", "type": "$type",
                             "time": {"$" + time_mask: {"date": "$timestamp", "timezone": local_tz}},
                             "month": {"$month": {"date": "$timestamp", "timezone": local_tz}}
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
    data.set_keys([time_mask, 'Username', 'Type', 'Total', 'IPs', 'Hosts'])
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
    col = get_mongo_connection()
    search_q = get_search_mask_ssh(search)
    q = [{"$match": {"$and": [{"name": "auth_ssh"}, mask, search_q]}},
         {"$group": {"_id": {"username": "$username", "type": "$type"}, "total": {"$sum": 1},
                     "hosts": {"$addToSet": "$host"},
                     "ips": {"$addToSet": "$ip_address"}}},
         {"$sort": {"total": -1}}
         ]
    data = Data_set('type', 'username', 'count')
    data.set_keys(['Username', 'Type', 'Count', 'IPs', "Hosts"])
    res = col.aggregate(q)
    for x in res:
        row = {
            'username': x['_id']['username'], 'type': x['_id']['type'], 'count': x['total'],
            'ips': ", ".join(x['ips']),
            'hosts': ", ".join(x['hosts'])
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
    data = Data_set('prefix' if name == 'ip_prefixes' else 'ip_address', None, 'count')
    for x in res:
        ip_addr = x['_id']['ip_address']
        row = {
            'ip_address': ip_addr, 'count': x['total'], 'type': x['_id']['type'],
            'users': ", ".join(sorted(x['users'])),
            'hosts': ", ".join(sorted(x['hosts']))
        }
        data.add_data_row(row)
    if name == 'ip_prefixes':
        data.set_keys(['IP Prefixes', 'Count', 'Type', 'Users', 'Hosts'])
        data.merge_prefixes(['count'], ['users', 'hosts'], ['type'])
    else:
        data.set_keys(['IP Addresses', 'type', 'count', 'users', 'Hosts'], )
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

    data = Data_set(None, None, None)
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
        u: str = x['_id']['username']
        ip: str = x['_id']['ip_address']
        t: int = x['total']
        o = pytz.UTC.localize(x['oldest'])
        if u not in users:
            users[u] = {}
        users[u][ip] = (t, o)
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

    data = Data_set(None, None, None)
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


def join_str_list(list1: str, list2: str) -> str:
    a: List[str] = list1.split(',')
    b: List[str] = list2.split(',')
    return ",".join(sorted(list(set(a + b))))


def get_apache_methods_data(mask: Dict[str, Any], search: str) -> Data_set:
    search_q = get_search_mask_apache(search)
    col = get_mongo_connection()
    res = col.aggregate(
        [{"$match": {"$and": [{"name": "apache_access"}, mask, search_q]}},
         {"$group": {
             "_id": "$http_command",
             "total": {"$sum": 1},
             'hosts': {"$addToSet": "$hostname"}}},
         {"$sort": {"total": -1}}

         ])
    data = Data_set('method', None, 'count')
    data.set_keys(['HTTP Method', 'Count', 'Hosts'])
    for x in res:
        row = {
            'method': x['_id'],
            'count': x['total'],
            'hosts': ", ".join(x['hosts'])
        }
        data.add_data_row(row)
    return data


def get_apache_codes_data(mask: Dict[str, Any], search: str) -> Data_set:
    search_q = get_search_mask_apache(search)
    col = get_mongo_connection()
    res = col.aggregate(
        [{"$match": {"$and": [{"name": "apache_access"}, mask, search_q]}},
         {"$group": {
             "_id": "$code",
             'hosts': {"$addToSet": "$hostname"},
             "total": {"$sum": 1}}},
         {"$sort": {"total": -1}}
         ])
    data = Data_set('code', None, 'count')
    data.set_keys(['Code', 'Count', 'Hosts'])
    for x in res:
        row = {
            'code': x['_id'],
            'count': x['total'],
            'hosts': ", ".join(x['hosts'])
        }
        data.add_data_row(row)
    return data


def get_apache_protocols_data(mask: Dict[str, Any], search: str) -> Data_set:
    search_q = get_search_mask_apache(search)
    col = get_mongo_connection()
    res = col.aggregate(
        [{"$match": {"$and": [{"name": "apache_access"}, mask, search_q]}},
         {"$group": {"_id": {"protocol": "$protocol", "protocol_version": "$protocol_version"},
                     'hosts': {"$addToSet": "$hostname"},
                     "total": {"$sum": 1}}},
         {"$sort": {"total": -1}}
         ])
    data = Data_set('protocol', 'protocol_version', 'count')
    data.set_keys(['Protocol', 'Version', 'Count', 'Hosts'])
    for x in res:
        row = {
            'protocol': x['_id']['protocol'],
            'protocol_version': x['_id']['protocol_version'],
            'count': x['total'],
            'hosts': ", ".join(x['hosts'])
        }
        data.add_data_row(row)
    return data


def get_apache_ips_data(mask: Dict[str, Any], search: str, name: str) -> Data_set:
    search_q = get_search_mask_apache(search)
    col = get_mongo_connection()
    res = col.aggregate(
        [{"$match": {"$and": [{"name": "apache_access"}, mask, search_q]}},
         {"$group": {"_id": "$ip_address", "total": {"$sum": 1},
                     'usernames': {"$addToSet": "$username"},
                     'hosts': {"$addToSet": "$hostname"},
                     "codes": {"$addToSet": "$code"}
                     }},
         {"$sort": {"total": -1}}
         ])
    data = Data_set('prefix' if name == 'ip_prefixes' else 'ip_address', None, 'count')
    if name == 'ip_address':
        data.set_keys(['IP address', 'Count', 'Users', 'Codes', 'Hosts'])
    else:
        data.set_keys(['IP Prefix', 'Count', 'Users', 'Codes', "Hosts"])

    for x in res:
        row = {
            'ip_address': x['_id'],
            'count': x['total'],
            'users': ",".join(sorted(x['usernames'])),
            'codes': ",".join(sorted(x['codes'])),
            'hosts': ",".join(sorted(x['hosts']))
        }
        data.add_data_row(row)
    if name == 'ip_prefixes':
        data.merge_prefixes(['count'], ['users', 'codes', 'hosts'])
    return data


def get_apache_new_ips_data(mask: Dict[str, Any], search: str, start_time: datetime.datetime) -> Data_set:
    search_q = get_search_mask_apache(search)
    col = get_mongo_connection()
    ips: Dict[str, Tuple[int, datetime.date]] = {}
    res = col.aggregate(
        [{"$match": {"$and": [{"name": "apache_access"}]}},
         {"$group": {
             "_id": {"ip_address": "$ip_address"},
             "total": {"$sum": 1},
             "oldest": {"$min": "$timestamp"}}},
         {"$sort": {"total": -1}}
         ])
    for x in res:
        ip: str = x['_id']['ip_address']
        t: int = x['total']
        o = pytz.UTC.localize(x['oldest'])
        if ip not in ips:
            ips[ip] = (t, o)
    res = col.aggregate(
        [{"$match": {"$and": [{"name": "apache_access"}, mask, search_q]}},
         {"$group": {
             "_id": {"ip_address": "$ip_address"},
             "total": {"$sum": 1},
             'hosts': {"$addToSet": "$hostname"},
             'users': {"$addToSet": "$username"}}},
         {"$sort": {"total": -1}}
         ])
    new_ips: Dict[str, Tuple[int, str, str]] = {}
    for x in res:
        ip1: str = x['_id']['ip_address']
        ts: int = x['total']
        ty: str = ", ".join(sorted(x['users']))
        th: str = ", ".join(sorted(x['hosts']))
        if ip1 not in ips or (ips[ip1][0] < (2 * ts)) or ips[ip1][1] >= start_time:
            if ip1 not in new_ips:
                new_ips[ip1] = (ts, ty, th)

    data = Data_set(None, None, None)
    data.set_keys(['IP address', 'Count', 'Types', 'Hosts'])
    for ip2 in new_ips:
        data.add_data_row({
            'ip_address': ip2,
            'count': new_ips[ip2][0],
            'types': new_ips[ip2][1],
            'hosts': new_ips[ip2][2]}
        )
    return data


def get_apache_urls_data(mask: Dict[str, Any], search: str) -> Data_set:
    search_q = get_search_mask_apache(search)
    col = get_mongo_connection()
    res = col.aggregate(
        [{"$match": {"$and": [{"name": "apache_access"}, mask, search_q]}},
         {"$group": {
             "_id": {"path": "$path", "code": "$code"},
             'hosts': {"$addToSet": "$hostname"},
             "total": {"$sum": 1}}},
         {"$sort": {"total": -1}}
         ])
    data = Data_set(None, None, None)
    data.set_keys(['Path', 'Code', 'Count', 'Hosts'])
    for x in res:
        row = {
            'path': x['_id']['path'],
            'code': x['_id']['code'],
            'count': x['total'],
            'hosts': ",".join(sorted(x['hosts']))
        }
        data.add_data_row(row)
    return data


def get_apache_time_ips_data(mask: Dict[str, Any], search: str, raw: bool,
                             intervals: List[Union[int, str, Tuple[int, int]]], time_mask: str) -> Data_set:
    local_tz = str(tzlocal.get_localzone())
    search_q = get_search_mask_apache(search)
    col: pymongo.collection.Collection = get_mongo_connection()
    orig_time_mask = time_mask.capitalize()
    if time_mask == 'day':
        time_mask = 'dayOfMonth'
    res = col.aggregate([
        {"$match": {"$and": [{"name": "apache_access"}, mask, search_q]}},
        {"$group": {
            "_id": {"time": {"$" + time_mask: {"date": "$timestamp", "timezone": local_tz}},
                    "month": {"$month": {"date": "$timestamp", "timezone": local_tz}},
                    "ip_address": "$ip_address"},
            "total": {"$sum": 1},
            "codes": {"$addToSet": "$code"},
            'hosts': {"$addToSet": "$hostname"},
            'hour': {"$addToSet": {"$hour": {"date": "$timestamp", "timezone": local_tz}}},
            # 'month': {"$addToSet": {"$month": {"date": "$timestamp", "timezone": local_tz}}}
        }},
        {"$sort": {'_id.month': 1, '_id.time': 1, 'total': -1}}])

    data = Data_set('ip_address', 'time', 'total')
    data.set_keys([orig_time_mask, 'IP Address', 'Total', 'Codes', 'Hosts'])
    if raw:
        data.prepare_time_output(time_mask, intervals, {'time': None, 'ip_address': "", 'total': 0, 'codes': ""})
    for x in res:
        time_str = format_time(time_mask, x['_id']['month'], x['hour'][0], x['_id']['time'])
        row = {
            'time': time_str,
            'ip_address': x['_id']['ip_address'],
            'total': x['total'],
            'codes': ", ".join(sorted(x['codes'])),
            'hosts': ",".join(sorted(x['hosts']))
        }
        data.add_data_row(row)
    return data


def get_apache_time_urls_data(mask: Dict[str, Any], search: str, raw: bool,
                              intervals: List[Union[int, str, Tuple[int, int]]], time_mask: str) -> Data_set:
    local_tz = str(tzlocal.get_localzone())
    search_q = get_search_mask_apache(search)
    col = get_mongo_connection()
    if time_mask == 'day':
        time_mask = 'dayOfMonth'
    res = col.aggregate([
        {"$match": {"$and": [{"name": "apache_access"}, mask, search_q]}},
        {"$group": {
            "_id": {"time": {"$" + time_mask: {"date": "$timestamp", "timezone": local_tz}},
                    "month": {"$month": {"date": "$timestamp", "timezone": local_tz}},
                    "path": "$path"},
            "total": {"$sum": 1},
            'hosts': {"$addToSet": "$hostname"},
            "ips": {"$addToSet": "$ip_address"},
            'hour': {"$addToSet": {"$hour": {"date": "$timestamp", "timezone": local_tz}}},
            # 'month': {"$addToSet": {"$month": {"date": "$timestamp", "timezone": local_tz}}}
        }},
        {"$sort": {'_id.month': 1, '_id.time': 1, 'total': -1}}])
    data = Data_set('path', 'time', 'total')
    data.set_keys([time_mask, 'Path', 'Total', 'IPs', 'Hosts'])
    if raw:
        data.prepare_time_output(time_mask, intervals, {'time': None, 'path': "", 'total': 0, 'ips': ""})
    for x in res:
        time_str = format_time(time_mask, x['_id']['month'], x['hour'][0], x['_id']['time'])
        row = {
            'time': time_str,
            'path': x['_id']['path'],
            'total': x['total'],
            'ips': ", ".join(x['ips']),
            'hosts': ",".join(sorted(x['hosts']))
        }
        data.add_data_row(row)
    return data


def get_apache_size_ip_data(mask: Dict[str, Any], search: str, name: str, raw: bool) -> Data_set:
    search_q = get_search_mask_apache(search)
    col = get_mongo_connection()
    res = col.aggregate(
        [{"$match": {"$and": [{"name": "apache_access"}, mask, search_q]}},
         {"$group": {
             "_id": {"ip_address": "$ip_address"},
             'hosts': {"$addToSet": "$hostname"},
             "total": {"$sum": "$size"}}},
         {"$sort": {"total": -1}}
         ])
    data = Data_set('prefix' if name == 'size_prefix' else 'ip_address', None, 'size')
    for x in res:
        row = {
            'ip_address': x['_id']['ip_address'],
            'size': x['total'],
            'hosts': ",".join(sorted(x['hosts']))
        }
        data.add_data_row(row)
    if name == 'size_prefix':
        data.set_keys(['IP Prefixes', 'Size', 'Hosts'])
        data.merge_prefixes(['size'], [])
    else:
        data.set_keys(['IP Addresses', 'Size', 'Hosts'])
    if not raw:
        data.format_size('size')
    return data


def get_apache_size_user_data(mask: Dict[str, Any], search: str, raw: bool) -> Data_set:
    search_q = get_search_mask_apache(search)
    col = get_mongo_connection()
    res = col.aggregate(
        [{"$match": {"$and": [{"name": "apache_access"}, mask, search_q]}},
         {"$group": {
             "_id": {"username": "$username"},
             'hosts': {"$addToSet": "$hostname"},
             "total": {"$sum": "$size"}}},
         {"$sort": {"total": -1}}
         ])
    data = Data_set('username', None, 'size')
    data.set_keys(['Username', 'Size', 'Hosts'])
    for x in res:
        row = {
            'username': x['_id']['username'],
            'size': x['total'],
            'hosts': ",".join(sorted(x['hosts']))
        }
        data.add_data_row(row)
    if not raw:
        data.format_size('size')
    return data


def get_apache_data(name: str, period: str, search: str, raw: bool, to_time: Optional[str] = None,
                    from_time: Optional[str] = None, host: str = "*") -> Data_set:
    local_tz: str = str(tzlocal.get_localzone())
    mask_range = get_period_mask(period, to_time, from_time, pytz.timezone(local_tz))
    time_mask: str = mask_range[2]
    intervals = mask_range[3]
    mask: Dict[str, Any] = {"$and": [{"timestamp": {"$gte": mask_range[0]}}, {"timestamp": {"$lte": mask_range[1]}}]}
    if host not in ["*", '']:
        mask['$and'].append({"hostname": {"$regex": host, "$options": "i"}})
    if name == 'codes':
        data = get_apache_codes_data(mask, search)
    elif name == 'method':
        data = get_apache_methods_data(mask, search)
    elif name == 'protocol':
        data = get_apache_protocols_data(mask, search)
    elif name == 'ip_addresses' or name == 'ip_prefixes':
        data = get_apache_ips_data(mask, search, name)
    elif name == 'new_ips':
        data = get_apache_new_ips_data(mask, search, mask_range[0])
    elif name == 'urls':
        data = get_apache_urls_data(mask, search)
    elif name == 'time_ips':
        data = get_apache_time_ips_data(mask, search, raw, intervals, time_mask)
    elif name == 'time_urls':
        data = get_apache_time_urls_data(mask, search, raw, intervals, time_mask)
    elif name == "size_ip" or name == 'size_prefix':
        data = get_apache_size_ip_data(mask, search, name, raw)
    elif name == "size_user":
        data = get_apache_size_user_data(mask, search, raw)
    else:
        raise ValueError("Invalid item: {}".format(name))
    return data


def get_flag(ip_address: str) -> str:
    try:
        return geoip2_db.country(ip_address).country.iso_code.lower()
    except (AttributeError, ValueError, geoip2.errors.AddressNotFoundError):
        return ''


@app.route('/data/', methods=['POST'])
def load_data() -> Tuple[str, int, Dict[str, str]]:
    name: str = request.json.get('name', '').strip()
    rtype: str = request.json.get('type', '').strip()
    period: str = request.json.get('period', '').strip()
    search: str = request.json.get('search', '').strip()
    to_time: str = request.json.get("to", '')
    from_time: str = request.json.get("from", '')
    host: str = request.json.get("host", '').strip()
    raw: bool = request.json.get('raw', False)
    if rtype == 'ssh':
        data: Data_set = get_ssh_data(name, period, search, raw, to_time, from_time, host)
    elif rtype == 'apache':
        data = get_apache_data(name, period, search, raw, to_time, from_time, host)
    else:
        raise ValueError("Unknown type: {}".format(rtype))
    if raw:
        res1 = data.raw_data
        keys: List[str] = data.raw_keys
        if keys != [] and keys[0] in res1 and type(res1[keys[0]]) == dict:
            fields = list(res1[keys[0]].keys())
            res2 = [[y for y in x.values()] for x in res1.values()]
        else:
            fields = keys
            res2 = [[x for x in res1.values()]]
        return json.dumps({'success': True, "data": res2, "labels": keys, "fields": fields}), 200, {
            'ContentType': 'application/json'}
    else:
        res3: List[Dict[str, str]] = []
        keys = data.keys
        flags: Dict[str, str] = {}
        res = data.data
        for x in res:
            for k, v in x.items():
                v = str(v)
                if k == 'ip_address' and v not in flags:
                    flags[v] = get_flag(v)
            # Force every thing to string so we can truncate stuff in the template
            res3.append({k: str(v) for k, v in x.items()})

        rhtml = render_template("data_table.html", data=res3, keys=keys, flags=flags)
        return json.dumps({'success': True, 'rhtml': rhtml}), 200, {'ContentType': 'application/json'}


def get_hosts() -> List[str]:
    col = get_mongo_connection()
    res = col.distinct("hostname")
    return list(set([x.lower() for x in res]))


@app.route('/hosts/', methods=['POST'])
def hosts() -> Tuple[str, int, Dict[str, str]]:
    try:
        selected = request.json.get('selected', '').strip()
        hostnames = get_hosts()
        html = render_template('hosts_list.html', hosts=hostnames, selected=selected)
        return json.dumps({'success': True, 'html': html}), 200, {'ContentType': 'application/json'}
    except Exception as e:
        return json.dumps({'success': False, "message": str(e)}), 200, {'ContentType': 'application/json'}


def modify_enable_types(cookie_val):
    global enabled_data_types
    if cookie_val is not None:
        cookie_val = json.loads(cookie_val)
        for item in dashboard_data_types:
            if item in cookie_val and item in enabled_data_types:
                enabled_data_types[item] = cookie_val[item]


@app.route('/set_item/', methods=['PUT'])
def set_item():
    cookie_val = request.cookies.get('dashboard_selects', None)
    modify_enable_types(cookie_val)
    item = request.json.get('item', '').strip()
    value = request.json.get('value', None)
    resp = make_response(('ok', 200, {'ContentType': 'application/json'}))
    if item != '' and value is not None and item in enabled_data_types:
        enabled_data_types[item] = value
        resp.set_cookie('dashboard_selects', json.dumps(enabled_data_types))
    return resp


@app.route('/dashboard/')
def dashboard() -> Tuple[str, int, Dict[str, str]]:
    try:
        cookie_val = request.cookies.get('dashboard_selects', None)
        modify_enable_types(cookie_val)
        prog_name = "{} {}".format(PROG_NAME_WEB, VERSION)
        resp = make_response(render_template("dashboard.html", data_types=dashboard_data_types, prog_name=prog_name,
                                             main_data_types=main_data_types, enabled=enabled_data_types,
                                             main_data_titles=main_data_titles), 200,
                             {'ContentType': 'application/json'})
        resp.set_cookie('test', 'test')
        return resp
    except Exception as e:
        return make_response(json.dumps({'success': False, "message": str(e)}), 200,
                             {'ContentType': 'application/json'})


@app.route('/reverse_dns/<item>/', methods=["GET"])
def reverse_dns(item) -> Tuple[str, int, Dict[str, str]]:
    try:
        result = []
        result1 = []
        ipaddress.ip_address(item)
        addr = dns.reversename.from_address(item)
        result = dns.resolver.resolve(addr, 'PTR')
    except ValueError as e:
        try:
            result = dns.resolver.resolve(item, 'A')
            result1 = dns.resolver.resolve(item, 'AAAA')
        except Exception:
            pass
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
        result = ['Not found']
        pass
    data = []
    for res in result:
        data.append(str(res))
    for res in result1:
        data.append(str(res))
    try:
        whois_data = whois.whois(item, True)
        # print(whois_data)
        wd = {
            "name": whois_data.name,
            "registrar": whois_data.registrar,
            "registrar address": whois_data.registrar_address,
            "registrar zip code": whois_data.registrar_zip_code,
            "registrar city": whois_data.registrar_city,
            "registrar country": whois_data.registrant_country,
            "creation date": whois_data.creation_date,
            'expiration data': whois_data.expiration_date,
            'last_updated': whois_data.last_updated,
            'status': whois_data.status,
            "statuses": whois_data.statuses,
            "dnssec": whois_data.dnssec,
            'name_servers': ", ".join(whois_data.name_servers) if whois_data.name_servers is not None else None,
            'emails': ", ".join(whois_data.emails) if whois_data.emails is not None else None,
            "whois_server": whois_data.whois_server,
        }
        wd = {i: wd[i] for i in wd if wd[i] is not None}
    except whois.parser.PywhoisError:
        wd = {}
    except Exception as e:
        print_exc(e)

    return render_template("reverse_dns.html", result=data, item=item, whois_data=wd), 200, {
        'ContentType': 'application/json'}


@app.route('/')
def homepage() -> Tuple[str, int, Dict[str, str]]:
    try:
        prog_name = "{} {}".format(PROG_NAME_WEB, VERSION)
        return render_template("main.html", data_types=main_data_types, prog_name=prog_name), 200, {
            'ContentType': 'application/json'}
    except Exception as e:
        # traceback.print_exc()
        return json.dumps({'success': False, "message": str(e)}), 200, {'ContentType': 'application/json'}


if __name__ == "__main__":
    logging.debug("{} {}".format(PROG_NAME_WEB, VERSION))
    parser = argparse.ArgumentParser(description="Log anaylyser")
    parser.add_argument("-c", '--config', help="Config File Directory", default="", metavar="FILE")
    args = parser.parse_args()
    if args.config:
        config_path = args.config

    app.jinja_env.trim_blocks = True
    app.jinja_env.lstrip_blocks = True
    app.run(host='0.0.0.0', debug=True)
