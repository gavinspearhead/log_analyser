import datetime
import json
import os
import re
import pymongo
import pytz
import tzlocal

from typing import List, Dict, Any, Optional, Tuple, Union
from functions import match_ip_address, get_mongo_connection, format_time, get_period_mask
from data_set import Data_set


class http_codes:
    def __init__(self):
        self.http_codes_filename: str = os.path.join(os.path.join(os.path.dirname(__file__), "data"), 'http_codes.json')
        self.http_codes: List[Dict[str, str]] = []
        with open(self.http_codes_filename) as http_codes_file:
            self.http_codes = json.load(http_codes_file)

    def map_code(self, code: str) -> str:
        for x in self.http_codes:
            if x['code'] == code:
                return x['phrase']
        return ''


def get_search_mask_apache(search: str) -> Dict[str, Any]:
    s = match_ip_address(search)
    if s is not None:
        return s
    if search.isnumeric():
        return {"code": search}
    return {"path": {"$regex": re.escape(search)}}


def get_apache_methods_data(mask: Dict[str, Any], search: str) -> Data_set:
    search_q = get_search_mask_apache(search)
    col = get_mongo_connection()
    res = col.aggregate(
        [{"$match": {"$and": [{"name": "apache_access"}, mask, search_q]}},
         {"$group": {
             "_id": "$http_command",
             "total": {"$sum": 1},
             'ip_addresses': {"$addToSet": "$ip_address"},
             'hosts': {"$addToSet": "$hostname"}}},
         {"$sort": {"total": -1}}
         ])
    data = Data_set('method', None, 'count')
    data.set_keys(['HTTP Method', 'Count', 'IP Addresses', 'Hosts'])
    for x in res:
        row = {
            'method': x['_id'],
            'count': x['total'],
            'ip_addresses': ', '.join(x['ip_addresses']),
            'hosts': ", ".join(x['hosts'])
        }
        data.add_data_row(row)
    return data


def get_apache_codes_data(mask: Dict[str, Any], search: str) -> Data_set:
    search_q = get_search_mask_apache(search)
    http_codes_list = http_codes()

    col = get_mongo_connection()
    res = col.aggregate(
        [{"$match": {"$and": [{"name": "apache_access"}, mask, search_q]}},
         {"$group": {
             "_id": "$code",
             'hosts': {"$addToSet": "$hostname"},
             'ip_addresses': {"$addToSet": "$ip_address"},
             "total": {"$sum": 1}}},
         {"$sort": {"total": -1}}
         ])
    data = Data_set('code', None, 'count')
    data.set_keys(['Code', 'Count', "IP Addresses", 'Hosts'])
    for x in res:
        row = {
            'code': x['_id'],
            '_code_description': http_codes_list.map_code(x['_id']),
            'count': x['total'],
            'ip_addresses': ", ".join(x['ip_addresses']),
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
         {"$group": {
             "_id": "$ip_address",
             "total": {"$sum": 1},
             'usernames': {"$addToSet": "$username"},
             'hosts': {"$addToSet": "$hostname"},
             "codes": {"$addToSet": "$code"}
         }},
         {"$sort": {"total": -1}}
         ])
    data = Data_set('prefix' if name == 'ip_prefixes' else 'ip_address', None, 'count')
    if name == 'ip_addresses':
        data.set_keys(['IP Address', 'Count', 'Users', 'Codes', 'Hosts'])
    else:
        data.set_keys(['IP Prefix', 'Count', 'Users', 'Codes', "Hosts"])

    http_codes_list = http_codes()
    for x in res:
        codes = sorted(x['codes'])
        code_names = [http_codes_list.map_code(code) for code in codes]
        row = {
            'ip_address': x['_id'],
            'count': x['total'],
            'users': ", ".join(sorted(x['usernames'])),
            'codes': ", ".join(codes),
            '_code_descriptions': ", ".join(code_names),
            'hosts': ", ".join(sorted(x['hosts']))
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

    data = Data_set()
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
             'ip_addresses': {"$addToSet": "$ip_address"},
             "total": {"$sum": 1}}},
         {"$sort": {"total": -1}}
         ])
    data = Data_set()
    data.set_keys(['Path', 'Code', 'Count', 'IP Addresses', 'Hosts'])
    for x in res:
        row = {
            'path': x['_id']['path'],
            'code': x['_id']['code'],
            'count': x['total'],
            'ip_addresses': ", ".join(sorted(x['ip_addresses'])),
            'hosts': ", ".join(sorted(x['hosts']))
        }
        data.add_data_row(row)
    return data


def get_apache_time_ips_data(mask: Dict[str, Any], search: str, raw: bool,
                             intervals: List[Union[int, str, Tuple[int, int]]], time_mask: str, name: str) -> Data_set:
    local_tz = str(tzlocal.get_localzone())
    search_q = get_search_mask_apache(search)
    col: pymongo.collection.Collection = get_mongo_connection()
    orig_time_mask = time_mask.capitalize()
    if time_mask == 'day':
        time_mask = 'dayOfMonth'
    res = col.aggregate([
        {"$match": {"$and": [{"name": "apache_access"}, mask, search_q]}},
        {"$group": {
            "_id": {
                "time": {"$" + time_mask: {"date": "$timestamp", "timezone": local_tz}},
                "month": {"$month": {"date": "$timestamp", "timezone": local_tz}},
                "ip_address": "$ip_address"},
            "total": {"$sum": 1},
            "volume": {"$sum": "$size"},
            "codes": {"$addToSet": "$code"},
            'hosts': {"$addToSet": "$hostname"},
            'hour': {"$addToSet": {"$hour": {"date": "$timestamp", "timezone": local_tz}}},
            # 'month': {"$addToSet": {"$month": {"date": "$timestamp", "timezone": local_tz}}}
        }},
        {"$sort": {'_id.month': 1, '_id.time': 1, 'total': -1}}])

    if name == 'size_time':
        data = Data_set('ip_address', 'time', 'volume')
    else:
        data = Data_set('ip_address', 'time', 'total')
    data.set_keys([orig_time_mask, 'IP Address', 'Count', "Volume", 'Codes', 'Hosts'])
    if raw:
        if name == 'size_time':
            data.prepare_time_output(time_mask, intervals, {'time': None, 'ip_address': "", 'volume': 0, 'codes': ""})
        else:
            data.prepare_time_output(time_mask, intervals, {'time': None, 'ip_address': "", 'total': 0, 'codes': ""})
    http_codes_list = http_codes()
    for x in res:
        time_str = format_time(time_mask, x['_id']['month'], x['hour'][0], x['_id']['time'])
        codes = sorted(x['codes'])
        code_names = [http_codes_list.map_code(code) for code in codes]
        row = {
            'time': time_str,
            'ip_address': x['_id']['ip_address'],
            'total': x['total'],
            'volume': x['volume'],
            'codes': ", ".join(sorted(x['codes'])),
            '_code_descriptions': ", ".join(code_names),
            'hosts': ", ".join(sorted(x['hosts']))
        }
        data.add_data_row(row)
    return data


def get_apache_time_urls_data(mask: Dict[str, Any], search: str, raw: bool,
                              intervals: List[Union[int, str, Tuple[int, int]]], time_mask: str) -> Data_set:
    local_tz = str(tzlocal.get_localzone())
    search_q = get_search_mask_apache(search)
    col = get_mongo_connection()
    orig_time_mask = time_mask.capitalize()
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
    data.set_keys([orig_time_mask, 'Path', 'Total', 'IPs', 'Hosts'])
    if raw:
        data.prepare_time_output(time_mask, intervals, {'time': None, 'path': "", 'total': 0, 'ips': ""})
    for x in res:
        time_str = format_time(time_mask, x['_id']['month'], x['hour'][0], x['_id']['time'])
        row = {
            'time': time_str,
            'path': x['_id']['path'],
            'total': x['total'],
            'ips': ", ".join(x['ips']),
            'hosts': ", ".join(sorted(x['hosts']))
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
            'hosts': ", ".join(sorted(x['hosts']))
        }
        data.add_data_row(row)
    if name == 'size_prefix':
        data.set_keys(['IP Prefixes', 'Size', 'Hosts'])
        data.merge_prefixes(['size'], [], None, 'size')
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
            'hosts': ", ".join(sorted(x['hosts']))
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
        data = get_apache_time_ips_data(mask, search, raw, intervals, time_mask, name)
    elif name == 'time_urls':
        data = get_apache_time_urls_data(mask, search, raw, intervals, time_mask)
    elif name == "size_ip" or name == 'size_prefix':
        data = get_apache_size_ip_data(mask, search, name, raw)
    elif name == "size_user":
        data = get_apache_size_user_data(mask, search, raw)
    elif name == "size_time":
        data = get_apache_time_ips_data(mask, search, raw, intervals, time_mask, name)
    else:
        raise ValueError("Invalid item: {}".format(name))
    return data
