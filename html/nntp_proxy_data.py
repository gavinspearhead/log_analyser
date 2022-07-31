import datetime
import logging
import os.path
import re
import sys
import pymongo
import pytz
import tzlocal

from data_set import Data_set
from typing import List, Dict, Any, Optional, Tuple, Union
from functions import match_ip_address, get_mongo_connection, format_time, get_period_mask

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def get_search_mask_nntp(search: str) -> Optional[Dict[str, Any]]:
    s = match_ip_address(search)
    if s is not None:
        return s
    return {"port": {"$regex": re.escape(search)}}


def get_nntp_proxy_new_ips_data(mask: Dict[str, Any], search: str, start_time: datetime.datetime) -> Data_set:
    search_q = get_search_mask_nntp(search)
    col = get_mongo_connection()
    ips: Dict[str, Tuple[int, datetime.date]] = {}
    res = col.aggregate(
        [{"$match": {"$and": [{"name": "nntp_proxy"}]}},
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
        [{"$match": {"$and": [{"name": "nntp_proxy"}, mask, search_q]}},
         {"$group": {
             "_id": {"ip_address": "$ip_address"},
             "total": {"$sum": 1},
             'hosts': {"$addToSet": "$hostname"},
         }},
         {"$sort": {"total": -1}}
         ])
    new_ips: Dict[str, Tuple[int, str, str]] = {}
    for x in res:
        ip1: str = x['_id']['ip_address']
        ts: int = x['total']
        th: str = ", ".join(sorted(x['hosts']))
        if ip1 not in ips or (ips[ip1][0] < (2 * ts)) or ips[ip1][1] >= start_time:
            if ip1 not in new_ips:
                new_ips[ip1] = (ts, '', th)

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


def get_nntp_proxy_time_ips_data(mask: Dict[str, Any], search: str, raw: bool,
                                 intervals: List[Union[int, str, Tuple[int, int]]], time_mask: str) -> Data_set:
    local_tz = str(tzlocal.get_localzone())
    search_q = get_search_mask_nntp(search)
    col: pymongo.collection.Collection = get_mongo_connection()
    orig_time_mask = time_mask.capitalize()
    if time_mask == 'day':
        time_mask = 'dayOfMonth'
    res = col.aggregate([
        {"$match": {"$and": [{"name": "nntp_proxy"}, mask, search_q]}},
        {"$group": {
            "_id": {"time": {"$" + time_mask: {"date": "$timestamp", "timezone": local_tz}},
                    "month": {"$month": {"date": "$timestamp", "timezone": local_tz}},
                    "ip_address": "$ip_address"},
            "total": {"$sum": 1},
            'hosts': {"$addToSet": "$hostname"},
            'hour': {"$addToSet": {"$hour": {"date": "$timestamp", "timezone": local_tz}}},
            # 'month': {"$addToSet": {"$month": {"date": "$timestamp", "timezone": local_tz}}}
        }},
        {"$sort": {'_id.month': 1, '_id.time': 1, 'total': -1}}])

    data = Data_set('ip_address', 'time', 'total')
    data.set_keys([orig_time_mask, 'IP Address', 'Total', 'Hosts'])
    if raw:
        data.prepare_time_output(time_mask, intervals, {'time': None, 'ip_address': "", 'total': 0})
    for x in res:
        time_str = format_time(time_mask, x['_id']['month'], x['hour'][0], x['_id']['time'])
        row = {
            'time': time_str,
            'ip_address': x['_id']['ip_address'],
            'total': x['total'],
            'hosts': ", ".join(sorted(x['hosts']))
        }
        data.add_data_row(row)
    return data


def get_nntp_proxy_ips_data(mask: Dict[str, Any], search: str, name: str) -> Data_set:
    search_q = get_search_mask_nntp(search)
    col = get_mongo_connection()
    res = col.aggregate(
        [{"$match": {"$and": [{"name": "nntp_proxy"}, mask, search_q]}},
         {"$group": {"_id": "$ip_address", "total": {"$sum": 1},
                     'hosts': {"$addToSet": "$hostname"},
                     'ports': {"$addToSet": "$port"},
                     'dest_ports': {"$addToSet": "$dest_port"},
                     }},
         {"$sort": {"total": -1}}
         ])
    data = Data_set('prefix' if name == 'ip_prefixes' else 'ip_address', None, 'count')
    if name == 'ip_addresses':
        data.set_keys(['IP Address', 'Count', 'Hosts', 'Ports', 'Destination Ports'])
    else:
        data.set_keys(['IP Prefix', 'Count', "Hosts", 'Ports', "Destination Ports"])

    for x in res:
        logging.error(x)
        row = {
            'ip_address': x['_id'],
            'count': x['total'],
            'hosts': ", ".join(sorted(x['hosts'])),
            'ports': ", ".join(sorted([str(y) for y in x['ports']])),
            'dest_ports': ", ".join((sorted([str(y) for y in x['dest_ports']])))
        }
        data.add_data_row(row)
    if name == 'ip_prefixes':
        data.merge_prefixes(['count'], ['users', 'codes', 'hosts', 'port', 'dest_ports'])
    return data


def get_nntp_proxy_size_ip_data(mask: Dict[str, Any], search: str, name: str, raw: bool) -> Data_set:
    search_q = get_search_mask_nntp(search)
    col = get_mongo_connection()
    res = col.aggregate(
        [{"$match": {"$and": [{"name": "nntp_proxy"}, mask, search_q]}},
         {"$group": {
             "_id": {"ip_address": "$ip_address"},
             'hosts': {"$addToSet": "$hostname"},
             "total_up": {"$sum": "$up_size"},
             "total_down": {"$sum": "$down_size"}}},
         {"$sort": {"total": -1}}
         ])
    data = Data_set('prefix' if name == 'size_prefix' else 'ip_address', None, ['size_up', 'size_down'])
    for x in res:
        row = {
            'ip_address': x['_id']['ip_address'],
            'size_down': x['total_down'],
            'size_up': x['total_up'],
            'hosts': ", ".join(sorted(x['hosts']))
        }
        # print(row)
        data.add_data_row(row)
    if name == 'size_prefix':
        data.set_keys(['IP Prefixes', 'Size Down', 'Size Up', 'Hosts'])
        data.merge_prefixes(['size_up', 'size_down'], [], None, 'size_up')
    else:
        data.set_keys(['IP Addresses', 'Size Down', 'Size Up', 'Hosts'])
    if not raw:
        data.format_size('size_up')
        data.format_size('size_down')
    return data


def get_nntp_proxy_data(name: str, period: str, search: str, raw: bool, to_time: Optional[str] = None,
                        from_time: Optional[str] = None, host: str = "*") -> Data_set:
    local_tz: str = str(tzlocal.get_localzone())
    mask_range = get_period_mask(period, to_time, from_time, pytz.timezone(local_tz))
    time_mask: str = mask_range[2]
    intervals = mask_range[3]
    mask: Dict[str, Any] = {"$and": [{"timestamp": {"$gte": mask_range[0]}}, {"timestamp": {"$lte": mask_range[1]}}]}
    if host not in ["*", '']:
        mask['$and'].append({"hostname": {"$regex": host, "$options": "i"}})
    if name == 'ip_addresses' or name == 'ip_prefixes':
        data = get_nntp_proxy_ips_data(mask, search, name)
    elif name == 'new_ips':
        data = get_nntp_proxy_new_ips_data(mask, search, mask_range[0])
    elif name == 'time_ips':
        data = get_nntp_proxy_time_ips_data(mask, search, raw, intervals, time_mask)
    elif name == 'size_ip':
        data = get_nntp_proxy_size_ip_data(mask, search, name, raw)
    elif name == 'size_prefix':
        data = get_nntp_proxy_size_ip_data(mask, search, name, raw)
    else:
        raise ValueError("Invalid item: {}".format(name))
    return data
