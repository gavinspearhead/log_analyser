#!/usr/bin/python3
import argparse
import datetime
import json
import os.path
import re
import sys
import traceback
from copy import deepcopy
import tzlocal

import dateutil.parser
import pytz
import geoip
import ipaddress

from natsort import natsorted
from flask import Flask, render_template, request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from config import Outputs
from output import MongoConnector

output_file_name = "loganalyser.output"
config_path = os.path.dirname(__file__)
app = Flask(__name__)
geoip_db = geoip.open_database(os.path.join(os.path.dirname(__file__), 'data/GeoLite2-Country.mmdb'))


def get_mongo_connection():
    output = Outputs()
    output.parse_outputs(os.path.join(config_path, '..', output_file_name))
    config = output.get_output('mongo')
    mc = MongoConnector(config)
    col = mc.get_collection()
    return col


def get_period_mask(period, to_time=None, from_time=None, tz=pytz.UTC):
    now = datetime.datetime.now(tz)
    # print(period)
    if period == 'today':
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        today_end = now.replace(hour=23, minute=59, second=59, microsecond=999999)
        intervals = list(range(0, 24))
        # print(today_start, today_end, 'hour', intervals)
        return today_start, today_end, 'hour', intervals
    elif period == 'hour':
        today_start = now - datetime.timedelta(hours=1)
        today_end = now
        intervals = list([((today_start + datetime.timedelta(minutes=x)).hour,
                           (today_start + datetime.timedelta(minutes=x)).minute) for x in range(60)])
        # print(intervals)
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

        # [(today_start + datetime.timedelta(weeks=x)).day for x in range(31)])
        return today_start, today_end, 'day', intervals
    elif period == 'custom':
        today_start = (dateutil.parser.isoparse(from_time).astimezone(pytz.UTC))
        today_end = (dateutil.parser.isoparse(to_time).astimezone(pytz.UTC))
        t_delta = int((today_end - today_start).total_seconds())
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
                # print(t)
                raise e
            # print(t, intervals)
        elif t_delta <= 28 * 24 * 3600:
            t = t_delta // (3600 * 24 * 28)
            p = 'month'
            intervals = list(
                [(today_start + datetime.timedelta(seconds=3600 * 24 * 28 * x)).isocalendar()[1] for x in range(t)])
        return today_start, today_end, p, intervals
    else:
        raise ValueError("Unknown period {}".format(period))


def match_ip_address(search):
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


def get_search_mask_ssh(search):
    s = match_ip_address(search)
    if s is not None:
        return s
    return {"username": {"$regex": re.escape(search)}}


def get_search_mask_apache(search):
    s = match_ip_address(search)
    if s is not None:
        return s

    if search.isnumeric():
        return {"code": search}

    return {"path": {"$regex": re.escape(search)}}


def get_raw_data(indata, field1, field2, field3):
    field1_values = list(set([x[field1] for x in indata]))
    field1_values = natsorted(field1_values)
    if field2 is not None:
        field2_values = list(set([x[field2] for x in indata]))
        field2_values = natsorted(field2_values)
    data_set = {}
    for t in field1_values:
        data_set[t] = {}
        if field2 is not None:
            for u in field2_values:
                data_set[t][u] = 0
    for x in indata:
        if field2 is not None:
            data_set[x[field1]][x[field2]] += x[field3]
        else:
            data_set[x[field1]] = x[field3]

    rv = data_set
    keys = list(field1_values)
    # print(rv, keys)
    return rv, keys


def prepare_time_output(time_mask, intervals, template):
    rv = []
    # print(time_mask)
    for i in intervals:
        # print(i, type(i))
        if type(i) == int or type(i) == str:
            t = '{}'.format(i)
        else:
            if time_mask == 'minute':
                f_str = "{:02}:{:02}"
            elif time_mask == 'dayOfMonth' or time_mask == 'week':
                f_str = "{:02}-{:02}"
            t = f_str.format(i[0], i[1])
        template['time'] = t
        rv.append(deepcopy(template))
    return rv


def format_time(time_mask, month, hour, time_val):
    if time_mask == 'dayOfMonth' or time_mask == 'week':
        time_str = "{:02}-{:02}".format(month, time_val)
    elif time_mask == 'minute':
        time_str = "{:02}:{:02}".format(hour, time_val)
    else:
        time_str = "{}".format(time_val)
    return time_str


def get_ssh_data(name, period, search, raw=False, to_time=None, from_time=None):
    local_tz = str(tzlocal.get_localzone())
    col = get_mongo_connection()
    rv = []
    keys = []
    mask_range = get_period_mask(period, to_time, from_time, pytz.timezone(local_tz))
    search_q = get_search_mask_ssh(search)
    time_mask = mask_range[2]
    if time_mask == 'day':
        time_mask = 'dayOfMonth'
    intervals = mask_range[3]
    mask = {"$and": [{"timestamp": {"$gte": mask_range[0]}}, {"timestamp": {"$lte": mask_range[1]}}]}
    if name == 'users':
        keys = ['username', 'type', 'count', 'ips']
        q = [{"$match": {"$and": [{"name": "auth_ssh"}, mask, search_q]}},
             {"$group": {"_id": {"username": "$username", "type": "$type"}, "total": {"$sum": 1},
                         "ips": {"$addToSet": "$ip_address"}}},
             {"$sort": {"total": -1}}
             ]
        res = col.aggregate(q)
        for x in res:
            row = {'username': x['_id']['username'], 'type': x['_id']['type'], 'count': x['total'],
                   'ips': ", ".join(x['ips'])}
            rv.append(row)
        if raw:
            rv, keys = get_raw_data(rv, 'type', 'username', 'count')

    elif name == 'time_users':
        res = col.aggregate(
            [{"$match": {"$and": [{"name": "auth_ssh"}, mask, search_q]}},
             {"$group": {"_id": {"username": "$username", "type": "$type",
                                 "time": {"$" + time_mask: {"date": "$timestamp", "timezone": local_tz}},
                                 "month": {"$month": {"date": "$timestamp", "timezone": local_tz}}
                                 },
                         "total": {"$sum": 1},
                         "ips": {"$addToSet": "$ip_address"},
                         'hour': {"$addToSet": {"$hour": {"date": "$timestamp", "timezone": local_tz}}},
                         # 'month': {"$addToSet": {"$month": {"date": "$timestamp", "timezone": local_tz}}}
                         }},
             {"$sort": {'_id.month': 1, '_id.time': 1, "total": -1}}
             ])
        if raw:
            rv = prepare_time_output(time_mask, intervals,
                                     {'time': None, 'username': "", 'type': None, 'total': 0, 'ips': ""})
        for x in res:
            time_str = format_time(time_mask, x['_id']['month'], x['hour'][0], x['_id']['time'])

            keys = [time_mask, 'username', 'type', 'total', 'ips']
            row = {
                "time": time_str,
                'username': x['_id']['username'],
                'type': x['_id']['type'],
                'total': x['total'],
                'ips': ", ".join(x['ips'])}
            rv.append(row)
        if raw:
            rv, keys = get_raw_data(rv, 'username', 'time', 'total')
    elif name == 'time_ips':
        res = col.aggregate(
            [{"$match": {"$and": [{"name": "auth_ssh"}, mask, search_q]}},
             {"$group": {"_id": {"ip_address": "$ip_address", "type": "$type",
                                 "time": {"$" + time_mask: {"date": "$timestamp", "timezone": local_tz}},
                                 "month": {"$month": {"date": "$timestamp", "timezone": local_tz}},
                                 },
                         "total": {"$sum": 1},
                         "usernames": {"$addToSet": "$username"},
                         'hour': {"$addToSet": {"$hour": {"date": "$timestamp", "timezone": local_tz}}},
                         'month': {"$addToSet": {"$month": {"date": "$timestamp", "timezone": local_tz}}}}},
             {"$sort": {'_id.month': 1, '_id.time': 1, "total": -1}}
             ])
        if raw:
            rv = prepare_time_output(time_mask, intervals,
                                     {'time': None, 'ip_address': "", 'type': None, 'total': 0, 'users': ""})
        for x in res:
            time_str = format_time(time_mask, x['_id']['month'], x['hour'][0], x['_id']['time'])
            keys = [time_mask, 'IP Addresses', 'type', 'total', 'usernames']
            row = {
                'time': time_str,
                'ip_address': x['_id']['ip_address'], 'type': x['_id']['type'],
                'total': x['total'], 'users': ", ".join(x['usernames'])}
            rv.append(row)
        if raw:
            rv, keys = get_raw_data(rv, 'ip_address', 'time', 'total')
    elif name == 'ip_addresses':
        keys = ['IP Addresses', 'type', 'count', 'users']
        res = col.aggregate(
            [{"$match": {"$and": [{"name": "auth_ssh"}, mask, search_q]}},
             {"$group": {"_id": {"ip_address": "$ip_address", "type": "$type"}, "total": {"$sum": 1},
                         "users": {"$addToSet": "$username"}}},
             {"$sort": {"total": -1}}
             ])
        for x in res:
            ip_addr = x['_id']['ip_address']
            row = {'ip_address': ip_addr, 'count': x['total'], 'type': x['_id']['type'], 'users': ", ".join(x['users'])}
            rv.append(row)
        if raw:
            rv, keys = get_raw_data(rv, 'type', 'ip_address', 'count')
    elif name == 'new_ips':
        keys = ['ip address', 'count', 'types']
        ips = dict()
        res = col.aggregate(
            [{"$match": {"$and": [{"name": "auth_ssh"}, {"type": "connect"}]}},
             {"$group": {"_id": {"ip_address": "$ip_address"}, "total": {"$sum": 1},
                         "oldest": {"$min": "$timestamp"}}},
             {"$sort": {"total": -1}}
             ])
        for x in res:
            ip = x['_id']['ip_address']
            t = x['total']
            o = pytz.UTC.localize(x['oldest'])
            if ip not in ips:
                ips[ip] = (t, o)
        res = col.aggregate(
            [{"$match": {"$and": [{"name": "auth_ssh"}, {"type": "connect"}, mask, search_q]}},
             {"$group": {
                 "_id": {"ip_address": "$ip_address"},
                 "total": {"$sum": 1},
                 'types': {"$addToSet": "$type"}}},
             {"$sort": {"total": -1}}
             ])
        new_ips = dict()
        for x in res:
            ip = x['_id']['ip_address']
            ts = x['total']
            ty = ", ".join(x['types'])

            if ip not in ips or (ips[ip][0] < (2 * ts)) or ips[ip][1] >= mask_range[0]:
                if ip not in new_ips:
                    new_ips[ip] = (ts, ty)

        for ip in new_ips:
            row = {'ip_address': ip, 'count': new_ips[ip][0], 'types': new_ips[ip][1]}
            rv.append(row)
    elif name == 'new_users':
        keys = ['username', 'ip address', 'count', 'types']
        users = dict()
        res = col.aggregate(
            [{"$match": {"$and": [{"name": "auth_ssh"}, {"type": "connect"}]}},
             {"$group": {"_id": {"username": "$username", "ip_address": "$ip_address"}, "total": {"$sum": 1},
                         "oldest": {"$min": "$timestamp"}}},
             {"$sort": {"total": -1}}
             ])
        for x in res:
            u = x['_id']['username']
            ip = x['_id']['ip_address']
            t = x['total']
            o = pytz.UTC.localize(x['oldest'])
            if u not in users:
                users[u] = dict()
            users[u][ip] = (t, o)
        res = col.aggregate(
            [{"$match": {"$and": [{"name": "auth_ssh"}, {"type": "connect"}, mask, search_q]}},
             {"$group": {
                 "_id": {"username": "$username", "ip_address": "$ip_address"},
                 "total": {"$sum": 1},
                 'types': {"$addToSet": "$type"}}},
             {"$sort": {"total": -1}}
             ])
        new_users = dict()
        for x in res:
            u = x['_id']['username']
            ip = x['_id']['ip_address']
            ts = x['total']
            ty = ", ".join(x['types'])

            if u not in users or ip not in users[u] or (users[u][ip][0] < (2 * ts)) or users[u][ip][1] >= mask_range[0]:
                if u not in new_users:
                    new_users[u] = dict()
                new_users[u][ip] = (ts, ty)

        for u in new_users:
            for ip in new_users[u]:
                row = {'username': u, 'ip_address': ip, 'count': new_users[u][ip][0], 'types': new_users[u][ip][1]}
                rv.append(row)
    else:
        raise ValueError(name)
    return rv, keys


def get_apache_data(name, period, search, raw, to_time=None, from_time=None):
    local_tz = str(tzlocal.get_localzone())
    col = get_mongo_connection()
    rv = []
    keys = []
    mask_range = get_period_mask(period, to_time, from_time, pytz.timezone(local_tz))
    time_mask = mask_range[2]
    if time_mask == 'day':
        time_mask = 'dayOfMonth'
    intervals = mask_range[3]
    mask = {"$and": [{"timestamp": {"$gte": mask_range[0]}}, {"timestamp": {"$lte": mask_range[1]}}]}
    search_q = get_search_mask_apache(search)
    if name == 'codes':
        res = col.aggregate(
            [{"$match": {"$and": [{"name": "apache_access"}, mask, search_q]}},
             {"$group": {"_id": "$code", "total": {"$sum": 1}}},
             {"$sort": {"total": -1}}
             ])
        keys = ['code', 'count']
        for x in res:
            row = {'code': x['_id'], 'count': x['total']}
            rv.append(row)
        if raw:
            rv, keys = get_raw_data(rv, 'code', None, 'count')
    elif name == 'method':
        res = col.aggregate(
            [{"$match": {"$and": [{"name": "apache_access"}, mask, search_q]}},
             {"$group": {"_id": "$http_command", "total": {"$sum": 1}}},
             {"$sort": {"total": -1}}
             ])
        keys = ['HTTP Method', 'count']
        for x in res:
            row = {'method': x['_id'], 'count': x['total']}
            rv.append(row)
        if raw:
            rv, keys = get_raw_data(rv, 'method', None, 'count')
    elif name == 'protocol':
        res = col.aggregate(
            [{"$match": {"$and": [{"name": "apache_access"}, mask, search_q]}},
             {"$group": {"_id": {"protocol": "$protocol", "protocol_version": "$protocol_version"},
                         "total": {"$sum": 1}}},
             {"$sort": {"total": -1}}
             ])
        keys = ['Protocol', 'version', 'count']
        for x in res:
            row = {'protocol': x['_id']['protocol'], 'protocol_version': x['_id']['protocol_version'],
                   'count': x['total']}
            rv.append(row)
        if raw:
            rv, keys = get_raw_data(rv, 'protocol', 'protocol_version', 'count')
    elif name == 'ip_addresses':
        res = col.aggregate(
            [{"$match": {"$and": [{"name": "apache_access"}, mask, search_q]}},
             {"$group": {"_id": "$ip_address", "total": {"$sum": 1},
                         'usernames': {"$addToSet": "$username"}}},
             {"$sort": {"total": -1}}
             ])
        keys = ['ip address', 'count', 'users']
        for x in res:
            row = {'ip_address': x['_id'], 'count': x['total'], 'users': ",".join(x['usernames'])}
            rv.append(row)
        if raw:
            rv, keys = get_raw_data(rv, 'ip_address', None, 'count')
    elif name == 'new_ips':
        keys = ['ip address', 'count', 'types']
        ips = dict()
        res = col.aggregate(
            [{"$match": {"$and": [{"name": "apache_access"}]}},
             {"$group": {"_id": {"ip_address": "$ip_address"}, "total": {"$sum": 1},
                         "oldest": {"$min": "$timestamp"}}},
             {"$sort": {"total": -1}}
             ])
        for x in res:
            ip = x['_id']['ip_address']
            t = x['total']
            o = pytz.UTC.localize(x['oldest'])
            if ip not in ips:
                ips[ip] = (t, o)
        res = col.aggregate(
            [{"$match": {"$and": [{"name": "apache_access"}, mask, search_q]}},
             {"$group": {
                 "_id": {"ip_address": "$ip_address"},
                 "total": {"$sum": 1},
                 'users': {"$addToSet": "$username"}}},
             {"$sort": {"total": -1}}
             ])
        new_ips = dict()
        for x in res:
            ip = x['_id']['ip_address']
            ts = x['total']
            ty = ", ".join(x['users'])
            if ip not in ips or (ips[ip][0] < (2 * ts)) or ips[ip][1] >= mask_range[0]:
                if ip not in new_ips:
                    new_ips[ip] = (ts, ty)

        for ip in new_ips:
            row = {'ip_address': ip, 'count': new_ips[ip][0], 'types': new_ips[ip][1]}
            rv.append(row)

    elif name == 'urls':
        res = col.aggregate(
            [{"$match": {"$and": [{"name": "apache_access"}, mask, search_q]}},
             {"$group": {"_id": {"path": "$path", "code": "$code"}, "total": {"$sum": 1}}},
             {"$sort": {"total": -1}}
             ])
        keys = ['path', 'code', 'count']
        for x in res:
            row = {'path': x['_id']['path'], 'code': x['_id']['code'], 'count': x['total']}
            rv.append(row)
    elif name == 'time_ips':
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
                'hour': {"$addToSet": {"$hour": {"date": "$timestamp", "timezone": local_tz}}},
                # 'month': {"$addToSet": {"$month": {"date": "$timestamp", "timezone": local_tz}}}
                }},
            {"$sort": {'_id.month': 1, '_id.time': 1, 'total': -1}}])
        if raw:
            rv = prepare_time_output(time_mask, intervals, {'time': None, 'ip_address': "", 'total': 0, 'codes': ""})
        for x in res:
            time_str = format_time(time_mask, x['_id']['month'], x['hour'][0], x['_id']['time'])
            keys = [time_mask, 'ip address', 'total', 'codes']
            row = {
                'time': time_str,
                'ip_address': x['_id']['ip_address'],
                'total': x['total'],
                'codes': ", ".join(x['codes'])
            }
            rv.append(row)
        if raw:
            rv, keys = get_raw_data(rv, 'ip_address', 'time', 'total')
    elif name == 'time_urls':
        if time_mask == 'day':
            time_mask = 'dayOfMonth'
        res = col.aggregate([
            {"$match": {"$and": [{"name": "apache_access"}, mask, search_q]}},
            {"$group": {
                "_id": {"time": {"$" + time_mask: {"date": "$timestamp", "timezone": local_tz}},
                        "month": {"$month": {"date": "$timestamp", "timezone": local_tz}},
                        "path": "$path"},
                "total": {"$sum": 1},
                "ips": {"$addToSet": "$ip_address"},
                'hour': {"$addToSet": {"$hour": {"date": "$timestamp", "timezone": local_tz}}},
                # 'month': {"$addToSet": {"$month": {"date": "$timestamp", "timezone": local_tz}}}
            }},
            {"$sort": {'_id.month': 1, '_id.time': 1, 'total': -1}}])
        if raw:
            rv = prepare_time_output(time_mask, intervals, {'time': None, 'path': "", 'total': 0, 'ips': ""})
        for x in res:
            time_str = format_time(time_mask, x['_id']['month'], x['hour'][0], x['_id']['time'])
            keys = [time_mask, 'path', 'total', 'ips']
            row = {
                'time': time_str,
                'path': x['_id']['path'],
                'total': x['total'],
                'ips': ", ".join(x['ips'])}
            rv.append(row)
    elif name == "size_ip":
        res = col.aggregate(
            [{"$match": {"$and": [{"name": "apache_access"}, mask, search_q]}},
             {"$group": {"_id": {"ip_address": "$ip_address"}, "total": {"$sum": "$size"}}},
             {"$sort": {"total": -1}}
             ])
        keys = ['path', 'size']
        for x in res:
            row = {'ip_address': x['_id']['ip_address'], 'size': x['total']}
            rv.append(row)
        if raw:
            rv, keys = get_raw_data(rv, 'ip_address', None, 'size')
    else:
        raise ValueError("Invalid item: {}".format(name))
    return rv, keys


@app.route('/data/', methods=['POST'])
def data():
    name = request.json.get('name', '').strip()
    rtype = request.json.get('type', '').strip()
    period = request.json.get('period', '').strip()
    search = request.json.get('search', '').strip()
    to_time = request.json.get("to", '')
    from_time = request.json.get("from", '')
    # print(from_time)

    raw = request.json.get('raw', False)
    if rtype == 'ssh':
        res, keys = get_ssh_data(name, period, search, raw, to_time, from_time)
    elif rtype == 'apache':
        res, keys = get_apache_data(name, period, search, raw, to_time, from_time)
    else:
        raise ValueError("Unknown type: {}".format(rtype))
    if raw:
        keys = list(res.keys())
        if keys != [] and keys[0] in res and type(res[keys[0]]) == dict:
            fields = list(res[keys[0]].keys())
            res = [[y for y in x.values()] for x in res.values()]
        else:
            fields = keys
            res = [[x for x in res.values()]]
        return json.dumps({'success': True, "data": res, "labels": keys, "fields": fields}), 200, {'ContentType': 'application/json'}
    else:
        res2 = []
        flags = dict()
        for x in res:
            for k, v in x.items():
                if k == 'ip_address' and k not in flags:
                    try:
                        flag = geoip_db.lookup(v).country.lower()
                        flags[v] = flag
                    except (AttributeError, ValueError):
                        # print(v)
                        flags[v] = ''

            # Force every thing to string so we can truncate stuff in the template
            res2.append({k: str(v) for k, v in x.items()})

        rhtml = render_template("data_table.html", data=res2, keys=keys, flags=flags)
        return json.dumps({'success': True, 'rhtml': rhtml}), 200, {'ContentType': 'application/json'}


dashboard_data_types = {
    "ssh_users": ("ssh", "users", "SSH Users"),
    "ssh_time_users": ("ssh", "time_users", "SSH Users Per time"),
    "ssh_time_ips": ("ssh", "time_ips", "SSH IPs per time"),
    "ssh_ipaddresses": ("ssh", "ip_addresses", "SSH IP Addresses"),
    # "ssh_ips": ("ssh", "ip_addresses"),
    "apache_ipaddresses": ("apache", "ip_addresses", "Apache IP addresses"),
    "apache_time_ips": ("apache", "time_ips", "Apache IPs per time"),
    "apache_codes": ("apache", "codes", "Apache Response codes"),
    "apache_method": ("apache", "method", "Apache HTTP methods"),
    "apache_protocol": ("apache", "protocol", "Apache Protocols"),
    "apache_size": ("apache", "size_ip", "Apache Volume per IP"),
}

main_data_types = {
    'ssh': {
        "ssh_users": ("ssh", "users", "Users"),
        "ssh_new_users": ("ssh", "new_users", "SSH New Users"),
        "ssh_time_users": ("ssh", "time_users", "Users Per time"),
        "ssh_time_ips": ("ssh", "time_ips", "IPs per time"),
        "ssh_ipaddresses": ("ssh", "ip_addresses", "IP Addresses"),
        "ssh_new_ips": ("ssh", "new_ips", "New IP Addresses"),
    },
    "apache": {
        # "ssh_ips": ("ssh", "ip_addresses"),
        "apache_ipaddresses": ("apache", "ip_addresses", "IP addresses"),
        "apache_new_ips": ("apache", "ip_addresses", "New IP addresses"),
        "apache_time_ips": ("apache", "time_ips", "IPs per time"),
        "apache_codes": ("apache", "codes", "Response codes"),
        "apache_method": ("apache", "method", "HTTP methods"),
        "apache_protocol": ("apache", "protocol", "Protocols and versions"),
        "apache_urls": ("apache", "urls", "URLs"),
        "apache_time_urls": ("apache", "time_urls", "URLs per time"),
        "apache_size": ("apache", "size_ip", "Volume per IP"),
    }
}


@app.route('/dashboard/')
def dashboard():
    try:
        return render_template("dashboard.html", data_types=dashboard_data_types)
    except Exception as e:
        return json.dumps({'success': False, "message": str(e)}), 200, {'ContentType': 'application/json'}


@app.route('/')
def homepage():
    try:
        return render_template("main.html", data_types=main_data_types)
    except Exception as e:
        traceback.print_exc()
        return json.dumps({'success': False, "message": str(e)}), 200, {'ContentType': 'application/json'}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="RSS update daemon")
    parser.add_argument("-c", '--config', help="Config File Directory", default="", metavar="FILE")
    args = parser.parse_args()
    if args.config:
        config_path = args.config

    app.jinja_env.trim_blocks = True
    app.jinja_env.lstrip_blocks = True
    app.run(host='0.0.0.0', debug=True)
