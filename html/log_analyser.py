#!/usr/bin/python3
import argparse
import datetime
import json
import os.path
import re
import sys
import pytz
import geoip
import ipaddress

from flask import Flask, render_template, request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from config import Outputs
from output import MongoConnector

output_file_name = "loganalyser.output"
config_path = os.path.dirname(__file__)
app = Flask(__name__)
geoip_db = geoip.open_database('data/GeoLite2-Country.mmdb')


def get_mongo_connection():
    output = Outputs()
    output.parse_outputs(os.path.join(config_path, '..', output_file_name))
    config = output.get_output('mongo')
    mc = MongoConnector(config)
    col = mc.get_collection()
    return col


def get_period_mask(period):
    now = datetime.datetime.now(pytz.UTC)
    if period == 'today':
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        today_end = now.replace(hour=23, minute=59, second=59, microsecond=999999)
        return today_start, today_end, 'hour'
    elif period == 'hour':
        today_start = now - datetime.timedelta(hours=1)
        today_end = now
        return today_start, today_end, 'minute'
    elif period == 'yesterday':
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0) - datetime.timedelta(days=1)
        today_end = now.replace(hour=23, minute=59, second=59, microsecond=0) - datetime.timedelta(days=1)
        return today_start, today_end, 'hour'
    elif period == 'week':
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0) - datetime.timedelta(weeks=1)
        today_end = now.replace(hour=23, minute=59, second=59, microsecond=0)
        return today_start, today_end, 'day'
    elif period == 'month':
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0) - datetime.timedelta(weeks=4)
        today_end = now.replace(hour=23, minute=59, second=59, microsecond=0)
        return today_start, today_end, 'week'
    else:
        raise ValueError("Unknown period {}".format(period))


def get_search_mask_ssh(search):
    try:
        ipaddress.ip_address(search)
        search_q = {"ip_address": search}
    except ValueError:
        search_q = {"username": {"$regex": re.escape(search)}}
        pass
    return search_q


def get_search_mask_apache(search):
    try:
        ipaddress.ip_address(search)
        return {"ip_address": search}
    except ValueError:
        pass
    if search.isnumeric():
        return {"code": search}

    return {"path": {"$regex": re.escape(search)}}


def get_ssh_data(name, period, search):
    col = get_mongo_connection()
    rv = []
    keys = []
    mask_range = get_period_mask(period)
    search_q = get_search_mask_ssh(search)

    time_mask = mask_range[2]
    mask = {"$and": [{"timestamp": {"$gte": mask_range[0]}}, {"timestamp": {"$lte": mask_range[1]}}]}
    if name == 'users':
        keys = ['username', 'type', 'count', 'ips']
        q = [{"$match": {"$and": [{"name": "auth_ssh"}, mask, search_q]}},
             {"$group": {"_id": {"username": "$username", "type": "$type"}, "total": {"$sum": 1},
                         "ips": {"$addToSet": "$ip_address"}}},
             {"$sort": {"total": -1}}
             ]
        print(q)
        res = col.aggregate(q)
        for x in res:
            print(x)
            row = {'username': x['_id']['username'], 'type': x['_id']['type'], 'count': x['total'],
                   'ips': ", ".join(x['ips'])}
            rv.append(row)
    elif name == 'time_users':
        if time_mask == 'day':
            time_mask = 'dayOfMonth'
        res = col.aggregate(
            [{"$match": {"$and": [{"name": "auth_ssh"}, mask, search_q]}},
             {"$group": {"_id": {"username": "$username", "type": "$type", "time": {"$" + time_mask: "$timestamp"}},
                         "total": {"$sum": 1},
                         "ips": {"$addToSet": "$ip_address"},
                         'hour': {"$addToSet": {"$hour": "$timestamp"}},
                         'month': {"$addToSet": {"$month": "$timestamp"}}}},
             {"$sort": {'_id.time': 1, "total": -1}}
             ])

        for x in res:
            extra_time = "-" + str(x['month'][0]) if time_mask == 'dayOfMonth' else ""
            extra_time2 = str(x['hour'][0]) + ":" if time_mask == 'minute' else ""

            keys = [time_mask, 'username', 'type', 'total', 'ips']
            row = {'time': "{} {} {}".format(extra_time2, x['_id']['time'], extra_time),
                   'username': x['_id']['username'],
                   'type': x['_id']['type'], 'total': x['total'], 'ips': ", ".join(x['ips'])}
            rv.append(row)
    elif name == 'time_ips':
        if time_mask == 'day':
            time_mask = 'dayOfMonth'
        res = col.aggregate(
            [{"$match": {"$and": [{"name": "auth_ssh"}, mask, search_q]}},
             {"$group": {"_id": {"ip_address": "$ip_address", "type": "$type", "time": {"$" + time_mask: "$timestamp"}},
                         "total": {"$sum": 1},
                         "usernames": {"$addToSet": "$username"},
                         'hour': {"$addToSet": {"$hour": "$timestamp"}},
                         'month': {"$addToSet": {"$month": "$timestamp"}}}},
             {"$sort": {'_id.time': 1, "total": -1}}
             ])
        for x in res:
            extra_time = "-" + str(x['month'][0]) if time_mask == 'dayOfMonth' else ''
            extra_time2 = str(x['hour'][0]) + ":" if time_mask == 'minute' else ""
            keys = [time_mask, 'IP Addresses', 'type', 'total', 'usernames']
            row = {'time': "{}{} {}".format(extra_time2, x['_id']['time'], extra_time),
                   'ip_address': x['_id']['ip_address'], 'type': x['_id']['type'],
                   'total': x['total'], 'users': ", ".join(x['usernames'])}
            rv.append(row)
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
            print(geoip_db.lookup(ip_addr))
            row = {'ip_address': ip_addr, 'count': x['total'], 'type': x['_id']['type'], 'users': ", ".join(x['users'])}
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
        # print(users)
        res = col.aggregate(
            [{"$match": {"$and": [{"name": "auth_ssh"}, mask, search_q]}},
             {"$group": {
                 "_id": {"username": "$username", "ip_address": "$ip_address"},
                 "total": {"$sum": 1},
                 'types': {"$addToSet": "$type"}}},
             {"$sort": {"total": -1}}
             ])
        new_users = dict()
        # mask_range[0] = pytz.UTC.localize(mask_range[0])
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
        # print('aouea')
        # print(rv)
    else:
        raise ValueError(name)
    return rv, keys


def get_apache_data(name, period, search):
    col = get_mongo_connection()
    rv = []
    keys = []
    mask = get_period_mask(period)
    time_mask = mask[2]
    mask = {"$and": [{"timestamp": {"$gte": mask[0]}}, {"timestamp": {"$lte": mask[1]}}]}
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
    elif name == 'ip_addresses':
        res = col.aggregate(
            [{"$match": {"$and": [{"name": "apache_access"}, mask, search_q]}},
             {"$group": {"_id": "$ip_address", "total": {"$sum": 1}}},
             {"$sort": {"total": -1}}
             ])
        keys = ['ip address', 'count']
        for x in res:
            row = {'code': x['_id'], 'count': x['total']}
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
                "_id": {"time": {"$" + time_mask: "$timestamp"}, "ip_address": "$ip_address"},
                "total": {"$sum": 1},
                "codes": {"$addToSet": "$code"},
                'hour': {"$addToSet": {"$hour": "$timestamp"}},
                'month': {"$addToSet": {"$month": "$timestamp"}}}},
            {"$sort": {'_id.time': 1, 'total': -1}}])
        for x in res:
            extra_time = "-" + str(x['month'][0]) if time_mask == 'dayOfMonth' else ''
            extra_time2 = str(x['hour'][0]) + ":" if time_mask == 'minute' else ""
            keys = [time_mask, 'ip address', 'total', 'codes']
            row = {'time': "{}{} {}".format(extra_time2, x['_id']['time'], extra_time),
                   'ip_address': x['_id']['ip_address'],
                   'total': x['total'], 'codes': ", ".join(x['codes'])}
            rv.append(row)
    elif name == 'time_urls':
        if time_mask == 'day':
            time_mask = 'dayOfMonth'
        res = col.aggregate([
            {"$match": {"$and": [{"name": "apache_access"}, mask, search_q]}},
            {"$group": {
                "_id": {"time": {"$" + time_mask: "$timestamp"}, "path": "$path"},
                "total": {"$sum": 1},
                "ips": {"$addToSet": "$ip_address"},
                'hour': {"$addToSet": {"$hour": "$timestamp"}},
                'month': {"$addToSet": {"$month": "$timestamp"}}}},
            {"$sort": {'_id.time': 1, 'total': -1}}])
        for x in res:
            extra_time = "-" + str(x['month'][0]) if time_mask == 'dayOfMonth' else ''
            extra_time2 = str(x['hour'][0]) + ":" if time_mask == 'minute' else ""
            keys = [time_mask, 'path', 'total', 'ips']
            row = {'time': "{}{} {}".format(extra_time2, x['_id']['time'], extra_time), 'path': x['_id']['path'],
                   'total': x['total'], 'ips': ", ".join(x['ips'])}
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
    else:
        raise ValueError("Invalid item: {}".format(name))
    return rv, keys


@app.route('/data/', methods=['POST'])
def data():
    name = request.json.get('name', '').strip()
    rtype = request.json.get('type', '').strip()
    period = request.json.get('period', '').strip()
    search = request.json.get('search', '').strip()
    print(search)
    if rtype == 'ssh':
        res, keys = get_ssh_data(name, period, search)
    elif rtype == 'apache':
        res, keys = get_apache_data(name, period, search)
    else:
        raise ValueError("Unknown type: {}".format(rtype))
    res2 = []
    flags = dict()
    for x in res:

        for k, v in x.items():
            if k == 'ip_address' and k not in flags:
                try :
                    flag = geoip_db.lookup(v).country.lower()
                    flags[k] = flag
                except AttributeError:
                    flags[k] = ''

        # Force every thing to string so we can truncate stuff in the template
        res2.append({k: str(v) for k, v in x.items()})

    rhtml = render_template("data_table.html", data=res2, keys=keys, flags=flags)
    return json.dumps({'success': True, 'rhtml': rhtml}), 200, {'ContentType': 'application/json'}


@app.route('/')
def homepage():
    try:
        return render_template("main.html")
    except Exception as e:
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
