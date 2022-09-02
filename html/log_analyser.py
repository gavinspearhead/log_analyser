#!/usr/bin/python3
import argparse
import ipaddress
import json
import logging
import os.path
import sys
from datetime import datetime

import pymongo
import pytz
import requests
import tzlocal

from typing import List, Dict, Any, Tuple
from flask import Flask, render_template, request, make_response, Response
from data_set import Data_set
from functions import get_period_mask, get_mongo_connection, get_dns_data, get_whois_data
from util import get_flag, get_asn_info, get_prefix, get_location_info
from ssh_data import get_ssh_data
from apache_data import get_apache_data
from nntp_proxy_data import get_nntp_proxy_data

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from outputters.output_mongo import MongoConnector
from notify import Notify
from hostnames import Hostnames
from log_analyser_version import get_prog_name
from filenames import notify_file_name, hostnames_file_name

config_path: str = os.path.dirname(__file__)
app = Flask(__name__)
hostnames = Hostnames(os.path.join(config_path, '..', hostnames_file_name))


class Dashboard_data_types:
    _dashboard_data_types: Dict[str, Tuple[str, str, str]] = {
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
        "apache_size_time": ("apache", "size_time", "Apache - Volume per time"),
        "nntp_proxy_time_ips": ("nntp_proxy", "time_ips", "NNTP - IP Addresses"),
        "nntp_proxy_size_up_time": ("nntp_proxy", "size_up_time", "NNTP - Volume per time up"),
        "nntp_proxy_size_down_time": ("nntp_proxy", "size_down_time", "NNTP - Volume per time down"),
        "nntp_proxy_size_ip": ("nntp_proxy", "size_ip", "NNTP - Volume per IP"),
        "nntp_proxy_size_prefix": ("nntp_proxy", "size_prefix", "NNTP - Volume per Prefix"),
    }

    def __init__(self) -> None:
        self._enabled_data_types: Dict[str, bool] = {}
        for item in self._dashboard_data_types:
            self._enabled_data_types[item] = True

    def toggle(self, item: str, value: bool) -> None:
        if item in self._enabled_data_types:
            self._enabled_data_types[item] = value
        else:
            raise ValueError("Item does not exist")

    @property
    def data_types(self) -> Dict[str, Tuple[str, str, str]]:
        return self._dashboard_data_types

    @property
    def enabled_data_types(self) -> Dict[str, bool]:
        return self._enabled_data_types


def modify_enable_types(cookie_val: str) -> None:
    if cookie_val is not None:
        cookie_val = json.loads(cookie_val)
        for item in dashboard_data_types.data_types:
            if item in cookie_val and item in dashboard_data_types.enabled_data_types:
                dashboard_data_types.toggle(item, cookie_val[item])


main_data_titles: Dict[str, str] = {
    'ssh': "SSH",
    'apache': 'Apache',
    'nntp_proxy': 'NNTP'
}

main_data_types: Dict[str, Dict[str, Tuple[str, str, str]]] = {
    'ssh': {
        "ssh_users": ("ssh", "users", "Users"),
        "ssh_new_users": ("ssh", "new_users", "New Users"),
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
        "apache_size_time": ("apache", "size_time", "Volume per Time"),
    },
    "nntp_proxy": {
        "nntp_proxy_ip_addresses": ("nntp_proxy", "ip_addresses", "IP Addresses"),
        "nntp_proxy_new_ips": ("nntp_proxy", "new_ips", "New IP Addresses"),
        "nntp_proxy_time_ips": ("nntp_proxy", "time_ips", "IPs per Time"),
        "nntp_proxy_size_ip": ("nntp_proxy", "size_ip", "Volume per IP"),
        "nntp_proxy_size_up_time": ("nntp_proxy", "size_up_time", "Volume Up per Time"),
        "nntp_proxy_size_down_time": ("nntp_proxy", "size_down_time", "Volume Down per Time"),
        "nntp_proxy_size_prefix": ("nntp_proxy", "size_prefix", "Volume per Prefix"),
    }
}


def get_mongo_notifications() -> pymongo.collection.Collection:
    notify = Notify()
    notify_file = os.path.join(os.path.join(config_path, '..', notify_file_name))
    notify.parse_notify(notify_file)
    config = notify.get_notify('mongo')
    if config is None and 'config' in config:
        raise ValueError("Configuration error: No Mongo configured")
    mc = MongoConnector(config['config'])
    col: pymongo.collection.Collection = mc.get_collection()
    return col


@app.route('/data/', methods=['POST'])
def load_data() -> Tuple[str, int, Dict[str, str]]:
    hostnames_list = hostnames.get_hostnames()
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
    elif rtype == 'nntp_proxy':
        data = get_nntp_proxy_data(name, period, search, raw, to_time, from_time, host)
    else:
        raise ValueError("Unknown type: {}".format(rtype))
    if raw:
        res1, keys = data.raw_data
        if keys != [] and keys[0] in res1 and type(res1[keys[0]]) == dict:
            fields = list(res1[keys[0]].keys())
            res2 = [[y for y in x.values()] for x in res1.values()]
        else:
            fields = keys
            res2 = [[x for x in res1.values()]]
        return json.dumps({'success': True, "data": res2, "labels": keys, "fields": fields,
                           "hostnames": hostnames_list}), 200, {'ContentType': 'application/json'}
    else:
        res3: List[Dict[str, str]] = []
        keys = data.keys
        res = data.data
        for x in res:
            # Force every thing to string, so we can truncate stuff in the template
            res3.append({k: str(v) for k, v in x.items()})
        rhtml = render_template("data_table.html", data=res3, keys=keys, hostnames=hostnames_list)
        return json.dumps({'success': True, 'rhtml': rhtml}), 200, {'ContentType': 'application/json'}


def get_hosts_mongo() -> List[str]:
    col = get_mongo_connection()
    res = col.distinct("hostname")
    return list(set([x.lower() for x in res]))


@app.context_processor
def utility_processor():
    def match_prefix(ip: str, prefixes: Dict[str, str]) -> str:
        try:
            for x in prefixes:
                if ipaddress.ip_address(ip.strip()) in ipaddress.ip_network(x.strip()):
                    return prefixes[x]
        except Exception:
            pass
        return ""

    def get_flag_by_ip(ip_address: str):
        return get_flag(ip_address)

    def get_hostname(ip_address: str):
        hostname = hostnames.translate(ip_address)
        if hostname is not None:
            return hostname.strip()
        p = match_prefix(ip_address, hostnames.get_hostnames())
        if p != "":
            return p
        return ip_address

    return dict(match_prefix=match_prefix, get_flag_by_ip=get_flag_by_ip, get_hostname=get_hostname)


@app.route('/hosts/', methods=['POST'])
def hosts() -> Tuple[str, int, Dict[str, str]]:
    try:
        selected = request.json.get('selected', '').strip()
        hostnames_list = get_hosts_mongo()
        html = render_template('hosts_list.html', hosts=hostnames_list, selected=selected)
        return json.dumps({'success': True, 'html': html}), 200, {'ContentType': 'application/json'}
    except Exception as e:
        return json.dumps({'success': False, "message": str(e)}), 200, {'ContentType': 'application/json'}


@app.route('/set_item/', methods=['PUT'])
def set_item() -> Response:
    item = request.json.get('item', '').strip()
    value = request.json.get('value', None)
    resp = make_response(('ok', 200, {'ContentType': 'application/json'}))
    cookie_val = request.cookies.get('dashboard_selects', None)
    modify_enable_types(cookie_val)
    if item != '' and value is not None:
        dashboard_data_types.toggle(item, value)
        resp.set_cookie('dashboard_selects', json.dumps(dashboard_data_types.enabled_data_types))
    return resp


@app.route('/dashboard/')
def dashboard() -> Response:
    try:
        cookie_val = request.cookies.get('dashboard_selects', None)
        modify_enable_types(cookie_val)
        program_name = get_prog_name('web')
        resp = make_response(
            render_template("dashboard.html", data_types=dashboard_data_types.data_types, prog_name=program_name,
                            main_data_types=main_data_types, enabled=dashboard_data_types.enabled_data_types,
                            main_data_titles=main_data_titles), 200,
            {'ContentType': 'application/json'})
        resp.set_cookie('test', 'test')
        return resp
    except Exception as e:
        return make_response(json.dumps({'success': False, "message": str(e)}), 200, {'ContentType': 'application/json'})


@app.route('/passive_dns/<item>/', methods=["GET"])
def passive_dns(item) -> Response:
    try:
        url = "https://api.mnemonic.no/pdns/v3/"
        response = requests.get(url + item)
        dns_data = response.json()
        # print(dns_data)
        if dns_data['responseCode'] != 200:
            raise ValueError(dns_data['messages'][0]['message'])
        for x in dns_data['data']:
            x['createdTimestamp'] = datetime.utcfromtimestamp(x['createdTimestamp'] // 1000).strftime(
                '%Y-%m-%d %H:%M:%S')
            x['lastUpdatedTimestamp'] = datetime.utcfromtimestamp(x['lastUpdatedTimestamp'] // 1000).strftime(
                '%Y-%m-%d %H:%M:%S')
            x['firstSeenTimestamp'] = datetime.utcfromtimestamp(x['firstSeenTimestamp'] // 1000).strftime(
                '%Y-%m-%d %H:%M:%S')
            x['lastSeenTimestamp'] = datetime.utcfromtimestamp(x['lastSeenTimestamp'] // 1000).strftime(
                '%Y-%m-%d %H:%M:%S')
        rhtml = render_template("passive_dns.html", dns_data=dns_data, item=item)
    except Exception as e:
        return make_response(json.dumps({'success': False, "message": str(e)}), 200, {'ContentType': 'application/json'})
    return make_response(json.dumps({'success': True, 'rhtml': rhtml}), 200, {'ContentType': 'application/json'})


@app.route('/threat_links/<item>/', methods=["GET"])
def threat_links(item) -> Response:
    rhtml = render_template("threat_links.html", item=item)
    return make_response(json.dumps({'success': True, 'rhtml': rhtml}), 200, {'ContentType': 'application/json'})


@app.route('/whois/<item>/', methods=["GET"])
def whois(item) -> Response:
    item = item.strip()
    whois_data = get_whois_data(item)
    # print(whois_data)
    rhtml = render_template("whois.html",  item=item, whois_data=whois_data)
    return make_response(json.dumps({'success': True, 'rhtml': rhtml}), 200, {'ContentType': 'application/json'})


@app.route('/asn/<item>/', methods=["GET"])
def asn(item) -> Response:
    item = item.strip()
    asn_data = get_asn_info(item)
    location = get_location_info(item)
    prefix = get_prefix(item)
    if prefix:
        asn_data['Prefix'] = prefix
    rhtml = render_template("asn.html",  item=item,  location=location, asn_data=asn_data)
    return make_response(json.dumps({'success': True, 'rhtml': rhtml}), 200, {'ContentType': 'application/json'})


@app.route('/reverse_dns/<item>/', methods=["GET"])
def reverse_dns(item) -> Response:
    item = item.strip()
    dns_data = get_dns_data(item)

    # print(location)
    rhtml = render_template("reverse_dns.html", dns_data=dns_data, item=item)
    return make_response(json.dumps({'success': True, 'rhtml': rhtml}), 200, {'ContentType': 'application/json'})


@app.route('/notifications_count/', methods=['POST'])
def notifications_count() -> Tuple[str, int, Dict[str, str]]:
    try:
        col = get_mongo_notifications()
        period: str = request.json.get("period", '')
        to_time: str = request.json.get("to", '')
        from_time: str = request.json.get("from", '')
        local_tz: str = str(tzlocal.get_localzone())
        mask_range = get_period_mask(period, to_time, from_time, pytz.timezone(local_tz))
        results = {}
        for data_type in ['ssh', 'apache', 'nntp_proxy']:
            if data_type == 'apache':
                type_mask = {"name": "apache_access"}
            elif data_type == 'ssh':
                type_mask = {"name": "auth_ssh"}
            elif data_type == 'nntp_proxy':
                type_mask = {"name": "nntp_proxy"}
            else:
                raise ValueError("Unknown data type: {}".format(data_type))
            mask: Dict[str, Any] = {
                "$and": [{"timestamp": {"$gte": mask_range[0]}}, {"timestamp": {"$lte": mask_range[1]}}, type_mask]}
            res = col.count_documents(mask)
            results[data_type] = res
        return json.dumps({'success': True, 'counts': results}), 200, {'ContentType': 'application/json'}

    except Exception as e:
        # traceback.print_exc()
        return json.dumps({'success': False, "message": str(e)}), 200, {'ContentType': 'application/json'}


@app.route('/notifications_data/', methods=['POST'])
def notifications_data() -> Tuple[str, int, Dict[str, str]]:
    try:
        prog_name: str = get_prog_name('web')
        col = get_mongo_notifications()
        period: str = request.json.get("period", '')
        req_type: str = request.json.get("type", '')
        to_time: str = request.json.get("to", '')
        from_time: str = request.json.get("from", '')
        local_tz: str = str(tzlocal.get_localzone())

        mask_range = get_period_mask(period, to_time, from_time, pytz.timezone(local_tz))
        if req_type == 'ssh':
            keys = ['host', 'hostname', 'timestamp', 'username', 'access', 'ip_address', 'port', 'protocol', 'type',
                    'remote_host']
            names = {'host': "Host", 'hostname': 'Hostname', 'timestamp': "Time", 'username': 'User',
                     'access': "Access", 'ip_address': "IP Address", 'port': "Port", 'protocol': "Protocol",
                     'type': "Type", 'remote_host': "Remote Host"}
            type_mask = {"name": "auth_ssh"}
            title_type = "SSH"
        elif req_type == 'apache':
            keys = ['hostname', 'ip_address', 'username', 'timestamp', 'http_command', 'path', 'protocol',
                    'protocol_version', 'code', 'size', 'remote_host']
            names = {'hostname': "Hostname", 'ip_address': "IP Address", 'username': "User", 'timestamp': "Time",
                     'http_command': "Command", 'path': "Path", 'protocol': "Protocol", 'protocol_version': "Version",
                     'code': "Code", 'size': "Size", 'remote_host': "Remote Host"}
            type_mask = {"name": "apache_access"}
            title_type = "Apache"
        elif req_type == 'nntp_proxy':
            keys = ['hostname', 'ip_address', 'dest_address', 'timestamp', 'port', 'dest_port', 'status']
            names = {'hostname': "Hostname", 'ip_address': "IP Address", 'dest_address': "Destination",
                     'timestamp': "Time", 'port': "Port", 'dest_port': "Destination Port", 'status': "Status"}
            type_mask = {"name": "nntp_proxy"}
            title_type = "NNTP"
        else:
            raise ValueError("Unknown type")
        mask: Dict[str, Any] = {
            "$and": [{"timestamp": {"$gte": mask_range[0]}}, {"timestamp": {"$lte": mask_range[1]}}, type_mask]}
        res = col.find(mask)
        data = []
        for i in res:
            local_tz: str = str(tzlocal.get_localzone())
            i['timestamp'] = pytz.timezone('utc').localize(i['timestamp']).astimezone(pytz.timezone(local_tz))
            data.append(i)
        rhtml = render_template("notifications_table.html", keys=keys, data=data, names=names, prog_name=prog_name)
        return json.dumps({'success': True, 'rhtml': rhtml, 'title_type': title_type}), 200, \
               {'ContentType': 'application/json'}
    except Exception as e:
        # traceback.print_exc()
        return json.dumps({'success': False, "message": str(e)}), 200, {'ContentType': 'application/json'}


@app.route('/notifications/')
def notifications() -> Tuple[str, int, Dict[str, str]]:
    try:
        prog_name = get_prog_name('web')
        return render_template("notifications.html", prog_name=prog_name, main_data_types=main_data_types,
                               main_data_titles=main_data_titles), 200, {
                   'ContentType': 'application/json'}
    except Exception as e:
        # traceback.print_exc()
        return json.dumps({'success': False, "message": str(e)}), 200, {'ContentType': 'application/json'}


@app.route('/')
def homepage() -> Tuple[str, int, Dict[str, str]]:
    try:
        prog_name = get_prog_name('web')
        return render_template("main.html", main_data_types=main_data_types, main_data_titles=main_data_titles,
                               prog_name=prog_name), 200, {'ContentType': 'application/json'}
    except Exception as e:
        # traceback.print_exc()
        return json.dumps({'success': False, "message": str(e)}), 200, {'ContentType': 'application/json'}


dashboard_data_types = Dashboard_data_types()


def main() -> None:
    prog_name: str = get_prog_name('web')
    debug: bool = False
    logging.debug(prog_name)
    parser = argparse.ArgumentParser(description="Log Analyser")
    parser.add_argument("-c", '--config', help="Config File Directory", default="", metavar="FILE")
    parser.add_argument("-D", '--debug', help="Debug mode", action='store_true')
    args = parser.parse_args()
    if args.config:
        global config_path
        config_path = args.config
    if args.debug:
        debug = True
    app.jinja_env.trim_blocks = True
    app.jinja_env.lstrip_blocks = True
    app.run(host='0.0.0.0', debug=debug)


if __name__ == "__main__":
    main()
