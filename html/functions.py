import datetime
import ipaddress
import os.path
import sys
import dateutil.parser
import pymongo
import pytz
import dns.resolver
import whois

from typing import List, Dict, Any, Optional, Tuple, Union
from filenames import output_file_name
from output import Outputs
from outputters.output_mongo import MongoConnector

# sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def get_period_mask(period: str, to_time: Optional[str] = None, from_time: Optional[str] = None,
                    tz: pytz.BaseTzInfo = pytz.UTC) -> Tuple[datetime.datetime, datetime.datetime, str,
                                                             Union[List[int], List[Tuple[int, int]]]]:
    now = datetime.datetime.now(tz)
    intervals: Union[List[int], List[Tuple[int, int]]] = []
    if period == 'today':
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        today_end = now.replace(hour=23, minute=59, second=59, microsecond=999999)
        intervals = list(range(0, 24))
        return today_start, today_end, 'hour', intervals
    elif period == '24hour':
        today_start = now - datetime.timedelta(hours=23)
        today_end = now

        intervals = list([(today_start + datetime.timedelta(hours=x)).hour for x in range(24)])
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


def get_mongo_connection() -> pymongo.collection.Collection:
    config_path: str = os.path.dirname(__file__)
    output = Outputs()
    output.parse_outputs(os.path.join(config_path, '..', output_file_name))
    config = output.get_output('mongo')
    if config is None:
        raise ValueError("Configuration error: No Mongo configured")
    mc = MongoConnector(config)
    col: pymongo.collection.Collection = mc.get_collection()
    return col


def join_str_list(list1: str, list2: str) -> str:
    a: List[str] = list1.split(',')
    b: List[str] = list2.split(',')
    return ",".join(sorted(list(set(a + b))))


def format_time(time_mask: str, month: int, hour: int, time_val: int) -> str:
    if time_mask == 'dayOfMonth' or time_mask == 'week':
        time_str: str = "{:02}-{:02}".format(month, time_val)
    elif time_mask == 'minute':
        time_str = "{:02}:{:02}".format(hour, time_val)
    else:
        time_str = "{}".format(time_val)
    return time_str


def get_dns_data(item: str) -> List[str]:
    result = []
    result1 = []
    try:
        ipaddress.ip_address(item)
        address = dns.reversename.from_address(item)
        result = dns.resolver.resolve(address, 'PTR')
    except ValueError:
        try:
            result = dns.resolver.resolve(item, 'A')
        except dns.exception.DNSException:
            pass
        result1 = dns.resolver.resolve(item, 'AAAA')
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout, dns.exception.DNSException):
        result = ['Not found']
    data: List[str] = []
    for res in result:
        data.append(str(res))
    for res in result1:
        data.append(str(res))
    return data


def get_whois_data(item: str) -> Dict[str, str]:
    try:
        whois_data = whois.whois(item, True)
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
    except Exception:
        wd = {}
        # print_exc()
    return wd
