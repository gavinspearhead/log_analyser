import datetime
import ipaddress
import logging
import os
import socket
import dns
import netifaces as ni
from typing import Dict, Optional, Tuple
from functools import lru_cache
import geoip2.database
import geoip2.errors

import log_analyser_version
from filenames import hostnames_file_name
from hostnames import Hostnames

geolite_country_data_filename: str = "html/data/GeoLite2-Country.mmdb"
geolite_asn_data_filename: str = "html/data/GeoLite2-ASN.mmdb"

geoip2_country_db = geoip2.database.Reader(os.path.join(os.path.dirname(__file__), geolite_country_data_filename))
geoip2_asn_db = geoip2.database.Reader(os.path.join(os.path.dirname(__file__), geolite_asn_data_filename))


def get_flag(ip_address: str) -> Tuple[str, str]:
    try:
        country = geoip2_country_db.country(ip_address.strip()).country
        return country.iso_code.lower(), country.name
    except (AttributeError, ValueError, geoip2.errors.AddressNotFoundError):
        return '', ''


def get_own_ip(ip_version: int = 4) -> str:
    interfaces = ni.interfaces()
    address: str = ''

    for i in interfaces:
        if i != "lo":
            try:
                if ip_version == 4:
                    address = ni.ifaddresses(i)[ni.AF_INET][0]['addr']
                elif ip_version == 6:
                    address = ni.ifaddresses(i)[ni.AF_INET6][0]['addr']
                else:
                    logging.debug("Unknown IP version: {}".format(ip_version))
                    raise KeyError("Unknown IP version")
                break
            except KeyError:
                pass
    return address


class DataSet:
    _data = {
        '$fqdn': lambda: socket.getfqdn(),
        '$hostname': lambda: socket.gethostname().lower(),
        '$host_ip': lambda: get_own_ip(4),
        '$host_ipv6': lambda: get_own_ip(6),
        '$time': lambda: datetime.datetime.now().strftime("%H:%M:%S"),
        '$date': lambda: datetime.datetime.now().strftime("%Y:%m:%d"),
        '$isotime': lambda: datetime.datetime.now().isoformat(),
        '$pid': lambda: str(os.getpid()),
        '$version': lambda: log_analyser_version.get_version(),
    }

    def __init__(self):
        pass

    def __getitem__(self, item):
        if item in self._data:
            return self._data[item]()
        else:
            raise IndexError(item)

    def get(self, item, default):
        try:
            return self[item]
        except IndexError:
            return default


def pid_running(pid_filename: str) -> bool:
    try:
        with open(pid_filename, "r") as fn:
            s: int = int(fn.readline().strip())
            if s > 0:
                os.kill(s, 0)
                return True
    except (ValueError, FileNotFoundError, OSError):
        return False
    except PermissionError:
        return True
    return False


def write_pidfile(pid_file: str) -> None:
    with open(pid_file, 'w') as f:
        pid: str = str(os.getpid())
        f.write(pid)


@lru_cache(maxsize=64)
def dns_translate(ip_address: str) -> Optional[str]:
    try:
        config_path: str = os.path.dirname(__file__)
        hostnames = Hostnames(os.path.join(config_path, hostnames_file_name))
        name = hostnames.translate(ip_address)
        if name is not None:
            return name
    except Exception:
        pass

    try:
        return str(dns.resolver.resolve(dns.resolver.resolve_address(ip_address).name, 'ptr', lifetime=3.0).rrset[0])
    except dns.exception.DNSException:
        return None


def get_prefix(ip_address: str) -> Optional[str]:
    local_addresses = ["127.0.0.0/8", "10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12", "fc00::/7", "169.254.0.0/16",
                       "fe80::/10"]
    try:
        r = geoip2_country_db.country(ip_address)
        network_address = ipaddress.ip_interface("{}/{}".format(ip_address, r.traits._prefix_len))
        return str(network_address.network)
    except geoip2.errors.AddressNotFoundError:
        for x in local_addresses:
            if ipaddress.ip_address(ip_address) in ipaddress.ip_network(x):
                return x
        return None


def get_asn_info(item: str) -> Dict[str, str]:
    try:
        asn = geoip2_asn_db.asn(item.strip())
        return {'AS Number': asn.autonomous_system_number, 'AS Organisation': asn.autonomous_system_organization}
    except geoip2.errors.AddressNotFoundError:
        return {}

