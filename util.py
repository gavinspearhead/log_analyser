import logging
import os
import socket
import dns
import netifaces as ni
from typing import Dict, Optional
from functools import lru_cache


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


def load_data_set() -> Dict[str, str]:
    return {
        '$fqdn': socket.getfqdn(),
        '$hostname': socket.gethostname().lower(),
        '$host_ip': get_own_ip(4),
        '$host_ipv6': get_own_ip(6)
    }


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
        return str(dns.resolver.resolve(dns.resolver.resolve_address(ip_address).name, 'ptr', lifetime=3.0).rrset[0])
    except dns.exception.DNSException:
        return None
