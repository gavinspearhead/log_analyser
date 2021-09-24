import os
import socket
import netifaces as ni


def get_own_ip(ip_version=4):
    interfaces = ni.interfaces()
    address = None
    for i in interfaces:
        if i != "lo":
            try:
                if ip_version == 4:
                    address = ni.ifaddresses(i)[ni.AF_INET][0]['addr']
                elif ip_version == 6:
                    address = ni.ifaddresses(i)[ni.AF_INET6][0]['addr']
                else:
                    raise KeyError
                break
            except KeyError:
                pass
    return address


def load_data_set():
    return {
        '$fqdn': socket.getfqdn(),
        '$hostname': socket.gethostname().lower(),
        '$host_ip': get_own_ip(4),
        '$host_ipv6': get_own_ip(6)
    }


def pid_running(pid_filename):
    try:
        with open(pid_filename, "r") as fn:
            s = int(fn.readline().strip())
            if s > 0:
                os.kill(s, 0)
                return True
    except (ValueError, FileNotFoundError, OSError):
        return False
    except PermissionError:
        return True
    return False
