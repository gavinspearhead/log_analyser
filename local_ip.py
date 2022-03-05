import ipaddress
import json
import logging
import typing


class Local_Addresses:
    def __init__(self) -> None:
        self._ranges: typing.List[typing.Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = []

    def load_ranges(self, ranges: typing.List[typing.Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]) -> None:
        self._ranges = ranges

    def is_local(self, address: str) -> bool:
        if ipaddress.ip_address(address).is_private:
            return True
        for i in self._ranges:
            if ipaddress.ip_address(address) in i:
                return True
        return False

    def load_local_addresses(self, filename: str) -> None:
        try:
            with open(filename, "r") as infile:
                config = json.load(infile)
            ranges = [ipaddress.ip_network(x) for x in config]
            self.load_ranges(ranges)
        except json.decoder.JSONDecodeError:
            logging.warning("Incorrect JSON file format: {}".format(filename))
            self._ranges = []
        except (FileNotFoundError, PermissionError):
            logging.warning("Cannot find open file: {}".format(filename))


_local_addresses = Local_Addresses()
set_local_address = _local_addresses.load_ranges
is_local_address = _local_addresses.is_local
load_local_address = _local_addresses.load_local_addresses

if __name__ == "__main__":
    x_ranges = map(ipaddress.ip_network, ["192.168.178.0/24", "2001:984:47bf:1::0/64", "127.0.0.0/8"])
    _local_addresses.load_ranges(list(x_ranges))
    print(is_local_address('2001:984:47bf:12:36a3:bf3c:d751:500b'))
