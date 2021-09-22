import ipaddress
import json


class Local_Addresses:
    def __init__(self):
        self._ranges = []

    def load_ranges(self, ranges):
        self._ranges = ranges

    def is_local(self, address):
        # print(address, self._ranges)
        if ipaddress.ip_address(address).is_private:
            return True
        for i in self._ranges:
            if ipaddress.ip_address(address) in i:
                return True
        return False

    def load_local_addresses(self, filename):
        with open(filename, "r") as infile:
            config = json.load(infile)
        ranges = []
        for x in config:
            ranges.append(ipaddress.ip_network(x))
        self.load_ranges(ranges)


_local_addresses = Local_Addresses()

set_local_address = _local_addresses.load_ranges
is_local_address = _local_addresses.is_local
load_local_address = _local_addresses.load_local_addresses
