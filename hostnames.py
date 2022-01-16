import json
import typing


class Hostnames:
    def __init__(self, filename) -> None:
        self._hostnames = []
        self.load_hostnames(filename)

    def load_hostnames(self, filename) -> None:
        with open(filename, "r") as infile:
            self._hostnames = json.load(infile)

    def get_hostnames(self):
        return self._hostnames

    def translate(self, ip_address):
        if ip_address in self._hostnames:
            return self._hostnames[ip_address]
        else:
            return None
