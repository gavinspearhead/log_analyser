import json
from typing import Optional, Dict


class Hostnames:
    def __init__(self, filename: str) -> None:
        self._hostnames: Dict[str, str] = {}
        self.load_hostnames(filename)

    def load_hostnames(self, filename: str) -> None:
        with open(filename, "r") as infile:
            self._hostnames = json.load(infile)

    def get_hostnames(self) -> Dict[str, str]:
        return self._hostnames

    def translate(self, ip_address: str) -> Optional[str]:
        return self._hostnames.get(ip_address)
