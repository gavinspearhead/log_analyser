import json
import logging
from typing import Optional, Dict


class Hostnames:
    def __init__(self, filename: str) -> None:
        self._hostnames: Dict[str, str] = {}
        self.load_hostnames(filename)

    def load_hostnames(self, filename: str) -> None:
        try:
            with open(filename, "r") as infile:
                self._hostnames = json.load(infile)
        except json.decoder.JSONDecodeError:
            logging.warning("Incorrect JSON file format: {}".format(filename))
            self._hostnames = {}
        except (FileNotFoundError, PermissionError):
            logging.warning("Cannot find open file: {}".format(filename))

    def get_hostnames(self) -> Dict[str, str]:
        return self._hostnames

    def translate(self, ip_address: str) -> Optional[str]:
        return self._hostnames.get(ip_address.strip())
