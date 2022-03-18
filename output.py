import json
import logging
from typing import List, Dict, Optional, Type

from outputters.output_abstract import AbstractOutput
from outputters.output_ignore import IgnoreOutput
from outputters.output_mongo import MongoOutput
from outputters.output_stdout import StdOutput


class Outputs:
    _outputs_types = {
        'stdout': StdOutput,
        'mongo': MongoOutput,
        'ignore': IgnoreOutput,
        # 'mysql': MysqlOutput,
        # 'sqlite': SqliteOutput,
    }

    def __init__(self) -> None:
        self._outputs: List[Dict[str, str]] = []

    def parse_outputs(self, filename: str) -> None:
        with open(filename, "r") as infile:
            outputs = json.load(infile)
        self._outputs = outputs

    def get_output(self, name: str) -> Optional[Dict[str, str]]:
        for i in self._outputs:
            if i['name'] == name:
                return i
        return None

    def _factory(self, config: Dict[str, str]) -> Type[AbstractOutput]:
        if config['type'] in self._outputs_types:
            return self._outputs_types[config['type']]
        raise NotImplementedError(config['type'])

    def connect(self, output_type: Dict[str, str]) -> AbstractOutput:
        logging.debug("Opening output: {} as {}".format(output_type['name'], output_type['type']))
        output_conn = self._factory(output_type)(output_type)
        output_conn.connect()
        return output_conn
