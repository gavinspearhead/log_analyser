import os.path
import sys

from typing import List, Dict, Optional, Tuple, Union
from humanfriendly import format_size
from natsort import natsorted
from copy import deepcopy
from collections import OrderedDict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from hostnames import Hostnames
from filenames import hostnames_file_name
from util import get_prefix
from functions import join_str_list


class Data_set:
    def __init__(self, field1: Optional[str] = None, field2: Optional[str] = None,
                 field3: Optional[Union[str, List]] = None):
        config_path: str = os.path.dirname(__file__)
        self.hostnames = Hostnames(os.path.join(config_path, '..', hostnames_file_name))
        self._field1: Optional[str] = field1
        self._field2: Optional[str] = field2
        self._field3: Optional[str] = field3
        self._data: List[Dict[str, Union[int, str]]] = []
        self._keys: List[str] = []
        self._raw_keys: List[str] = []

    def __str__(self):
        return "F1:{}\nF2: {} \nF3: {}\nD: {}\nK: {}\n RK:{}".format(self._field1, self._field2, self._field3,
                                                                     self._data, self._keys, self._raw_keys)

    def set_keys(self, keys: List[str]) -> None:
        self._keys = keys

    @property
    def raw_keys(self) -> List[str]:
        return self._raw_keys

    @property
    def keys(self) -> List[str]:
        return self._keys

    def add_data_row(self, row: Dict[str, Union[int, str]]) -> None:
        self._data.append(row)

    @property
    def raw_data(self) -> Tuple[Dict[str, Dict[str, Union[int, str]]], List[str]]:
        if (self._field1 is None and type(self._field3) != list) or self._field3 is None:
            raise ValueError("Can't get raw data")
        rv, self._raw_keys = self._get_raw_data_internal()
        return rv, self._raw_keys

    @property
    def data(self) -> List[Dict[str, Union[int, str]]]:
        return self._data

    def merge_prefixes(self, sum_list: List[str], join_list: List[str], hash_list: Optional[List[str]] = None,
                       sort_by=None) -> None:
        rv2: Dict[str, Dict[str, Union[str, int]]] = {}

        for x in self._data:
            prefix: Optional[str] = get_prefix(str(x['ip_address']))
            if prefix is None:
                prefix = str(x['ip_address'])
            key = prefix
            if hash_list is not None:
                key = str(prefix) + str(hash(str([x[y] for y in hash_list])))
            if key in rv2:
                for z in sum_list:
                    rv2[key][z] += x[z]
                for y in join_list:
                    rv2[key][y] = join_str_list(rv2[key][y], x[y])
            else:
                rv2[key] = {}
                rv2[key]['prefix'] = prefix
                rv2[key].update(x)
                del rv2[key]['ip_address']
        self._data = list(rv2.values())
        if sort_by is not None:
            self._data.sort(key=lambda r: r[sort_by], reverse=True)

    def format_size(self, field: str) -> None:
        for x in self._data:
            if field in x:
                x['_unformatted_' + field] = x[field]
                x[field] = format_size(x[field])

    def prepare_time_output(self, time_mask: str, intervals: List[Union[int, str, Tuple[int, int]]],
                            template: Dict[str, Union[Optional[str], int]]) -> None:
        for i in intervals:
            if type(i) == int or type(i) == str:
                t: str = '{}'.format(i)
            elif type(i) == tuple:
                if time_mask == 'minute':
                    f_str = "{:02}:{:02}"
                elif time_mask == 'dayOfMonth' or time_mask == 'week':
                    f_str = "{:02}-{:02}"
                else:
                    f_str = "{}{}"
                t = f_str.format(i[0], i[1])
            else:
                raise TypeError('invalid time value')
            template['time'] = t

            self._data.append(deepcopy(template))

    def _map_hostname(self, ip_address: str) -> str:
        # translate the ip addresses to hostnames
        hn: str = self.hostnames.translate(ip_address)
        if hn is not None:
            return "{} ({})".format(hn, ip_address)
        else:
            return ip_address

    def _map_ip_addresses_to_hostname(self, values):
        values = [self._map_hostname(x) for x in values]
        return values

    def _get_raw_data_internal(self) -> Tuple[Dict[str, Dict[str, Union[str, int]]], List[str]]:
        # this function is still crap... needs rewrite
        for item in self._data:
            if 'ip_address' in item:
                item['ip_address'] = self._map_hostname(item['ip_address'])
        keys: List[str] = natsorted(list(set([x[self._field1] for x in self._data])))
        data_set: Dict[str, Dict[str, Union[str, int]]] = {}

        if type(self._field3) == list:
            for t in self._field3:
                data_set[t] = {u: 0 for u in keys}
            for item in self._data:
                for field in self._field3:
                    data_set[field][item[self._field1]] = item[field]
            keys = self._field3
        elif self._field2 is not None:
            field2_values: List[str] = list(OrderedDict.fromkeys([x[self._field2] for x in self._data]))
            for t in keys:
                data_set[t] = {u: 0 for u in field2_values}
            for item in self._data:
                data_set[item[self._field1]][item[self._field2]] += item[self._field3]
        else:
            for t in keys:
                data_set[t] = {}
            for item in self._data:
                data_set[item[self._field1]] = item[self._field3]

        return data_set, keys
