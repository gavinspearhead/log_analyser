from abc import ABC


class Config_Checker(ABC):
    OPTIONAL = 1
    MANDATORY = 2

    def __init__(self):
        pass

    @staticmethod
    def config_validate(config_items, config) -> bool:
        if type(config) is list:
            for x in config:
                Config_Checker.config_validate(config_items, x)
        for item in config_items:
            if item not in config:
                if config_items[item] is Config_Checker.OPTIONAL:
                    continue
                elif config_items[item] is Config_Checker.MANDATORY:
                    raise ValueError("Config item {} not found".format(item))
            elif type(config_items[item]) is dict and type(config[item] is dict):
                Config_Checker.config_validate(config_items[item], config[item])
            elif type(config_items[item]) is dict or type(config[item]) is dict:
                # print(type(config_items[item]), type(config[item]))
                raise ValueError("Config item {} incorrect".format(item))
            else:
                continue
            return False
