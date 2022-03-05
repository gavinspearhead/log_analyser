class LogAnalyserVersion:
    MAJOR_VERSION: int = 0
    MINOR_VERSION: int = 5
    PATCH_NUMBER: int = 0
    PROG_NAME_COLLECTOR: str = "Log Collector"
    PROG_NAME_WEB: str = "Log Analyser"
    AUTHOR: str = "Gavin Spearhead"
    MIN_YEAR: int = 2021
    MAX_YEAR: int = 2022
    LICENCE: str = "GPL 3"

    @property
    def version(self) -> str:
        return "{}.{}.{}".format(self.MAJOR_VERSION, self.MINOR_VERSION, self.PATCH_NUMBER)

    def get_prog_name(self, type_of_program: str) -> str:
        if type_of_program == 'web':
            return "{} {}".format(self.PROG_NAME_WEB, self.version)
        elif type_of_program == 'collector':
            return "{} {}".format(self.PROG_NAME_COLLECTOR, self.version)
        else:
            raise ValueError("Unknown type: {}".format(type_of_program))

    def get_version(self) -> str:
        return self.version

    def get_copyright(self) -> str:
        return "{}-{} (C) {} {}".format(self.MIN_YEAR, self.MAX_YEAR, self.LICENCE, self.AUTHOR)


la = LogAnalyserVersion()
get_version = la.get_version
get_prog_name = la.get_prog_name
get_copyright = la.get_copyright
