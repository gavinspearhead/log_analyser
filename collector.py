import argparse
import os
import logging
import local_ip
import traceback

from output import Outputs
from config import Config
from state import State
from notify import Notify
from parsers import RegexParser
from util import pid_running, write_pidfile
from log_analyser_version import get_prog_name, get_copyright
from log_observer import LogObserver
from filenames import config_file_name, state_file_name, output_file_name, notify_file_name, ip_range_file_name, \
    pid_file_name


def main() -> None:
    LOG_LEVEL: int = logging.INFO
    CLEANUP_INTERVAL: int = 60 * 60  # 1 hour
    pid_path: str = '/tmp/'
    config_path: str = ''
    try:
        state_dump_timeout: int = LogObserver.STATE_DUMP_TIMEOUT
        parser = argparse.ArgumentParser(description=get_prog_name('collector') + "\n" + get_copyright())
        parser.add_argument("-v", '--version', help="Print Version information", action='store_true')
        parser.add_argument("-D", '--debug', help="Debug mode", action='store_true')
        parser.add_argument("-c", '--config', help="Config File Directory", default="", metavar="FILE")
        parser.add_argument("-p", '--pid', help="PID File Directory", default="", metavar="FILE")
        parser.add_argument("-d", '--dump_state_timeout', help="Timeout between periods dumping state", type=int,
                            default=LogObserver.STATE_DUMP_TIMEOUT, metavar="SECONDS")
        args = parser.parse_args()
        if args.version:
            print(get_prog_name('collector'))
            print(get_copyright())
            exit(0)
        if args.config:
            config_path = args.config
        if args.dump_state_timeout:
            state_dump_timeout = args.dump_state_timeout
        if args.debug:
            LOG_LEVEL = logging.DEBUG
        if args.pid:
            pid_path = args.pid

        logging.basicConfig(level=LOG_LEVEL)
        logging.info(get_prog_name('collector') + "  --  " + get_copyright())
        pid_file: str = os.path.join(pid_path, pid_file_name)
        config_file: str = os.path.join(config_path, config_file_name)
        state_file: str = os.path.join(config_path, state_file_name)
        output_file: str = os.path.join(config_path, output_file_name)
        notify_file: str = os.path.join(config_path, notify_file_name)
        local_ip_file: str = os.path.join(config_path, ip_range_file_name)

        config = Config()
        state = State()
        output = Outputs()
        notify = Notify()

        notify.parse_notify(notify_file)
        config.parse_config(config_file)
        state.parse_state(state_file)
        output.parse_outputs(output_file)
        local_ip.load_local_address(local_ip_file)

        observer = LogObserver(state_file, CLEANUP_INTERVAL, state_dump_timeout, notify.cleanup)

        if os.path.isfile(pid_file):
            if pid_running(pid_file):
                print("File already running")
                exit()
            else:
                os.unlink(pid_file)
        try:
            for fl in config.get_files():
                pos: int = state.pos(fl)
                inode, dev = state.id(fl)
                filters = config.get_filter(fl)
                log_name: str = config.get_name(fl)
                retention_time: int = config.get_retention(fl)
                output_type = output.get_output(config.get_output(fl))

                output_conn = output.connect(output_type)
                res = []
                for x in filters:
                    res.append(
                        RegexParser(x['regex'], x['emit'], x['transform'], x['notify'], notify, output_conn, log_name))

                observer.add(fl, pos, res, inode, dev, output_conn, log_name, retention_time)

            write_pidfile(pid_file)
            observer.start()
        except KeyboardInterrupt as e:
            logging.debug(e)
        finally:
            logging.debug('Finale')
            observer.stop()
            observer.join()
            observer.flush_output()
            observer.dump_state()
            logging.debug('Removing PID file')
            os.unlink(pid_file)
    except Exception as e:
        traceback.print_exc()
        logging.info(str(e))
        exit(0)


if __name__ == '__main__':
    main()
