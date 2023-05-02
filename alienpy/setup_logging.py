'''alienpy:: Setup logging'''

import os
import sys
import logging
from pathlib import Path
from .global_vars import *  # nosec PYL-W0614


#############################################
###   ENABLE LOGGING BEFORE ANYTHIN ELSE
#############################################
def print_out(msg: str, toLog: bool = False):
    if toLog:
        logging.log(90, msg)
    else:
        print(msg, flush = True)


def print_err(msg: str, toLog: bool = False):
    if toLog:
        logging.log(95, msg)
    else:
        print(msg, file = sys.stderr, flush = True)


def setup_logging(debug: bool = False, debug_file:str = ''):
    """Setup logging machinery"""
    if not debug_file: debug_file = f'{Path.home().as_posix()}/alien_py.log'

    logging.addLevelName(90, 'STDOUT')
    logging.addLevelName(95, 'STDERR')
    
    MSG_LVL = logging.DEBUG if debug else logging.INFO
    line_fmt = '%(levelname)s:%(asctime)s %(message)s'
    file_mode = 'a' if os.getenv('ALIENPY_DEBUG_APPEND', '') else 'w'
    try:
        logging.basicConfig(format = line_fmt, filename = debug_file, filemode = file_mode, level = MSG_LVL)
    except Exception:
        print_err(f'Could not write the log file {debug_file}; falling back to detected tmp dir')
        debug_file = f'{TMPDIR}/{os.path.basename(debug_file)}'
        try:
            logging.basicConfig(format = line_fmt, filename = debug_file, filemode = file_mode, level = MSG_LVL)
        except Exception:
            print_err(f'Could not write the log file {debug_file}')

    logging.getLogger().setLevel(MSG_LVL)
    logging.getLogger('wb_client').setLevel(MSG_LVL)
    if os.getenv('ALIENPY_DEBUG_CONCURENT'):
        logging.getLogger('concurrent').setLevel(MSG_LVL)
        logging.getLogger('concurrent.futures').setLevel(MSG_LVL)
    if os.getenv('ALIENPY_DEBUG_ASYNCIO'):
        logging.getLogger('asyncio').setLevel(MSG_LVL)
    if os.getenv('ALIENPY_DEBUG_STAGGER'):
        logging.getLogger('async_stagger').setLevel(MSG_LVL)


if __name__ == '__main__':
    print('This file should not be executed!', file = sys.stderr, flush = True)
    sys.exit(95)
    
    