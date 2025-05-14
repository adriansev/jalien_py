"""alienpy:: Setup logging"""

import os
import sys
import logging

from .global_vars import ALIENPY_FANCY_PRINT, TMPDIR, USER_HOME, rich_print

#############################################
###   ENABLE LOGGING BEFORE ANYTHING ELSE
#############################################

DEBUG = os.getenv('ALIENPY_DEBUG', '')
DEBUG_FILE = os.getenv('ALIENPY_DEBUG_FILE', f'{USER_HOME}/alien_py.log')


def print_out(msg: str, toLog: bool = False) -> None:
    """wrapper for print/log to stdout"""
    if toLog:
        logging.log(90, msg)
    else:
        if ALIENPY_FANCY_PRINT:
            rich_print(msg, flush = True)
        else:
            print(msg, flush = True)


def print_err(msg: str, toLog: bool = False) -> None:
    """wrapper for print/log to stderr"""
    if toLog:
        logging.log(95, msg)
    else:
        if ALIENPY_FANCY_PRINT:
            rich_print(msg, file = sys.stderr, flush = True)
        else:
            print(msg, file = sys.stderr, flush = True)


def setup_logging(debug: bool = False, debug_file:str = f'{USER_HOME}/alien_py.log') -> None:
    """Setup logging machinery"""
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
    if os.getenv('ALIENPY_DEBUG_CONCURRENT'):
        logging.getLogger('concurrent').setLevel(MSG_LVL)
        logging.getLogger('concurrent.futures').setLevel(MSG_LVL)
    if os.getenv('ALIENPY_DEBUG_ASYNCIO'):
        logging.getLogger('asyncio').setLevel(MSG_LVL)
    if os.getenv('ALIENPY_DEBUG_STAGGER'):
        logging.getLogger('async_stagger').setLevel(MSG_LVL)


if __name__ == '__main__':
    print('This file should not be executed!', file = sys.stderr, flush = True)
    sys.exit(95)
