'''alienpy:: Definitions of global variables'''

import os
import sys
import multiprocessing as mp
from pathlib import Path
import re
import tempfile
from collections import deque

ALIENPY_EXECUTABLE = ''

HAS_TTY = sys.stdout.isatty()
HAS_COLOR = HAS_TTY  # if it has tty then it supports colors

NCPU = int(mp.cpu_count() * 0.8)  # use at most 80% of host CPUs

REGEX_PATTERN_TYPE = type(re.compile('.'))
guid_regex = re.compile('[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}', re.IGNORECASE)  # regex for identification of GUIDs
cmds_split = re.compile(';|\n')  # regex for spliting chained commands
specs_split = re.compile('@|,')  # regex for spliting the specification of cp command
lfn_prefix_re = re.compile('(alien|file){1}(:|/{2})+')  # regex for identification of lfn prefix
ignore_comments_re = re.compile('^\\s*(#|;|//)+', re.MULTILINE)  # identifiy a range of comments
emptyline_re = re.compile('^\\s*$', re.MULTILINE)  # whitespace line

# environment debug variable
JSON_OUT = bool(os.getenv('ALIENPY_JSON'))
JSON_OUT_GLOBAL = JSON_OUT
DEBUG = os.getenv('ALIENPY_DEBUG', '')
DEBUG_FILE = os.getenv('ALIENPY_DEBUG_FILE', f'{Path.home().as_posix()}/alien_py.log')
TIME_CONNECT = os.getenv('ALIENPY_TIMECONNECT', '')
DEBUG_TIMING = os.getenv('ALIENPY_TIMING', '')  # enable really detailed timings in logs

TMPDIR = tempfile.gettempdir()
TOKENCERT_NAME = f'{TMPDIR}/tokencert_{str(os.getuid())}.pem'
TOKENKEY_NAME = f'{TMPDIR}/tokenkey_{str(os.getuid())}.pem'

# global session state;
AlienSessionInfo = {'alienHome': '', 'currentdir': '', 'prevdir': '', 'commandlist': [], 'user': '', 'exitcode': int(-1), 'session_started': False,
                    'cmd2func_map_nowb': dict(), 'cmd2func_map_client': dict(), 'cmd2func_map_srv': dict(), 'templist': list(), 'alias_cache': dict(),
                    'pathq': deque([]), 'show_date': False, 'show_lpwd': False,
                    'use_usercert': False, 'verified_cert': False, 'verified_token': False}


if __name__ == '__main__':
    print('This file should not be executed!', file = sys.stderr, flush = True)
    sys.exit(95)
