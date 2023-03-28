'''alienpy:: GLOBALS'''

import os
import re
import sys
import tempfile
from collections import deque
from pathlib import Path
from .data_structs import *  # nosec PYL-W0614

COLORS = COLORS_COLL()

TMPDIR = tempfile.gettempdir()

HAS_TTY = sys.stdout.isatty()
HAS_COLOR = HAS_TTY  # if it has tty then it supports colors

# environment debug variable
if os.getenv('ALIENPY_JSON'): os.environ['ALIENPY_JSON_OUT_GLOBAL'] = '1'

TIME_CONNECT = os.getenv('ALIENPY_TIMECONNECT', '')
DEBUG_TIMING = os.getenv('ALIENPY_TIMING', '')  # enable really detailed timings in logs

DEBUG = os.getenv('ALIENPY_DEBUG', '')
DEBUG_FILE = os.getenv('ALIENPY_DEBUG_FILE', f'{Path.home().as_posix()}/alien_py.log')

REGEX_PATTERN_TYPE = type(re.compile('.'))
guid_regex = re.compile('[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}', re.IGNORECASE)  # regex for identification of GUIDs
cmds_split = re.compile(';|\n')  # regex for spliting chained commands
specs_split = re.compile('@|,')  # regex for spliting the specification of cp command
lfn_prefix_re = re.compile('(alien|file){1}(:|/{2})+')  # regex for identification of lfn prefix
ignore_comments_re = re.compile('^\\s*(#|;|//)+', re.MULTILINE)  # identifiy a range of comments
emptyline_re = re.compile('^\\s*$', re.MULTILINE)  # whitespace line

# global session state;
AlienSessionInfo = {'alienHome': '', 'currentdir': '', 'prevdir': '', 'commandlist': [], 'user': '', 'exitcode': int(-1), 'session_started': False,
                    'cmd2func_map_nowb': {}, 'cmd2func_map_client': {}, 'cmd2func_map_srv': {}, 'templist': [], 'alias_cache': {},
                    'pathq': deque([]), 'show_date': False, 'show_lpwd': False,
                    'use_usercert': False, 'verified_cert': False, 'verified_token': False}


if __name__ == '__main__':
    print('This file should not be executed!', file = sys.stderr, flush = True)
    sys.exit(95)


