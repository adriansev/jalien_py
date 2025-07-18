"""alienpy:: GLOBALS"""

import os
import platform
import re
import requests
import sys
from socket import gethostname
import tempfile
from collections import deque
from pathlib import Path
import uuid

from .version import ALIENPY_VERSION_STR
from .data_structs import COLORS_COLL, CertsInfo

try:
    from rich import print as rich_print
    from rich import print_json as rich_print_json
    from rich.pretty import pprint as rich_pprint
    from rich.console import Console
    # from rich.highlighter import ISO8601Highlighter, JSONHighlighter
except Exception:
    print("rich module could not be imported! Make sure you can do:\npython3 -c 'from rich.pretty import pprint'", file = sys.stderr, flush = True)
    sys.exit(1)

try:
    from websockets.version import version as wb_version
except Exception:
    print("websockets.version module could not be imported! Make sure you can do:\npython3 -c 'from websockets.version import version as wb_version'", file = sys.stderr, flush = True)
    sys.exit(1)


TMPDIR = tempfile.gettempdir()


def get_certs_names() -> CertsInfo:
    """Provide the standard file names for used certificates"""
    usercert = os.getenv('X509_USER_CERT', f'{USER_HOME}/.globus/usercert.pem')
    userkey = os.getenv('X509_USER_KEY', f'{USER_HOME}/.globus/userkey.pem')
    tokencert = os.getenv('JALIEN_TOKEN_CERT', f'{TMPDIR}/tokencert_{str(os.getuid())}.pem')
    tokenkey = os.getenv('JALIEN_TOKEN_KEY', f'{TMPDIR}/tokenkey_{str(os.getuid())}.pem')
    return CertsInfo(usercert, userkey, tokencert, tokenkey)


##################################################
#   GLOBAL POINTER TO WB CONNECTION  #############
ALIENPY_GLOBAL_WB = None
##################################################
##################################################
#   GLOBAL VARS
##################################################

# enable rich pretty printing
ALIENPY_FANCY_PRINT = bool(os.getenv('ALIENPY_FANCY_PRINT'))
RICH_CONSOLE = Console()

ALIENPY_EXECUTABLE = ''

COLORS = COLORS_COLL()  # definition of colors

USER_HOME = Path.home().as_posix()

HOSTNAME = gethostname()

UNAME = platform.uname()
PLATFORM_ID = f'{UNAME.system}-{UNAME.machine}/{UNAME.release}'

ALIEN_JOB_ID = os.getenv('ALIEN_PROC_ID', '')
ALIEN_MASTERJOB_ID = os.getenv('ALIEN_MASTERJOB_ID', '')
I_AM_GRID_JOB = bool(ALIEN_JOB_ID)

session_id = str(uuid.uuid1())

USER = None
try:
    USER = os.getlogin()
except Exception:
    USER = 'unknown'

PYTHON_VERSION = f'{sys.version_info[0]}.{sys.version_info[1]}.{sys.version_info[2]}'
USER_AGENT = f'alienpy/{ALIENPY_VERSION_STR} websockets/{wb_version} Python/{PYTHON_VERSION} platform/{PLATFORM_ID} id/{USER}@{HOSTNAME}'
USER_AGENT_HTTP = f'alienpy/{ALIENPY_VERSION_STR} requests/{requests.__version__} Python/{PYTHON_VERSION} platform/{PLATFORM_ID} id/{USER}@{HOSTNAME} session/{session_id}'

if I_AM_GRID_JOB:
    USER_AGENT = f'{USER_AGENT} jobid/{ALIEN_JOB_ID}'
    USER_AGENT_HTTP = f'{USER_AGENT_HTTP} jobid/{ALIEN_JOB_ID}'
    if ALIEN_MASTERJOB_ID:
        USER_AGENT = f'{USER_AGENT} masterjobid/{ALIEN_MASTERJOB_ID}'
        USER_AGENT_HTTP = f'{USER_AGENT_HTTP} masterjobid/{ALIEN_MASTERJOB_ID}'

CERT_NAMES = get_certs_names()
# Have global variables for certificate file names, defaults being overridden by env vars
USERCERT_NAME = CERT_NAMES.user_cert
USERKEY_NAME = CERT_NAMES.user_key
TOKENCERT_NAME = CERT_NAMES.token_cert
TOKENKEY_NAME = CERT_NAMES.token_key

HAS_TTY = sys.stdout.isatty()
HAS_COLOR = HAS_TTY  # if it has tty then it supports colors

# environment debug variable
if os.getenv('ALIENPY_JSON'): os.environ['ALIENPY_JSON_OUT_GLOBAL'] = '1'

TIME_CONNECT = os.getenv('ALIENPY_TIMECONNECT', '')
DEBUG_TIMING = os.getenv('ALIENPY_TIMING', '')  # enable really detailed timings in logs

# Give information to central services that connection wise we want to be treateat as specified site
SET_SITE = os.getenv('ALIEN_SITE', '')

REGEX_PATTERN_TYPE = type(re.compile('.'))
guid_regex = re.compile('[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}', re.IGNORECASE)  # regex for identification of GUIDs
cmds_split = re.compile(';|\n')  # regex for splitting chained commands
specs_split = re.compile('@|,')  # regex for splitting the specification of cp command
lfn_prefix_re = re.compile('(alien|file){1}(:|/{2})+')  # regex for identification of lfn prefix
ignore_comments_re = re.compile('^\\s*(#|;|//)+', re.MULTILINE)  # identify a range of comments
emptyline_re = re.compile('^\\s*$', re.MULTILINE)  # whitespace line
time_pattern_match_13 = re.compile(r'\d{13}', re.ASCII)
time_pattern_match_10 = re.compile(r'\d{10}', re.ASCII)

# global session state;
AlienSessionInfo = {'alienHome': '', 'currentdir': '', 'prevdir': '', 'user': '', 'exitcode': int(-1), 'session_started': False,
                    'commandlist': [], 'commandlist_srv': [], 'cmd2func_map_nowb': {}, 'cmd2func_map_client': {}, 'cmd2func_map_srv': {}, 'templist': [], 'alias_cache': {},
                    'pathq': deque([]), 'show_date': False, 'show_lpwd': False,
                    'use_usercert': False, 'verified_cert': False, 'verified_token': False,
                    'user_cert': '', 'user_key': '', 'token_cert': '', 'token_key': ''}


if __name__ == '__main__':
    print('This file should not be executed!', file = sys.stderr, flush = True)
    sys.exit(95)
