'''alienpy:: GLOBALS'''

import os
import re
import sys
import tempfile
from collections import deque
from pathlib import Path
from .data_structs import * # nosec PYL-W0614
from .version import *  # nosec PYL-W0614


HAS_PPRINT = False
if os.getenv('ALIENPY_FANCY_PRINT'):
    try:
        from rich import print
        from rich import print_json
        # from rich.highlighter import ISO8601Highlighter, JSONHighlighter
        HAS_PPRINT = True
    except Exception:
        msg = ("rich module could not be imported! Not fatal, but some pretty print features will not be available.\n Make sure you can do:\npython3 -c 'from rich.pretty import pprint'")
        logging.error(msg)


##################################################
#   GLOBAL POINTER TO WB CONNECTION  #############
ALIENPY_GLOBAL_WB = None
##################################################
##################################################
#   GLOBAL VARS
##################################################
ALIENPY_EXECUTABLE = ''

COLORS = COLORS_COLL()  # definition of colors

TMPDIR = tempfile.gettempdir()
USER_HOME = Path.home().as_posix()

def get_certs_names() -> CertsInfo:
    """Provide the standard file names for used certificates"""
    usercert = os.getenv('X509_USER_CERT', f'{USER_HOME}/.globus/usercert.pem')
    userkey = os.getenv('X509_USER_KEY',  f'{USER_HOME}/.globus/userkey.pem')
    tokencert = os.getenv('JALIEN_TOKEN_CERT', f'{TMPDIR}/tokencert_{str(os.getuid())}.pem')
    tokenkey = os.getenv('JALIEN_TOKEN_KEY',  f'{TMPDIR}/tokenkey_{str(os.getuid())}.pem')
    return CertsInfo(usercert, userkey, tokencert, tokenkey)

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

DEBUG = os.getenv('ALIENPY_DEBUG', '')
DEBUG_FILE = os.getenv('ALIENPY_DEBUG_FILE', f'{USER_HOME}/alien_py.log')

REGEX_PATTERN_TYPE = type(re.compile('.'))
guid_regex = re.compile('[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}', re.IGNORECASE)  # regex for identification of GUIDs
cmds_split = re.compile(';|\n')  # regex for spliting chained commands
specs_split = re.compile('@|,')  # regex for spliting the specification of cp command
lfn_prefix_re = re.compile('(alien|file){1}(:|/{2})+')  # regex for identification of lfn prefix
ignore_comments_re = re.compile('^\\s*(#|;|//)+', re.MULTILINE)  # identifiy a range of comments
emptyline_re = re.compile('^\\s*$', re.MULTILINE)  # whitespace line

# global session state;
AlienSessionInfo = {'alienHome': '', 'currentdir': '', 'prevdir': '', 'user': '', 'exitcode': int(-1), 'session_started': False,
                    'commandlist': [], 'commandlist_srv': [], 'cmd2func_map_nowb': {}, 'cmd2func_map_client': {}, 'cmd2func_map_srv': {}, 'templist': [], 'alias_cache': {},
                    'pathq': deque([]), 'show_date': False, 'show_lpwd': False,
                    'use_usercert': False, 'verified_cert': False, 'verified_token': False,
                    'user_cert': '', 'user_key': '', 'token_cert': '', 'token_key': ''}


if __name__ == '__main__':
    print('This file should not be executed!', file = sys.stderr, flush = True)
    sys.exit(95)


