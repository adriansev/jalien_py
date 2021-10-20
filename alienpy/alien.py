#!/usr/bin/env python3
"""Executable/module for interaction with GRID services of ALICE experiment"""

import sys
import os
import atexit
import re
import subprocess
import signal
import json
import traceback
import logging
import ssl
import uuid
import statistics
import collections
import multiprocessing as mp
from typing import Union
from typing import NamedTuple
import shlex
import tempfile
import time
import datetime
from pathlib import Path
from urllib.parse import urlparse
import urllib.request as urlreq
import socket
import threading
import asyncio
import pwd
import grp
import OpenSSL
import async_stagger
import websockets
from websockets.client import connect as _wb_connect
from websockets.client import unix_connect as _wb_unix_connect
from websockets.extensions import permessage_deflate as _wb_permessage_deflate
import xml.dom.minidom
import xml.etree.ElementTree as ET
import zipfile

deque = collections.deque

ALIENPY_VERSION_DATE = '20211020_162055'
ALIENPY_VERSION_STR = '1.3.4'
ALIENPY_EXECUTABLE = ''


if sys.version_info[0] != 3 or sys.version_info[1] < 6:
    print("This script requires a minimum of Python version 3.6", file=sys.stderr, flush = True)
    sys.exit(1)

_HAS_READLINE = False
try:
    import readline as rl
    _HAS_READLINE = True
except ImportError:
    try:
        import gnureadline as rl
        _HAS_READLINE = True
    except ImportError:
        _HAS_READLINE = False

if _HAS_READLINE:
    def setupHistory():
        """Setup up history mechanics for readline module"""
        histfile = os.path.join(os.path.expanduser("~"), ".alienpy_history")
        if not os.path.exists(histfile): open(histfile, 'wb').close()
        rl.set_history_length(-1)  # unlimited history
        rl.read_history_file(histfile)

        def startup_hook(): rl.append_history_file(1, histfile)  # before next prompt save last line
        rl.set_startup_hook(startup_hook)

_XRDVER_MAJOR = None
_XRDVER_MINOR = None
# _XRDVER_PATCH = None
_XRDVER_DATE = None
_XRDVER_GIT = None  # for cases of git build
_HAS_XROOTD = False
try:  # let's fail fast if the xrootd python bindings are not present
    from XRootD import client as xrd_client
    _HAS_XROOTD = True

    xrd_ver_arr = xrd_client.__version__.split(".")
    if len(xrd_ver_arr) > 1:
        _XRDVER_MAJOR = xrd_ver_arr[0][1:] if xrd_ver_arr[0].startswith('v') else xrd_ver_arr[0]  # take out the v if present
        _XRDVER_MINOR = xrd_ver_arr[1]
    else:  # version is not of x.y.z form
        xrdver_git = xrd_ver_arr[0].split("-")
        _XRDVER_DATE = xrdver_git[0][1:] if xrdver_git[0].startswith('v') else xrdver_git[0]  # take out the v if present
        _XRDVER_GIT = xrdver_git[1]
except ImportError:
    _HAS_XROOTD = False

if _HAS_XROOTD:
    os.environ["XRD_APPNAME"] = f'alien.py/{ALIENPY_VERSION_STR} xrootd/{xrd_client.__version__}'  # Override the application name reported to the xrootd server.

_HAS_XROOTD_GETDEFAULT = True if (_HAS_XROOTD and hasattr(xrd_client, 'EnvGetDefault')) else False

_HAS_TTY = sys.stdout.isatty()
_HAS_COLOR = _HAS_TTY  # if it has tty then it supports colors

_NCPU = mp.cpu_count()

REGEX_PATTERN_TYPE = type(re.compile('.'))
guid_regex = re.compile('[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}', re.IGNORECASE)  # regex for identification of GUIDs
cmds_split = re.compile(';|\n')  # regex for spliting chained commands
specs_split = re.compile('@|,')  # regex for spliting the specification of cp command
lfn_prefix_re = re.compile('(alien|file){1}(:|/{2})+')  # regex for identification of lfn prefix
ignore_comments_re = re.compile('^\\s*(#|;|//)+', re.MULTILINE)  # identifiy a range of comments
emptyline_re = re.compile('^\\s*$', re.MULTILINE)  # whitespace line

# environment debug variable
_JSON_OUT = bool(os.getenv('ALIENPY_JSON'))
_JSON_OUT_GLOBAL = _JSON_OUT
_DEBUG = os.getenv('ALIENPY_DEBUG', '')
_DEBUG_FILE = os.getenv('ALIENPY_DEBUG_FILE', f'{Path.home().as_posix()}/alien_py.log')
_TIME_CONNECT = os.getenv('ALIENPY_TIMECONNECT', '')
_TMPDIR = os.getenv('TMPDIR', '/tmp')
_DEBUG_TIMING = os.getenv('ALIENPY_TIMING', '')  # enable really detailed timings in logs

# global session state;
AlienSessionInfo = {'alienHome': '', 'currentdir': '', 'prevdir': '', 'commandlist': [], 'user': '', 'exitcode': int(-1), 'stdout': '', 'error': '', 'session_started': False,
                    'cmd2func_map_nowb': {}, 'cmd2func_map_client': {}, 'cmd2func_map_srv': {}, 'templist': [], 'use_usercert': False, 'alias_cache': {},
                    'q_out': deque([]), 'q_err': deque([]), 'pathq': deque([]),
                    'show_date': False, 'show_lpwd': False}


class COLORS(NamedTuple):  # pylint: disable=inherit-non-class
    """Collection of colors for terminal printing"""
    ColorReset = '\033[00m'     # Text Reset
    Black = '\033[0;30m'        # Black
    Red = '\033[0;31m'          # Red
    Green = '\033[0;32m'        # Green
    Yellow = '\033[0;33m'       # Yellow
    Blue = '\033[0;34m'         # Blue
    Purple = '\033[0;35m'       # Purple
    Cyan = '\033[0;36m'         # Cyan
    White = '\033[0;37m'        # White
    BBlack = '\033[1;30m'       # Bold Black
    BRed = '\033[1;31m'         # Bold Red
    BGreen = '\033[1;32m'       # Bold Green
    BYellow = '\033[1;33m'      # Bold Yellow
    BBlue = '\033[1;34m'        # Bold Blue
    BPurple = '\033[1;35m'      # Bold Purple
    BCyan = '\033[1;36m'        # Bold Cyan
    BWhite = '\033[1;37m'       # Bold White
    UBlack = '\033[4;30m'       # Underline Black
    URed = '\033[4;31m'         # Underline Red
    UGreen = '\033[4;32m'       # Underline Green
    UYellow = '\033[4;33m'      # Underline Yellow
    UBlue = '\033[4;34m'        # Underline Blue
    UPurple = '\033[4;35m'      # Underline Purple
    UCyan = '\033[4;36m'        # Underline Cyan
    UWhite = '\033[4;37m'       # Underline White
    IBlack = '\033[0;90m'       # High Intensity Black
    IRed = '\033[0;91m'         # High Intensity Red
    IGreen = '\033[0;92m'       # High Intensity Green
    IYellow = '\033[0;93m'      # High Intensity Yellow
    IBlue = '\033[0;94m'        # High Intensity Blue
    IPurple = '\033[0;95m'      # High Intensity Purple
    ICyan = '\033[0;96m'        # High Intensity Cyan
    IWhite = '\033[0;97m'       # High Intensity White
    BIBlack = '\033[1;90m'      # Bold High Intensity Black
    BIRed = '\033[1;91m'        # Bold High Intensity Red
    BIGreen = '\033[1;92m'      # Bold High Intensity Green
    BIYellow = '\033[1;93m'     # Bold High Intensity Yellow
    BIBlue = '\033[1;94m'       # Bold High Intensity Blue
    BIPurple = '\033[1;95m'     # Bold High Intensity Purple
    BICyan = '\033[1;96m'       # Bold High Intensity Cyan
    BIWhite = '\033[1;97m'      # Bold High Intensity White
    On_Black = '\033[40m'       # Background Black
    On_Red = '\033[41m'         # Background Red
    On_Green = '\033[42m'       # Background Green
    On_Yellow = '\033[43m'      # Background Yellow
    On_Blue = '\033[44m'        # Background Blue
    On_Purple = '\033[45m'      # Background Purple
    On_Cyan = '\033[46m'        # Background Cyan
    On_White = '\033[47m'       # Background White
    On_IBlack = '\033[0;100m'   # High Intensity backgrounds Black
    On_IRed = '\033[0;101m'     # High Intensity backgrounds Red
    On_IGreen = '\033[0;102m'   # High Intensity backgrounds Green
    On_IYellow = '\033[0;103m'  # High Intensity backgrounds Yellow
    On_IBlue = '\033[0;104m'    # High Intensity backgrounds Blue
    On_IPurple = '\033[0;105m'  # High Intensity backgrounds Purple
    On_ICyan = '\033[0;106m'    # High Intensity backgrounds Cyan
    On_IWhite = '\033[0;107m'   # High Intensity backgrounds White


class XrdCpArgs(NamedTuple):  # pylint: disable=inherit-non-class
    """Structure to keep the set of xrootd flags used for xrootd copy process"""
    overwrite: bool
    batch: int
    sources: int
    chunks: int
    chunksize: int
    makedir: bool
    tpc: str
    posc: bool
    hashtype: str
    streams: int
    cksum: bool
    timeout: int
    rate: int


class CopyFile(NamedTuple):  # pylint: disable=inherit-non-class
    """Structure to keep a generic copy task"""
    src: str
    dst: str
    isUpload: bool
    token_request: dict
    lfn: str
    isSuccess: bool = False


class lfn2file(NamedTuple):  # pylint: disable=inherit-non-class
    """Map a lfn to file (and reverse)"""
    lfn: str
    file: str


class KV(NamedTuple):  # pylint: disable=inherit-non-class
    """Assign a value to a key"""
    key: str
    val: str


class RET(NamedTuple):  # pylint: disable=inherit-non-class
    """Structure for POSIX like function return: exitcode, stdout, stderr, dictionary of server reply"""
    exitcode: int = -1
    out: str = ''
    err: str = ''
    ansdict: dict = {}

    def print(self, opts = ''):
        if 'json' in opts:
            if self.ansdict:
                json_out = json.dumps(self.ansdict, sort_keys = True, indent = 4)
                print_out(json_out)
                if _DEBUG: logging.debug(json_out)
            else:
                print_err('This command did not return a json dictionary')
            return

        if self.exitcode != 0:
            if 'info' in opts: logging.info(self.err)
            if 'warn' in opts: logging.warning(self.err)
            if 'err' in opts: logging.error(self.err)
            if 'debug' in opts: logging.debug(self.err)
            if self.err and not ('noerr' in opts or 'noprint' in opts):
                print_err(f'{self.err.strip()}')
        else:
            if self.out and not ('noout' in opts or 'noprint' in opts):
                print_out(f'{self.out.strip()}')

    __call__ = print

    def __bool__(self):
        return True if self.exitcode == 0 else False


class ALIEN_COLLECTION_EL(NamedTuple):  # pylint: disable=inherit-non-class
    """AliEn style xml collection element strucure"""
    name: str = ''
    aclId: str = ''
    broken: str = ''
    ctime: str = ''
    dir: str = ''
    entryId: str = ''
    expiretime: str = ''
    gowner: str = ''
    guid: str = ''
    guidtime: str = ''
    jobid: str = ''
    lfn: str = ''
    md5: str = ''
    owner: str = ''
    perm: str = ''
    replicated: str = ''
    size: str = ''
    turl: str = ''
    type: str = ''


class Msg:
    """Class to create json messages to be sent to server"""
    __slots__ = ('cmd', 'args', 'opts')

    def __init__(self, cmd = '', args = None, opts = ''):
        self.cmd = cmd
        self.opts = opts
        if not args:
            self.args = []
        elif isinstance(args, str):
            self.args = shlex.split(args)
        elif isinstance(args, list):
            self.args = args.copy()

    def add_arg(self, arg):
        if isinstance(arg, str): self.args.append(arg)
        if isinstance(arg, list): self.args.extend(arg)

    def dict(self):
        return CreateJsonCommand(self.cmd, self.args, self.opts, True)

    def str(self):
        return CreateJsonCommand(self.cmd, self.args, self.opts)

    def __call__(self):
        return (self.cmd, self.args, self.opts)

    def __bool__(self):
        return True if self.cmd else False


class AliEn:
    """Class to be used as advanced API for interaction with central servers"""
    __slots__ = ('internal_wb', 'opts')

    def __init__(self, opts = ''):
        self.internal_wb = InitConnection()
        self.opts = opts

    def run(self, cmd, opts = '') -> Union[RET, str]:
        """SendMsg to server a string command, a RET object will be returned"""
        if not opts: opts = self.opts
        return SendMsg(self.internal_wb, cmd, opts = opts)

    def ProcessMsg(self, cmd, opts = '') -> int:
        """ProcessCommandChain - the app main function to process a (chain of) command(s)"""
        if not opts: opts = self.opts
        return ProcessCommandChain(self.internal_wb, cmd)

    def wb(self):
        """Get the websocket, to be used in other functions"""
        return self.internal_wb

    def help(self):  # pylint: disable=no-self-use
        """Print help message"""
        print_out('Methods of AliEn session:\n'
                  '.run(cmd, opts) : alias to SendMsg(cmd, opts); It will return a RET object: named tuple (exitcode, out, err, ansdict)\n'
                  '.ProcessMsg(cmd_list) : alias to ProcessCommandChain, it will have the same output as in the alien.py interaction\n'
                  '.wb() : return the session WebSocket to be used with other function within alien.py')


def signal_handler(sig, frame):  # pylint: disable=unused-argument
    """Generig signal handler: just print the signal and exit"""
    print_out(f'\nCought signal {sig.name}, let\'s exit')
    exit_message(int(AlienSessionInfo['exitcode']))


def exit_message(code: int = 0, msg = ''):
    """Exit with msg and with specied code"""
    print_out(msg if msg else 'Exit')
    sys.exit(code)


def is_guid(guid: str) -> bool:
    """Recognize a GUID format"""
    return bool(guid_regex.fullmatch(guid))  # identify if argument in an AliEn GUID


def run_function(function_name: str, *args, **kwargs):
    """Python code:: run some arbitrary function name (found in globals) with arbitrary arguments"""
    return globals()[function_name](*args, *kwargs)  # run arbitrary function


def print_out(msg: str, toLog: bool = False):
    if toLog:
        logging.log(90, msg)
    else:
        print(msg, flush = True)


def print_err(msg: str, toLog: bool = False):
    if toLog:
        logging.log(95, msg)
    else:
        print(msg, file=sys.stderr, flush = True)


def isfloat(arg: Union[str, float, None]) -> bool:
    if not arg: return False
    return str(arg).replace('.', '', 1).isdigit()


def time_unix2simple(time_arg: Union[str, int, None]) -> str:
    if not time_arg: return ''
    return datetime.datetime.fromtimestamp(time_arg).replace(microsecond=0).isoformat().replace('T', ' ')


def time_str2unixmili(time_arg: Union[str, int, None]) -> int:
    if not time_arg:
        return int((datetime.datetime.utcnow() - datetime.datetime(1970, 1, 1)).total_seconds() * 1000)
    time_arg = str(time_arg)
    if (time_arg.isdigit() or isfloat(time_arg)) and (len(time_arg) != 10 or len(time_arg) != 13): return int(-1)
    if isfloat(time_arg) and len(time_arg) == 10:
        return int(float(time_arg) * 1000)
    if time_arg.isdigit() and len(time_arg) == 13:
        return int(time_arg)
    # asume that this is a strptime arguments in the form of: time_str, format_str
    try:
        time_obj = eval(f"datetime.datetime.strptime({time_arg})")
        return int((time_obj - datetime.datetime(1970, 1, 1)).total_seconds() * 1000)
    except Exception as e:
        return int(-1)


def io_q_proc():
    """IO queue:: print stdout/stderr and clear queue"""
    global AlienSessionInfo
    stderr = "\n". join(AlienSessionInfo['q_err'])
    AlienSessionInfo['q_err'].clear()
    stdout = "\n". join(AlienSessionInfo['q_out'])
    AlienSessionInfo['q_out'].clear()
    if stdout: print_out(stdout)
    if stderr: print_err(stderr)


def io_q_proc_out():
    """IO queue:: print stdout and clear queue"""
    global AlienSessionInfo
    stdout = "\n". join(AlienSessionInfo['q_out'])
    AlienSessionInfo['q_out'].clear()
    if stdout: print_out(stdout)


def io_q_get_out() -> str:
    """IO queue:: get stdout and clear queue"""
    global AlienSessionInfo
    stdout = "\n". join(AlienSessionInfo['q_out'])
    AlienSessionInfo['q_out'].clear()
    return stdout


def io_q_proc_err():
    """IO queue:: print stderr and clear queue"""
    global AlienSessionInfo
    stderr = "\n". join(AlienSessionInfo['q_err'])
    AlienSessionInfo['q_err'].clear()
    if stderr: print_err(stderr)


def io_q_get_err() -> str:
    """IO queue:: get stderr and clear queue"""
    global AlienSessionInfo
    stderr = "\n". join(AlienSessionInfo['q_err'])
    AlienSessionInfo['q_err'].clear()
    return stderr


def io_q_push_err(msg: str):
    """IO queue:: push to stderr queue"""
    global AlienSessionInfo
    if msg: AlienSessionInfo['q_err'].append(msg)


def io_q_push_out(msg: str):
    """IO queue:: push to stdout queue"""
    global AlienSessionInfo
    if msg: AlienSessionInfo['q_out'].append(msg)


def start_asyncio():
    """Initialization of main thread that will keep the asyncio loop"""
    loop = None
    ready = threading.Event()

    def run(mainasync, *, debug=False):
        if asyncio.events._get_running_loop() is not None: raise RuntimeError("asyncio.run() cannot be called from a running event loop")  # pylint: disable=protected-access
        if not asyncio.coroutines.iscoroutine(mainasync): raise ValueError("a coroutine was expected, got {!r}".format(mainasync))

        loop = asyncio.events.new_event_loop()
        try:
            asyncio.events.set_event_loop(loop)
            loop.set_debug(debug)
            return loop.run_until_complete(mainasync)
        finally:
            try:
                _cancel_all_tasks(loop)
                loop.run_until_complete(loop.shutdown_asyncgens())
            finally:
                asyncio.events.set_event_loop(None)
                loop.close()

    def _cancel_all_tasks(loop):
        if sys.version_info[1] < 8:
            to_cancel = asyncio.Task.all_tasks(loop)  # pylint: disable=no-member # asyncio.tasks
        else:
            to_cancel = asyncio.all_tasks(loop)  # asyncio.tasks
        if not to_cancel: return
        for task in to_cancel: task.cancel()
        loop.run_until_complete(asyncio.tasks.gather(*to_cancel, loop=loop, return_exceptions=True))

        for task in to_cancel:
            if task.cancelled(): continue
            if task.exception() is not None:
                loop.call_exception_handler({'message': 'unhandled exception during asyncio.run() shutdown', 'exception': task.exception(), 'task': task, })

    async def wait_forever():
        nonlocal loop
        loop = asyncio.get_event_loop()
        ready.set()
        await loop.create_future()

    threading.Thread(daemon=True, target=run, args=(wait_forever(),)).start()
    ready.wait()
    return loop


# GLOBAL STATE ASYNCIO LOOP !!! REQUIRED TO BE GLOBAL !!!
_loop = start_asyncio()


# PREPARATIONS FOR PRINTING THREAD
# print_io_th = threading.Thread(daemon=True, target=io_q_proc, name = 'PRINT_IO', )
# print_io_th.start()
# print_io_th.join()

def syncify(fn):
    """DECORATOR FOR SYNCIFY FUNCTIONS:: the magic for un-async functions"""
    def syncfn(*args, **kwds):
        # submit the original coroutine to the event loop and wait for the result
        conc_future = asyncio.run_coroutine_threadsafe(fn(*args, **kwds), _loop)
        return conc_future.result()
    syncfn.as_async = fn
    return syncfn


@syncify
async def IsWbConnected(wb) -> bool:
    """Check if websocket is connected with the protocol ping/pong"""
    time_begin = None
    if _DEBUG_TIMING: time_begin = datetime.datetime.now().timestamp()
    if _DEBUG:
        logging.info(f"Called from: {sys._getframe().f_back.f_code.co_name}")  # pylint: disable=protected-access
    try:
        pong_waiter = await wb.ping()
        await pong_waiter
    except Exception as e:
        logging.debug('WB ping/pong failed!!!')
        logging.exception(e)
        return False
    if time_begin: logging.error(f">>>IsWbConnected time = {(datetime.datetime.now().timestamp() - time_begin) * 1000:.3f} ms")
    return True


@syncify
async def wb_close(wb, code, reason):
    """Send close to websocket"""
    await wb.close(code = code, reason = reason)


@syncify
async def msg_proxy(websocket, use_usercert = False):
    """Proxy messages from a connection point to another"""
    wb_jalien = AlienConnect(None, use_usercert)
    local_query = await websocket.recv()
    jalien_answer = await SendMsg(wb_jalien, local_query)
    await websocket.send(jalien_answer.ansdict)


@syncify
async def __sendmsg(wb, jsonmsg: str) -> str:
    """The low level async function for send/receive"""
    time_begin = None
    if _DEBUG_TIMING: time_begin = datetime.datetime.now().timestamp()
    await wb.send(jsonmsg)
    result = await wb.recv()
    if time_begin: logging.debug(f">>>__sendmsg time = {(datetime.datetime.now().timestamp() - time_begin) * 1000:.3f} ms")
    return result


@syncify
async def __sendmsg_multi(wb, jsonmsg_list: list) -> list:
    """The low level async function for send/receive multiple messages once"""
    if not jsonmsg_list: return []
    time_begin = None
    if _DEBUG_TIMING: time_begin = datetime.datetime.now().timestamp()
    for msg in jsonmsg_list: await wb.send(msg)

    result_list = []
    for i in range(len(jsonmsg_list)):
        result = await wb.recv()
        result_list.append(result)

    if time_begin: logging.debug(f">>>__sendmsg time = {(datetime.datetime.now().timestamp() - time_begin) * 1000:.3f} ms")
    return result_list


def SendMsg(wb, cmdline: str, args: Union[None, list] = None, opts: str = '') -> Union[RET, str]:
    """Send a json message to the specified websocket; it will return the server answer"""
    if not wb:
        msg = "SendMsg:: websocket not initialized"
        logging.info(msg)
        return '' if 'rawstr' in opts else RET(1, '', msg)
    if not args: args = []
    time_begin = None
    if _DEBUG or _DEBUG_TIMING: time_begin = datetime.datetime.now().timestamp()
    if _JSON_OUT_GLOBAL or _JSON_OUT or _DEBUG:  # if jsout output was requested, then make sure we get the full answer
        opts = opts.replace('nokeys', '').replace('nomsg', '')

    if '{"command":' in cmdline and '"options":' in cmdline:  # seems as json input
        jsonmsg = cmdline
    else:
        jsonmsg = CreateJsonCommand(cmdline, args, opts)  # nomsg/nokeys will be passed to CreateJsonCommand

    if not jsonmsg:
        logging.info("SendMsg:: json message is empty!")
        return '' if 'rawstr' in opts else RET(1, '', f"SendMsg:: empty json with args:: {cmdline} {' '.join(args)} /opts= {opts}")

    if _DEBUG:
        logging.debug(f"Called from: {sys._getframe().f_back.f_code.co_name}")  # pylint: disable=protected-access
        # logging.info(f"With argumens: cmdline: {cmdline} ; args: {args}")
        logging.debug(f"SEND COMMAND:: {jsonmsg}")

    nr_tries = int(0)
    result = None
    while result is None:
        if nr_tries > 3:
            msg = f"SendMsg:: {nr_tries - 1} communication errors!\nSent command: {jsonmsg}"
            print_err(msg)
            logging.error(msg)
            break
        try:
            nr_tries += 1
            result = __sendmsg(wb, jsonmsg)
        except (websockets.ConnectionClosed, websockets.ConnectionClosedError, websockets.ConnectionClosedOK) as e:
            logging.exception(e)
            try:
                wb = InitConnection()
            except Exception as e:
                logging.exception(e)
                msg = f'SendMsg:: Could not recover connection when disconnected!! Check {_DEBUG_FILE}'
                logging.error(msg)
                print_err(msg)
        except Exception as e:
            logging.exception(e)
            msg = f'SendMsg:: Non-connection related exception!! Check {_DEBUG_FILE}\n{str(e)}'
            logging.error(msg)
            print_err(msg)
            break
        if result is None: time.sleep(0.1)

    if time_begin: logging.debug(f"SendMsg::Result received: {deltat_ms(time_begin)} ms")
    if not result: return RET(1, '', 'SendMsg:: Empty result received from server')
    if 'rawstr' in opts: return result
    ret_obj = retf_result2ret(result)
    if time_begin: logging.debug(f"SendMsg::Result decoded: {deltat_ms(time_begin)} ms")
    return ret_obj


def SendMsgMulti(wb, cmds_list: list, opts: str = '') -> list:
    """Send a json message to the specified websocket; it will return the server answer"""
    if not wb:
        msg = "SendMsg:: websocket not initialized"
        logging.info(msg)
        return '' if 'rawstr' in opts else RET(1, '', msg)
    if not cmds_list: return []
    time_begin = None
    if _DEBUG or _DEBUG_TIMING: time_begin = datetime.datetime.now().timestamp()
    if _JSON_OUT_GLOBAL or _JSON_OUT or _DEBUG:  # if jsout output was requested, then make sure we get the full answer
        opts = opts.replace('nokeys', '').replace('nomsg', '')

    json_cmd_list = []
    for cmd_str in cmds_list:
        if '{"command":' in cmd_str and '"options":' in cmd_str:  # seems as json input
            jsonmsg = cmd_str
        else:
            jsonmsg = CreateJsonCommand(cmd_str, [], opts)  # nomsg/nokeys will be passed to CreateJsonCommand
        json_cmd_list.append(jsonmsg)

    if _DEBUG:
        logging.debug(f"Called from: {sys._getframe().f_back.f_code.co_name}")  # pylint: disable=protected-access
        logging.debug(f"SEND COMMAND LIST:: {chr(32).join(json_cmd_list)}")

    nr_tries = int(0)
    result_list = None
    while result_list is None:
        if nr_tries > 3:
            msg = f"SendMsg:: {nr_tries - 1} communication errors!\nSent command: {chr(32).join(json_cmd_list)}"
            print_err(msg)
            logging.error(msg)
            break
        try:
            nr_tries += 1
            result_list = __sendmsg_multi(wb, json_cmd_list)
        except (websockets.ConnectionClosed, websockets.ConnectionClosedError, websockets.ConnectionClosedOK) as e:
            logging.exception(e)
            try:
                wb = InitConnection()
            except Exception as e:
                logging.exception(e)
                msg = f'SendMsg:: Could not recover connection when disconnected!! Check {_DEBUG_FILE}'
                logging.error(msg)
                print_err(msg)
        except Exception as e:
            logging.exception(e)
            if not IsWbConnected(wb):
                try:
                    wb = InitConnection()
                except Exception as e:
                    logging.exception(e)
                    msg = f'SendMsg:: Could not recover connection after non-connection related exception!! Check {_DEBUG_FILE}'
                    logging.error(msg)
                    print_err(msg)
                    break
        if result_list is None: time.sleep(0.1)

    if time_begin: logging.debug(f"SendMsg::Result received: {deltat_ms(time_begin)} ms")
    if not result_list: return []
    if 'rawstr' in opts: return result_list
    ret_obj_list = [retf_result2ret(result) for result in result_list]
    if time_begin: logging.debug(f"SendMsg::Result decoded: {deltat_ms(time_begin)} ms")
    return ret_obj_list


def retf_result2ret(result: Union[str, dict, None], internal_cmd = False) -> Union[None, RET]:
    """Convert AliEn answer dictionary to RET object"""
    global AlienSessionInfo
    if not result: return RET()
    out_dict = None
    if isinstance(result, str):
        try:
            out_dict = json.loads(result)
        except Exception as e:
            msg = 'retf_result2ret:: Could not load argument as json!\n{0}'.format(e)
            logging.error(msg)
            return RET(1, '', msg)
    else:
        out_dict = result.copy()

    if 'metadata' not in out_dict or 'results' not in out_dict:  # these works only for AliEn responses
        msg = 'retf_results2ret:: Dictionary does not have AliEn answer format'
        if not internal_cmd:
            try:  # reset global result output
                AlienSessionInfo['exitcode'] = '-1'
                AlienSessionInfo['stdout'] = ''
                AlienSessionInfo['error'] = ''
            except Exception:
                pass
        logging.error(msg)
        return RET(1, '', msg)

    message_list = [str(item['message']) for item in out_dict['results'] if 'message' in item]
    output = '\n'.join(message_list)
    ret_obj = RET(int(out_dict["metadata"]["exitcode"]), output.strip(), out_dict["metadata"]["error"], out_dict)

    try:  # update global state of session
        if not internal_cmd:
            AlienSessionInfo['exitcode'] = int(out_dict["metadata"]["exitcode"])
            AlienSessionInfo['stdout'] = output.strip()
            AlienSessionInfo['error'] = out_dict["metadata"]["error"]

        current_dir = out_dict["metadata"]["currentdir"]
        if not AlienSessionInfo['alienHome']:
            AlienSessionInfo['alienHome'] = current_dir  # if this is first connection, current dir is alien home

        prev_dir = AlienSessionInfo['currentdir']  # last known current dir
        if prev_dir != current_dir:
            AlienSessionInfo['currentdir'] = current_dir
            AlienSessionInfo['prevdir'] = prev_dir
        short_current_dir = current_dir.replace(AlienSessionInfo['alienHome'][:-1], '~')
        short_current_dir = short_current_dir[:-1]  # remove the last /
        if AlienSessionInfo['pathq']:
            if AlienSessionInfo['pathq'][0] != short_current_dir: AlienSessionInfo['pathq'][0] = short_current_dir
        else:
            push2stack(short_current_dir)
    except Exception:
        pass
    return ret_obj


def retf_session_update(ret_info: RET):
    """Update global result state"""
    global AlienSessionInfo
    AlienSessionInfo['exitcode'] = int(ret_info.exitcode)
    AlienSessionInfo['stdout'] = ret_info.out
    AlienSessionInfo['error'] = ret_info.err


def PrintDict(in_arg: Union[str, dict, list]):
    """Print a dictionary in a nice format"""
    if isinstance(in_arg, str):
        try:
            in_arg = json.loads(in_arg)
        except Exception as e:
            print_err('PrintDict:: Could not load argument as json!\n{0}'.format(e))
    print_out(json.dumps(in_arg, sort_keys = True, indent = 4))


def CreateJsonCommand(cmdline: Union[str, dict], args: Union[None, list] = None, opts: str = '', get_dict: bool = False) -> Union[str, dict]:
    """Return a json with command and argument list"""
    if args is None: args = []
    if isinstance(cmdline, dict):
        out_dict = cmdline.copy()
        if 'showmsg' in opts: opts = opts.replace('nomsg', '')
        if 'showkeys' in opts: opts = opts.replace('nokeys', '')
        if 'nomsg' in opts: out_dict["options"].insert(0, '-nomsg')
        if 'nokeys' in opts: out_dict["options"].insert(0, '-nokeys')
        return out_dict if get_dict else json.dumps(out_dict)

    if not args:
        args = shlex.split(cmdline)
        cmd = args.pop(0) if args else ''
    else:
        cmd = cmdline
    if 'nomsg' in opts: args.insert(0, '-nomsg')
    if 'nokeys' in opts: args.insert(0, '-nokeys')
    jsoncmd = {"command": cmd, "options": args}
    return jsoncmd if get_dict else json.dumps(jsoncmd)


def GetMeta(result: dict, meta: str = '') -> list:
    """Extract from input and return a list of 2nd arg selectable of cwd user error exitcode"""
    output = []
    if not result: return output
    if isinstance(result, dict) and 'metadata' in result:  # these works only for AliEn responses
        meta_opts_list = meta.split() if meta else []
        if 'cwd' in meta_opts_list or 'all' in meta_opts_list: output.append(result["metadata"]["currentdir"])
        if 'user' in meta_opts_list or 'all' in meta_opts_list: output.append(result["metadata"]["user"])
        if 'error' in meta_opts_list or 'all' in meta_opts_list: output.append(result["metadata"]["error"])
        if 'exitcode' in meta_opts_list or 'all' in meta_opts_list: output.append(result["metadata"]["exitcode"])
    return output


def PrintColor(color: str) -> str:
    """Disable color if the terminal does not have capability"""
    return color if _HAS_COLOR else ''


def cursor_vertical(lines: int = 0):
    """Move the cursor up/down N lines"""
    if lines == 0: return
    out_char = '\x1b[1A'  # UP
    if lines < 0:
        out_char = '\x1b[1B'  # DOWN
        lines = abs(lines)
    sys.stdout.write(out_char * lines)
    sys.stdout.flush()


def cursor_horizontal(lines: int = 0):
    """Move the cursor left/right N lines"""
    if lines == 0: return
    out_char = '\x1b[1C'  # RIGHT
    if lines < 0:
        out_char = '\x1b[1D'  # LEFT
        lines = abs(lines)
    sys.stdout.write(out_char * lines)
    sys.stdout.flush()


def cleanup_temp():
    """Remove from disk all recorded temporary files"""
    if AlienSessionInfo['templist']:
        for f in AlienSessionInfo['templist']:
            if os.path.isfile(f): os.remove(f)


def now_str() -> str: return str(datetime.datetime.now().strftime("%Y%m%d_%H%M%S"))


def deltat_ms(t0: Union[str, float, None] = None) -> str:
    "Return delta t in ms from a time start; if no argment it return a timestamp in ms"
    if not t0:
        return f"{datetime.datetime.now().timestamp() * 1000:.3f}"
    else:
        t0 = float(t0)
        return f"{(datetime.datetime.now().timestamp() - t0) * 1000:.3f}"


def deltat_us(t0: Union[str, float, None] = None) -> str:
    "Return delta t in ms from a time start; if no argment it return a timestamp in ms"
    if not t0:
        return f"{datetime.datetime.now().timestamp() * 1000000:.3f}"
    else:
        t0 = float(t0)
        return f"{(datetime.datetime.now().timestamp() - t0) * 1000000:.3f}"


def is_help(args: Union[str, list]) -> bool:
    if not args: return False
    if isinstance(args, str): args = args.split()
    help_opts = ('-h', '--h', '-help', '--help')
    return any(opt in args for opt in help_opts)


def retf_global_get() -> RET:
    global AlienSessionInfo
    return RET(AlienSessionInfo['exitcode'], AlienSessionInfo['stdout'], AlienSessionInfo['error'])


def retf_print(ret_obj: RET, opts: str = '') -> int:
    """Process the return struture of function"""
    if ret_obj.exitcode == -1:
        print_err('Default RET object used, invalid return')
        return ret_obj.exitcode

    retf_session_update(ret_obj)
    if 'json' in opts:
        if ret_obj.ansdict:
            json_out = json.dumps(ret_obj.ansdict, sort_keys = True, indent = 4)
            print_out(json_out)
            if _DEBUG: logging.debug(json_out)
        else:
            print_err('This command did not return a json dictionary')
        return ret_obj.exitcode

    if ret_obj.exitcode != 0:
        if 'info' in opts: logging.info(ret_obj.err)
        if 'warn' in opts: logging.warning(ret_obj.err)
        if 'err' in opts: logging.error(ret_obj.err)
        if 'debug' in opts: logging.debug(ret_obj.err)
        if ret_obj.err and not ('noerr' in opts or 'noprint' in opts):
            print_err(f'{ret_obj.err.strip()}')
    else:
        if ret_obj.out and not ('noout' in opts or 'noprint' in opts):
            print_out(f'{ret_obj.out.strip()}')
    return ret_obj.exitcode


def read_conf_file(file: str) -> dict:
    """Convert a configuration file with key = value format to a dict"""
    DICT_INFO = {}
    with open(file) as rel_file:
        for line in rel_file:
            line = line.partition('#')[0].rstrip()
            name, var = line.partition("=")[::2]
            var = re.sub(r"^\"", '', str(var.strip()))
            var = re.sub(r"\"$", '', var)
            DICT_INFO[name.strip()] = var
    return DICT_INFO


def file2list(file: str) -> list:
    """Parse a file and return a list of elements"""
    if not file or not os.path.isfile(file): return []
    file_list = []
    with open(file) as filecontent:
        for line in filecontent:
            if not line or ignore_comments_re.search(line) or emptyline_re.match(line): continue
            file_list.extend(line.strip().split())
    return file_list


def fileline2list(file: str) -> list:
    """Parse a file and return a list of file lines"""
    if not file or not os.path.isfile(file): return []
    file_list = []
    with open(file) as filecontent:
        for line in filecontent:
            if not line or ignore_comments_re.search(line) or emptyline_re.match(line): continue
            file_list.extend([line.strip()])
    return file_list


def import_aliases():
    global AlienSessionInfo
    alias_file = os.path.join(os.path.expanduser("~"), ".alienpy_aliases")
    global AlienSessionInfo
    if os.path.exists(alias_file): AlienSessionInfo['alias_cache'] = read_conf_file(alias_file)


def os_release() -> dict:
    return read_conf_file('/etc/os-release')


def get_lfn_key(lfn_obj: dict) -> str:
    """get either lfn key or file key from a file description"""
    if not lfn_obj or not isinstance(lfn_obj, dict): return ''
    if "lfn" in lfn_obj: return lfn_obj["lfn"]
    if "file" in lfn_obj: return lfn_obj["file"]
    return ''


def pid_uid(pid: int) -> int:
    '''Return username of UID of process pid'''
    uid = int(-1)
    try:
        with open(f'/proc/{pid}/status') as proc_status:
            for line in proc_status:
                # Uid, Gid: Real, effective, saved set, and filesystem UIDs(GIDs)
                if line.startswith('Uid:'): uid = int((line.split()[1]))
    except Exception:
        pass
    return uid


def is_my_pid(pid: int) -> bool: return bool(pid_uid(int(pid)) == os.getuid())


def writePidFile(filename: str):
    try:
        with open(filename, 'w') as f: f.write(str(os.getpid()))
    except Exception as e:
        logging.error('{0}'.format(e))


def GetSessionFilename() -> str: return os.path.join(os.path.expanduser("~"), ".alienpy_session")


def SessionSave():
    try:
        with open(GetSessionFilename(), "w") as f:
            line1 = f"CWD = {AlienSessionInfo['currentdir']}\n"
            if not AlienSessionInfo['prevdir']: AlienSessionInfo['prevdir'] = AlienSessionInfo['currentdir']
            line2 = f"CWDPREV = {AlienSessionInfo['prevdir']}\n"
            f.writelines([line1, line2])
    except Exception as e:
        logging.warning("SessionSave:: failed to write file")
        logging.exception(e)


def SessionRestore(wb):
    if os.getenv('ALIENPY_NO_CWD_RESTORE'): return
    global AlienSessionInfo
    if os.path.exists(GetSessionFilename()):
        session = read_conf_file(GetSessionFilename())
        sys_cur_dir = AlienSessionInfo['currentdir']
        AlienSessionInfo['currentdir'] = session['CWD']
        AlienSessionInfo['prevdir'] = session['CWDPREV']
        if AlienSessionInfo['currentdir'] and (sys_cur_dir != AlienSessionInfo['currentdir']): cd(wb, AlienSessionInfo['currentdir'], opts = 'nocheck')


def exitcode(args: Union[list, None] = None):  # pylint: disable=unused-argument
    """Return the latest global recorded exitcode"""
    return RET(0, f"{AlienSessionInfo['exitcode']}", '')


def error(args: Union[list, None] = None):  # pylint: disable=unused-argument
    """Return the latest global recorded error"""
    return RET(0, f"{AlienSessionInfo['error']}", '')


def unixtime2local(timestamp: Union[str, int], decimals: bool = True) -> str:
    """Convert unix time to a nice custom format"""
    timestr = str(timestamp)
    if len(timestr) < 10: return ''
    micros = None
    millis = None
    if len(timestr) > 10:
        time_decimals = timestr[10:]
        if len(time_decimals) <= 3:
            time_decimals = time_decimals.ljust(3, '0')
            millis = datetime.timedelta(milliseconds=int(time_decimals))
        else:
            time_decimals = time_decimals.ljust(6, '0')
            micros = datetime.timedelta(microseconds=int(time_decimals))

    unixtime = timestr[:10]
    utc_time = datetime.datetime.fromtimestamp(int(unixtime), datetime.timezone.utc)
    local_time = utc_time.astimezone()
    if decimals and millis:
        return f'{(local_time + millis).strftime("%Y-%m-%d %H:%M:%S")}.{time_decimals}{local_time.strftime("%z")}'
    if decimals and micros:
        return (local_time + micros).strftime("%Y-%m-%d %H:%M:%S.%f%z")  # (%Z)"))
    return local_time.strftime("%Y-%m-%d %H:%M:%S%z")  # (%Z)"))


def convert_time(str_line: str) -> str:
    """Convert the first 10 digit unix time like string from str argument to a nice time"""
    timestamp = re.findall(r"^(\d{10}) \[.*", str_line)
    if timestamp:
        nice_timestamp = f"{PrintColor(COLORS.BIGreen)}{unixtime2local(timestamp[0])}{PrintColor(COLORS.ColorReset)}"
        return str_line.replace(str(timestamp[0]), nice_timestamp)
    return ''


def cd(wb, args: Union[str, list] = None, opts: str = '') -> RET:
    """Override cd to add to home and to prev functions"""
    if args is None: args = []
    if isinstance(args, str): args = args.split()
    if is_help(args): return get_help_srv(wb, 'cd')
    if args:
        if args[0] == '-': args = [AlienSessionInfo['prevdir']]
        if 'nocheck' not in opts and AlienSessionInfo['currentdir'].rstrip('/') == args[0].rstrip('/'): return RET(0)
    return SendMsg(wb, 'cd', args, opts)


def push2stack(path: str):
    if not str: return
    global AlienSessionInfo
    if AlienSessionInfo['alienHome']: home = AlienSessionInfo['alienHome'][:-1]
    if home and home in path: path = path.replace(home, '~')
    AlienSessionInfo['pathq'].appendleft(path)


def deque_pop_pos(dq: deque, pos: int = 1) -> str:
    if abs(pos) > len(dq) - 1: return ''
    pos = - pos
    dq.rotate(pos)
    if pos > 0:
        val = dq.pop()
        if len(dq) > 1: dq.rotate(- (pos - 1))
    else:
        val = dq.popleft()
        if len(dq) > 1: dq.rotate(abs(pos) - 1)
    return val


def list_remove_item(target_list: list, item_list):
    target_list[:] = [el for el in target_list if el != item_list]


def get_arg(target: list, item) -> bool:
    """Remove inplace all instances of item from list and return True if found"""
    len_begin = len(target)
    list_remove_item(target, item)
    len_end = len(target)
    return len_begin != len_end


def get_arg_value(target: list, item):
    """Remove inplace all instances of item and item+1 from list and return item+1"""
    val = None
    for x in target:
        if x == item:
            val = target.pop(target.index(x) + 1)
            target.pop(target.index(x))
    return val


def get_arg_2values(target: list, item):
    """Remove inplace all instances of item, item+1 and item+2 from list and return item+1, item+2"""
    val = None
    for x in target:
        if x == item:
            val2 = target.pop(target.index(x) + 2)
            val1 = target.pop(target.index(x) + 1)
            target.pop(target.index(x))
    return (val1, val2)


def DO_dirs(wb, args: Union[str, list, None] = None) -> RET:
    """dirs"""
    return DO_path_stack(wb, 'dirs', args)


def DO_popd(wb, args: Union[str, list, None] = None) -> RET:
    """popd"""
    return DO_path_stack(wb, 'popd', args)


def DO_pushd(wb, args: Union[str, list, None] = None) -> RET:
    """pushd"""
    return DO_path_stack(wb, 'pushd', args)


def DO_path_stack(wb, cmd: str = '', args: Union[str, list, None] = None) -> RET:
    """Implement dirs/popd/pushd for directory stack manipulation"""
    if not cmd: return RET(1)
    if args is None: return RET(1)
    global AlienSessionInfo
    arg_list = args.split() if isinstance(args, str) else args
    do_not_cd = False
    if '-n' in arg_list:
        do_not_cd = True
        arg_list.remove('-n')

    msg = ''
    help_msg = ('The folloswinf syntax is required\n'
                'dirs [-clpv] [+N | -N]\n'
                'popd [-n] [+N | -N]\n'
                'pushd [-n] [+N | -N | dir]')

    if (cmd != 'dirs' and len(arg_list) > 1) or (cmd == 'dirs' and len(arg_list) > 2) or is_help(arg_list):
        return RET(1, '', help_msg)

    sign = None
    position = None
    pos = None
    for arg in arg_list:
        if arg[0] == '+' or arg[0] == '-':
            sign = arg[0]
            if not arg[1:].isdecimal(): return RET(1, '', "-N | +N argument is invalid")
            position = int(arg[1:])
            arg_list.remove(arg)
            pos = int(arg)

    if cmd == "dirs":
        if '-c' in arg_list:
            AlienSessionInfo['pathq'].clear()
            return RET(0)
        if not arg_list: msg = ' '.join(AlienSessionInfo['pathq'])

        if position and sign:
            if position > len(AlienSessionInfo['pathq']) - 1: return RET(0)
            if sign == "+":
                msg = AlienSessionInfo['pathq'][position]  # Nth position from top (last/top element have the index 0)
            if sign == "-":
                msg = AlienSessionInfo['pathq'][len(AlienSessionInfo['pathq']) - 1 - position]  # Nth position from last
        return RET(0, msg)  # end of dirs

    if cmd == "popd":
        if position and sign:
            if position > len(AlienSessionInfo['pathq']) - 1: return RET(0)
            deque_pop_pos(AlienSessionInfo['pathq'], pos)
            msg = " ".join(AlienSessionInfo['pathq'])
            return RET(0, msg)

        if not arg_list:
            AlienSessionInfo['pathq'].popleft()
            if not do_not_cd: cd(wb, AlienSessionInfo['pathq'][0])  # cd to the new top of stack
        msg = " ".join(AlienSessionInfo['pathq'])
        return RET(0, msg)  # end of popd

    if cmd == "pushd":
        if position and sign:
            if position > len(AlienSessionInfo['pathq']) - 1: return RET(0)
            if sign == "+":
                AlienSessionInfo['pathq'].rotate(-1 * position)
                if not do_not_cd: cd(wb, AlienSessionInfo['pathq'][0], 'log')  # cd to the new top of stack
            if sign == "-":
                AlienSessionInfo['pathq'].rotate(-(len(AlienSessionInfo['pathq']) - 1 - position))
                if not do_not_cd: cd(wb, AlienSessionInfo['pathq'][0], 'log')  # cd to the new top of stack
            msg = " ".join(AlienSessionInfo['pathq'])
            return RET(0, msg)  # end of +N|-N

        if not arg_list:
            if len(AlienSessionInfo['pathq']) < 2: return RET(0)
            old_cwd = AlienSessionInfo['pathq'].popleft()
            new_cwd = AlienSessionInfo['pathq'].popleft()
            push2stack(old_cwd)
            push2stack(new_cwd)
            if not do_not_cd: cd(wb, AlienSessionInfo['pathq'][0], 'log')
            msg = " ".join(AlienSessionInfo['pathq'])
            return RET(0, msg)  # end of +N|-N

        path = expand_path_grid(wb, arg_list[0])
        if do_not_cd:
            cwd = AlienSessionInfo['pathq'].popleft()
            push2stack(path)
            push2stack(cwd)
        else:
            push2stack(path)
            cd(wb, AlienSessionInfo['pathq'][0], 'log')  # cd to the new top of stack
        msg = " ".join(AlienSessionInfo['pathq'])
        return RET(0, msg)  # end of +N|-N
    return RET()  # dummy return just in case cmd is not proper


def DO_version(args: Union[list, None] = None) -> RET:  # pylint: disable=unused-argument
    stdout = (f'alien.py version: {ALIENPY_VERSION_STR}\n'
              f'alien.py version date: {ALIENPY_VERSION_DATE}\n'
              f'alien.py location: {os.path.realpath(__file__)}\n'
              f'script location: {ALIENPY_EXECUTABLE}\n'
              f'Interpreter: {os.path.realpath(sys.executable)}\n'
              f'Python version: {sys.version}\n')
    if _HAS_XROOTD:
        stdout = f'{stdout}XRootD version: {xrd_client.__version__}\nXRootD path: {xrd_client.__file__}'
    else:
        stdout = f'{stdout}XRootD version: Not Found!'
    return RET(0, stdout, "")


def DO_exit(args: Union[list, None] = None) -> RET:
    if args is None: args = []
    if len(args) > 0 and args[0] == '-h':
        msg = 'Command format: exit [code] [stderr|err] [message]'
        return RET(0, msg)
    code = AlienSessionInfo['exitcode']
    msg = ''
    if len(args) > 0:
        if args[0].isdecimal(): code = args.pop(0)
        if args[0] == 'stderr' or args[0] == 'err':
            args.pop(0)
            print2stdout = sys.stderr
        msg = ' '.join(args).strip()
        if msg:
            if code != 0: print_err(msg)
            else: print_out(msg)
    sys.exit(int(code))


def xrdcp_help() -> str:
    helpstr = f'''Command format is of the form of (with the strict order of arguments):
        cp <options> src dst
        or
        cp <options> -input input_file
where src|dst are local files if prefixed with file:// or file: or grid files otherwise
and -input argument is a file with >src dst< pairs
after each src,dst can be added comma separated specifiers in the form of: @disk:N,SE1,SE2,!SE3
where disk selects the number of replicas and the following specifiers add (or remove) storage endpoints from the received list
options are the following :
-h : print help
-f : replace destination file (if destination is local it will be replaced only if integrity check fails)
-P : enable persist on successful close semantic
-cksum : check hash sum of the file; for downloads the central catalogue md5 will be verified;
         for uploads (for xrootd client > 4.12.0) a hash type will be negociated with remote and transfer will be validated
-y <nr_sources> : use up to the number of sources specified in parallel (N.B. Ignored as it breaks download of files stored in archives)
-S <aditional TPC streams> : uses num additional parallel streams to do the transfer. (max = 15)
-chunks <nr chunks> : number of chunks that should be requested in parallel
-chunksz <bytes> : chunk size (bytes)
-T <nr_copy_jobs> : number of parralel copy jobs from a set (for recursive copy); defaults to 8 for downloads
-noxrdzip: circumvent the XRootD mechanism of zip member copy and download the archive and locally extract the intended member.
N.B.!!! for recursive copy (all files) the same archive will be downloaded for each member.
If there are problems with native XRootD zip mechanism, download only the zip archive and locally extract the contents

for the recursive copy of directories the following options (of the find command) can be used:
-glob <globbing pattern> : this is the usual AliEn globbing format; {PrintColor(COLORS.BIGreen)}N.B. this is NOT a REGEX!!!{PrintColor(COLORS.ColorReset)} defaults to all "*"
-select <pattern> : select only these files to be copied; {PrintColor(COLORS.BIGreen)}N.B. this is a REGEX applied to full path!!!{PrintColor(COLORS.ColorReset)}
-name <pattern> : select only these files to be copied; {PrintColor(COLORS.BIGreen)}N.B. this is a REGEX applied to a directory or file name!!!{PrintColor(COLORS.ColorReset)}
-name <verb>_string : where verb = begin|contain|ends|ext and string is the text selection criteria.
verbs are aditive : -name begin_myf_contain_run1_ends_bla_ext_root
{PrintColor(COLORS.BIRed)}N.B. the text to be filtered cannont have underline <_> within!!!{PrintColor(COLORS.ColorReset)}
-parent <parent depth> : in destination use this <parent depth> to add to destination ; defaults to 0
-a : copy also the hidden files .* (for recursive copy)
-j <queue_id> : select only the files created by the job with <queue_id>  (for recursive copy)
-l <count> : copy only <count> nr of files (for recursive copy)
-o <offset> : skip first <offset> files found in the src directory (for recursive copy)'''
    return helpstr


def _xrdcp_sysproc(cmdline: str, timeout: Union[str, int, None] = None) -> RET:
    """xrdcp stanalone system command"""
    if not cmdline: return RET(1, '', '_xrdcp_sysproc :: no cmdline')
    if timeout is not None: timeout = int(timeout)
    # --nopbar --posc
    xrdcp_cmdline = f'xrdcp -N -P {cmdline}'
    return runShellCMD(xrdcp_cmdline, captureout = True, do_shell = False, timeout = timeout)


def _xrdcp_copyjob(wb, copy_job: CopyFile, xrd_cp_args: XrdCpArgs, printout: str = '') -> int:
    """xrdcp based task that process a copyfile and it's arguments"""
    if not copy_job: return

    overwrite = xrd_cp_args.overwrite
    batch = xrd_cp_args.batch
    sources = xrd_cp_args.sources
    chunks = xrd_cp_args.chunks
    chunksize = xrd_cp_args.chunksize
    makedir = xrd_cp_args.makedir
    tpc = xrd_cp_args.tpc
    posc = xrd_cp_args.posc
    # hashtype = xrd_cp_args.hashtype
    streams = xrd_cp_args.streams
    cksum = xrd_cp_args.cksum
    timeout = xrd_cp_args.timeout
    rate = xrd_cp_args.rate

    cmdline = f'{copy_job.src} {copy_job.dst}'
    return retf_print(_xrdcp_sysproc(cmdline, timeout))


def XrdCopy_xrdcp(wb, job_list: list, xrd_cp_args: XrdCpArgs, printout: str = '') -> list:
    """XRootD copy command :: the actual XRootD copy process"""
    if not _HAS_XROOTD:
        print_err("XRootD not found")
        return []
    if not xrd_cp_args:
        print_err("cp arguments are not set, XrdCpArgs tuple missing")
        return []

    overwrite = xrd_cp_args.overwrite
    batch = xrd_cp_args.batch
    makedir = xrd_cp_args.makedir

    # ctx = mp.get_context('forkserver')
    # q = ctx.JoinableQueue()
    # p = ctx.Process(target=_xrdcp_copyjob, args=(q,))
    # p.start()
    # print(q.get())
    # p.join()
    for copy_job in job_list:
        if _DEBUG: logging.debug("\nadd copy job with\nsrc: {0}\ndst: {1}\n".format(copy_job.src, copy_job.dst))
        xrdcp_cmd = f' {copy_job.src} {copy_job.dst}'
        if _DEBUG: print_out(copy_job)
    return []


def getEnvelope_lfn(wb, arg_lfn2file: lfn2file, specs: Union[None, list] = None, isWrite: bool = False, strictspec: bool = False, httpurl: bool = False) -> dict:
    """Query central services for the access envelope of a lfn, it will return a lfn:server answer with envelope pairs"""
    if not wb: return {}
    if not arg_lfn2file: return {}
    lfn = arg_lfn2file.lfn
    file = arg_lfn2file.file
    if not specs: specs = []
    if isWrite:
        access_type = 'write'
        size = int(os.stat(file).st_size)
        md5sum = md5(file)
        files_with_default_replicas = ['.sh', '.C', '.jdl', '.xml']
        if any(lfn.endswith(ext) for ext in files_with_default_replicas) and size < 1048576:  # we have a special lfn
            if not specs: specs.append('disk:4')  # if no specs defined then default to disk:4
        get_envelope_arg_list = ['-s', size, '-m', md5sum, access_type, lfn]
        if not specs: specs.append('disk:2')  # hard default if nothing is specified
    else:
        access_type = 'read'
        get_envelope_arg_list = [access_type, lfn]

    if specs: get_envelope_arg_list.append(",".join(specs))
    if httpurl: get_envelope_arg_list.insert(0, '-u')
    if strictspec: get_envelope_arg_list.insert(0, '-f')
    ret_obj = SendMsg(wb, 'access', get_envelope_arg_list, opts = 'nomsg')
    if ret_obj.exitcode != 0:
        ret_obj = ret_obj._replace(err = f'No token for {lfn} :: {ret_obj.err}')
        retf_print(ret_obj, opts = 'err noprint')
        return {}
    result = ret_obj.ansdict
    qos_tags = [el for el in specs if 'ALICE::' not in el]  # for element in specs, if not ALICE:: then is qos tag
    SEs_list_specs = [el for el in specs if 'ALICE::' in el]  # explicit requests of SEs
    SEs_list_total = [replica["se"] for replica in result["results"]]
    # let's save for each replica the orginal request info
    for replica in result["results"]:
        replica["qos_specs"] = qos_tags  # qos tags from specs
        replica["SElist_specs"] = SEs_list_specs  # SE from specs
        replica["SElist"] = SEs_list_total  # list of SEs that were used
        replica["file"] = file
        replica["lfn"] = lfn
    return {"lfn": lfn, "answer": result}


def getEnvelope(wb, input_lfn_list: list, specs: Union[None, list] = None, isWrite: bool = False, strictspec: bool = False, httpurl: bool = False) -> list:
    """Query central services for the access envelope of the list of lfns, it will return a list of lfn:server answer with envelope pairs"""
    if not wb: return []
    access_list = []
    if not input_lfn_list: return access_list
    if specs is None: specs = []
    for l2f in input_lfn_list: access_list.append(getEnvelope_lfn(wb, l2f, specs, isWrite, strictspec, httpurl))
    return access_list


def expand_path_local(path_input: str, check_path: bool = False, check_writable: bool = False) -> str:
    """Given a string representing a local file, return a full path after interpretation of HOME location, current directory, . and .. and making sure there are only single /"""
    exp_path = None
    try:
        exp_path = Path(path_input).expanduser().resolve().as_posix()
    except RuntimeError:
        print_err(f"Loop encountered along the resolution of {path_input}")
    if exp_path is None: return ''
    if os.path.exists(exp_path):
        is_dir = os.path.isdir(exp_path)
        is_file = os.path.isfile(exp_path)
        if is_dir:
            exp_path = f'{exp_path}/'
            if check_writable and not os.access(exp_path, os.W_OK): return ''  # checking for writable dir
    else:
        if check_path: return ''
        if path_input.endswith('/'): exp_path = f'{exp_path}/'
    return exp_path


def expand_path_grid(wb, path_input: str, check_path: bool = False, check_writable: bool = False) -> str:
    """Given a string representing a GRID file (lfn), return a full path after interpretation of AliEn HOME location, current directory, . and .. and making sure there are only single /"""
    exp_path = path_input
    exp_path = lfn_prefix_re.sub('', exp_path)
    exp_path = re.sub(r"^\/*\%ALIEN[\/\s]*", AlienSessionInfo['alienHome'], exp_path)  # replace %ALIEN token with user grid home directory
    if exp_path == '.': exp_path = AlienSessionInfo['currentdir']
    if exp_path == '~': exp_path = AlienSessionInfo['alienHome']
    if exp_path.startswith('./'): exp_path = exp_path.replace('.', AlienSessionInfo['currentdir'], 1)
    if exp_path.startswith('~/'): exp_path = exp_path.replace('~', AlienSessionInfo['alienHome'], 1)  # replace ~ for the usual meaning
    if not exp_path.startswith('/'): exp_path = f'{AlienSessionInfo["currentdir"]}/{exp_path}'  # if not full path add current directory to the referenced path
    is_dir = exp_path.endswith('/')
    exp_path = os.path.normpath(exp_path)
    if is_dir: exp_path = f'{exp_path}/'
    if check_path:
        ret_obj = SendMsg(wb, 'stat', [exp_path], opts = 'nomsg log')
        if ret_obj.exitcode != 0: return ''
        file_stat = ret_obj.ansdict["results"][0]  # stat can query and return multiple results, but we are using only one
        exp_path = get_lfn_key(file_stat)
        if not exp_path:
            logging.error("expand_path_grid:: {exp_path} stat have no lfn nor file key!!")
            return ''
        path_type = file_stat["type"]
        if check_writable and path_type == "d":
            writable_user = writable_group = writable_others = False
            perms = file_stat["perm"]
            p_user = int(perms[0])
            p_group = int(perms[1])
            p_others = int(perms[2])
            path_owner = file_stat["owner"]
            path_gowner = file_stat["gowner"]
            if AlienSessionInfo['user'] == path_owner and p_user == 6 or p_user == 7: writable_user = True
            if AlienSessionInfo['user'] == path_gowner and p_group == 6 or p_group == 7: writable_group = True
            if p_others == 6 or p_others == 7: writable_others = True
            if not (p_user or p_group or p_others): return ''
    return exp_path


def pathtype_grid(wb, path: str) -> str:
    """Query if a lfn is a file or directory, return f, d or empty"""
    if not wb: return ''
    if not path: return ''
    ret_obj = SendMsg(wb, 'type', [path], opts = 'nomsg log')
    if ret_obj.exitcode != 0: return ''
    return str(ret_obj.ansdict['results'][0]["type"])[0]


def pathtype_local(path: str) -> str:
    """Query if a local path is a file or directory, return f, d or empty"""
    if not path: return ''
    p = Path(path)
    if p.is_dir(): return str('d')
    if p.is_file(): return str('f')
    return ''


def fileIsValid(file: str, size: Union[str, int], reported_md5: str) -> RET:
    """Check if the file path is consistent with the size and md5 argument. N.B.! the local file will be deleted with size,md5 not match"""
    global AlienSessionInfo
    if os.path.isfile(file):  # first check
        if int(os.stat(file).st_size) != int(size):
            os.remove(file)
            return RET(1, '', f'{file} : Removed (invalid size)')
        if md5(file) != reported_md5:
            os.remove(file)
            return RET(1, '', f'{file} : Removed (invalid md5 hash)')
        return RET(0, f'{file} --> TARGET VALID')
    return RET(2, '', f'{file} : No such file')  # ENOENT


def create_metafile(meta_filename: str, lfn: str, local_filename: str, size: Union[str, int], md5in: str, replica_list: Union[None, list] = None) -> str:
    """Generate a meta4 xrootd virtual redirector with the specified location and using the rest of arguments"""
    if not (meta_filename and replica_list): return ''
    try:
        with open(meta_filename, 'w') as f:
            published = str(datetime.datetime.now().replace(microsecond=0).isoformat())
            f.write('<?xml version="1.0" encoding="UTF-8"?>\n')
            f.write(' <metalink xmlns="urn:ietf:params:xml:ns:metalink">\n')
            f.write("   <published>{}</published>\n".format(published))
            f.write("   <file name=\"{}\">\n".format(local_filename))
            f.write("     <lfn>{}</lfn>\n".format(lfn))
            f.write("     <size>{}</size>\n".format(size))
            if md5in: f.write("     <hash type=\"md5\">{}</hash>\n".format(md5in))
            for url in replica_list:
                f.write("     <url><![CDATA[{}]]></url>\n".format(url))
            f.write('   </file>\n')
            f.write(' </metalink>\n')
        return meta_filename
    except Exception:
        logging.error(traceback.format_exc())
        return ''


def md5(file: str) -> str:
    """Compute the md5 digest of the specified file"""
    import hashlib
    BLOCKSIZE = 65536
    hasher = hashlib.md5()
    with open(file, 'rb') as f:
        buf = f.read(BLOCKSIZE)
        while len(buf) > 0:
            hasher.update(buf)
            buf = f.read(BLOCKSIZE)
    return hasher.hexdigest()


def format_dst_fn(src_dir, src_file, dst, parent):
    """Return the destination filename given the source dir/name, destination directory and number of parents to keep"""
    # let's get destination file name (relative path with parent value)
    if src_dir != src_file:  # recursive operation
        total_relative_path = src_file.replace(src_dir, '', 1)
        src_dir_path = Path(src_dir)
        src_dir_parts = src_dir_path.parts
        if not src_dir.endswith('/'): src_dir_parts[:] = src_dir_parts[:-1]
        src_dir = '/'.join(map(lambda x: str(x or ''), src_dir_parts))
        src_dir = src_dir.replace('//', '/')
        components_list = src_dir.split('/')
        components_list[0] = '/'  # first slash is lost in split
        file_components = len(components_list)  # it's directory'
        if parent >= file_components: parent = file_components  # make sure maximum parent var point to first dir in path
        parent_selection = components_list[(file_components - parent):]
        rootdir_src_dir = '/'.join(parent_selection)
        file_relative_name = f'{rootdir_src_dir}/{total_relative_path}'
    else:
        src_file_path = Path(src_file)
        file_components = len(src_file_path.parts) - 1 - 1  # without the file and up to slash
        if parent >= file_components: parent = file_components  # make sure maximum parent var point to first dir in path
        rootdir_src_file = src_file_path.parents[parent].as_posix()
        file_relative_name = src_file.replace(rootdir_src_file, '', 1)

    dst_file = f'{dst}/{file_relative_name}' if dst.endswith('/') else dst
    dst_file = re.sub(r"\/{2,}", "/", dst_file)
    return dst_file


def setDst(file: str = '', parent: int = 0) -> str:
    """For a given file path return the file path keeping the <parent> number of components"""
    p = Path(file)
    path_components = len(p.parts)
    if parent >= (path_components - 1): parent = path_components - 1 - 1  # IF parent >= number of components without filename THEN make parent = number of component without / and filename
    basedir = p.parents[parent].as_posix()
    if basedir == '/': return file
    return p.as_posix().replace(basedir, '', 1)


def commit(wb, tokenstr: str, size: int, lfn: str, perm: str, expire: str, pfn: str, se: str, guid: str, md5sum: str) -> RET:
    """Upon succesful xrootd upload to server, commit the guid name into central catalogue"""
    if not wb: return RET()
    arg_list = [tokenstr, int(size), lfn, perm, expire, pfn, se, guid, md5sum]
    return SendMsg(wb, 'commit', arg_list, opts = 'log')


def file_set_atime(path: str):
    """Set atime of file to now"""
    if not os.path.isfile(path): return
    file_stat = os.stat(path)
    os.utime(path, (datetime.datetime.now().timestamp(), file_stat.st_mtime))


def GetHumanReadable(size, precision = 2):
    """Convert bytes to higher units"""
    suffixes = ['B', 'KiB', 'MiB', 'GiB']
    suffixIndex = 0
    while size > 1024 and suffixIndex < 5:
        suffixIndex += 1  # increment the index of the suffix
        size = size/1024.0  # apply the division
    return '%.*f %s' % (precision, size, suffixes[suffixIndex])


def valid_regex(regex_str: str) -> Union[None, REGEX_PATTERN_TYPE]:
    """Validate a regex string and return a re.Pattern if valid"""
    regex = None
    try:
        regex = re.compile(regex_str.encode('unicode-escape').decode())  # try to no hit https://docs.python.org/3.6/howto/regex.html#the-backslash-plague
    except re.error:
        logging.error(f"regex validation failed:: {regex_str}")
    return regex


def name2regex(pattern_regex: str = '') -> str:
    if not pattern_regex: return ''
    translated_pattern_regex = ''
    re_all = '.*'
    re_all_end = '[^/]*'
    verbs = ('begin', 'contain', 'ends', 'ext')
    pattern_list = pattern_regex.split('_')
    if any(verb in pattern_regex for verb in verbs):
        if pattern_list.count('begin') > 1 or pattern_list.count('end') > 1 or pattern_list.count('ext') > 1:
            print_out('<begin>, <end>, <ext> verbs cannot appear more than once in the name selection')
            return ''

        list_begin = []
        list_contain = []
        list_ends = []
        list_ext = []
        for idx, tokenstr in enumerate(pattern_list):
            if tokenstr == 'begin': list_begin.append(KV(tokenstr, pattern_list[idx + 1]))
            if tokenstr == 'contain': list_contain.append(KV(tokenstr, pattern_list[idx + 1]))
            if tokenstr == 'ends': list_ends.append(KV(tokenstr, pattern_list[idx + 1]))
            if tokenstr == 'ext': list_ext.append(KV(tokenstr, pattern_list[idx + 1]))

        if list_begin:
            translated_pattern_regex = re_all + '/' + f'{list_begin[0].val}{re_all_end}'  # first string after the last slash (last match exclude /)
        for patt in list_contain:
            if not list_begin: translated_pattern_regex = f'{re_all}'
            translated_pattern_regex = f'{translated_pattern_regex}{patt.val}{re_all_end}'
        if list_ends:
            translated_pattern_regex = f'{translated_pattern_regex}{list_ends[0].val}{re_all_end}'
        if list_ext:
            translated_pattern_regex = translated_pattern_regex + "\\." + list_ext[0].val
        if translated_pattern_regex:
            if list_ext:
                translated_pattern_regex = f'{translated_pattern_regex}' + '$'
            else:
                translated_pattern_regex = f'{translated_pattern_regex}{re_all_end}' + '$'
    return translated_pattern_regex


def gid2name(gid: Union[str, int]) -> str:
    """From the list of all groups return the name of gid"""
    return str(grp.getgrgid(int(gid)).gr_name)


def file2file_dict(fn: str) -> dict:
    """Take a string as path and retur a dict with file propreties"""
    try:
        file_path = Path(fn)
    except Exception as e:
        return {}
    try:
        file_name = file_path.expanduser().resolve(strict = True).as_posix()
    except Exception as e:
        return {}
    file_dict = {"file": file_name}
    file_dict["lfn"] = file_name
    file_dict["size"] = str(file_path.stat().st_size)
    file_dict["mtime"] = str(int(file_path.stat().st_mtime * 1000))
    file_dict["md5"] = md5(file_name)
    file_dict["owner"] = pwd.getpwuid(file_path.stat().st_uid).pw_name
    file_dict["gowner"] = gid2name(file_path.stat().st_gid)
    return file_dict


def filter_file_prop(f_obj: dict, base_dir: str, find_opts: Union[str, list, None]) -> bool:
    """Return True if an file dict object pass the conditions in find_opts"""
    if not f_obj or not base_dir: return False
    if not find_opts: return True
    opts = find_opts.split() if isinstance(find_opts, str) else find_opts.copy()
    min_depth = get_arg_value(opts, '-min_depth')
    if min_depth and min_depth.startswith("-"):
        print_err(f'filter_file_prop::Missing argument in list:: {" ".join(opts)}')
        return False

    max_depth = get_arg_value(opts, '-max_depth')
    if max_depth and max_depth.startswith("-"):
        print_err(f'filter_file_prop::Missing argument in list:: {" ".join(opts)}')
        return False

    min_size = get_arg_value(opts, '-min_size')
    if min_size and min_size.startswith("-"):
        print_err(f'filter_file_prop::Missing argument in list:: {" ".join(opts)}')
        return False

    max_size = get_arg_value(opts, '-max_size')
    if max_size and max_size.startswith("-"):
        print_err(f'filter_file_prop::Missing argument in list:: {" ".join(opts)}')
        return False

    min_ctime = get_arg_value(opts, '-min_ctime')
    if min_ctime and min_ctime.startswith("-"):
        print_err(f'filter_file_prop::Missing argument in list:: {" ".join(opts)}')
        return False

    max_ctime = get_arg_value(opts, '-max_ctime')
    if max_ctime and max_ctime.startswith("-"):
        print_err(f'filter_file_prop::Missing argument in list:: {" ".join(opts)}')
        return False

    jobid = get_arg_value(opts, '-jobid')
    if jobid and jobid.startswith("-"):
        print_err(f'filter_file_prop::Missing argument in list:: {" ".join(opts)}')
        return False

    user = get_arg_value(opts, '-user')
    if user and user.startswith("-"):
        print_err(f'filter_file_prop::Missing argument in list:: {" ".join(opts)}')
        return False

    group = get_arg_value(opts, '-group')
    if group and group.startswith("-"):
        print_err(f'filter_file_prop::Missing argument in list:: {" ".join(opts)}')
        return False

    if min_depth or max_depth:
        lfn = get_lfn_key(f_obj)
        relative_lfn = lfn.replace(base_dir, '')  # it will have N directories + 1 file components

        if min_depth:
            min_depth = abs(int(min_depth)) + 1  # add +1 for the always present file component of relative_lfn
            if len(relative_lfn.split('/')) < int(min_depth): return False

        if max_depth:
            max_depth = abs(int(max_depth)) + 1  # add +1 for the always present file component of relative_lfn
            if len(relative_lfn.split('/')) > int(max_depth): return False

    if min_size and int(f_obj["size"]) < abs(int(min_size)): return False
    if max_size and int(f_obj["size"]) > abs(int(max_size)): return False
    if user and f_obj["owner"] != user: return False
    if group and f_obj["gowner"] != group: return False

    # the argument can be a string with a form like: '20.12.2016 09:38:42,76','%d.%m.%Y %H:%M:%S,%f'
    # see: https://docs.python.org/3.6/library/datetime.html#strftime-strptime-behavior
    if min_ctime:
        min_ctime = time_str2unixmili(min_ctime)
        if int(f_obj["ctime"]) < min_ctime: return False

    if max_ctime:
        max_ctime = time_str2unixmili(max_ctime)
        if int(f_obj["ctime"]) > max_ctime: return False

    if jobid:
        if "jobid" not in f_obj: return False
        if f_obj["jobid"] != jobid: return False

    return True


def list_files_grid(wb, dir: str, pattern: Union[None, REGEX_PATTERN_TYPE, str] = None, is_regex: bool = False, find_args: str = '') -> RET:
    """Return a list of files(lfn/grid files) that match pattern found in dir
    Returns a RET object (from find), and takes: wb, directory, pattern, is_regex, find_args"""
    if not dir: return RET(-1, "", "No search directory specified")
    # lets process the pattern: extract it from src if is in the path globbing form
    is_single_file = False  # dir actually point to a file

    dir_arg_list = dir.split()
    if len(dir_arg_list) > 1:  # dir is actually a list of arguments
        if not pattern: pattern = dir_arg_list.pop(-1)
        dir = dir_arg_list.pop(-1)
        if dir_arg_list: find_args = ' '.join(dir_arg_list)

    if '*' in dir:  # we have globbing in src path
        is_regex = False
        src_arr = dir.split("/")
        base_path_arr = []  # let's establish the base path
        for el in src_arr:
            if '*' not in el:
                base_path_arr.append(el)
            else:
                break
        for el in base_path_arr: src_arr.remove(el)  # remove the base path
        dir = '/'.join(base_path_arr) + '/'  # rewrite the source path without the globbing part
        pattern = '/'.join(src_arr)  # the globbing part is the rest of element that contain *
    else:  # pattern is specified by argument
        if pattern is None:
            if not dir.endswith('/'):  # this is a single file
                is_single_file = True
            else:
                pattern = '*'  # prefer globbing as default
        elif type(pattern) == REGEX_PATTERN_TYPE:  # unlikely but supported to match signatures
            pattern = pattern.pattern  # We pass the regex pattern into command as string
            is_regex = True

        if is_regex and type(pattern) is str:  # it was explictly requested that pattern is regex
            if valid_regex(pattern) is None:
                logging.error(f"list_files_grid:: {pattern} failed to re.compile")
                return RET(-1, "", f"list_files_grid:: {pattern} failed to re.compile")

    # remove default from additional args
    find_args_list = None
    filter_args_list = []
    if find_args:
        find_args_list = find_args.split()
        get_arg(find_args_list, '-a')
        get_arg(find_args_list, '-s')
        get_arg(find_args_list, '-f')
        get_arg(find_args_list, '-d')
        get_arg(find_args_list, '-w')
        get_arg(find_args_list, '-wh')

        min_depth = get_arg_value(find_args_list, '-min_depth')
        if min_depth:
            if min_depth.startswith("-"): print_err(f'filter_file_prop::Missing argument in list:: {" ".join(find_args_list)}')
            filter_args_list.extend(['-min_depth', min_depth])

        max_depth = get_arg_value(find_args_list, '-max_depth')
        if max_depth:
            if max_depth.startswith("-"): print_err(f'filter_file_prop::Missing argument in list:: {" ".join(find_args_list)}')
            filter_args_list.extend(['-max_depth', max_depth])

        min_size = get_arg_value(find_args_list, '-min_size')
        if min_size:
            if min_size.startswith("-"): print_err(f'filter_file_prop::Missing argument in list:: {" ".join(find_args_list)}')
            filter_args_list.extend(['-min_size', min_size])

        max_size = get_arg_value(find_args_list, '-max_size')
        if max_size:
            if max_size.startswith("-"): print_err(f'filter_file_prop::Missing argument in list:: {" ".join(find_args_list)}')
            filter_args_list.extend(['-max_size', max_size])

        min_ctime = get_arg_value(find_args_list, '-min_ctime')
        if min_ctime:
            if min_ctime.startswith("-"): print_err(f'filter_file_prop::Missing argument in list:: {" ".join(find_args_list)}')
            filter_args_list.extend(['-min_ctime', min_ctime])

        max_ctime = get_arg_value(find_args_list, '-max_ctime')
        if max_ctime:
            if max_ctime.startswith("-"): print_err(f'filter_file_prop::Missing argument in list:: {" ".join(find_args_list)}')
            filter_args_list.extend(['-max_ctime', max_ctime])

        jobid = get_arg_value(find_args_list, '-jobid')
        if jobid:
            if jobid.startswith("-"): print_err(f'filter_file_prop::Missing argument in list:: {" ".join(find_args_list)}')
            filter_args_list.extend(['-jobid', jobid])

        user = get_arg_value(find_args_list, '-user')
        if user:
            if user.startswith("-"): print_err(f'filter_file_prop::Missing argument in list:: {" ".join(find_args_list)}')
            filter_args_list.extend(['-user', user])

        group = get_arg_value(find_args_list, '-group')
        if group:
            if group.startswith("-"): print_err(f'filter_file_prop::Missing argument in list:: {" ".join(find_args_list)}')
            filter_args_list.extend(['-group', group])

    # create and return the list object just for a single file
    if is_single_file:
        send_opts = 'nomsg' if not _DEBUG else ''
        ret_obj = SendMsg(wb, 'stat', [dir], opts = send_opts)
    else:
        find_args_default = ['-f', '-a', '-s']
        if is_regex: find_args_default.insert(0, '-r')
        if find_args_list: find_args_default.extend(find_args_list)  # insert any other additional find arguments
        find_args_default.append(dir)
        find_args_default.append(pattern)
        send_opts = 'nomsg' if not _DEBUG else ''
        ret_obj = SendMsg(wb, 'find', find_args_default, opts = send_opts)

    if ret_obj.exitcode != 0:
        logging.error(f"list_files_grid error:: {dir} {pattern} {find_args}")
        return ret_obj
    if 'results' not in ret_obj.ansdict or not ret_obj.ansdict["results"]:
        logging.error(f"list_files_grid exitcode==0 but no results(!!!):: {dir} /pattern: {pattern} /find_args: {find_args}")
        return RET(2, "", f"No files found in :: {dir} /pattern: {pattern} /find_args: {find_args}")

    exitcode = ret_obj.exitcode
    stderr = ret_obj.err
    results_list = ret_obj.ansdict["results"]
    results_list_filtered = []
    # items that pass the conditions are the actual/final results
    for found_lfn_dict in results_list:  # parse results to apply filters
        if not filter_file_prop(found_lfn_dict, dir, filter_args_list): continue
        # at this point all filters were passed
        results_list_filtered.append(found_lfn_dict)

    if not results_list_filtered:
        return RET(2, "", f"No files passed the filters :: {dir} /pattern: {pattern} /find_args: {find_args}")

    ansdict = {"results": results_list_filtered}
    lfn_list = [get_lfn_key(lfn_obj) for lfn_obj in results_list_filtered]
    stdout = '\n'.join(lfn_list)
    return RET(exitcode, stdout, stderr, ansdict)


def list_files_local(dir: str, pattern: Union[None, REGEX_PATTERN_TYPE, str] = None, is_regex: bool = False, find_args: str = '') -> RET:
    """Return a list of files(local)(N.B! ONLY FILES) that match pattern found in dir"""
    if not dir: return RET(2, "", "No search directory specified")

    # lets process the pattern: extract it from src if is in the path globbing form
    regex = None
    is_single_file = False  # dir actually point to a file
    if '*' in dir:  # we have globbing in src path
        is_regex = False
        src_arr = dir.split("/")
        base_path_arr = []  # let's establish the base path
        for el in src_arr:
            if '*' not in el:
                base_path_arr.append(el)
            else:
                break
        for el in base_path_arr: src_arr.remove(el)  # remove the base path
        dir = '/'.join(base_path_arr) + '/'  # rewrite the source path without the globbing part
        pattern = '/'.join(src_arr)  # the globbing part is the rest of element that contain *
    else:  # pattern is specified by argument or not specified
        if pattern is None:
            if not dir.endswith('/'):  # this is a single file
                is_single_file = True
            else:
                pattern = '*'  # prefer globbing as default
        elif type(pattern) == REGEX_PATTERN_TYPE:  # unlikely but supported to match signatures
            regex = pattern
            is_regex = True
        elif type(pattern) is str and is_regex:  # it was explictly requested that pattern is regex
            regex = valid_regex(pattern)
            if regex is None:
                logging.error(f"list_files_grid:: {pattern} failed to re.compile")
                return RET(-1, "", f"list_files_grid:: {pattern} failed to re.compile")

    directory = None  # resolve start_dir to an absolute_path
    try:
        directory = Path(dir).expanduser().resolve(strict = True).as_posix()
    except FileNotFoundError:
        return RET(2, "", f"{dir} not found")
    except RuntimeError:
        return RET(2, "", f"Loop encountered along the resolution of {dir}")

    filter_args_list = None
    if find_args: filter_args_list = find_args.split()  # for local files listing we have only filtering options

    file_list = None  # make a list of filepaths (that match a regex or a glob)
    if is_single_file:
        file_list = [directory]
    elif is_regex:
        file_list = [os.path.join(root, f) for (root, dirs, files) in os.walk(directory) for f in files if regex.match(os.path.join(root, f))]
    else:
        file_list = [p.expanduser().resolve(strict = True).as_posix() for p in list(Path(directory).glob(f'**/{pattern}')) if p.is_file()]

    if not file_list:
        return RET(2, "", f"No files found in :: {str} /pattern: {pattern} /find_args: {find_args}")

    # convert the file_list to a list of file properties dictionaries
    results_list = [file2file_dict(filepath) for filepath in file_list]

    results_list_filtered = []
    # items that pass the conditions are the actual/final results
    for found_lfn_dict in results_list:  # parse results to apply filters
        if not filter_file_prop(found_lfn_dict, directory, filter_args_list): continue
        # at this point all filters were passed
        results_list_filtered.append(found_lfn_dict)

    if not results_list_filtered:
        return RET(2, "", f"No files passed the filters :: {str} /pattern: {pattern} /find_args: {find_args}")

    ansdict = {"results": results_list_filtered}
    lfn_list = [get_lfn_key(lfn_obj) for lfn_obj in results_list_filtered]
    stdout = '\n'.join(file_list)
    return RET(exitcode, stdout, '', ansdict)


def extract_glob_pattern(path_arg: str) -> tuple:
    """Extract glob pattern from a path"""
    if not path_arg: return None, None
    base_path = pattern = None
    if '*' in path_arg:  # we have globbing in src path
        path_components = path_arg.split("/")
        base_path_arr = []  # let's establish the base path
        for el in path_components:
            if '*' not in el: base_path_arr.append(el)
            else: break

        for el in base_path_arr: path_components.remove(el)  # remove the base path components (those without *) from full path components
        base_path = '/'.join(base_path_arr) + '/'  # rewrite the source path without the globbing part
        pattern = '/'.join(path_components)  # the globbing part is the rest of element that contain *
    else:
        base_path = path_arg
    return (base_path, pattern)


def check_path(wb, path_arg: str, check_path: bool = False) -> tuple:
    """Check if path exists and what kind; returns the resolved path and the location"""
    location = filepath = ''
    if lfn_prefix_re.match(path_arg):  # if any prefix is present
        if path_arg.startswith('file:'): location = 'local'
        if path_arg.startswith('alien:'): location = 'grid'
        path_arg = lfn_prefix_re.sub('', path_arg)  # lets remove any prefixes
    filepath = path_arg
    if check_path:
        if location:
            if location == 'local':
                filepath = expand_path_local(path_arg, check_path = True)
            if location == 'grid':
                filepath = expand_path_grid(wb, path_arg, check_path = True)
        else:
            filepath = expand_path_local(path_arg, check_path = True)
            if filepath:
                location = 'local'
            else:
                filepath = expand_path_grid(wb, path_arg, check_path = True)
                if filepath: location = 'grid'
    return (filepath, location)


def makelist_lfn(wb, arg_source, arg_target, find_args: list, parent: int, overwrite: bool, pattern: Union[None, REGEX_PATTERN_TYPE, str], is_regex: bool, copy_list: list, strictspec: bool = False, httpurl: bool = False) -> RET:  # pylint: disable=unused-argument
    """Process a source and destination copy arguments and make a list of individual lfns to be copied"""
    if (arg_source.startswith('file:') and arg_target.startswith('file:')) or (arg_source.startswith('alien:') and arg_target.startswith('alien:')):
        return RET(22, '', 'The operands cannot have the same type and if missing they will be determined from the type of source.\nUse any of "file:" and or "alien:" specifiers for any path arguments')  # EINVAL /* Invalid argument */

    isSrcDir = isDstDir = isSrcLocal = isDownload = specs = None  # make sure we set these to valid values later

    # lets extract the specs from both src and dst if any (to clean up the file-paths) and record specifications like disk=3,SE1,!SE2
    src_specs_remotes = specs_split.split(arg_source, maxsplit = 1)  # NO comma allowed in names (hopefully)
    arg_src = src_specs_remotes.pop(0)  # first item is the file path, let's remove it; it remains disk specifications
    src_specs = src_specs_remotes.pop(0) if src_specs_remotes else None  # whatever remains is the specifications

    dst_specs_remotes = specs_split.split(arg_target, maxsplit = 1)
    arg_dst = dst_specs_remotes.pop(0)
    dst_specs = dst_specs_remotes.pop(0) if dst_specs_remotes else None

    # lets process the pattern: extract it from src if is in the path globbing form
    src_glob = False
    if '*' in arg_src:  # we have globbing in src path
        src_glob = True
        arg_src, pattern = extract_glob_pattern(arg_src)
    else:  # pattern is specified by argument
        if type(pattern) == REGEX_PATTERN_TYPE:  # unlikely but supported to match signatures
            pattern = pattern.pattern  # We pass the regex pattern into command as string
            is_regex = True

        if is_regex and type(pattern) is str:  # it was explictly requested that pattern is regex
            if valid_regex(pattern) is None:
                msg = f"makelist_lfn:: {pattern} failed to re.compile"
                logging.error(msg)
                return RET(64, '', msg)  # EX_USAGE /* command line usage error */

    slashend_src = arg_src.endswith('/')  # after extracting the globbing if present we record the slash
    # N.B.!!! the check will be wrong when the same relative path is present local and on grid
    # first let's check only prefixes
    src, src_type = check_path(wb, arg_src, check_path = False)
    dst, dst_type = check_path(wb, arg_dst, check_path = False)  # do not check path, it can be missing and then auto-created

    if not src_type and not dst_type:
        src, src_type = check_path(wb, arg_src, check_path = True)  # src must be always valid
    if not dst_type:
        if src_type == 'grid': dst_type = 'local'
        if src_type == 'local': dst_type = 'grid'
    if not src_type:
        if dst_type == 'grid': src_type = 'local'
        if dst_type == 'local': src_type = 'grid'

    if src_type == dst_type:
        return RET(1, '', 'Location of src,dst cannot be determined! use at least one prefix -> file: or alien:')
    isSrcLocal = True if (src_type == 'local' or dst_type == 'grid') else False

    if isSrcLocal:
        src = expand_path_local(src, check_path = True)
        dst = expand_path_grid(wb, dst, check_path = False)
    else:
        src = expand_path_grid(wb, src, check_path = True)
        dst = expand_path_local(dst, check_path = False)
    if not src: return RET(2, '', f'{arg_src} => {src} does not exist (or not accessible) either local or on grid')  # ENOENT /* No such file or directory */

    if slashend_src and not src.endswith('/'): src = f"{src}/"  # recover the slash if lost
    if src.endswith('/') and not dst.endswith('/'): dst = f"{dst}/"
    isDstDir = isSrcDir = src.endswith('/')  # is src is dir, so dst must be
    isDownload = not isSrcLocal
    if isSrcDir and not src_glob and not slashend_src: parent = parent + 1  # cp/rsync convention: with / copy the contents, without it copy the actual dir

    if isDownload:
        try:  # we can try anyway, this is like mkdir -p
            mk_path = Path(dst) if dst.endswith('/') else Path(dst).parent  # if destination is file create it dir parent
            mk_path.mkdir(parents=True, exist_ok=True)
        except Exception:
            logging.error(traceback.format_exc())
            msg = f"Could not create local destination directory: {mk_path.as_posix()}\ncheck log file {_DEBUG_FILE}"
            return RET(42, '', msg)  # ENOMSG /* No message of desired type */
    else:  # this is upload to GRID
        mk_path = dst if dst.endswith('/') else Path(dst).parent.as_posix()
        ret_obj = SendMsg(wb, 'mkdir', ['-p', mk_path], opts = 'nomsg')  # do it anyway, there is not point in checking before
        retf_print(ret_obj, opts = 'noprint err')
        if ret_obj.exitcode != 0: return ret_obj  # just return the mkdir result

    specs = src_specs if isDownload else dst_specs  # only the grid path can have specs
    specs_list = specs_split.split(specs) if specs else []

    if strictspec: print_out("Strict specifications were enabled!! Command may fail!!")
    if httpurl and isSrcLocal:
        print_out("httpurl option is ignored for uploads")
        httpurl = False

    error_msg = ''  # container which accumulates the error messages
    isWrite = not isDownload
    if isDownload:  # pylint: disable=too-many-nested-blocks  # src is GRID, we are DOWNLOADING from GRID directory
        results_list = list_files_grid(wb, src, pattern, is_regex, " ".join(find_args))
        if "results" not in results_list.ansdict or len(results_list.ansdict["results"]) < 1:
            msg = f"No files found with: find {' '.join(find_args)} {'-r' if is_regex else ''} -a -s {src} {pattern}"
            return RET(42, '', msg)  # ENOMSG /* No message of desired type */

        for lfn_obj in results_list.ansdict["results"]:  # make CopyFile objs for each lfn
            lfn = get_lfn_key(lfn_obj)
            dst_filename = format_dst_fn(src, lfn, dst, parent)
            if os.path.isfile(dst_filename):
                if not overwrite:
                    print_out(f'{dst_filename} exists, skipping..')
                    continue
                # -f (force) was used
                file_size = lfn_obj['size']
                file_md5 = lfn_obj['md5']
                if retf_print(fileIsValid(dst_filename, file_size, file_md5)) == 0:
                    continue  # destination exists and is valid, no point to re-download

            tokens = getEnvelope_lfn(wb, lfn2file(lfn, dst_filename), specs_list, isWrite, strictspec, httpurl)
            if not tokens or 'answer' not in tokens: continue
            copy_list.append(CopyFile(lfn, dst_filename, isWrite, tokens['answer'], ''))
    else:  # src is LOCAL, we are UPLOADING from LOCAL directory
        results_list = list_files_local(src, pattern, is_regex, " ".join(find_args))
        if "results" not in results_list.ansdict or len(results_list.ansdict["results"]) < 1:
            msg = f"No files found in: {src} /pattern: {pattern} /find_args: {' '.join(find_args)}"
            return RET(42, '', msg)  # ENOMSG /* No message of desired type */

        for file in results_list.ansdict["results"]:
            file_path = get_lfn_key(file)
            lfn = format_dst_fn(src, file_path, dst, parent)
            if pathtype_grid(wb, lfn) == 'f':  # lfn exists
                if not overwrite:
                    print_out(f'{lfn} exists, skipping..')
                    continue
                print_out(f'{lfn} exists, deleting..')  # we want to overwrite so clear up the destination lfn
                ret_obj = SendMsg(wb, 'rm', ['-f', lfn], opts = 'nomsg')

            tokens = getEnvelope_lfn(wb, lfn2file(lfn, file_path), specs_list, isWrite)
            if not tokens or 'answer' not in tokens: continue
            copy_list.append(CopyFile(file_path, lfn, isWrite, tokens['answer'], ''))
    return RET(1, '', error_msg) if error_msg else RET(0)


def makelist_xrdjobs(copylist_lfns: list, copylist_xrd: list):
    """Process a list of lfns to add to XRootD copy jobs list"""
    for cpfile in copylist_lfns:
        if 'results' not in cpfile.token_request:
            print_err(f"No token info for {cpfile}\nThis message should not happen! Please contact the developer if you see this!")
            continue

        if len(cpfile.token_request['results']) < 1:
            print_err(f'Could not find working replicas for {cpfile.src}')
            continue

        if cpfile.isUpload:  # src is local, dst is lfn, request is replica(pfn)
            for replica in cpfile.token_request['results']:
                copylist_xrd.append(CopyFile(cpfile.src, f"{replica['url']}?xrd.wantprot=unix&authz={replica['envelope']}", cpfile.isUpload, replica, cpfile.dst))
        else:  # src is lfn(remote), dst is local, request is replica(pfn)
            size_4meta = cpfile.token_request['results'][0]['size']  # size SHOULD be the same for all replicas
            md5_4meta = cpfile.token_request['results'][0]['md5']  # the md5 hash SHOULD be the same for all replicas
            file_in_zip = None
            url_list_4meta = []
            for replica in cpfile.token_request['results']:
                url_components = replica['url'].rsplit('#', maxsplit = 1)
                if len(url_components) > 1: file_in_zip = url_components[1]
                # if is_pfn_readable(url_components[0]):  # it is a lot cheaper to check readability of replica than to try and fail a non-working replica
                url_list_4meta.append(f'{url_components[0]}?xrd.wantprot=unix&authz={replica["envelope"]}')

            # Create the metafile as a temporary uuid5 named file (the lfn can be retrieved from meta if needed)
            metafile = create_metafile(make_tmp_fn(cpfile.src, '.meta4', uuid5 = True), cpfile.src, cpfile.dst, size_4meta, md5_4meta, url_list_4meta)
            if not metafile:
                print_err(f"Could not create the download metafile for {cpfile.src}")
                continue
            if file_in_zip and 'ALIENPY_NOXRDZIP' not in os.environ: metafile = f'{metafile}?xrdcl.unzip={file_in_zip}'
            if not cpfile.isUpload and _DEBUG: print_out(f'makelist_xrdjobs:: {metafile}')
            copylist_xrd.append(CopyFile(metafile, cpfile.dst, cpfile.isUpload, {}, cpfile.src))  # we do not need the tokens in job list when downloading


def DO_XrootdCp(wb, xrd_copy_command: Union[None, list] = None, printout: str = '') -> RET:
    """XRootD cp function :: process list of arguments for a xrootd copy command"""
    if not _HAS_XROOTD: return RET(1, "", 'DO_XrootdCp:: python XRootD module cannot be found, the copy process cannot continue')
    if xrd_copy_command is None: xrd_copy_command = []
    global AlienSessionInfo
    if not wb: return RET(107, "", 'DO_XrootdCp:: websocket not found')  # ENOTCONN /* Transport endpoint is not connected */

    if not xrd_copy_command or len(xrd_copy_command) < 2 or is_help(xrd_copy_command):
        help_msg = xrdcp_help()
        return RET(0, help_msg)  # EX_USAGE /* command line usage error */

    # XRootD copy parameters
    # inittimeout: copy initialization timeout(int)
    # tpctimeout: timeout for a third-party copy to finish(int)
    # coerce: ignore file usage rules, i.e. apply `FORCE` flag to open() (bool)
    # :param checksummode: checksum mode to be used #:type    checksummode: string
    # :param checksumtype: type of the checksum to be computed  #:type    checksumtype: string
    # :param checksumpreset: pre-set checksum instead of computing it #:type  checksumpreset: string
    hashtype = str('md5')
    batch = int(1)   # from a list of copy jobs, start <batch> number of downloads
    sources = int(1)  # max number of download sources
    streams = int(1)  # uses num additional parallel streams to do the transfer; use defaults from XrdCl/XrdClConstants.hh
    chunks = int(4)  # number of chunks that should be requested in parallel; use defaults from XrdCl/XrdClConstants.hh
    chunksize = int(8388608)  # chunk size for remote transfers; use defaults from XrdCl/XrdClConstants.hh
    makedir = bool(True)  # create the parent directories when creating a file
    overwrite = bool(False)  # overwrite target if it exists
    posc = bool(True)  # persist on successful close; Files are automatically deleted should they not be successfully closed.
    cksum = bool(False)
    timeout = int(0)
    rate = int(0)

    # xrdcp parameters (used by ALICE tests)
    # http://xrootd.org/doc/man/xrdcp.1.html
    # xrootd defaults https://github.com/xrootd/xrootd/blob/master/src/XrdCl/XrdClConstants.hh

    # TODO these will not work for xrdcp subprocess; the env vars should also be set
    # Resolution for the timeout events. Ie. timeout events will be processed only every XRD_TIMEOUTRESOLUTION seconds.
    if not os.getenv('XRD_TIMEOUTRESOLUTION'): XRD_EnvPut('TimeoutResolution', int(1))  # let's check the status every 1s

    # Number of connection attempts that should be made (number of available connection windows) before declaring a permanent failure.
    if not os.getenv('XRD_CONNECTIONRETRY'): XRD_EnvPut('ConnectionRetry', int(3))

    # A time window for the connection establishment. A connection failure is declared if the connection is not established within the time window.
    # N.B.!!. If a connection failure happens earlier then another connection attempt will only be made at the beginning of the next window
    if not os.getenv('XRD_CONNECTIONWINDOW'): XRD_EnvPut('ConnectionWindow', int(10))

    # Default value for the time after which an error is declared if it was impossible to get a response to a request.
    if not os.getenv('XRD_REQUESTTIMEOUT'): XRD_EnvPut('RequestTimeout', int(30))

    # Maximum time allowed for the copy process to initialize, ie. open the source and destination files.
    if not os.getenv('XRD_CPINITTIMEOUT'): XRD_EnvPut('CPInitTimeout', int(30))

    # Time period after which an idle connection to a data server should be closed.
    if not os.getenv('XRD_DATASERVERTTL'): XRD_EnvPut('DataServerTTL', int(20))  # we have no reasons to keep idle connections

    # Time period after which an idle connection to a manager or a load balancer should be closed.
    if not os.getenv('XRD_LOADBALANCERTTL'): XRD_EnvPut('LoadBalancerTTL', int(30))  # we have no reasons to keep idle connections

    # If set the client tries first IPv4 address (turned off by default).
    if not os.getenv('XRD_PREFERIPV4'): XRD_EnvPut('PreferIPv4', int(1))

    if get_arg(xrd_copy_command, '-noxrdzip'): os.environ["ALIENPY_NOXRDZIP"] = "nozip"

    _use_system_xrdcp = get_arg(xrd_copy_command, '-xrdcp')
    overwrite = get_arg(xrd_copy_command, '-f')
    posc = get_arg(xrd_copy_command, '-P')
    cksum = get_arg(xrd_copy_command, '-cksum')

    tpc = 'none'
    tpc_arg = get_arg_value(xrd_copy_command, '-tpc')
    if tpc_arg: return RET(1, "", 'DO_XrootdCp:: TPC is not allowed!!')

    y_arg_val = get_arg_value(xrd_copy_command, '-y')
    # sources = int(y_arg_val)
    if y_arg_val: print_out("Ignored option! multiple source usage is known to break the files stored in zip files, so better to be ignored")

    streams_arg = get_arg_value(xrd_copy_command, '-S')
    if streams_arg:
        streams = int(streams)
        if (streams > 15): streams = 15

    batch = 8  # a nice enough default
    batch_arg = get_arg_value(xrd_copy_command, '-T')
    if batch_arg: batch = int(batch_arg)

    chunks_arg = get_arg_value(xrd_copy_command, '-chunks')
    if chunks_arg: chunks = int(chunks_arg)

    chunksz_arg = get_arg_value(xrd_copy_command, '-chunksz')
    if chunksz_arg: chunksize = int(chunksz_arg)

    timeout_arg = get_arg_value(xrd_copy_command, '-timeout')
    if timeout_arg:
        timeout = int(timeout_arg)
        XRD_EnvPut('CPTimeout', timeout)

    rate_arg = get_arg_value(xrd_copy_command, '-ratethreshold')
    if rate_arg:
        rate = int(rate_arg)
        XRD_EnvPut('XRateThreshold', rate)

    XRD_EnvPut('CpRetryPolicy', 'force')
    retry_arg = get_arg_value(xrd_copy_command, '-retry')
    if rate_arg:
        retry = int(retry_arg)
        XRD_EnvPut('CpRetry', retry)

    # options for envelope request
    strictspec = get_arg(xrd_copy_command, '-strictspec')
    httpurl = get_arg(xrd_copy_command, '-http')

    # keep this many path components into destination filepath
    parent = int(0)
    parent_arg = get_arg_value(xrd_copy_command, '-parent')
    if parent_arg: parent = int(parent_arg)

    # find options for recursive copy of directories
    find_args = []
    if get_arg(xrd_copy_command, '-v'): print_out("Verbose mode not implemented, ignored; enable debugging with ALIENPY_DEBUG=1")
    if get_arg(xrd_copy_command, '-a'): print_out("-a is enabled as default")
    if get_arg(xrd_copy_command, '-s'): print_out("-s is enabled as default")
    if get_arg(xrd_copy_command, '-f'): print_out("-f API flag not usefull for copy operations")
    if get_arg(xrd_copy_command, '-w'): print_out("-w flag not usefull for copy operations")
    if get_arg(xrd_copy_command, '-wh'): print_out("-wh flag not usefull for copy operations")
    if get_arg(xrd_copy_command, '-d'): print_out("-d flag not usefull for copy operations")

    mindepth_arg = get_arg_value(xrd_copy_command, '-mindepth')
    if mindepth_arg: find_args.extend(['-mindepth', mindepth_arg])

    maxdepth_arg = get_arg_value(xrd_copy_command, '-maxdepth')
    if maxdepth_arg: find_args.extend(['-maxdepth', maxdepth_arg])

    qid = get_arg_value(xrd_copy_command, '-j')
    if qid: find_args.extend(['-j', qid])

    files_limit = get_arg_value(xrd_copy_command, '-l')
    if files_limit: find_args.extend(['-l', files_limit])

    offset = get_arg_value(xrd_copy_command, '-o')
    if offset: find_args.extend(['-o', offset])

    use_regex = False
    filtering_enabled = False
    pattern = get_arg_value(xrd_copy_command, '-glob')
    if pattern:
        use_regex = False
        filtering_enabled = True

    pattern_regex = None
    select_arg = get_arg_value(xrd_copy_command, '-select')
    if select_arg:
        if filtering_enabled:
            msg = "Only one rule of selection can be used, either -select (full path match), -name (match on file name) or -glob (globbing)"
            return RET(22, '', msg)  # EINVAL /* Invalid argument */
        pattern_regex = select_arg
        use_regex = True
        filtering_enabled = True

    name_arg = get_arg_value(xrd_copy_command, '-name')
    if name_arg:
        if filtering_enabled:
            msg = "Only one rule of selection can be used, either -select (full path match), -name (match on file name) or -glob (globbing)"
            return RET(22, '', msg)  # EINVAL /* Invalid argument */
        use_regex = True
        filtering_enabled = True
        pattern_regex = name2regex(name_arg)
        if use_regex and not pattern_regex:
            msg = ("-name :: No selection verbs were recognized!"
                   "usage format is -name <attribute>_<string> where attribute is one of: begin, contain, ends, ext"
                   f"The invalid pattern was: {pattern_regex_arg}")
            return RET(22, '', msg)  # EINVAL /* Invalid argument */

    if use_regex: pattern = pattern_regex
    copy_lfnlist = []  # list of lfn copy tasks
    input_file = ''  # input file with <source, destination> pairs

    inputfile_arg = get_arg_value(xrd_copy_command, '-input')
    if inputfile_arg:
        cp_arg_list = fileline2list(inputfile_arg)
        if not cp_arg_list: return RET(1, '', f'Input file {inputfile_arg} not found or invalid content')
        for cp_line in cp_arg_list:
            cp_line_items = cp_line.strip().split()
            if len(cp_line_items) > 2:
                print_out(f'Line skipped, it has more than 2 arguments => f{line.strip()}')
                continue
            retobj = makelist_lfn(wb, cp_line_items[0], cp_line_items[1], find_args, parent, overwrite, pattern, use_regex, copy_lfnlist, strictspec, httpurl)
            if retobj.exitcode != 0: retf_print(retobj, "err")  # print error and continue with the other files
    else:
        retobj = makelist_lfn(wb, xrd_copy_command[-2], xrd_copy_command[-1], find_args, parent, overwrite, pattern, use_regex, copy_lfnlist, strictspec, httpurl)
        if retobj.exitcode != 0: return retobj  # if any error let's just return what we got

    if not copy_lfnlist:  # at this point if any errors, the processing was already stopped
        return RET(0)

    if _DEBUG:
        logging.debug("We are going to copy these files:")
        for file in copy_lfnlist: logging.debug(file)

    # create a list of copy jobs to be passed to XRootD mechanism
    xrdcopy_job_list = []
    makelist_xrdjobs(copy_lfnlist, xrdcopy_job_list)

    if not xrdcopy_job_list:
        msg = "No XRootD operations in list! enable the DEBUG mode for more info"
        logging.info(msg)
        return RET(2, '', msg)  # ENOENT /* No such file or directory */

    if _DEBUG:
        logging.debug("XRootD copy jobs:")
        for file in xrdcopy_job_list: logging.debug(file)

    my_cp_args = XrdCpArgs(overwrite, batch, sources, chunks, chunksize, makedir, tpc, posc, hashtype, streams, cksum, timeout, rate)
    # defer the list of url and files to xrootd processing - actual XRootD copy takes place
    copy_failed_list = XrdCopy(wb, xrdcopy_job_list, my_cp_args, printout) if not _use_system_xrdcp else XrdCopy_xrdcp(wb, xrdcopy_job_list, my_cp_args, printout)

    # hard to return a single exitcode for a copy process optionally spanning multiple files
    # we'll return SUCCESS if at least one lfn is confirmed, FAIL if not lfns is confirmed
    copy_jobs_nr = len(xrdcopy_job_list)
    copy_jobs_failed_nr = len(copy_failed_list)
    copy_jobs_success_nr = copy_jobs_nr - copy_jobs_failed_nr
    msg = f"Succesful copy jobs: {copy_jobs_success_nr}/{copy_jobs_nr}" if not ('quiet' in printout or 'silent' in printout) else ''
    if 'ALIENPY_NOXRDZIP' in os.environ: os.environ.pop("ALIENPY_NOXRDZIP")
    return RET(0, msg) if copy_jobs_failed_nr < copy_jobs_nr else RET(1, '', msg)


if _HAS_XROOTD:
    class MyCopyProgressHandler(xrd_client.utils.CopyProgressHandler):
        """Custom ProgressHandler for XRootD copy process"""
        __slots__ = ('wb', 'copy_failed_list', 'jobs', 'job_list', 'xrdjob_list', 'printout', 'debug')

        def __init__(self):
            self.wb = None
            self.copy_failed_list = []  # record the tokens of succesfully uploaded files. needed for commit to catalogue
            self.jobs = int(0)
            self.job_list = []
            self.xrdjob_list = []
            self.printout = ''
            self.debug = False

        def begin(self, jobId, total, source, target):
            timestamp_begin = datetime.datetime.now().timestamp()
            if not ('quiet' in self.printout or 'silent' in self.printout):
                print_out("jobID: {0}/{1} >>> Start".format(jobId, total))
            self.jobs = int(total)
            jobInfo = {'src': source, 'tgt': target, 'bytes_total': 0, 'bytes_processed': 0, 'start': timestamp_begin}
            self.job_list.insert(jobId - 1, jobInfo)
            if self.debug: logging.debug(f"CopyProgressHandler.src: {source}\nCopyProgressHandler.dst: {target}\n")

        def end(self, jobId, results):
            if results['status'].ok:
                status = f'{PrintColor(COLORS.Green)}OK{PrintColor(COLORS.ColorReset)}'
            elif results['status'].error:
                status = f'{PrintColor(COLORS.BRed)}ERROR{PrintColor(COLORS.ColorReset)}'
            elif results['status'].fatal:
                status = f'{PrintColor(COLORS.BIRed)}FATAL{PrintColor(COLORS.ColorReset)}'
            else:
                status = f'{PrintColor(COLORS.BIRed)}UNKNOWN{PrintColor(COLORS.ColorReset)}'
            job_info = self.job_list[jobId - 1]
            xrdjob = self.xrdjob_list[jobId - 1]  # joblist initilized when starting; we use the internal index to locate the job
            replica_dict = xrdjob.token_request

            deltaT = datetime.datetime.now().timestamp() - float(job_info['start'])
            if os.getenv('XRD_LOGLEVEL'): logging.debug(f'XRD copy job time:: {xrdjob.lfn} -> {deltaT}')

            if results['status'].ok:
                speed = float(job_info['bytes_total'])/deltaT
                speed_str = f'{GetHumanReadable(speed)}/s'
                if xrdjob.isUpload:  # isUpload
                    perm = '644'
                    ret_obj = commit(self.wb, replica_dict['envelope'], replica_dict['size'], xrdjob.lfn, perm, '0', replica_dict['url'], replica_dict['se'], replica_dict['guid'], replica_dict['md5'])
                    if self.debug:
                        print_out('MyCopyProgressHandler::commit result: ', end = '', flush = True)
                        retf_print(ret_obj, 'debug')
                else:  # isDownload
                    if 'ALIENPY_NOXRDZIP' in os.environ:  # NOXRDZIP was requested
                        if os.path.isfile(xrdjob.dst) and zipfile.is_zipfile(xrdjob.dst):
                            src_file_name = os.path.basename(xrdjob.lfn)
                            dst_file_name = os.path.basename(xrdjob.dst)
                            dst_file_path = os.path.dirname(xrdjob.dst)
                            zip_name = f'{xrdjob.dst}_{uuid.uuid4()}.zip'
                            os.replace(xrdjob.dst, zip_name)
                            with zipfile.ZipFile(zip_name) as myzip:
                                if src_file_name in myzip.namelist():
                                    out_path = myzip.extract(src_file_name, path = dst_file_path)
                                    if out_path and (src_file_name != dst_file_name): os.replace(src_file_name, dst_file_name)
                                else:  # the downloaded file is actually a zip file
                                    os.replace(zip_name, xrdjob.dst)
                            if os.path.isfile(zip_name): os.remove(zip_name)

                if not ('quiet' in self.printout or 'silent' in self.printout):
                    print_out(f"jobID: {jobId}/{self.jobs} >>> STATUS {status} >>> SPEED {speed_str}")
            else:
                if self.debug:
                    codes_info = f">>> ERRNO/CODE/XRDSTAT {results['status'].errno}/{results['status'].code}/{results['status'].status}"
                    xrd_resp_msg = results['status'].message
                    logging.debug(f"\n{codes_info}\n{xrd_resp_msg}")
                if xrdjob.isUpload:
                    self.copy_failed_list.append(xrdjob.token_request)
                    print_out(f"jobID: {jobId}/{self.jobs} >>> STATUS {status} : {xrdjob.token_request['file']} to {xrdjob.token_request['se']}, {xrdjob.token_request['nSEs']} replicas")
                    if self.debug: logging.debug(f"{xrdjob.token_request['file']}\n")
                else:
                    self.copy_failed_list.append(xrdjob.lfn)
                    print_out(f"jobID: {jobId}/{self.jobs} >>> STATUS {status} : {xrdjob.lfn}")
                    if self.debug: logging.debug(f"{xrdjob.lfn}\n")

            if not xrdjob.isUpload:
                meta_path, sep, url_opts = str(xrdjob.src).partition("?")
                if os.getenv('ALIENPY_KEEP_META'):
                    subprocess.run(shlex.split(f'mv {meta_path} {os.getcwd()}/'))
                else:
                    os.remove(meta_path)  # remove the created metalink

        def update(self, jobId, processed, total):
            self.job_list[jobId - 1]['bytes_processed'] = processed
            self.job_list[jobId - 1]['bytes_total'] = total

        def should_cancel(self, jobId):
            return False

    def XRD_EnvPut(key, value):
        """Sets the given key in the xrootd client environment to the given value.
        Returns false if there is already a shell-imported setting for this key, true otherwise"""
        if str(value).isdigit():
            return xrd_client.EnvPutInt(key, value)
        else:
            return xrd_client.EnvPutString(key, value)


def XrdCopy(wb, job_list: list, xrd_cp_args: XrdCpArgs, printout: str = '') -> list:
    """XRootD copy command :: the actual XRootD copy process"""
    if not _HAS_XROOTD:
        print_err("XRootD not found")
        return []
    if not xrd_cp_args:
        print_err("cp arguments are not set, XrdCpArgs tuple missing")
        return []

    overwrite = xrd_cp_args.overwrite
    batch = xrd_cp_args.batch
    sources = xrd_cp_args.sources
    chunks = xrd_cp_args.chunks
    chunksize = xrd_cp_args.chunksize
    makedir = xrd_cp_args.makedir
    tpc = xrd_cp_args.tpc
    posc = xrd_cp_args.posc
    # hashtype = xrd_cp_args.hashtype
    streams = xrd_cp_args.streams
    cksum = xrd_cp_args.cksum
    timeout = xrd_cp_args.timeout
    rate = xrd_cp_args.rate

    if streams > 0:
        if streams > 15: streams = 15
        xrd_client.EnvPutInt('SubStreamsPerChannel', streams)

    cksum_mode = 'none'
    cksum_type = ''
    delete_invalid_chk = False
    if cksum:
        xrd_client.EnvPutInt('ZipMtlnCksum', 1)
        cksum_mode = 'end2end'
        cksum_type = 'auto'
        delete_invalid_chk = True

    handler = MyCopyProgressHandler()
    handler.wb = wb
    handler.xrdjob_list = job_list
    handler.printout = printout
    if _DEBUG: handler.debug = True

    # get xrootd client version
    has_cksum = False
    if (_XRDVER_MAJOR and _XRDVER_MAJOR.isdecimal() and int(_XRDVER_MAJOR) >= 5) \
            or (_XRDVER_MAJOR and _XRDVER_MAJOR == '4' and int(_XRDVER_MINOR) > 12) \
            or (_XRDVER_DATE and int(_XRDVER_DATE) > 20200408):
        has_cksum = True

    process = xrd_client.CopyProcess()
    process.parallel(int(batch))
    for copy_job in job_list:
        if _DEBUG: logging.debug("\nadd copy job with\nsrc: {0}\ndst: {1}\n".format(copy_job.src, copy_job.dst))
        if has_cksum:
            process.add_job(copy_job.src, copy_job.dst, sourcelimit = sources,
                            force = overwrite, posc = posc, mkdir = makedir,
                            chunksize = chunksize, parallelchunks = chunks,
                            checksummode = cksum_mode, checksumtype = cksum_type, rmBadCksum = delete_invalid_chk)
        else:
            process.add_job(copy_job.src, copy_job.dst, sourcelimit = sources,
                            force = overwrite, posc = posc, mkdir = makedir,
                            chunksize = chunksize, parallelchunks = chunks)
    process.prepare()
    process.run(handler)
    return handler.copy_failed_list  # for upload jobs we must return the list of token for succesful uploads


def xrd_stat(pfn: str):
    if not _HAS_XROOTD:
        print_err('python XRootD module cannot be found, the copy process cannot continue')
        return None
    url_components = urlparse(pfn)
    endpoint = xrd_client.FileSystem(url_components.netloc)
    answer = endpoint.stat(url_components.path)
    return answer


def get_pfn_flags(pfn: str):
    answer = xrd_stat(pfn)
    if not answer[0].ok: return None
    return answer[1].flags


def is_pfn_readable(pfn: str) -> bool:
    flags = get_pfn_flags(pfn)
    if flags is None: return False
    return bool(flags & xrd_client.flags.StatInfoFlags.IS_READABLE)


def DO_pfnstatus(args: Union[list, None] = None) -> RET:
    global AlienSessionInfo
    if args is None: args = []
    if not args or is_help(args):
        msg = ('Command format: pfn_status <pfn>\n'
               'It will return all flags reported by the xrootd server - this is direct access to server')
        return RET(0, msg)
    pfn = args.pop(0)
    answer = xrd_stat(pfn)
    response_stat = answer[0]
    response_statinfo = answer[1]
    if not response_stat.ok:
        msg = (f'{response_stat.message}; code/status: {response_stat.code}/{response_stat.status}')
        return RET(response_stat.shellcode, '', msg)
    size = response_statinfo.size
    modtime = response_statinfo.modtimestr
    flags = response_statinfo.flags
    x_bit_set = 1 if flags & xrd_client.flags.StatInfoFlags.X_BIT_SET else 0
    is_dir = 1 if flags & xrd_client.flags.StatInfoFlags.IS_DIR else 0
    other = 1 if flags & xrd_client.flags.StatInfoFlags.OTHER else 0
    offline = 1 if flags & xrd_client.flags.StatInfoFlags.OFFLINE else 0
    posc_pending = 1 if flags & xrd_client.flags.StatInfoFlags.POSC_PENDING else 0
    is_readable = 1 if flags & xrd_client.flags.StatInfoFlags.IS_READABLE else 0
    is_writable = 1 if flags & xrd_client.flags.StatInfoFlags.IS_WRITABLE else 0
    msg = (f'''Size: {size}\n'''
           f'''Modification time: {modtime}\n'''
           f'''Executable bit: {x_bit_set}\n'''
           f'''Is directory: {is_dir}\n'''
           f'''Not a file or directory: {other}\n'''
           f'''File is offline (not on disk): {offline}\n'''
           f'''File opened with POSC flag, not yet successfully closed: {posc_pending}\n'''
           f'''Is readable: {is_readable}\n'''
           f'''Is writable: {is_writable}''')
    return RET(response_stat.shellcode, msg)


def get_pfn_list(wb, lfn: str) -> list:
    if not wb: return []
    if not lfn: return []
    if pathtype_grid(wb, lfn) != 'f': return []
    ret_obj = SendMsg(wb, 'whereis', [lfn], opts = 'nomsg')
    retf_print(ret_obj, 'debug')
    return [str(item['pfn']) for item in ret_obj.ansdict['results']]


def DO_getSE(wb, args: list = None) -> RET:
    if not wb: return []
    if not args: args = []
    if is_help(args):
        msg = 'Command format: getSE <-id | -name | -srv> identifier_string\nReturn the specified property for the SE specified label'
        return RET(0, msg)

    ret_obj = SendMsg(wb, 'listSEs', [], 'nomsg')
    if ret_obj.exitcode != 0: return ret_obj

    arg_select = None
    if get_arg(args, '-id'): arg_select = 'id'
    if get_arg(args, '-name'): arg_select = 'name'
    if get_arg(args, '-srv'): arg_select = 'srv'
    if arg_select is None: arg_select = 'name'

    if not args:
        se_list = [f"{se['seNumber']}\t{se['seName']}\t{se['endpointUrl'].replace('root://','')}" for se in ret_obj.ansdict["results"]]
        return RET(0, '\n'.join(se_list))

    def match_name(se: Union[dict, None] = None, name: str = '') -> bool:
        if se is None or not name: return False
        if name.isdecimal(): return name in se['seNumber']
        return name.casefold() in se['seName'].casefold() or name.casefold() in se['seNumber'].casefold() or name.casefold() in se['endpointUrl'].casefold()

    se_name = args[-1].casefold()
    se_list = []
    rez_list = []
    for se in ret_obj.ansdict["results"]:
        if match_name(se, se_name): se_list.append(se)
    if not se_list: return RET(1, '', f">{args[-1]}< label(s) not found in SE list")

    for se_info in se_list:
        srv_name = urlparse(se_info["endpointUrl"]).netloc.strip()
        if se_name.isdecimal():
            if arg_select == 'name':
                rez_list.append(se_info['seName'])
            elif arg_select == 'srv':
                rez_list.append(srv_name)
            else:
                rez_list.append(f"{se_info['seName']}    {srv_name}")
        else:
            if arg_select == 'name':
                rez_list.append(se_info['seName'])
            elif arg_select == 'srv':
                rez_list.append(srv_name)
            elif arg_select == 'id':
                rez_list.append(se_info['seNumber'])
            else:
                rez_list.append(f"{se_info['seNumber']}\t{se_info['seName']}\t\t{srv_name}")

    if not rez_list: return RET(1, '', f"Empty result when searching for: {args[-1]}")
    return RET(0, '\n'.join(rez_list))


def get_qos(wb, se_str: str) -> str:
    """Get qos tags for a given SE"""
    if not wb: return ''
    if '::' not in se_str: return ''  # the se name should have :: in it
    ret_obj = SendMsg(wb, 'listSEs', [], 'nomsg')
    for se in ret_obj.ansdict["results"]:
        if se["seName"].lower().replace('alice::', '') == se_str.lower().replace('alice::', ''):
            return se["qos"]
    return ''


def DO_SEqos(wb, args: list = None) -> RET:
    if not wb: return []
    if not args or is_help(args):
        msg = 'Command format: SEqos <SE name>\nReturn the QOS tags for the specified SE (ALICE:: can be ommited and capitalization does not matter)'
        return RET(0, msg)
    return RET(0, get_qos(wb, args[0]))


def get_lfn_meta(meta_fn: str) -> str:
    if not os.path.isfile(meta_fn): return ''
    content = xml.dom.minidom.parse(meta_fn).documentElement
    return content.getElementsByTagName('lfn')[0].firstChild.nodeValue


def lfn2tmp_fn(lfn: str = '', uuid5: bool = False) -> str:
    """make temporary file name that can be reconstructed back to the lfn"""
    if not lfn: return str(uuid.uuid4())
    if uuid5:
        return str(uuid.uuid5(uuid.NAMESPACE_URL, lfn))
    return lfn.replace("/", '%%')


def make_tmp_fn(lfn: str = '', ext: str = '', uuid5: bool = False) -> str:
    """make temporary file path string either random or based on grid lfn string"""
    if not ext: ext = f'_{str(os.getuid())}.alienpy_tmp'
    return f'{_TMPDIR}/{lfn2tmp_fn(lfn, uuid5)}{ext}'


def get_lfn_name(tmp_name: str = '', ext: str = '') -> str:
    lfn = tmp_name.replace(ext, '') if ext else tmp_name.replace(f'_{str(os.getuid())}.alienpy_tmp', '')
    return lfn.replace(f'{_TMPDIR}/', '').replace("%%", "/")


def download_tmp(wb, lfn: str, overwrite: bool = False) -> str:
    """Download a lfn to a temporary file, it will return the file path of temporary"""
    global AlienSessionInfo
    tmpfile = make_tmp_fn(expand_path_grid(wb, lfn))
    if os.path.isfile(tmpfile):
        if overwrite:
            os.remove(tmpfile)
            if tmpfile in AlienSessionInfo['templist']: AlienSessionInfo['templist'].remove(tmpfile)
        else:
            if tmpfile not in AlienSessionInfo['templist']: AlienSessionInfo['templist'].append(tmpfile)
            return tmpfile

    if tmpfile in AlienSessionInfo['templist']: AlienSessionInfo['templist'].remove(tmpfile)  # just in case it is still in list
    copycmd = f"-f {lfn} file:{tmpfile}"
    ret_obj = DO_XrootdCp(wb, copycmd.split(), printout = 'silent')  # print only errors for temporary downloads
    if ret_obj.exitcode == 0 and os.path.isfile(tmpfile):
        AlienSessionInfo['templist'].append(tmpfile)
        return tmpfile
    return ''


def upload_tmp(wb, temp_file_name: str, upload_specs: str = '', dated_backup: bool = False) -> str:
    """Upload a temporary file: the original lfn will be renamed and the new file will be uploaded with the original lfn"""
    lfn = get_lfn_name(temp_file_name)  # lets recover the lfn from temp file name
    lfn_backup = f'{lfn}.{now_str()}' if dated_backup else f'{lfn}~'
    if not dated_backup:
        ret_obj = SendMsg(wb, 'rm', ['-f', lfn_backup])  # remove already present old backup; useless to pre-check
    ret_obj = SendMsg(wb, 'mv', [lfn, lfn_backup])  # let's create a backup of old lfn
    retf_print(ret_obj, 'debug')
    if retf_print(ret_obj) != 0: return ''
    tokens = getEnvelope_lfn(wb, lfn2file(lfn, temp_file_name), [upload_specs], isWrite = True)
    access_request = tokens['answer']
    replicas = access_request["results"][0]["nSEs"]
    if "disk:" not in upload_specs: upload_specs = f'disk:{replicas}'
    if upload_specs: upload_specs = f'@{upload_specs}'
    copycmd = f'-f file:{temp_file_name} {lfn}{upload_specs}'
    ret_obj = DO_XrootdCp(wb, copycmd.split())
    if ret_obj.exitcode == 0: return lfn
    ret_obj = SendMsg(wb, 'mv', [lfn_backup, lfn])  # if the upload failed let's move back the backup to original lfn name'
    retf_print(ret_obj, 'debug')
    return ''


def queryML(args: list = None) -> str:
    """submit: process submit commands for local jdl cases"""
    global AlienSessionInfo
    alimon = 'http://alimonitor.cern.ch/rest/'
    type_json = '?Accept=application/json'
    type_xml = '?Accept=text/xml'
    type_plain = '?Accept=text/plain'
    type_default = ''
    predicate = ''

    if 'text' in args:
        type_default = type_plain
        args.remove('text')
    if 'xml' in args:
        type_default = type_xml
        args.remove('xml')
    if 'json' in args:
        type_default = type_json
        args.remove('json')

    if args: predicate = args[0]
    url = f"{alimon}{predicate}{type_default}"
    req = urlreq.urlopen(url)
    ansraw = req.read().decode()

    if req.getcode() == 200:
        AlienSessionInfo['exitcode'] = 0
    else:
        AlienSessionInfo['exitcode'] = req.getcode()
    return ansraw


def file2xml_el(filepath: str) -> ALIEN_COLLECTION_EL:
    """Get a file and return an XML element structure"""
    if not filepath or not os.path.isfile(filepath): return ALIEN_COLLECTION_EL()
    p = Path(filepath).expanduser().resolve(strict = True)
    p_stat = p.stat()
    turl = f'file://{p.as_posix()}'
    return ALIEN_COLLECTION_EL(
        name = p.name, aclId = "", broken = "0", ctime = time_unix2simple(p_stat.st_ctime),
        dir = '', entryId = '', expiretime = '', gowner = p.group(), guid = '', guidtime = '', jobid = '', lfn = turl,
        md5 = md5(p.as_posix()), owner = p.owner(), perm = str(oct(p_stat.st_mode))[5:], replicated = "0",
        size = str(p_stat.st_size), turl = turl, type = 'f')


def mk_xml_local(filepath_list: list):
    xml_root = ET.Element('alien')
    collection = ET.SubElement(xml_root, 'collection', attrib={'name': 'tempCollection'})
    for idx, item in enumerate(filepath_list, start = 1):
        e = ET.SubElement(collection, 'event', attrib={'name': str(idx)})
        f = ET.SubElement(e, 'file', attrib=file2xml_el(lfn_prefix_re.sub('', item))._asdict())
    oxml = ET.tostring(xml_root, encoding = 'ascii')
    dom = xml.dom.minidom.parseString(oxml)
    return dom.toprettyxml()


def DO_2xml(wb, args: Union[list, None] = None) -> RET:
    if args is None: args = []
    if not args or is_help(args):
        central_help = SendMsg(wb, 'toXml', ['-h'], opts = 'nokeys')
        central_help_msg = central_help.out
        msg_local = (f'\nAdditionally the client implements these options:'
                     '\n-local: specify that the target lfns are local files'
                     '\nfor -x (output file) and -l (file with lfns) the file: and alien: represent the location of file'
                     '\nthe inferred defaults are that the target files and the output files are of the same type'
                     )
        msg = f'{central_help_msg}{msg_local}'
        return RET(0, msg)

    is_local = get_arg(args, '-local')
    ignore_missing = get_arg(args, '-i')
    do_append = get_arg(args, '-a')
    output_file = get_arg_value(args, '-x')
    if do_append and output_file is None: return RET(1, '', 'Append operation need -x argument for specification of target file')

    lfn_filelist = get_arg_value(args, '-l')

    lfn_list = []
    find_arg_list = None
    lfn_arg_list = None

    if lfn_filelist:  # a given file with list of files/lfns was provided
        if is_local:
            if not os.path.exists(lfn_filelist): return RET(1, '', 'filelist {lfn_filelist} could not be found!!')
            filelist_content_list = file2list(lfn_filelist)
            if not filelist_content_list: return RET(1, '', f'No files could be read from {lfn_filelist}')
            if filelist_content_list[0].startswith('alien:'):
                return RET(1, '', 'Local filelists should contain only local files (not alien: lfns)')
            xml_coll = mk_xml_local(filelist_content_list)
            if output_file:
                if output_file.startswith('alien:'):
                    return RET(1, '', 'For the moment upload the resulting file by hand in grid')
                output_file = lfn_prefix_re.sub('', output_file)
                try:
                    with open(output_file, 'w') as f: f.write(xml_coll)
                    return RET(0)
                except Exception as e:
                    logging.exception(e)
                    return RET(1, '', f'Error writing {output_file}')
            else:
                return RET(0, xml_coll)
        else:
            grid_args = []
            if ignore_missing: grid_args.append('-i')
            if do_append: grid_args.append('-a')
            if lfn_filelist: grid_args.extend(['-l', lfn_filelist])
            if output_file and not output_file.startswith("file:"): grid_args.extend(['-x', lfn_prefix_re.sub('', output_file)])
            ret_obj = SendMsg(wb, 'toXml', grid_args)
            if output_file and output_file.startswith("file:"):
                output_file = lfn_prefix_re.sub('', output_file)
                try:
                    with open(output_file, 'w') as f: f.write(ret_obj.out)
                    return RET(0)
                except Exception as e:
                    logging.exception(e)
                    return RET(1, '', f'Error writing {output_file}')
            return ret_obj
        return RET(1, '', 'Allegedly unreachable point in DO_2xml. If you see this, contact developer!')

    else:
        lfn_arg_list = args.copy()  # the rest of arguments are lfns
        if is_local:
            lfn_list_obj_list = [file2file_dict(filepath) for filepath in lfn_arg_list]
            if not lfn_list_obj_list: return RET(1, '', f'Invalid list of files: {lfn_arg_list}')
            lfn_list = [get_lfn_key(lfn_obj) for lfn_obj in lfn_list_obj_list]
            xml_coll = mk_xml_local(lfn_list)
            if output_file:
                if output_file.startswith('alien:'):
                    return RET(1, '', 'For the moment upload the resulting file by hand in grid')
                output_file = lfn_prefix_re.sub('', output_file)
                with open(output_file, 'w') as f: f.write(xml_coll)
                return RET(0)
            else:
                return RET(0, xml_coll)
        else:
            grid_args = []
            if ignore_missing: grid_args.append('-i')
            if do_append: grid_args.append('-a')
            if output_file and not output_file.startswith("file:"): grid_args.extend(['-x', lfn_prefix_re.sub('', output_file)])
            grid_args.extend(lfn_arg_list)
            ret_obj = SendMsg(wb, 'toXml', grid_args)
            if output_file and output_file.startswith("file:"):
                output_file = lfn_prefix_re.sub('', output_file)
                try:
                    with open(output_file, 'w') as f: f.write(ret_obj.out)
                    return RET(0)
                except Exception as e:
                    logging.exception(e)
                    return RET(1, '', f'Error writing {output_file}')
            return ret_obj
        return RET(1, '', 'Allegedly unreachable point in DO_2xml. If you see this, contact developer!')


def DO_queryML(args: Union[list, None] = None) -> RET:
    """submit: process submit commands for local jdl cases"""
    global AlienSessionInfo
    if args is None: args = []
    if is_help(args):
        msg_help = ('usage: queryML <ML node>\n'
                    'time range can be specified for a parameter:\n'
                    '/[starting time spec]/[ending time spec]/parameter\n'
                    'where the two time specs can be given in absolute epoch timestamp (in milliseconds), as positive values,\n'
                    'or relative timestamp to `now`, when they are negative.\nFor example `-60000` would be "1 minute ago" and effectively `-1` means "now".')
        return RET(0, msg_help)
    types = ('text', 'xml', 'json')
    if any(type in types for arg in args): args.remove(type)
    args.append('json')
    ansraw = queryML(args)
    ans2dict = json.loads(ansraw)
    ans_list = ans2dict["results"]
    if len(ans_list) == 0:
        return RET(AlienSessionInfo['exitcode'], "", "queryML:: Empty answer")

    if 'Timestamp' in ans_list[0]:
        for item in ans_list: item['Timestamp'] = unixtime2local(item['Timestamp'])

    # all elements will have the same key names
    # n_columns = len(ans_list[0])
    keys = ans_list[0].keys()

    # establish keys width
    max_value_size = [len(key) for key in keys]
    for row in ans_list:
        for idx, key in enumerate(keys):
            max_value_size[idx] = max(max_value_size[idx], len(str(row.get(key))))
    max_value_size[:] = [w + 3 for w in max_value_size]

    # create width specification list
    row_format_list = [f'{{: <{str(w)}}}' for w in max_value_size]
    row_format = "".join(row_format_list)

    msg = row_format.format(*keys)
    for row in ans_list:
        value_list = [row.get(key) for key in keys]
        msg = f'{msg}\n{row_format.format(*value_list)}'
    return RET(AlienSessionInfo['exitcode'], msg, "")


def DO_submit(wb, args: Union[list, None] = None) -> RET:
    """submit: process submit commands for local jdl cases"""
    if not args or args is None: args = ['-h']
    if is_help(args): return get_help_srv(wb, 'submit')
    if args[0].startswith("file:"):
        msg = ("Specifications as where to upload the jdl to be submitted and with what parameters are not yet defined"
               "Upload first the jdl to a suitable location (with a safe number of replicas) and then submit")
        return RET(0, msg)
    args[0] = expand_path_grid(wb, args[0])
    return SendMsg(wb, 'submit', args)


def DO_ps(wb, args: Union[list, None] = None) -> RET:
    """ps : show and process ps output"""
    if args is None: args = []
    ret_obj = SendMsg(wb, 'ps', args)
    if '-trace' in args:
        nice_lines = [convert_time(str(msgline)) for item in ret_obj.ansdict['results'] for msgline in item['message'].split('\n')]
        return ret_obj._replace(out = '\n'.join(nice_lines))
    return ret_obj


def DO_cat(wb, args: Union[list, None] = None) -> RET:
    """cat lfn :: apply cat on a downloaded lfn as a temporary file"""
    args.insert(0, '-noout')  # keep app open, do not terminate
    args.insert(0, 'cat')
    return DO_run(wb, args, external = True)


def DO_less(wb, args: Union[list, None] = None) -> RET:
    """less lfn :: apply less on a downloaded lfn as a temporary file"""
    args.insert(0, '-noout')  # keep app open, do not terminate
    args.insert(0, 'less')
    return DO_run(wb, args, external = True)


def DO_more(wb, args: Union[list, None] = None) -> RET:
    """more lfn :: apply more on a downloaded lfn as a temporary file"""
    args.insert(0, '-noout')  # keep app open, do not terminate
    args.insert(0, 'more')
    return DO_run(wb, args, external = True)


def DO_pfn(wb, args: Union[list, None] = None) -> RET:
    if args is None: args = []
    if is_help(args):
        msg = 'Command format : pfn [lfn]\nIt will print only the list of associtated pfns (simplified form of whereis)'
        return RET(0, msg)
    cmd = 'whereis'
    args.insert(0, '-r')
    ret_obj = SendMsg(wb, cmd, args, opts = 'nomsg')
    msg = '\n'.join(str(item['pfn']) for item in ret_obj.ansdict['results'] if 'pfn' in item).strip()
    return ret_obj._replace(out = msg)


def token(wb, args: Union[None, list] = None) -> int:
    """(Re)create the tokencert and tokenkey files"""
    if not wb: return 1
    if not args: args = []
    global AlienSessionInfo
    tokencert, tokenkey = get_token_names(True)

    ret_obj = SendMsg(wb, 'token', args, opts = 'nomsg')
    if ret_obj.exitcode != 0: return retf_print(ret_obj)
    tokencert_content = ret_obj.ansdict.get('results')[0].get('tokencert', '')
    tokenkey_content = ret_obj.ansdict.get('results')[0].get('tokenkey', '')
    if not tokencert_content or not tokenkey_content: return int(1)

    if os.path.isfile(tokencert):
        os.chmod(tokencert, 0o600)  # make it writeable
        os.remove(tokencert)
    with open(tokencert, "w") as tcert: print(f"{tokencert_content}", file=tcert)  # write the tokencert
    os.chmod(tokencert, 0o400)  # make it readonly

    if os.path.isfile(tokenkey):
        os.chmod(tokenkey, 0o600)  # make it writeable
        os.remove(tokenkey)
    with open(tokenkey, "w") as tkey: print(f"{tokenkey_content}", file=tkey)  # write the tokenkey
    os.chmod(tokenkey, 0o400)  # make it readonly
    return ret_obj.exitcode


def token_regen(wb, args: Union[None, list] = None):
    global AlienSessionInfo
    if not AlienSessionInfo['use_usercert']:
        wb_close(wb, code = 1000, reason = 'Lets connect with usercert to be able to generate token')
        try:
            wb = InitConnection(use_usercert = True)  # we have to reconnect with the new token
        except Exception:
            logging.debug(traceback.format_exc())

    # now we are connected with usercert, so we can generate token
    if token(wb, args) != 0: return wb
    # we have to reconnect with the new token
    wb_close(wb, code = 1000, reason = 'Re-initialize the connection with the new token')
    try:
        AlienSessionInfo['use_usercert'] = False
        wb = InitConnection()
    except Exception:
        logging.debug(traceback.format_exc())
    return wb


def DO_token(wb, args: Union[list, None] = None) -> RET:
    if args is None: args = []
    msg = "Print only command!!! Use >token-init< for token (re)generation, see below the arguments\n"
    ret_obj = SendMsg(wb, 'token', args, opts = 'nokeys')
    return ret_obj._replace(out = f'{msg}{ret_obj.out}')


def DO_token_init(wb, args: Union[list, None] = None) -> RET:
    if args is None: args = []
    if len(args) > 0 and is_help(args):
        ret_obj = SendMsg(wb, 'token', ['-h'], opts = 'nokeys')
        return ret_obj._replace(out = ret_obj.out.replace('usage: token', 'usage: token-init'))
    wb = token_regen(wb, args)
    tokencert, tokenkey = get_token_names()
    return CertInfo(tokencert)


def DO_edit(wb, args: Union[list, None] = None, editor: str = '') -> RET:
    """Edit a grid lfn; download a temporary, edit with the specified editor and upload the new file"""
    if not args or args is None: args = ['-h']
    if is_help(args):
        msg = """Command format: edit lfn\nAfter editor termination the file will be uploaded if md5 differs
-datebck : the backup filename will be date based
N.B. EDITOR env var must be set or fallback will be mcedit (not checking if exists)"""
        return RET(0, msg)
    if not editor:
        editor = os.getenv('EDITOR')
        if not editor:
            print_out('EDITOR env variable not set, we will fallback to mcedit (no check if exists)')
            editor = 'mcedit -u'
    versioned_backup = False
    if get_arg(args, '-datebck'): versioned_backup = True
    lfn = expand_path_grid(wb, args[-1])  # assume that the last argument is the lfn
    # check for valid (single) specifications delimiter
    count_tokens = collections.Counter(lfn)
    if count_tokens[','] + count_tokens['@'] > 1:
        msg = f"At most one of >,< or >@< tokens used for copy specification can be present in the argument. The offender is: {''.join(count_tokens)}"
        return RET(64, '', msg)  # EX_USAGE /* command line usage error */

    specs = specs_split.split(lfn, maxsplit = 1)  # NO comma allowed in grid names (hopefully)
    lfn = specs.pop(0)  # first item is the file path, let's remove it; it remains disk specifications
    tmp = download_tmp(wb, lfn)
    if tmp and os.path.isfile(tmp):
        md5_begin = md5(tmp)
        ret_obj = runShellCMD(f'{editor} {tmp}', captureout = False)
        if ret_obj.exitcode != 0: return retf_print(ret_obj)
        md5_end = md5(tmp)
        if md5_begin != md5_end:
            uploaded_file = upload_tmp(wb, tmp, ','.join(specs), dated_backup = versioned_backup)
            os.remove(tmp)  # clean up the temporary file not matter if the upload was succesful or not
            return RET(0, f'Uploaded {uploaded_file}') if uploaded_file else RET(1, '', f'Error uploading {uploaded_file}')
        return RET(0)
    return RET(1, '', f'Error downloading {lfn}, editing could not be done.')


def DO_mcedit(wb, args: Union[list, None] = None) -> RET: return DO_edit(wb, args, editor = 'mcedit')


def DO_vi(wb, args: Union[list, None] = None) -> RET: return DO_edit(wb, args, editor = 'vi')


def DO_vim(wb, args: Union[list, None] = None) -> RET: return DO_edit(wb, args, editor = 'vim')


def DO_nano(wb, args: Union[list, None] = None) -> RET: return DO_edit(wb, args, editor = 'nano')


def DO_run(wb, args: Union[list, None] = None, external: bool = False) -> RET:
    """run shell_command lfn|alien: tagged lfns :: download lfn(s) as a temporary file and run shell command on the lfn(s)"""
    if args is None: args = []
    if not args: return RET(1, '', 'No shell command specified')
    if is_help(args) or len(args) == 1:
        msg_last = ('Command format: shell_command arguments lfn\n'
                    'N.B.!! the lfn must be the last element of the command!!\n'
                    'N.B.! The output and error streams will be captured and printed at the end of execution!\n'
                    'for working within application use <edit> or -noout argument\n'
                    'additiona arguments recognized independent of the shell command:\n'
                    '-force : will re-download the lfn even if already present\n'
                    '-noout : will not capture output, the actual application can be used')

        if external:
            ret_obj = runShellCMD(f'{args[0]} -h', captureout = True, do_shell = True)
            return ret_obj._replace(out = f'{ret_obj.out}\n{msg_last}')
        msg = ('Command format: run shell_command arguments lfn\n'
               'the lfn must be the last element of the command\n'
               'N.B.! The output and error streams will be captured and printed at the end of execution!\n'
               'for working within application use <edit>\n'
               'additiona arguments recognized independent of the shell command:\n'
               '-force : will re-download the lfn even if already present\n'
               '-noout : will not capture output, the actual application can be used')
        return RET(0, msg)

    overwrite = get_arg(args, '-force')
    capture_out = get_arg(args, '-noout')

    list_of_lfns = [arg for arg in args if 'alien:' in arg]
    if not list_of_lfns: list_of_lfns = [args.pop(-1)]

    tmp_list = [download_tmp(wb, lfn, overwrite) for lfn in list_of_lfns]  # list of temporary downloads
    new_args = [arg for arg in args if arg not in list_of_lfns]  # command arguments without the files
    args = list(new_args)
    cmd = " ".join(args)
    files = " ".join(tmp_list)
    if tmp_list and all(os.path.isfile(tmp) for tmp in tmp_list):
        return runShellCMD(f'{cmd} {files}', capture_out, do_shell = True)
    return RET(1, '', f'There was an error downloading the following files:\n{chr(10).join(tmp_list)}')


def DO_exec(wb,  args: Union[list, None] = None) -> RET:
    """exec lfn :: download lfn as a temporary file and executed in the shell"""
    if args is None: args = []
    if not args or is_help(args):
        msg = ('Command format: exec lfn list_of_arguments\n'
               'N.B.! The output and error streams will be captured and printed at the end of execution!\n'
               'for working within application use <edit>')
        return RET(0, msg)

    overwrite = get_arg(args, '-force')
    capture_out = get_arg(args, '-noout')

    lfn = args.pop(0)  # the script to be executed
    opt_args = " ".join(args)
    tmp = download_tmp(wb, lfn, overwrite)
    if tmp and os.path.isfile(tmp):
        os.chmod(tmp, 0o700)
        return runShellCMD(f'{tmp} {opt_args}' if opt_args else tmp, capture_out)
    return RET(1, '', f'There was an error downloading script: {lfn}')


def DO_syscmd(wb, cmd: str = '', args: Union[None, list, str] = None) -> RET:
    """run system command with all the arguments but all alien: specifications are downloaded to temporaries"""
    global AlienSessionInfo
    if args is None: args = []
    if isinstance(args, str): args = args.split()
    if not cmd: return RET(1, '', 'No system command specified!')
    new_arg_list = [download_tmp(wb, arg) if arg.startswith('alien:') else arg for arg in args]
    new_arg_list.index(0, cmd)
    return runShellCMD(' '.join(new_arg_list), captureout = True, do_shell = True)


def DO_find2(wb,  args: list) -> RET:
    if args is None: args = []
    if is_help(args):
        msg_client = (f'''Client-side implementation of find, it contain the following helpers.
Command formant: find2 <options> <directory>
-select <pattern> : select only these files; {PrintColor(COLORS.BIGreen)}N.B. this is a REGEX applied to full path!!!{PrintColor(COLORS.ColorReset)} defaults to all ".*"
-name <pattern> : select only these files; {PrintColor(COLORS.BIGreen)}N.B. this is a REGEX applied to a directory or file name!!!{PrintColor(COLORS.ColorReset)} defaults to all ".*"
-name <verb>_string : where verb = begin|contain|ends|ext and string is the text selection criteria. verbs are aditive e.g.:
-name begin_myf_contain_run1_ends_bla_ext_root
{PrintColor(COLORS.BIRed)}N.B. the text to be filtered cannont have underline <_> within!!!{PrintColor(COLORS.ColorReset)}\n
The server options:''')
        srv_answ = get_help_srv(wb, 'find')
        msg_srv = srv_answ.out
        return RET(0, f'{msg_client}\n{msg_srv}')

    find_args = ['-a', '-s']
    get_arg(args, '-a')
    get_arg(args, '-s')
    if get_arg(args, '-v'): print_out("Verbose mode not implemented, ignored")

    pattern = '*'
    pattern_regex = None
    use_regex = False
    filtering_enabled = False

    glob_arg = get_arg_value(args, '-glob')
    if glob_arg:
        pattern = glob_arg
        use_regex = False
        filtering_enabled = True

    select_arg = get_arg_value(args, '-select')
    if select_arg:
        if filtering_enabled:
            msg = "Only one rule of selection can be used, either -select (full path match), -name (match on file name) or -glob (globbing)"
            return RET(22, '', msg)  # EINVAL /* Invalid argument */
        pattern_regex = select_arg
        use_regex = True
        filtering_enabled = True

    name_arg = get_arg_value(args, '-name')
    if name_arg:
        if filtering_enabled:
            msg = "Only one rule of selection can be used, either -select (full path match), -name (match on file name) or -glob (globbing)"
            return RET(22, '', msg)  # EINVAL /* Invalid argument */
        pattern_regex_arg = name_arg
        use_regex = True
        filtering_enabled = True

        pattern_regex = name2regex(pattern_regex_arg)
        if use_regex and not pattern_regex:
            msg = ("No selection verbs were recognized!"
                   "usage format is -name <attribute>_<string> where attribute is one of: begin, contain, ends, ext"
                   f"The invalid pattern was: {pattern_regex_arg}")
            return RET(22, '', msg)  # EINVAL /* Invalid argument */

    if use_regex:
        find_args.insert(0, '-r')
        pattern = pattern_regex
    start_location = args[-1] if filtering_enabled else args[-2]
    find_args.append(expand_path_grid(wb, start_location))
    find_args.append(pattern)
    return SendMsg(wb, 'find', find_args, opts = 'nokeys')


def runShellCMD(INPUT: str = '', captureout: bool = True, do_shell: bool = False, timeout: Union[str, int, None] = None) -> RET:
    """Run shell command in subprocess; if exists, print stdout and stderr"""
    if not INPUT: return RET(1, '', 'No command to be run provided')
    sh_cmd = re.sub(r'^!', '', INPUT)
    args = sh_cmd if do_shell else shlex.split(sh_cmd)
    capture_args = {'stdout': subprocess.PIPE, 'stderr': subprocess.PIPE} if captureout else {}
    status = exitcode = except_msg = None
    msg_out = msg_err = ''
    try:
        status = subprocess.run(args, encoding = 'utf-8', errors = 'replace', shell = do_shell, **capture_args)  # pylint: disable=subprocess-run-check
    except subprocess.TimeoutExpired:
        print_err(f"Expired timeout: {timeout} for: {sh_cmd}")
        exitcode = int(62)
    except FileNotFoundError:
        print_err(f"Command not found: {sh_cmd}")
        exitcode = int(2)
    except Exception as e:
        ex_type, ex_value, ex_traceback = sys.exc_info()
        except_msg = f'Exception:: {ex_type} -> {ex_value}\n{ex_traceback}\n'
        exitcode = int(1)

    if status:
        if status.stdout: msg_out = status.stdout.strip()
        if status.stderr: msg_err = status.stderr.strip()
        exitcode = status.returncode
    if except_msg: msg_err = f'{except_msg}{msg_err}'
    return RET(exitcode, msg_out, msg_err)


def DO_quota(wb, args: Union[None, list] = None) -> RET:
    """quota : put togheter both job and file quota"""
    if not args: args = []
    if is_help(args):
        msg = ('Client-side implementation that make use of server\'s jquota and fquota (hidden by this implementation)\n'
               'Command format: quota [user]\n'
               'if [user] is not provided, it will be assumed the current user')
        return RET(0, msg)

    user = AlienSessionInfo['user']
    if len(args) > 0:
        if args[0] != "set":  # we asume that if 'set' is not used then the argument is a username
            user = args[0]
        else:
            msg = '>set< functionality not implemented yet'
            return RET(0, msg)

    jquota_out = SendMsg(wb, f'jquota -nomsg list {user}')
    jquota_dict = jquota_out.ansdict
    fquota_out = SendMsg(wb, f'fquota -nomsg list {user}')
    fquota_dict = fquota_out.ansdict

    username = jquota_dict['results'][0]["username"]
    running_time = float(jquota_dict['results'][0]["totalRunningTimeLast24h"])/3600
    running_time_max = float(jquota_dict['results'][0]["maxTotalRunningTime"])/3600
    running_time_perc = (running_time/running_time_max)*100
    cpucost = float(jquota_dict['results'][0]["totalCpuCostLast24h"])/3600
    cpucost_max = float(jquota_dict['results'][0]["maxTotalCpuCost"])/3600
    cpucost_perc = (cpucost/cpucost_max)*100
    pjobs_nominal = int(jquota_dict['results'][0]["nominalparallelJobs"])
    pjobs_max = int(jquota_dict['results'][0]["maxparallelJobs"])

    unfinishedjobs_max = int(jquota_dict['results'][0]["maxUnfinishedJobs"])
    waiting = int(jquota_dict['results'][0]["waiting"])

    size = float(fquota_dict['results'][0]["totalSize"])
    size_MiB = size/(1024*1024)
    size_max = float(fquota_dict['results'][0]["maxTotalSize"])
    size_max_MiB = size_max/(1024*1024)
    size_perc = (size/size_max)*100

    files = float(fquota_dict['results'][0]["nbFiles"])
    files_max = float(fquota_dict['results'][0]["maxNbFiles"])
    files_perc = (files/files_max)*100

    msg = (f"""Quota report for user : {username}
Running time (last 24h) :\t{running_time:.2f}/{running_time_max:.2f}(h) --> {running_time_perc:.2f}% used
CPU Cost :\t\t\t{cpucost:.2f}/{cpucost_max:.2f}(h) --> {cpucost_perc:.2f}% used
ParallelJobs (nominal/max) :\t{pjobs_nominal}/{pjobs_max}
Unfinished jobs :\t\tMAX={unfinishedjobs_max}
Waiting :\t\t\t{waiting}
Storage size :\t\t\t{size_MiB:.2f}/{size_max_MiB:.2f} MiB --> {size_perc:.2f}%
Number of files :\t\t{files}/{files_max} --> {files_perc:.2f}%""")
    return RET(0, msg)


def check_ip_port(addr_port: tuple) -> bool:
    """Check connectivity to an address, port; adress should be the tuple given by getaddrinfo"""
    if not addr_port: return False
    s = socket.socket()  # Create a TCP socket
    s.settimeout(2)  # timeout 2s
    is_open = False
    try:
        s.connect(addr_port)
        is_open = True
    except Exception:
        pass
    s.close()
    return is_open


def check_port(address: str, port: Union[str, int]) -> list:
    """Check TCP connection to fqdn:port"""
    ip_list = socket.getaddrinfo(address, int(port), proto = socket.IPPROTO_TCP)
    return [(*ip_port[-1], check_ip_port(ip_port[-1])) for ip_port in ip_list]


def isReachable(address: str = 'alice-jcentral.cern.ch', port: Union[str, int] = 8097) -> bool:
    result_list = check_port(address, port)
    for ip in result_list:
        if ip[-1]: return True
    return False


def DO_checkAddr(args: Union[list, None] = None) -> RET:
    global AlienSessionInfo
    if is_help(args):
        msg = ('checkAddr [reference] fqdn/ip port\n'
               'defaults are: alice-jcentral.cern.ch 8097\n'
               'reference arg will check connection to google dns and www.cern.ch')
        return RET(0, msg)
    result_list = []
    if get_arg(args, 'reference'):
        result_list.extend(check_port('8.8.8.8', 53))
        result_list.extend(check_port('2001:4860:4860::8888', 53))
        result_list.extend(check_port('www.cern.ch', 80))
    addr = args[0] if args else 'alice-jcentral.cern.ch'
    port = args[1] if (args and len(args) > 1) else 8097
    result_list.extend(check_port(addr, port))
    stdout = ''
    for res in result_list:
        stdout += f'{res[0]}:{res[1]}        {PrintColor(COLORS.BIGreen) + "OK" if res[2] else PrintColor(COLORS.BIRed) + "FAIL"}{PrintColor(COLORS.ColorReset)}\n'
    return RET(0, stdout)


def get_help(wb, cmd: str = '') -> RET:
    """Return the help option even for client-side commands"""
    if not cmd: return RET(1, '', 'No command specified for help')
    return ProcessInput(wb, cmd, ['-h'])


def get_help_srv(wb, cmd: str = '') -> RET:
    """Return the help option for server-side known commands"""
    if not cmd: return RET(1, '', 'No command specified for help request')
    return SendMsg(wb, f'{cmd} -h')


def DO_help(wb, args: Union[list, None] = None) -> RET:
    global AlienSessionInfo
    if args is None: args = []
    if not args:
        msg = ('Project documentation can be found at:\n'
               'https://jalien.docs.cern.ch/\n'
               'https://gitlab.cern.ch/jalien/xjalienfs/blob/master/README.md\n'
               'the following commands are available:')
        nr = len(AlienSessionInfo['commandlist'])
        column_width = 24
        try:
            columns = os.get_terminal_size()[0]//column_width
        except Exception:
            columns = 5

        for ln in range(0, nr, columns):
            if ln + 1 > nr: ln = nr - 1
            el_ln = AlienSessionInfo['commandlist'][ln:ln + columns]
            ln = [str(i).ljust(column_width) for i in el_ln]
            msg = f'{msg}\n{"".join(ln)}'
        return RET(0, msg)
    return get_help(wb, args.pop(0))


def DO_user(wb, args: Union[list, None] = None) -> RET:
    global AlienSessionInfo
    if args is None: args = []
    ret_obj = SendMsg(wb, 'user', args)
    if ret_obj.exitcode == 0 and 'homedir' in ret_obj.ansdict['results'][0]: AlienSessionInfo['alienHome'] = ret_obj.ansdict['results'][0]['homedir']
    return ret_obj


def DO_prompt(args: Union[list, None] = None) -> RET:
    """Add local dir and date information to the alien.py shell prompt"""
    global AlienSessionInfo
    if args is None: args = []
    if not args or is_help(args):
        msg = "Toggle the following in the command prompt : <date> for date information and <pwd> for local directory"
        return RET(0, msg)

    if 'date' in args: AlienSessionInfo['show_date'] = (not AlienSessionInfo['show_date'])
    if 'pwd' in args: AlienSessionInfo['show_lpwd'] = (not AlienSessionInfo['show_lpwd'])
    return RET(0)


def get_list_entries(wb, lfn, fullpath: bool = False) -> list:
    """return a list of entries of the lfn argument, full paths if 2nd arg is True"""
    key = 'path' if fullpath else 'name'
    ret_obj = SendMsg(wb, 'ls', ['-nomsg', '-a', '-F', os.path.normpath(lfn)])
    return list(item[key] for item in ret_obj.ansdict['results']) if ret_obj.exitcode == 0 else []


def lfn_list(wb, lfn: str = ''):
    """Completer function : for a given lfn return all options for latest leaf"""
    if not wb: return []
    if not lfn: lfn = '.'  # AlienSessionInfo['currentdir']
    list_lfns = []
    lfn_path = Path(lfn)
    base_dir = '/' if lfn_path.parent.as_posix() == '/' else f'{lfn_path.parent.as_posix()}/'
    name = f'{lfn_path.name}/' if lfn.endswith('/') else lfn_path.name

    def item_format(base_dir, name, item):
        # print_out(f'\nbase_dir: {base_dir} ; name: {name} ; item: {item}')
        if name.endswith('/') and name != '/':
            return f'{name}{item}' if base_dir == './' else f'{base_dir}{name}{item}'
        return item if base_dir == './' else f'{base_dir}{item}'

    if lfn.endswith('/'):
        listing = get_list_entries(wb, lfn)
        list_lfns = [item_format(base_dir, name, item) for item in listing]
    else:
        listing = get_list_entries(wb, base_dir)
        list_lfns = [item_format(base_dir, name, item) for item in listing if item.startswith(name)]
    # print_out(f'\n{list_lfns}\n')
    return list_lfns


def wb_ping(wb) -> float:
    """Websocket ping function, it will return rtt in ms"""
    init_delta = float(-999.0)
    init_begin = datetime.datetime.now().timestamp()
    if IsWbConnected(wb):
        init_end = datetime.datetime.now().timestamp()
        init_delta = float((init_end - init_begin) * 1000)
        return init_delta
    return float(-1)


def DO_ping(wb, args: Union[list, None] = None) -> RET:
    """Command implementation for ping functionality"""
    if args is None: args = []
    if is_help(args): return RET(0, "ping <count>\nwhere count is integer")

    if len(args) > 0 and args[0].isdigit():
        count = int(args[0])
    elif not args:
        count = int(3)
    else:
        return RET(1, '', 'Unrecognized argument, it should be int type')

    results = []
    for i in range(count):
        p = wb_ping(wb)
        results.append(p)

    rtt_min = min(results)
    rtt_max = max(results)
    rtt_avg = statistics.mean(results)
    rtt_stddev = statistics.stdev(results) if len(results) > 1 else 0.0
    endpoint = wb.remote_address[0]
    msg = (f"Websocket ping/pong(s) : {count} time(s) to {endpoint}\nrtt min/avg/max/mdev (ms) = {rtt_min:.3f}/{rtt_avg:.3f}/{rtt_max:.3f}/{rtt_stddev:.3f}")
    return RET(0, msg)


def get_files_cert() -> list:
    return (os.getenv('X509_USER_CERT', f'{Path.home().as_posix()}/.globus/usercert.pem'), os.getenv('X509_USER_KEY', f'{Path.home().as_posix()}/.globus/userkey.pem'))


def get_token_names(files: bool = False) -> tuple:
    if files:
        return (f'{_TMPDIR}/tokencert_{str(os.getuid())}.pem', f'{_TMPDIR}/tokenkey_{str(os.getuid())}.pem')
    else:
        return os.getenv('JALIEN_TOKEN_CERT', f'{_TMPDIR}/tokencert_{str(os.getuid())}.pem'), os.getenv('JALIEN_TOKEN_KEY', f'{_TMPDIR}/tokenkey_{str(os.getuid())}.pem')


def DO_tokendestroy(args: Union[list, None] = None) -> RET:
    if args is None: args = []
    if len(args) > 0 and is_help(args): return RET(0, "Delete the token{cert,key}.pem files")
    tokencert, tokenkey = get_token_names()
    if os.path.exists(tokencert): os.remove(tokencert)
    if os.path.exists(tokenkey): os.remove(tokenkey)
    return RET(0, "Token was destroyed! Re-connect for token re-creation.")


def IsValidCert(fname: str):
    """Check if the certificate file (argument) is present and valid. It will return false also for less than 5min of validity"""
    try:
        with open(fname) as f:
            cert_bytes = f.read()
    except Exception:
        return False

    try:
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_bytes)
    except Exception:
        return False

    x509_notafter = x509.get_notAfter()
    utc_time = datetime.datetime.strptime(x509_notafter.decode("utf-8"), "%Y%m%d%H%M%SZ")
    time_notafter = int((utc_time - datetime.datetime(1970, 1, 1)).total_seconds())
    time_current  = int(datetime.datetime.now().timestamp())
    time_remaining = time_notafter - time_current
    return time_remaining > 300


def CertInfo(fname: str) -> RET:
    """Print certificate information (subject, issuer, notbefore, notafter)"""
    try:
        with open(fname) as f:
            cert_bytes = f.read()
    except Exception:
        return RET(2, "", f"File >>>{fname}<<< not found")  # ENOENT /* No such file or directory */

    try:
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_bytes)
    except Exception:
        return RET(5, "", f"Could not load certificate >>>{fname}<<<")  # EIO /* I/O error */

    utc_time_notafter = datetime.datetime.strptime(x509.get_notAfter().decode("utf-8"), "%Y%m%d%H%M%SZ")
    utc_time_notbefore = datetime.datetime.strptime(x509.get_notBefore().decode("utf-8"), "%Y%m%d%H%M%SZ")
    issuer = '/%s' % ('/'.join(['%s=%s' % (k.decode("utf-8"), v.decode("utf-8")) for k, v in x509.get_issuer().get_components()]))
    subject = '/%s' % ('/'.join(['%s=%s' % (k.decode("utf-8"), v.decode("utf-8")) for k, v in x509.get_subject().get_components()]))
    info = f"DN >>> {subject}\nISSUER >>> {issuer}\nBEGIN >>> {utc_time_notbefore}\nEXPIRE >>> {utc_time_notafter}"
    return RET(0, info)


def DO_certinfo(args: Union[list, None] = None) -> RET:
    if args is None: args = []
    cert, key = get_files_cert()
    if len(args) > 0 and is_help(args): return RET(0, "Print user certificate information", "")
    return CertInfo(cert)


def DO_tokeninfo(args: Union[list, None] = None) -> RET:
    if not args: args = []
    if len(args) > 0 and is_help(args): return RET(0, "Print token certificate information", "")
    tokencert, tokenkey = get_token_filenames()
    return CertInfo(tokencert)


def CertVerify(fname: str) -> RET:
    """Print certificate information (subject, issuer, notbefore, notafter)"""
    try:
        with open(fname) as f:
            cert_bytes = f.read()
    except Exception:
        return RET(2, "", f"File >>>{fname}<<< not found")  # ENOENT /* No such file or directory */

    try:
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_bytes)
    except Exception:
        logging.debug(traceback.format_exc())
        return RET(5, "", f"Could not load certificate >>>{fname}<<<")  # EIO /* I/O error */

    x509store = OpenSSL.crypto.X509Store()
    x509store.set_flags(OpenSSL.crypto.X509StoreFlags.ALLOW_PROXY_CERTS)
    ca_verify_location = get_ca_path()
    try:
        if os.path.isfile(ca_verify_location):
            x509store.load_locations(cafile = ca_verify_location)
        else:
            x509store.load_locations(None, capath = ca_verify_location)
    except Exception:
        logging.debug(traceback.format_exc())
        return RET(5, "", f"Could not load verify location >>>{ca_verify_location}<<<")  # EIO /* I/O error */

    store_ctx = OpenSSL.crypto.X509StoreContext(x509store, x509)
    try:
        store_ctx.verify_certificate()
        return RET(0, f'SSL Verification {PrintColor(COLORS.BIGreen)}succesful{PrintColor(COLORS.ColorReset)} for {fname}')
    except Exception:
        logging.debug(traceback.format_exc())
        return RET(1, '', f'SSL Verification {PrintColor(COLORS.BIRed)}failed{PrintColor(COLORS.ColorReset)} for {fname}')


def DO_certverify(args: Union[list, None] = None) -> RET:
    if args is None: args = []
    cert, key = get_files_cert()
    if len(args) > 0 and is_help(args): return RET(0, "Verify the user cert against the found CA stores (file or directory)", "")
    return CertVerify(cert)


def DO_tokenverify(args: Union[list, None] = None) -> RET:
    if not args: args = []
    if len(args) > 0 and is_help(args): return RET(0, "Print token certificate information", "")
    tokencert, tokenkey = get_token_filenames()
    return CertVerify(tokencert)


def CertKeyMatch(cert_fname: str, key_fname: str) -> RET:
    """Check if Certificate and key match"""
    try:
        with open(cert_fname) as f: cert_bytes = f.read()
        x509cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_bytes)
    except Exception:
        logging.debug(traceback.format_exc())
        return RET(5, "", f'Could not load certificate >>>{cert_fname}<<<')  # EIO /* I/O error */

    try:
        with open(key_fname) as g: key_bytes = g.read()
        x509key = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, key_bytes)
    except Exception:
        logging.debug(traceback.format_exc())
        return RET(5, "", f'Could not load key >>>{key_fname}<<<')  # EIO /* I/O error */

    context = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_METHOD)
    context.use_privatekey(x509key)
    context.use_certificate(x509cert)
    try:
        context.check_privatekey()
        return RET(0, f'Cert/key {PrintColor(COLORS.BIGreen)}match{PrintColor(COLORS.ColorReset)}')
    except OpenSSL.SSL.Error:
        return RET(0, '', f'Cert/key {PrintColor(COLORS.BIRed)}DO NOT match{PrintColor(COLORS.ColorReset)}')


def DO_certkeymatch(args: Union[list, None] = None) -> RET:
    if args is None: args = []
    cert, key = get_files_cert()
    if len(args) > 0 and is_help(args): return RET(0, "Check match of user cert with key cert", "")
    return CertKeyMatch(cert, key)


def DO_tokenkeymatch(args: Union[list, None] = None) -> RET:
    if args is None: args = []
    cert, key = get_token_filenames()
    if len(args) > 0 and is_help(args): return RET(0, "Check match of user token with key token", "")
    return CertKeyMatch(cert, key)


def get_ca_path() -> str:
    """Return either the CA path or file; bailout application if not found"""
    system_ca_path = '/etc/grid-security/certificates'
    alice_cvmfs_ca_path_lx = '/cvmfs/alice.cern.ch/etc/grid-security/certificates'
    alice_cvmfs_ca_path_macos = f'/Users/Shared{alice_cvmfs_ca_path_lx}'

    x509file = os.getenv('X509_CERT_FILE') if os.path.isfile(str(os.getenv('X509_CERT_FILE'))) else ''
    if x509file:
        if _DEBUG: logging.debug(f'X509_CERT_FILE = {x509file}')
        return x509file

    x509dir = os.getenv('X509_CERT_DIR') if os.path.isdir(str(os.getenv('X509_CERT_DIR'))) else ''
    if x509dir:
        if _DEBUG: logging.debug(f'X509_CERT_DIR = {x509dir}')
        return x509dir

    capath_default = None
    if os.path.exists(alice_cvmfs_ca_path_lx):
        capath_default = alice_cvmfs_ca_path_lx
    elif os.path.exists(alice_cvmfs_ca_path_macos):
        capath_default = alice_cvmfs_ca_path_macos
    else:
        if os.path.exists(system_ca_path): capath_default = system_ca_path

    if not capath_default:
        msg = "No CA location or files specified or found!!! Connection will not be possible!!"
        print_err(msg)
        logging.info(msg)
        sys.exit(2)
    if _DEBUG: logging.debug(f'CApath = {capath_default}')
    return capath_default


def get_token_filenames() -> tuple:
    """Get the token filenames, including the temporary ones used as env variables"""
    global AlienSessionInfo
    tokencert, tokenkey = get_token_names()
    random_str = None
    if not os.path.isfile(tokencert) and tokencert.startswith('-----BEGIN CERTIFICATE-----'):  # and is not a file
        random_str = str(uuid.uuid4())
        temp_cert = tempfile.NamedTemporaryFile(prefix = 'tokencert_', suffix = f'_{str(os.getuid())}_{random_str}.pem', delete = False)
        temp_cert.write(tokencert.encode(encoding="ascii", errors="replace"))
        temp_cert.seek(0)
        tokencert = temp_cert.name  # temp file was created, let's give the filename to tokencert
        AlienSessionInfo['templist'].append(tokencert)
    if not os.path.isfile(tokenkey) and tokenkey.startswith('-----BEGIN RSA PRIVATE KEY-----'):  # and is not a file
        if random_str is None: random_str = str(uuid.uuid4())
        temp_key = tempfile.NamedTemporaryFile(prefix = 'tokenkey_', suffix = f'_{str(os.getuid())}_{random_str}.pem', delete = False)
        temp_key.write(tokenkey.encode(encoding="ascii", errors="replace"))
        temp_key.seek(0)
        tokenkey = temp_key.name  # temp file was created, let's give the filename to tokenkey
        AlienSessionInfo['templist'].append(tokenkey)
    return (tokencert, tokenkey) if (IsValidCert(tokencert) and os.path.isfile(tokenkey)) else (None, None)


def create_ssl_context(use_usercert: bool = False) -> ssl.SSLContext:
    """Create SSL context using either the default names for user certificate and token certificate or X509_USER_{CERT,KEY} JALIEN_TOKEN_{CERT,KEY} environment variables"""
    global AlienSessionInfo
    # SSL SETTINGS
    cert = key = None  # vars for discovered credentials
    usercert, userkey = get_files_cert()
    tokencert, tokenkey = get_token_filenames()

    if not use_usercert and tokencert and tokenkey:
        cert, key = tokencert, tokenkey
        AlienSessionInfo['use_usercert'] = False
    else:
        if not (os.path.exists(usercert) and os.path.exists(userkey)):
            msg = "User certificate files NOT FOUND!!! Connection will not be possible!!"
            print_err(msg)
            logging.info(msg)
            sys.exit(126)
        cert, key = usercert, userkey
        if not IsValidCert(cert):
            msg = f'Invalid user certificate!! Check the content of {cert}'
            print_err(msg)
            logging.info(msg)
            sys.exit(129)
        AlienSessionInfo['use_usercert'] = True

    if _DEBUG: logging.debug(f"Cert = {cert}; Key = {key}; Creating SSL context .. ")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
    try:
        ctx.set_ciphers('DEFAULT@SECLEVEL=1')  # Server uses only 80bit (sigh); set SECLEVEL only for newer than EL7
    except ssl.SSLError:
        pass
    ctx.options |= ssl.OP_NO_SSLv3
    ctx.verify_mode = ssl.CERT_REQUIRED  # CERT_NONE, CERT_OPTIONAL, CERT_REQUIRED
    ctx.check_hostname = False
    if _DEBUG: logging.debug("SSL context:: Load verify locations")
    ca_verify_location = get_ca_path()
    if os.path.isfile(ca_verify_location):
        ctx.load_verify_locations(cafile = ca_verify_location)
    else:
        ctx.load_verify_locations(capath = ca_verify_location)
    if _DEBUG: logging.debug("SSL context:: Load certificate chain (cert/key)")
    ctx.load_cert_chain(certfile=cert, keyfile=key)
    if _DEBUG: logging.debug("SSL context done.")
    return ctx


@syncify
async def wb_create(host: str = 'localhost', port: Union[str, int] = '0', path: str = '/', use_usercert: bool = False, localConnect: bool = False):
    """Create a websocket to wss://host:port/path (it is implied a SSL context)"""
    QUEUE_SIZE = int(128)  # maximum length of the queue that holds incoming messages
    MSG_SIZE = None  # int(20 * 1024 * 1024)  # maximum size for incoming messages in bytes. The default value is 1 MiB. None disables the limit
    PING_TIMEOUT = int(os.getenv('ALIENPY_TIMEOUT', '20'))  # If the corresponding Pong frame isn’t received within ping_timeout seconds, the connection is considered unusable and is closed
    PING_INTERVAL = PING_TIMEOUT  # Ping frame is sent every ping_interval seconds
    CLOSE_TIMEOUT = int(10)  # maximum wait time in seconds for completing the closing handshake and terminating the TCP connection
    # https://websockets.readthedocs.io/en/stable/api.html#websockets.protocol.WebSocketCommonProtocol
    # we use some conservative values, higher than this might hurt the sensitivity to intreruptions

    wb = None
    ctx = None
    deflateFact = _wb_permessage_deflate.ClientPerMessageDeflateFactory(compress_settings={'memLevel': 6},)
    headers_list = []
    headers_list.append(('User-Agent', f'alien.py/{ALIENPY_VERSION_STR} websockets/{websockets.__version__}'))
    if localConnect:
        fHostWSUrl = 'ws://localhost/'
        logging.info(f"Request connection to : {fHostWSUrl}")
        socket_filename = f'{_TMPDIR}/jboxpy_{str(os.getuid())}.sock'
        try:
            wb = await _wb_unix_connect(socket_filename, fHostWSUrl,
                                        max_queue=QUEUE_SIZE,
                                        max_size=MSG_SIZE,
                                        ping_interval=PING_INTERVAL,
                                        ping_timeout=PING_TIMEOUT,
                                        close_timeout=CLOSE_TIMEOUT,
                                        extra_headers=headers_list
                                        )
        except Exception as e:
            msg = 'Could NOT establish connection (local socket) to {0}\n{1}'.format(socket_filename, e)
            logging.error(msg)
            print_err(f'{msg}\nCheck the logfile: {_DEBUG_FILE}')
            return None
    else:
        fHostWSUrl = f'wss://{host}:{port}{path}'  # conection url
        ctx = create_ssl_context(use_usercert)  # will check validity of token and if invalid cert will be usercert
        logging.info(f"Request connection to : {host}:{port}{path}")

        socket_endpoint = None
        # https://async-stagger.readthedocs.io/en/latest/reference.html#async_stagger.create_connected_sock
        # AI_* flags --> https://linux.die.net/man/3/getaddrinfo
        try:
            if _DEBUG:
                logging.debug(f"TRY ENDPOINT: {host}:{port}")
                init_begin = datetime.datetime.now().timestamp()
            if os.getenv('ALIENPY_NO_STAGGER'):
                socket_endpoint = socket.create_connection((host, int(port)))
            else:
                socket_endpoint = await async_stagger.create_connected_sock(host, int(port), async_dns=True, resolution_delay=0.050, detailed_exceptions=True)
            if _DEBUG:
                init_delta = (datetime.datetime.now().timestamp() - init_begin) * 1000
                logging.debug(f"TCP SOCKET DELTA: {init_delta:.3f} ms")
        except Exception as e:
            msg = 'Could NOT establish connection (TCP socket) to {0}:{1}\n{2}'.format(host, port, e)
            logging.error(msg)
            print_err(f'{msg}\nCheck the logfile: {_DEBUG_FILE}')
            return None

        if socket_endpoint:
            socket_endpoint_addr = socket_endpoint.getpeername()[0]
            socket_endpoint_port = socket_endpoint.getpeername()[1]
            logging.info(f"GOT SOCKET TO: {socket_endpoint_addr}")
            try:
                if _DEBUG: init_begin = datetime.datetime.now().timestamp()
                wb = await _wb_connect(fHostWSUrl, sock = socket_endpoint, server_hostname = host, ssl = ctx,
                                       extensions=[deflateFact, ],
                                       max_queue=QUEUE_SIZE,
                                       max_size=MSG_SIZE,
                                       ping_interval=PING_INTERVAL,
                                       ping_timeout=PING_TIMEOUT,
                                       close_timeout=CLOSE_TIMEOUT,
                                       extra_headers=headers_list
                                       )
                if _DEBUG:
                    init_delta = (datetime.datetime.now().timestamp() - init_begin) * 1000
                    logging.debug(f"WEBSOCKET DELTA: {init_delta:.3f} ms")
            except Exception as e:
                msg = 'Could NOT establish connection (WebSocket) to {0}:{1}\n{2}'.format(socket_endpoint_addr, socket_endpoint_port, e)
                logging.error(msg)
                print_err(f'{msg}\nCheck the logfile: {_DEBUG_FILE}')
                return None
        if wb: logging.info(f"CONNECTED: {wb.remote_address[0]}:{wb.remote_address[1]}")
    return wb


def wb_create_tryout(host: str = 'localhost', port: Union[str, int] = '0', path: str = '/', use_usercert: bool = False, localConnect: bool = False):
    """WebSocket creation with tryouts (configurable by env ALIENPY_CONNECT_TRIES and ALIENPY_CONNECT_TRIES_INTERVAL)"""
    wb = None
    nr_tries = 0
    init_begin = init_delta = None
    if _TIME_CONNECT or _DEBUG: init_begin = datetime.datetime.now().timestamp()
    connect_tries = int(os.getenv('ALIENPY_CONNECT_TRIES', '3'))
    connect_tries_interval = float(os.getenv('ALIENPY_CONNECT_TRIES_INTERVAL', '0.5'))

    while wb is None:
        try:
            nr_tries += 1
            wb = wb_create(host, str(port), path, use_usercert, localConnect)
        except Exception as e:
            logging.error('{0}'.format(e))
        if not wb:
            if nr_tries + 1 > connect_tries:
                logging.error(f"We tried on {host}:{port}{path} {nr_tries} times")
                break
            time.sleep(connect_tries_interval)

    if wb and init_begin:
        init_delta = (datetime.datetime.now().timestamp() - init_begin) * 1000
        msg = f'>>>   Endpoint total connecting time: {init_delta:.3f} ms'
        if _DEBUG: logging.debug(msg)
        if _TIME_CONNECT: print_out(msg)

    if wb and localConnect:
        pid_filename = f'{_TMPDIR}/jboxpy_{os.getuid()}.pid'
        writePidFile(pid_filename)
    return wb


def AlienConnect(token_args: Union[None, list] = None, use_usercert: bool = False, localConnect: bool = False):
    """Create a websocket connection to AliEn services either directly to alice-jcentral.cern.ch or trough a local found jbox instance"""
    jalien_server = os.getenv("ALIENPY_JCENTRAL", 'alice-jcentral.cern.ch')  # default value for JCENTRAL
    jalien_websocket_port = os.getenv("ALIENPY_JCENTRAL_PORT", '8097')  # websocket port
    jalien_websocket_path = '/websocket/json'
    jclient_env = f'{_TMPDIR}/jclient_token_{str(os.getuid())}'

    # let's try to get a websocket
    wb = None
    if localConnect:
        wb = wb_create(localConnect = True)
    else:
        if not os.getenv("ALIENPY_JCENTRAL") and os.path.exists(jclient_env):  # If user defined ALIENPY_JCENTRAL the intent is to set and use the endpoint
            # lets check JBOX availability
            jalien_info = read_conf_file(jclient_env)
            if jalien_info:
                if is_my_pid(jalien_info['JALIEN_PID']) and isReachable(jalien_info['JALIEN_HOST'], jalien_info['JALIEN_WSPORT']):
                    jalien_server, jalien_websocket_port = jalien_info['JALIEN_HOST'], jalien_info['JALIEN_WSPORT']

        wb = wb_create_tryout(jalien_server, str(jalien_websocket_port), jalien_websocket_path, use_usercert)

        # if we stil do not have a socket, then try to fallback to jcentral if we did not had explicit endpoint and jcentral was not already tried
        if wb is None and not os.getenv("ALIENPY_JCENTRAL") and jalien_server != 'alice-jcentral.cern.ch':
            jalien_server, jalien_websocket_port = 'alice-jcentral.cern.ch', '8097'
            wb = wb_create_tryout(jalien_server, str(jalien_websocket_port), jalien_websocket_path, use_usercert)

    if wb is None:
        msg = f'Check the logfile: {_DEBUG_FILE}\nCould not get a websocket connection to {jalien_server}:{jalien_websocket_port}'
        logging.error(msg)
        print_err(msg)
        sys.exit(1)

    if AlienSessionInfo['use_usercert']: token(wb, token_args)  # if we connect with usercert then let get a default token
    return wb


def make_func_map_nowb():
    '''client side functions (new commands) that do not require connection to jcentral'''
    global AlienSessionInfo
    if AlienSessionInfo['cmd2func_map_nowb']: return
    AlienSessionInfo['cmd2func_map_nowb']['prompt'] = DO_prompt
    AlienSessionInfo['cmd2func_map_nowb']['token-info'] = DO_tokeninfo
    AlienSessionInfo['cmd2func_map_nowb']['token-verify'] = DO_tokenverify
    AlienSessionInfo['cmd2func_map_nowb']['token-destroy'] = DO_tokendestroy
    AlienSessionInfo['cmd2func_map_nowb']['cert-info'] = DO_certinfo
    AlienSessionInfo['cmd2func_map_nowb']['cert-verify'] = DO_certverify
    AlienSessionInfo['cmd2func_map_nowb']['certkey-match'] = DO_certkeymatch
    AlienSessionInfo['cmd2func_map_nowb']['tokenkey-match'] = DO_tokenkeymatch
    AlienSessionInfo['cmd2func_map_nowb']['exitcode'] = exitcode
    AlienSessionInfo['cmd2func_map_nowb']['$?'] = exitcode
    AlienSessionInfo['cmd2func_map_nowb']['error'] = error
    AlienSessionInfo['cmd2func_map_nowb']['$?err'] = error
    AlienSessionInfo['cmd2func_map_nowb']['version'] = DO_version
    AlienSessionInfo['cmd2func_map_nowb']['pfn-status'] = DO_pfnstatus
    AlienSessionInfo['cmd2func_map_nowb']['queryML'] = DO_queryML
    AlienSessionInfo['cmd2func_map_nowb']['exit'] = DO_exit
    AlienSessionInfo['cmd2func_map_nowb']['quit'] = DO_exit
    AlienSessionInfo['cmd2func_map_nowb']['logout'] = DO_exit
    AlienSessionInfo['cmd2func_map_nowb']['checkAddr'] = DO_checkAddr


def make_func_map_client():
    '''client side functions (new commands) that do not require connection to jcentral'''
    global AlienSessionInfo
    if AlienSessionInfo['cmd2func_map_client']: return

    # client side function (overrides) with signature : (wb, args, opts)
    AlienSessionInfo['cmd2func_map_client']['cd'] = cd
    del AlienSessionInfo['cmd2func_map_srv']['cd']
    list_remove_item(AlienSessionInfo['commandlist'], 'cd')

    AlienSessionInfo['cmd2func_map_client']['cp'] = DO_XrootdCp
    del AlienSessionInfo['cmd2func_map_srv']['cp']
    list_remove_item(AlienSessionInfo['commandlist'], 'cp')

    AlienSessionInfo['cmd2func_map_client']['ping'] = DO_ping
    del AlienSessionInfo['cmd2func_map_srv']['ping']
    list_remove_item(AlienSessionInfo['commandlist'], 'ping')

    AlienSessionInfo['cmd2func_map_client']['ps'] = DO_ps
    del AlienSessionInfo['cmd2func_map_srv']['ps']
    list_remove_item(AlienSessionInfo['commandlist'], 'ps')

    AlienSessionInfo['cmd2func_map_client']['submit'] = DO_submit
    del AlienSessionInfo['cmd2func_map_srv']['submit']
    list_remove_item(AlienSessionInfo['commandlist'], 'submit')

    AlienSessionInfo['cmd2func_map_client']['token'] = DO_token
    del AlienSessionInfo['cmd2func_map_srv']['token']
    list_remove_item(AlienSessionInfo['commandlist'], 'token')

    AlienSessionInfo['cmd2func_map_client']['user'] = DO_user
    del AlienSessionInfo['cmd2func_map_srv']['user']
    list_remove_item(AlienSessionInfo['commandlist'], 'user')

    AlienSessionInfo['cmd2func_map_client']['cat'] = DO_cat
    del AlienSessionInfo['cmd2func_map_srv']['cat']
    list_remove_item(AlienSessionInfo['commandlist'], 'cat')

    AlienSessionInfo['cmd2func_map_client']['toXml'] = DO_2xml
    del AlienSessionInfo['cmd2func_map_srv']['toXml']
    list_remove_item(AlienSessionInfo['commandlist'], 'toXml')

    # client side function (new commands) with signature : (wb, args)
    AlienSessionInfo['cmd2func_map_client']['quota'] = DO_quota
    AlienSessionInfo['cmd2func_map_client']['token-init'] = DO_token_init
    AlienSessionInfo['cmd2func_map_client']['pfn'] = DO_pfn
    AlienSessionInfo['cmd2func_map_client']['run'] = DO_run
    AlienSessionInfo['cmd2func_map_client']['exec'] = DO_exec
    AlienSessionInfo['cmd2func_map_client']['getSE'] = DO_getSE
    AlienSessionInfo['cmd2func_map_client']['find2'] = DO_find2
    AlienSessionInfo['cmd2func_map_client']['dirs'] = DO_dirs
    AlienSessionInfo['cmd2func_map_client']['popd'] = DO_popd
    AlienSessionInfo['cmd2func_map_client']['pushd'] = DO_pushd
    AlienSessionInfo['cmd2func_map_client']['help'] = DO_help
    AlienSessionInfo['cmd2func_map_client']['?'] = DO_help
    AlienSessionInfo['cmd2func_map_client']['edit'] = DO_edit
    AlienSessionInfo['cmd2func_map_client']['mcedit'] = DO_mcedit
    AlienSessionInfo['cmd2func_map_client']['nano'] = DO_nano
    AlienSessionInfo['cmd2func_map_client']['vi'] = DO_vi
    AlienSessionInfo['cmd2func_map_client']['vim'] = DO_vim
    AlienSessionInfo['cmd2func_map_client']['SEqos'] = DO_SEqos
    AlienSessionInfo['cmd2func_map_client']['less'] = DO_less
    AlienSessionInfo['cmd2func_map_client']['more'] = DO_more


def getSessionVars(wb):
    """Initialize the global session variables : cleaned up command list, user, home dir, current dir"""
    if not wb: return
    global AlienSessionInfo
    if not AlienSessionInfo['commandlist']:  # get the command list just once per session connection (a reconnection will skip this)
        ret_obj = SendMsg(wb, 'commandlist', [])
        # first executed commands, let's initialize the following (will re-read at each ProcessReceivedMessage)
        cmd_list = ret_obj.ansdict["results"][0]['message'].split()
        regex = re.compile(r'.*_csd$')
        AlienSessionInfo['commandlist'] = [i for i in cmd_list if not regex.match(i)]
        AlienSessionInfo['commandlist'].remove('jquota')
        AlienSessionInfo['commandlist'].remove('fquota')

        # server commands, signature is : (wb, command, args, opts)
        for cmd in AlienSessionInfo['commandlist']: AlienSessionInfo['cmd2func_map_srv'][cmd] = SendMsg
        make_func_map_client()  # add to cmd2func_map_client the list of client-side implementations

        # these are aliases, or directly interpreted
        AlienSessionInfo['commandlist'].append('ll')
        AlienSessionInfo['commandlist'].append('la')
        AlienSessionInfo['commandlist'].append('lla')
        AlienSessionInfo['commandlist'].extend(AlienSessionInfo['cmd2func_map_client'])  # add clien-side cmds to list
        AlienSessionInfo['commandlist'].extend(AlienSessionInfo['cmd2func_map_nowb'])  # add nowb cmds to list
        AlienSessionInfo['commandlist'].sort()

    # when starting new session prevdir is empty, if set then this is a reconnection
    if AlienSessionInfo['prevdir'] and (AlienSessionInfo['prevdir'] != AlienSessionInfo['currentdir']): cd(wb, AlienSessionInfo['prevdir'], 'log')


def InitConnection(token_args: Union[None, list] = None, use_usercert: bool = False, localConnect: bool = False):
    """Create a session to AliEn services, including session globals"""
    global AlienSessionInfo
    init_begin = init_delta = None
    if _TIME_CONNECT or _DEBUG: init_begin = datetime.datetime.now().timestamp()
    wb = AlienConnect(token_args, use_usercert, localConnect)
    if init_begin:
        init_delta = (datetime.datetime.now().timestamp() - init_begin) * 1000
        if _DEBUG: logging.debug(f">>>   Time for websocket connection: {init_delta:.3f} ms")
        if _TIME_CONNECT: print_out(f">>>   Time for websocket connection: {init_delta:.3f} ms")

    if wb is not None: AlienSessionInfo['session_started'] = True
    # no matter if command or interactive mode, we need alienHome, currentdir, user and commandlist
    getSessionVars(wb)
    if init_begin:
        init_delta = (datetime.datetime.now().timestamp() - init_begin) * 1000
        if _DEBUG: logging.debug(f">>>   Time for session connection: {init_delta:.3f} ms")
        if _TIME_CONNECT: print_out(f">>>   Time for session connection: {init_delta:.3f} ms")
    return wb


def ProcessInput(wb, cmd: str, args: Union[list, None] = None, shellcmd: Union[str, None] = None) -> RET:
    """Process a command line within shell or from command line mode input"""
    global AlienSessionInfo
    if not cmd: return RET(1, '', 'ProcessInput:: Empty input')
    if args is None: args = []
    ret_obj = None

    # early command aliases and default flags
    if cmd == 'ls': args[0:0] = ['-F']
    if cmd == 'll':
        cmd = 'ls'
        args[0:0] = ['-F', '-l']
    if cmd == 'la':
        cmd = 'ls'
        args[0:0] = ['-F', '-a']
    if cmd == 'lla':
        cmd = 'ls'
        args[0:0] = ['-F', '-l', '-a']

    # implement a time command for measurement of sent/recv delay; for the commands above we do not use timing
    time_begin = msg_timing = None

    if cmd == 'time':  # first to be processed is the time token, it will start the timing and be removed from command
        if not args or is_help(args): return RET(0, 'Command format: time command arguments')
        cmd = args.pop(0)
        time_begin = datetime.datetime.now().timestamp()

    if cmd in AlienSessionInfo['cmd2func_map_nowb']:  # these commands do NOT need wb connection
        ret_obj = AlienSessionInfo['cmd2func_map_nowb'][cmd](args)
        retf_session_update(ret_obj)
        return ret_obj

    opts = ''  # let's proccess special server args
    if get_arg(args, '-nokeys'): opts = f'{opts} nokeys'
    if get_arg(args, '-nomsg'): opts = f'{opts} nomsg'
    if get_arg(args, '-showkeys'): opts = f'{opts} showkeys'
    if get_arg(args, '-showmsg'): opts = f'{opts} showmsg'

    # We will not check for websocket connection as: 1. there is keep alive mechanism 2. there is recovery in SendMsg
    if cmd in AlienSessionInfo['cmd2func_map_client']:  # lookup in clien-side implementations list
        ret_obj = AlienSessionInfo['cmd2func_map_client'][cmd](wb, args)
    elif cmd in AlienSessionInfo['cmd2func_map_srv']:  # lookup in server-side list
        ret_obj = AlienSessionInfo['cmd2func_map_srv'][cmd](wb, cmd, args, opts)
    if ret_obj is None: return RET(1, '', f"NO RET OBJ!! The command was not found: {cmd} {chr(32).join(args)}")
    if time_begin: msg_timing = f">>>ProcessInput time: {(datetime.datetime.now().timestamp() - time_begin) * 1000:.3f} ms"

    if shellcmd:
        if ret_obj.exitcode != 0: return ret_obj
        if not ret_obj.out:
            return RET(1, '', f'Command >>>{cmd} {chr(32).join(args)}<<< do not have output but exitcode == 0')
        shell_run = subprocess.run(shellcmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, input=ret_obj.out, encoding='ascii', shell=True)  # pylint: disable=subprocess-run-check # env=os.environ default is already the process env
        if msg_timing: shell_run.stdout = f'{shell_run.stdout}\n{msg_timing}'
        return RET(shell_run.returncode, shell_run.stdout, shell_run.stderr)

    if msg_timing: ret_obj = ret_obj._replace(out = f'{ret_obj.out}\n{msg_timing}')
    if ret_obj.ansdict and 'timing_ms' in ret_obj.ansdict['metadata']: ret_obj = ret_obj._replace(out = f"{ret_obj.out}\ntiming_ms = {ret_obj.ansdict['metadata']['timing_ms']}")
    return ret_obj


def ProcessCommandChain(wb = None, cmd_chain: str = '') -> int:
    global AlienSessionInfo, _JSON_OUT, _JSON_OUT_GLOBAL
    if not cmd_chain: return int(1)
    # translate aliases in place in the whole string
    if AlienSessionInfo['alias_cache']:
        for alias in AlienSessionInfo['alias_cache']: cmd_chain = cmd_chain.replace(alias, AlienSessionInfo['alias_cache'][alias])
    cmdline_list = [str(cmd).strip() for cmd in cmds_split.split(cmd_chain)]  # split commands on ; and \n

    ret_obj = None
    for cmdline in cmdline_list:
        if not cmdline: continue
        if _DEBUG: logging.info(f'>>> RUN COMMAND: {cmdline}')
        if cmdline.startswith('!'):  # if shell command, just run it and return
            capture_out = True
            if '-noout' in cmdline:
                cmdline = cmdline.replace(' -noout', '')
                capture_out = False
            ret_obj = runShellCMD(cmdline, capture_out)
            retf_session_update(ret_obj)  # Update the globals exitcode, out, err
            retf_print(ret_obj, 'debug')
            continue

        # process the input and take care of pipe to shell
        input_alien, sep, pipe_to_shell_cmd = cmdline.partition('|')
        if not input_alien:
            print_out("AliEn command before the | token was not found")
            continue

        args = shlex.split(input_alien.strip())
        cmd = args.pop(0)

        _JSON_OUT = _JSON_OUT_GLOBAL  # if globally enabled then enable per command
        if get_arg(args, '-json'): _JSON_OUT = True  # if enabled for this command
        print_opts = 'debug json' if _JSON_OUT else 'debug'
        if _JSON_OUT and 'json' not in print_opts: print_opts = f'{print_opts} {json}'

        if cmd in AlienSessionInfo['cmd2func_map_nowb']:
            ret_obj = AlienSessionInfo['cmd2func_map_nowb'][cmd](args)
        else:
            if wb is None: wb = InitConnection()  # we are doing the connection recovery and exception treatment in AlienConnect()
            args.insert(0, '-nokeys')  # Disable return of the keys. ProcessCommandChain is used for user-based communication so json keys are not needed
            ret_obj = ProcessInput(wb, cmd, args, pipe_to_shell_cmd)

        retf_session_update(ret_obj)  # Update the globals exitcode, out, err
        retf_print(ret_obj, print_opts)
        if cmd == 'cd': SessionSave()
        _JSON_OUT = _JSON_OUT_GLOBAL  # reset _JSON_OUT if it's not globally enabled (env var or argument to alien.py)
    return ret_obj.exitcode


def JAlien(commands: str = '') -> int:
    """Main entry-point for interaction with AliEn"""
    global AlienSessionInfo, _JSON_OUT
    import_aliases()
    wb = None
    make_func_map_nowb()  # add to cmd2func_map_nowb the functions that do not need wb session

    # Command mode interaction
    if commands: return ProcessCommandChain(wb, commands)

    # Start interactive mode
    wb = InitConnection()  # we are doing the connection recovery and exception treatment in AlienConnect()
    # Begin Shell-like interaction
    if _HAS_READLINE:
        rl.parse_and_bind("tab: complete")
        rl.set_completer_delims(" ")

        def complete(text, state):
            prompt_line = rl.get_line_buffer()
            tokens = prompt_line.split()
            results = []
            if len(tokens) == 0:
                results = [f'{x} ' for x in AlienSessionInfo['commandlist']]
            elif len(tokens) == 1 and not prompt_line.endswith(' '):
                results = [f'{x} ' for x in AlienSessionInfo['commandlist'] if x.startswith(text)] + [None]
            else:
                results = lfn_list(wb, text) + [None]
            return results[state]
        rl.set_completer(complete)
        setupHistory()  # enable history saving

    print_out('Welcome to the ALICE GRID\nsupport mail: adrian.sevcenco@cern.ch\n')
    if os.getenv('ALIENPY_PROMPT_DATE'): AlienSessionInfo['show_date'] = True
    if os.getenv('ALIENPY_PROMPT_CWD'): AlienSessionInfo['show_lpwd'] = True
    if not os.getenv('ALIENPY_NO_CWD_RESTORE'): SessionRestore(wb)
    while True:
        INPUT = None
        prompt = f"AliEn[{AlienSessionInfo['user']}]:{AlienSessionInfo['currentdir']}"
        if AlienSessionInfo['show_date']: prompt = f'{datetime.datetime.now().replace(microsecond=0).isoformat()} {prompt}'
        if AlienSessionInfo['show_lpwd']: prompt = f'{prompt} local:{Path.cwd().as_posix()}'
        prompt = f'{prompt} >'
        try:
            INPUT = input(prompt)
        except EOFError:
            exit_message()

        if not INPUT: continue
        ProcessCommandChain(wb, INPUT)


def setup_logging():
    global _DEBUG_FILE
    logging.addLevelName(90, 'STDOUT')
    logging.addLevelName(95, 'STDERR')
    MSG_LVL = logging.DEBUG if _DEBUG else logging.INFO
    line_fmt = '%(levelname)s:%(asctime)s %(message)s'
    file_mode = 'a' if os.getenv('ALIENPY_DEBUG_APPEND', '') else 'w'
    try:
        logging.basicConfig(format = line_fmt, filename = _DEBUG_FILE, filemode = file_mode, level = MSG_LVL)
    except Exception:
        print_err(f'Could not write the log file {_DEBUG_FILE}; falling back to /tmp')
        _DEBUG_FILE = f'/tmp/{os.path.basename(_DEBUG_FILE)}'
        pass
    try:
        logging.basicConfig(format = line_fmt, filename = _DEBUG_FILE, filemode = file_mode, level = MSG_LVL)
    except Exception:
        print_err(f'Could not write the log file {_DEBUG_FILE}')

    logging.getLogger().setLevel(MSG_LVL)
    logging.getLogger('websockets').setLevel(MSG_LVL)
    # logging.getLogger('websockets.protocol').setLevel(MSG_LVL)
    # logging.getLogger('websockets.client').setLevel(MSG_LVL)
    if os.getenv('ALIENPY_DEBUG_CONCURENT'):
        logging.getLogger('concurrent').setLevel(MSG_LVL)
        logging.getLogger('concurrent.futures').setLevel(MSG_LVL)
    if os.getenv('ALIENPY_DEBUG_ASYNCIO'):
        logging.getLogger('asyncio').setLevel(MSG_LVL)
    if os.getenv('ALIENPY_DEBUG_STAGGER'):
        logging.getLogger('async_stagger').setLevel(MSG_LVL)


def main():
    setup_logging()
    signal.signal(signal.SIGINT, signal_handler)
    # signal.signal(sig, signal.SIG_DFL)  # register the default signal handler usage for a sig signal
    global _JSON_OUT, _JSON_OUT_GLOBAL, ALIENPY_EXECUTABLE
    # at exit delete all temporary files
    atexit.register(cleanup_temp)

    ALIENPY_EXECUTABLE = os.path.realpath(sys.argv[0])
    exec_name = Path(sys.argv.pop(0)).name  # remove the name of the script(alien.py)
    arg_list_expanded = []
    for arg in sys.argv:
        for item in shlex.split(arg):
            arg_list_expanded.append(item)
    sys.argv = arg_list_expanded

    if get_arg(sys.argv, '-json'):
        _JSON_OUT = True
        _JSON_OUT_GLOBAL = True

    if _DEBUG:
        ret_obj = DO_version()
        logging.debug(f'{ret_obj.out}\n')

    if len(sys.argv) > 0 and (sys.argv[0] == 'term' or sys.argv[0] == 'terminal' or sys.argv[0] == 'console'):
        import code
        term = code.InteractiveConsole(locals = globals())
        term.push('jalien = AliEn()')
        banner = 'Welcome to the ALICE GRID - Python interpreter shell\nsupport mail: adrian.sevcenco@cern.ch\nAliEn seesion object is >jalien< ; try jalien.help()'
        exitmsg = 'Exiting..'
        term.interact(banner, exitmsg)
        os._exit(int(AlienSessionInfo['exitcode']))  # pylint: disable=protected-access

    verb = exec_name.replace('alien_', '') if exec_name.startswith('alien_') else ''
    if verb: sys.argv.insert(0, verb)

    cmd_string = ''
    if len(sys.argv) > 0 and os.path.isfile(sys.argv[0]):
        with open(sys.argv[0]) as input_file:
            cmd_string = input_file.read()
    else:
        cmd_string = ' '.join(sys.argv)

    try:
        JAlien(cmd_string)
    except KeyboardInterrupt as e:
        print_out("Received keyboard intrerupt, exiting..")
        sys.exit(int(AlienSessionInfo['exitcode']))
    except Exception as e:
        logging.exception("\n\n>>>   EXCEPTION   <<<", exc_info = True)
        logging.error("\n\n")
        print_err(f'''{PrintColor(COLORS.BIRed)}Exception encountered{PrintColor(COLORS.ColorReset)}! it will be logged to {_DEBUG_FILE}
Please report the error and send the log file and "alien.py version" output to Adrian.Sevcenco@cern.ch
If the exception is reproductible including on lxplus, please create a detailed debug report this way:
ALIENPY_DEBUG=1 ALIENPY_DEBUG_FILE=log.txt your_command_line''')
        sys.exit(1)
    sys.exit(int(AlienSessionInfo['exitcode']))


def _cmd(what):
    sys.argv = [sys.argv[0]] + [what] + sys.argv[1:]
    main()


def cmd_cert_info(): _cmd('cert-info')


def cmd_token_info(): _cmd('token-info')


def cmd_token_destroy(): _cmd('token-destroy')


def cmd_token_init():
    print_out('INFO: JAliEn client automatically creates tokens, '
              'alien-token-init is deprecated')
    _cmd('token-init')


if __name__ == '__main__':
    main()
