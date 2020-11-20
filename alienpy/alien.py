#!/usr/bin/env python3

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
import OpenSSL
import async_stagger
import websockets
import websockets.extensions

deque = collections.deque

ALIENPY_VERSION_DATE = '20201120_091344'
ALIENPY_VERSION_STR = '1.2.8'
ALIENPY_EXECUTABLE = ''

if sys.version_info[0] != 3 or sys.version_info[1] < 6:
    print("This script requires a minimum of Python version 3.6", flush = True)
    sys.exit(1)

has_readline = False
try:
    import readline as rl
    has_readline = True
except ImportError:
    try:
        import gnureadline as rl
        has_readline = True
    except ImportError:
        has_readline = False

if has_readline:
    def setupHistory():
        histfile = os.path.join(os.path.expanduser("~"), ".alienpy_history")
        if not os.path.exists(histfile): open(histfile, 'wb').close()
        rl.set_history_length(-1)  # unlimited history
        rl.read_history_file(histfile)

        def startup_hook(): rl.append_history_file(1, histfile)  # before next prompt save last line
        rl.set_startup_hook(startup_hook)


has_xrootd = False
try:  # let's fail fast if the xrootd python bindings are not present
    from XRootD import client
    has_xrootd = True
except ImportError:
    has_xrootd = False

hasColor = False
if (hasattr(sys.stdout, "isatty") and sys.stdout.isatty()): hasColor = True

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
DEBUG_FILE = os.getenv('ALIENPY_DEBUG_FILE', Path.home().as_posix() + '/alien_py.log')
TIME_CONNECT = os.getenv('ALIENPY_TIMECONNECT', '')
TMPDIR = os.getenv('TMPDIR', '/tmp')
DEBUG_TIMING = os.getenv('ALIENPY_TIMING', '')  # enable really detailed timings in logs

# global session state;
AlienSessionInfo = {'alienHome': '', 'currentdir': '', 'prevdir': '', 'commandlist': [], 'user': '', 'exitcode': int(-1), 'stdout': '', 'error': '', 'session_started': False,
                    'cmd2func_map_nowb': {}, 'cmd2func_map_client': {}, 'cmd2func_map_srv': {}, 'templist': [], 'use_usercert': False, 'alias_cache': {},
                    'q_out': deque([]), 'q_err': deque([]), 'pathq': deque([]),
                    'show_date': False, 'show_lpwd': False}


class COLORS(NamedTuple):
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


class XrdCpArgs(NamedTuple):
    """Structure to keep the set of xrootd flags used for xrootd copy process"""
    overwrite: bool
    batch: int
    sources: int
    chunks: int
    chunksize: int
    makedir: bool
    posc: bool
    hashtype: str
    streams: int
    cksum: bool


class CopyFile(NamedTuple):
    """Structure to keep a generic copy task"""
    src: str
    dst: str
    isUpload: bool
    token_request: dict
    lfn: str


class lfn2file(NamedTuple):
    """Map a lfn to file (and reverse)"""
    lfn: str
    file: str


class KV(NamedTuple):
    """Assign a value to a key"""
    key: str
    val: str


class RET(NamedTuple):
    """Structure for POSIX like function return: exitcode, stdout, stderr, dictionary of server reply"""
    exitcode: int = -1
    out: str = ''
    err: str = ''
    ansdict: dict = {}


class AliEn:
    """Class to be used as advanced API for interaction with central servers"""
    def __init__(self, opts = ''):
        self.internal_wb = InitConnection()
        self.opts = opts

    def run(self, cmd, opts = '') -> Union[RET, str]:
        if not opts: opts = self.opts
        return SendMsg(self.internal_wb, cmd, opts = opts)

    def ProcessMsg(self, cmd, opts = '') -> int:
        if not opts: opts = self.opts
        return ProcessCommandChain(self.internal_wb, cmd)

    def wb(self) -> websockets.client.WebSocketClientProtocol:
        return self.internal_wb

    def help(self):
        print('Methods of AliEn session:\n'
              '.run(cmd, opts) : alias to SendMsg(cmd, opts); It will return a RET object: named tuple (exitcode, out, err, ansdict)\n'
              '.ProcessMsg(cmd_list) : alias to ProcessCommandChain, it will have the same output as in the alien.py interaction\n'
              '.wb() : return the session WebSocket to be used with other function within alien.py', flush = True)


def signal_handler(sig, frame):
    """Generig signal handler: just print the signal and exit"""
    print(f'\nCought signal {signal.Signals(sig).name}, let\'s exit')
    exit_message(int(AlienSessionInfo['exitcode']))


def exit_message(code: int = 0):
    print('Exit')
    sys.exit(code)


def is_guid(guid: str) -> bool: return bool(guid_regex.fullmatch(guid))  # identify if argument in an AliEn GUID


def run_function(function_name: str, *args, **kwargs): return globals()[function_name](*args, *kwargs)  # run arbitrary function


def io_q_proc():
    global AlienSessionInfo
    stderr = "\n". join(AlienSessionInfo['q_err'])
    AlienSessionInfo['q_err'].clear()
    stdout = "\n". join(AlienSessionInfo['q_out'])
    AlienSessionInfo['q_out'].clear()
    if stdout: print(stdout, flush = True)
    if stderr: print(stderr, file=sys.stderr, flush = True)


def io_q_proc_out():
    global AlienSessionInfo
    stdout = "\n". join(AlienSessionInfo['q_out'])
    AlienSessionInfo['q_out'].clear()
    if stdout: print(stdout, flush = True)


def io_q_get_out() -> str:
    global AlienSessionInfo
    stdout = "\n". join(AlienSessionInfo['q_out'])
    AlienSessionInfo['q_out'].clear()
    return stdout


def io_q_proc_err():
    global AlienSessionInfo
    stderr = "\n". join(AlienSessionInfo['q_err'])
    AlienSessionInfo['q_err'].clear()
    if stderr: print(stderr, file=sys.stderr, flush = True)


def io_q_get_err() -> str:
    global AlienSessionInfo
    stderr = "\n". join(AlienSessionInfo['q_err'])
    AlienSessionInfo['q_err'].clear()
    return stderr


def io_q_push_err(msg: str):
    global AlienSessionInfo
    if msg: AlienSessionInfo['q_err'].append(msg)


def io_q_push_out(msg: str):
    global AlienSessionInfo
    if msg: AlienSessionInfo['q_out'].append(msg)


def start_asyncio():
    """Initialization of main thread that will keep the asyncio loop"""
    loop = None
    ready = threading.Event()

    def run(main, *, debug=False):
        if asyncio.events._get_running_loop() is not None: raise RuntimeError("asyncio.run() cannot be called from a running event loop")
        if not asyncio.coroutines.iscoroutine(main): raise ValueError("a coroutine was expected, got {!r}".format(main))

        loop = asyncio.events.new_event_loop()
        try:
            asyncio.events.set_event_loop(loop)
            loop.set_debug(debug)
            return loop.run_until_complete(main)
        finally:
            try:
                _cancel_all_tasks(loop)
                loop.run_until_complete(loop.shutdown_asyncgens())
            finally:
                asyncio.events.set_event_loop(None)
                loop.close()

    def _cancel_all_tasks(loop):
        if sys.version_info[1] < 8:
            to_cancel = asyncio.Task.all_tasks(loop)  # asyncio.tasks.
        else:
            to_cancel = asyncio.all_tasks(loop)  # asyncio.tasks.
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


# DECORATOR FOR SYNCIFY FUNCTIONS
def syncify(fn):
    def syncfn(*args, **kwds):
        # submit the original coroutine to the event loop and wait for the result
        conc_future = asyncio.run_coroutine_threadsafe(fn(*args, **kwds), _loop)
        return conc_future.result()
    syncfn.as_async = fn
    return syncfn


@syncify
async def IsWbConnected(wb: websockets.client.WebSocketClientProtocol) -> bool:
    """Check if websocket is connected with the protocol ping/pong"""
    time_begin = None
    if DEBUG_TIMING: time_begin = datetime.datetime.now().timestamp()
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
    await wb.close(code = code, reason = reason)


@syncify
async def msg_proxy(websocket, use_usercert = False):
    # start client to upstream
    wb_jalien = AlienConnect(None, use_usercert)
    local_query = await websocket.recv()
    jalien_answer = await SendMsg(wb_jalien, local_query)
    await websocket.send(jalien_answer.ansdict)


@syncify
async def __sendmsg(wb: websockets.client.WebSocketClientProtocol, jsonmsg: str) -> str:
    """The low level async function for send/receive"""
    time_begin = None
    if DEBUG_TIMING: time_begin = datetime.datetime.now().timestamp()
    await wb.send(jsonmsg)
    result = await wb.recv()
    if time_begin: logging.debug(f">>>__sendmsg time = {(datetime.datetime.now().timestamp() - time_begin) * 1000:.3f} ms")
    return result


def SendMsg(wb: websockets.client.WebSocketClientProtocol, cmdline: str, args: Union[None, list] = None, opts: str = '') -> Union[RET, str]:
    """Send a json message to the specified websocket; it will return the server answer"""
    if not wb:
        msg = "SendMsg:: websocket not initialized"
        logging.info(msg)
        return '' if 'rawstr' in opts else RET(1, '', msg)
    if not args: args = []
    time_begin = None
    if DEBUG or DEBUG_TIMING: time_begin = datetime.datetime.now().timestamp()
    if JSON_OUT_GLOBAL or JSON_OUT or DEBUG:  # if jsout output was requested, then make sure we get the full answer
        opts = opts.replace('nokeys', '').replace('nomsg', '')
    if DEBUG:
        logging.info(f"Called from: {sys._getframe().f_back.f_code.co_name}")
        logging.info(f"With argumens: cmdline: {cmdline} ; args: {args}")
    if '{"command":' in cmdline and '"options":' in cmdline:
        jsonmsg = cmdline
    else:
        jsonmsg = CreateJsonCommand(cmdline, args, opts)  # nomsg/nokeys will be passed to CreateJsonCommand
    if DEBUG: logging.info(f"We send this json: {jsonmsg}")

    if not jsonmsg:
        logging.info("SendMsg:: json message is empty or invalid")
        return '' if 'rawstr' in opts else RET(1, '', "SendMsg:: json message is empty or invalid")
    if DEBUG: logging.debug(f"SEND COMMAND: {jsonmsg}")
    nr_tries = int(0)
    result = None
    while result is None:
        if nr_tries > 3:
            msg = f"SendMsg:: {nr_tries - 1} communication errors!\nSent command: {jsonmsg}"
            print(msg, file=sys.stderr, flush = True)
            logging.error(msg)
            break
        try:
            nr_tries += 1
            result = __sendmsg(wb, jsonmsg)
        except (websockets.exceptions.ConnectionClosed, websockets.exceptions.ConnectionClosedError, websockets.exceptions.ConnectionClosedOK) as e:
            logging.exception(e)
            try:
                wb = InitConnection()
            except Exception as e:
                logging.exception(e)
                msg = f'SendMsg:: Could not recover connection when disconnected!! Check {DEBUG_FILE}'
                logging.error(msg)
                print(msg, file=sys.stderr, flush = True)
        except Exception as e:
            logging.exception(e)
            if not IsWbConnected(wb):
                try:
                    wb = InitConnection()
                except Exception as e:
                    logging.exception(e)
                    msg = f'SendMsg:: Could not recover connection after non-connection related exception!! Check {DEBUG_FILE}'
                    logging.error(msg)
                    print(msg, file=sys.stderr, flush = True)
                    break
        if result is None: time.sleep(0.1)

    if time_begin: logging.debug(f"SendMsg::Result received: {(datetime.datetime.now().timestamp() - time_begin) * 1000:.3f} ms")
    if not result: return RET(1, '', 'SendMsg:: Empty result received from server')
    if 'rawstr' in opts: return result
    ret_obj = GetDict(result)
    if time_begin: logging.debug(f"SendMsg::Result decoded: {(datetime.datetime.now().timestamp() - time_begin) * 1000:.3f} ms")
    return ret_obj


def GetDict(result: Union[str, dict]) -> RET:
    """Convert server reply string to dict, update all relevant globals"""
    if not result: return RET(1, '', 'GetDict:: empty argument')
    out_dict = None
    if type(result) == str:
        try:
            out_dict = json.loads(result)
        except Exception as e:
            return RET(1, '', 'GetDict:: Could not load argument as json!\n{0}'.format(e))
    else:
        out_dict = result  # result.copy()
    if 'metadata' not in out_dict or 'results' not in out_dict:
        return RET(1, '', 'GetDict:: Input dictionary not of AliEn format')

    ret_obj = retf_result2ret(out_dict)  # convert server answer to RET object
    retf_session_update(ret_obj)  # update global session: exitcode, stdout, stderr
    Update_meta2session(ret_obj.ansdict)
    return ret_obj


def PrintDict(in_arg: Union[str, dict, list]):
    """Print a dictionary in a nice format"""
    if type(in_arg) == str:
        try:
            in_arg = json.loads(in_arg)
        except Exception as e:
            print('PrintDict:: Could not load argument as json!\n{0}'.format(e))
    print(json.dumps(in_arg, sort_keys = True, indent = 4))


def Update_meta2session(message: dict = None):
    """Export session information from a AliEn reply to global session info: cur/prev dir, user, home, dir stack"""
    if not message or 'metadata' not in message: return
    global AlienSessionInfo
    AlienSessionInfo['user'] = message["metadata"]["user"]

    current_dir = message["metadata"]["currentdir"]
    if not AlienSessionInfo['alienHome']: AlienSessionInfo['alienHome'] = current_dir  # if this is first connection, current dir is alien home

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


def CreateJsonCommand(cmdline: Union[str, dict], args: Union[None, list] = None, opts: str = '') -> str:
    """Return a json with command and argument list"""
    if args is None: args = []
    if type(cmdline) == dict:
        out_dict = cmdline.copy()
        if 'showmsg' in opts: opts = opts.replace('nomsg', '')
        if 'showkeys' in opts: opts = opts.replace('nokeys', '')
        if 'nomsg' in opts: out_dict["options"].insert(0, '-nomsg')
        if 'nokeys' in opts: out_dict["options"].insert(0, '-nokeys')
        return json.dumps(out_dict)

    if not args:
        args = cmdline.split()
        cmd = args.pop(0)
    else:
        cmd = cmdline
    if 'nomsg' in opts: args.insert(0, '-nomsg')
    if 'nokeys' in opts: args.insert(0, '-nokeys')
    jsoncmd = {"command": cmd, "options": args}
    return json.dumps(jsoncmd)


def GetMeta(result: dict, meta: str = '') -> list:
    if not result: return []
    if type(result) == dict and 'metadata' in result:  # these works only for AliEn responses
        output = []
        meta_opts_list = meta.split() if meta else []
        if 'cwd' in meta_opts_list or 'all' in meta_opts_list: output.append(result["metadata"]["currentdir"])
        if 'user' in meta_opts_list or 'all' in meta_opts_list: output.append(result["metadata"]["user"])
        if 'error' in meta_opts_list or 'all' in meta_opts_list: output.append(result["metadata"]["error"])
        if 'exitcode' in meta_opts_list or 'all' in meta_opts_list: output.append(result["metadata"]["exitcode"])
        return output
    return []


def PrintColor(color: str) -> str:
    """Print colored string if terminal has color, print nothing otherwise"""
    if hasColor: return color
    return ''


def cursor_up(lines: int = 1):
    """Move the cursor up N lines"""
    if lines < 1: lines = 1
    for k in range(lines):
        sys.stdout.write('\x1b[1A')
        sys.stdout.flush()


def cursor_down(lines: int = 1):
    """Move the cursor down N lines"""
    if lines < 1: lines = 1
    for k in range(lines):
        sys.stdout.write('\x1b[1B')
        sys.stdout.flush()


def cursor_right(pos: int = 1):
    """Move the cursor right N positions"""
    if pos < 1: pos = 1
    for k in range(pos):
        sys.stdout.write('\x1b[1C')
        sys.stdout.flush()


def cursor_left(pos: int = 1):
    """Move the cursor left N positions"""
    if pos < 1: pos = 1
    for k in range(pos):
        sys.stdout.write('\x1b[1D')
        sys.stdout.flush()


def cleanup_temp():
    """Remove from disk all recorded temporary files"""
    if AlienSessionInfo['templist']:
        for f in AlienSessionInfo['templist']:
            if os.path.isfile(f): os.remove(f)


def now_str() -> str: return str(datetime.datetime.now().strftime("%Y%m%d_%H%M%S"))


def retf_session_update(ret_info: RET):
    global AlienSessionInfo
    AlienSessionInfo['exitcode'] = int(ret_info.exitcode)
    AlienSessionInfo['stdout'] = ret_info.out
    AlienSessionInfo['error'] = ret_info.err


def retf_global_get() -> RET:
    global AlienSessionInfo
    return RET(AlienSessionInfo['exitcode'], AlienSessionInfo['stdout'], AlienSessionInfo['error'])


def retf_result2ret(result: Union[dict, str]) -> Union[None, RET]:
    """Convert AliEn answer dictionary to RET object"""
    if not result: return RET()
    out_dict = None
    if type(result) == str:
        try:
            out_dict = json.loads(result)
        except Exception as e:
            msg = 'retf_dict2ret:: Could not load argument as json!\n{0}'.format(e)
            logging.error(msg)
            return RET(1, '', msg)
    else:
        out_dict = result.copy()

    if 'metadata' not in out_dict or 'results' not in out_dict:  # these works only for AliEn responses
        msg = 'retf_dict2ret:: Dictionary does not have AliEn answer format'
        logging.error(msg)
        return RET(1, '', msg)

    # print(json.dumps(out_dict, sort_keys = True, indent = 4))
    message_list = [str(item['message']) for item in out_dict['results'] if 'message' in item]
    output = '\n'.join(message_list)
    return RET(int(out_dict["metadata"]["exitcode"]), output.strip(), out_dict["metadata"]["error"], out_dict)


def retf_print(ret_obj: RET, opts: str = '') -> int:
    """Process the return struture of function"""
    if ret_obj.exitcode == -1:
        print('Default RET object used, invalid return', file=sys.stderr, flush = True)
        return ret_obj.exitcode

    if 'json' in opts:
        if ret_obj.ansdict:
            json_out = json.dumps(ret_obj.ansdict, sort_keys = True, indent = 4)
            print(json_out, flush = True)
            if DEBUG: logging.debug(json_out)
        else:
            print('This command did not return a json dictionary', file=sys.stderr, flush = True)
        return ret_obj.exitcode

    if ret_obj.exitcode != 0:
        if 'info' in opts: logging.info(ret_obj.err)
        if 'warn' in opts: logging.warning(ret_obj.err)
        if 'err' in opts: logging.error(ret_obj.err)
        if 'debug' in opts: logging.debug(ret_obj.err)
        if ret_obj.err and not ('noerr' in opts or 'noprint' in opts):
            print(f'{ret_obj.err.strip()}', file=sys.stderr, flush = True)
    else:
        if ret_obj.out and not ('noout' in opts or 'noprint' in opts):
            print(f'{ret_obj.out.strip()}', flush = True)
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


def import_aliases():
    global AlienSessionInfo
    alias_file = os.path.join(os.path.expanduser("~"), ".alienpy_aliases")
    global AlienSessionInfo
    if os.path.exists(alias_file): AlienSessionInfo['alias_cache'] = read_conf_file(alias_file)


def os_release() -> dict:
    return read_conf_file('/etc/os-release')


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


def SessionRestore(wb: websockets.client.WebSocketClientProtocol):
    if os.getenv('ALIENPY_NO_CWD_RESTORE'): return
    global AlienSessionInfo
    if os.path.exists(GetSessionFilename()):
        session = read_conf_file(GetSessionFilename())
        sys_cur_dir = AlienSessionInfo['currentdir']
        AlienSessionInfo['currentdir'] = session['CWD']
        AlienSessionInfo['prevdir'] = session['CWDPREV']
        if AlienSessionInfo['currentdir'] and (sys_cur_dir != AlienSessionInfo['currentdir']): cd(wb, AlienSessionInfo['currentdir'], opts = 'nocheck')


def exitcode(args: Union[list, None] = None): return RET(0, f"{AlienSessionInfo['exitcode']}", '')


def error(args: Union[list, None] = None): return RET(0, f"{AlienSessionInfo['error']}", '')


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
        local_time = local_time + millis
        return str(local_time.strftime("%Y-%m-%d %H:%M:%S")) + "." + time_decimals + str(local_time.strftime("%z"))
    if decimals and micros:
        local_time = local_time + micros
        return str(local_time.strftime("%Y-%m-%d %H:%M:%S.%f%z"))  # (%Z)"))
    return str(local_time.strftime("%Y-%m-%d %H:%M:%S%z"))  # (%Z)"))


def convert_time(str_line: str) -> str:
    """Convert the first 10 digit unix time like string from str argument to a nice time"""
    timestamp = re.findall(r"^(\d{10}) \[.*", str_line)
    if timestamp:
        nice_timestamp = f"{PrintColor(COLORS.BIGreen)}{unixtime2local(timestamp[0])}{PrintColor(COLORS.ColorReset)}"
        return str_line.replace(str(timestamp[0]), nice_timestamp)
    return ''


def cd(wb: websockets.client.WebSocketClientProtocol, args: Union[str, list] = None, opts: str = '') -> RET:
    """Override cd to add to home and to prev functions"""
    if args is None: args = []
    if type(args) == str: args = args.split()
    if '-h' in args: return get_help_srv(wb, 'cd')
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


def DO_dirs(wb: websockets.client.WebSocketClientProtocol, args: Union[str, list, None] = None) -> RET: return DO_path_stack(wb, 'dirs', args)


def DO_popd(wb: websockets.client.WebSocketClientProtocol, args: Union[str, list, None] = None) -> RET: return DO_path_stack(wb, 'popd', args)


def DO_pushd(wb: websockets.client.WebSocketClientProtocol, args: Union[str, list, None] = None) -> RET: return DO_path_stack(wb, 'pushd', args)


def DO_path_stack(wb: websockets.client.WebSocketClientProtocol, cmd: str = '', args: Union[str, list, None] = None) -> RET:
    """Implement dirs/popd/pushd for directory stack manipulation"""
    if not cmd: return RET(1)
    if args is None: return RET(1)
    global AlienSessionInfo
    arg_list = args.split() if type(args) == str else args

    do_not_cd = False
    if '-n' in arg_list:
        do_not_cd = True
        arg_list.remove('-n')

    msg = ''
    help_msg = ('The folloswinf syntax is required\n'
                'dirs [-clpv] [+N | -N]\n'
                'popd [-n] [+N | -N]\n'
                'pushd [-n] [+N | -N | dir]')

    if (cmd != 'dirs' and len(arg_list) > 1) or (cmd == 'dirs' and len(arg_list) > 2) or ('-h' in arg_list):
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
                AlienSessionInfo['pathq'].rotate(-position)
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

        path = expand_path_grid(arg_list[0])
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


def DO_version(args: Union[list, None] = None) -> RET:
    stdout = (f'alien.py version: {ALIENPY_VERSION_STR}\n'
              f'alien.py version date: {ALIENPY_VERSION_DATE}\n'
              f'alien.py location: {os.path.realpath(__file__)}\n'
              f'script location: {ALIENPY_EXECUTABLE}\n'
              f'Interpreter: {os.path.realpath(sys.executable)}\n'
              f'Python version: {sys.version}\n')
    if has_xrootd:
        stdout = stdout + f'XRootD version: {client.__version__}\nXRootD path: {client.__file__}'
    else:
        stdout = stdout + 'XRootD version: Not Found!'
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
            if code != 0: print(msg, file = sys.stderr, flush = True)
            else: print(msg, flush = True)
    sys.exit(int(code))


def DO_certinfo(args: Union[list, None] = None) -> RET:
    if args is None: args = []
    cert, key = get_files_cert()
    if len(args) > 0 and (args[0] in ['-h', 'help', '-help']):
        return RET(0, "Print user certificate information", "")
    return CertInfo(cert)


def DO_tokeninfo(args: Union[list, None] = None) -> RET:
    if not args: args = []
    if len(args) > 0 and (args[0] in ['-h', 'help', '-help']):
        return RET(0, "Print token certificate information", "")
    tokencert, tokenkey = get_files_token()
    if not os.path.isfile(tokencert) and 'BEGIN CERTIFICATE' in tokencert:  # it is not a file and contains a certificate
        temp_cert = tempfile.NamedTemporaryFile(prefix = 'tokencert_', suffix = f'_{str(os.getuid())}.pem')
        temp_cert.write(tokencert.encode(encoding="ascii", errors="replace"))
        temp_cert.seek(0)
        tokencert = temp_cert.name
    return CertInfo(tokencert)


def DO_tokendestroy(args: Union[list, None] = None) -> RET:
    if args is None: args = []
    if len(args) > 0 and (args[0] in ['-h', 'help', '-help']):
        return RET(0, "Delete the token{cert,key}.pem files")
    tokencert, tokenkey = get_files_token()
    if os.path.exists(tokencert): os.remove(tokencert)
    if os.path.exists(tokenkey): os.remove(tokenkey)
    return RET(0, "Token was destroyed! Re-connect for token re-creation.")


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


def getEnvelope_lfn(wb: websockets.client.WebSocketClientProtocol, arg_lfn2file: lfn2file, specs: Union[None, list] = None, isWrite: bool = False) -> dict:
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
        get_envelope_arg_list = ['-s', size, '-m', md5sum, access_type, lfn]
    else:
        access_type = 'read'
        get_envelope_arg_list = [access_type, lfn]
    if specs: get_envelope_arg_list.append(str(",".join(specs)))
    ret_obj = SendMsg(wb, 'access', get_envelope_arg_list, opts = 'nomsg')
    if ret_obj.exitcode != 0:
        retf_print(ret_obj, opts = 'err')
        return {}
    result = ret_obj.ansdict
    replica_list = []
    for replica in result["results"]:
        replica_list.append(replica["se"])
    for replica in result["results"]:
        replica["SElist"] = ",".join(replica_list)
        replica["file"] = file
        replica["lfn"] = lfn
    return {"lfn": lfn, "answer": result}


def getEnvelope(wb: websockets.client.WebSocketClientProtocol, input_lfn_list: list, specs: Union[None, list] = None, isWrite: bool = False) -> list:
    """Query central services for the access envelope of the list of lfns, it will return a list of lfn:server answer with envelope pairs"""
    if not wb: return []
    access_list = []
    if not input_lfn_list: return access_list
    if specs is None: specs = []
    for l2f in input_lfn_list: access_list.append(getEnvelope_lfn(wb, l2f, specs, isWrite))
    return access_list


def setDst(file: str = '', parent: int = 0) -> str:
    """For a fiven file path return the file path keeping the <parent> number of components"""
    p = Path(file)
    path_components = len(p.parts)
    if parent >= (path_components - 1): parent = path_components - 1 - 1  # IF parent >= number of components without filename THEN make parent = number of component without / and filename
    basedir = p.parents[parent].as_posix()
    if basedir == '/': return file
    return p.as_posix().replace(basedir, '', 1)


def expand_path_local(path_input: str) -> str:
    """Given a string representing a local file, return a full path after interpretation of HOME location, current directory, . and .. and making sure there are only single /"""
    exp_path = path_input
    exp_path = lfn_prefix_re.sub('', exp_path)
    exp_path = re.sub(r"^\~\/*", Path.home().as_posix() + "/", exp_path)
    if not exp_path.startswith('/'): exp_path = Path.cwd().as_posix() + "/" + exp_path
    exp_path = os.path.normpath(exp_path)
    exp_path = os.path.realpath(exp_path)
    if path_input.endswith("/") or os.path.isdir(exp_path): exp_path = exp_path + "/"
    return exp_path


def expand_path_grid(path_input: str) -> str:
    """Given a string representing a GRID file (lfn), return a full path after interpretation of AliEn HOME location, current directory, . and .. and making sure there are only single /"""
    exp_path = path_input
    exp_path = lfn_prefix_re.sub('', exp_path)
    exp_path = re.sub(r"^\/*\%ALIEN[\/\s]*", AlienSessionInfo['alienHome'], exp_path)  # replace %ALIEN token with user grid home directory
    if not exp_path.startswith('/') and not exp_path.startswith('~'): exp_path = AlienSessionInfo['currentdir'] + "/" + exp_path  # if not full path add current directory to the referenced path
    exp_path = os.path.normpath(exp_path)
    if path_input.endswith("/") or os.path.isdir(exp_path): exp_path = exp_path + "/"
    return exp_path


def pathtype_grid(wb: websockets.client.WebSocketClientProtocol, path: str) -> str:
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
            return RET(1, '', f"Removed file (invalid size): {file}")
        if md5(file) != reported_md5:
            os.remove(file)
            return RET(1, '', f"Removed file (invalid md5): {file}")
        return RET(0, f"{file} --> TARGET VALID")
    return RET(1)


def create_metafile(meta_filename: str, lfn: str, local_filename: str, size: Union[str, int], md5in: str, replica_list: Union[None, list] = None):
    """Generate a meta4 xrootd virtual redirector with the specified location and using the rest of arguments"""
    if not replica_list: return
    published = str(datetime.datetime.now().replace(microsecond=0).isoformat())
    with open(meta_filename, 'w') as f:
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
    src_path = Path(src_dir)
    if not src_dir.endswith('/'): parent = parent + 1
    if parent > len(src_path.parents): parent = len(src_path.parents)  # make sure maximum parent var point to first dir in path
    if parent == 0 and src_dir != '/':
        file_relative_name = src_file.replace(src_dir, '', 1)
    elif parent > 0:
        src_root = src_path.parents[parent - 1].as_posix()
        file_relative_name = src_file.replace(src_root, '', 1)
    else:
        file_relative_name = src_file
    dst_file = dst + "/" + file_relative_name
    dst_file = re.sub(r"\/{2,}", "/", dst_file)
    return dst_file


def commit(wb: websockets.client.WebSocketClientProtocol, tokenstr: str, size: int, lfn: str, perm: str, expire: str, pfn: str, se: str, guid: str, md5sum: str) -> RET:
    if not wb: return RET()
    arg_list = [tokenstr, int(size), lfn, perm, expire, pfn, se, guid, md5sum]
    return SendMsg(wb, 'commit', arg_list, opts = 'log')


def GetHumanReadable(size, precision = 2):
    suffixes = ['B', 'KiB', 'MiB']
    suffixIndex = 0
    while size > 1024 and suffixIndex < 4:
        suffixIndex += 1  # increment the index of the suffix
        size = size/1024.0  # apply the division
    return "%.*f %s" % (precision, size, suffixes[suffixIndex])


def name2regex(pattern_regex: str = '') -> str:
    if not pattern_regex: return ''
    translated_pattern_regex = '.*'
    re_all = '.*'
    verbs = ('begin', 'contain', 'ends', 'ext')
    pattern_list = pattern_regex.split('_')
    if any(verb in pattern_regex for verb in verbs):
        if pattern_list.count('begin') > 1 or pattern_list.count('end') > 1 or pattern_list.count('ext') > 1:
            print('<begin>, <end>, <ext> verbs cannot appear more than once in the name selection')
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

        if list_begin: translated_pattern_regex = re_all + list_begin[0].val  # first string after the last slash (last match explude /)
        for patt in list_contain: translated_pattern_regex = translated_pattern_regex + re_all + patt.val
        for patt in list_ends:
            translated_pattern_regex = translated_pattern_regex + re_all + patt.val
            if list_ext:
                translated_pattern_regex = translated_pattern_regex + '\\.' + list_ext[0].val
            else:
                translated_pattern_regex = translated_pattern_regex + re_all

        for path in list_ext:
            if not list_ends:  # we already added the ext in list_ends
                translated_pattern_regex = translated_pattern_regex + list_ext[0].val

        if DEBUG: print(f"Regex to be applied: {translated_pattern_regex}")
        return translated_pattern_regex
    return pattern_regex  # catch-all return just in case pattern_regex is rubbish


def makelist_lfn(wb: websockets.client.WebSocketClientProtocol, arg_source, arg_target, find_args: list, parent: int, overwrite: bool, pattern: str, pattern_regex: str, use_regex: bool, filtering_enabled: bool, copy_list: list):
    """Process a source and destination copy arguments and make a list of individual lfns to be copied"""
    isSrcDir = bool(False)
    # isDstDir = bool(False)
    slashend_src = arg_source.endswith('/')
    # slashend_dst = arg_target.endswith('/')  # not used

    isSrcLocal = isDstLocal = isDownload = None
    if (arg_source.startswith('file:') and arg_target.startswith('file:')) or (arg_source.startswith('alien:') and arg_target.startswith('alien:')):
        return RET(22, '', 'The operands cannot have the same type and need at least one specifier.\nUse any of "file:" and or "alien:" specifiers for any path arguments')  # EINVAL /* Invalid argument */

    isSrcLocal = (arg_source.startswith('file:') or arg_target.startswith('alien:')) and not (arg_source.startswith('alien:') or arg_target.startswith('file:'))
    isDownload = isDstLocal = not isSrcLocal
    arg_source = lfn_prefix_re.sub('', arg_source)
    arg_target = lfn_prefix_re.sub('', arg_target)

    arg_glob = False
    if '*' in arg_source:
        arg_glob = True
        src_arr = arg_source.split("/")
        base_path_arr = []
        for el in src_arr:
            if '*' not in el:
                base_path_arr.append(el)
            else:
                break

        for el in base_path_arr: src_arr.remove(el)  # remove the base path
        arg_source = '/'.join(base_path_arr)  # rewrite the source path without the globbing part
        if arg_source: arg_source = arg_source + '/'

        if isSrcLocal:
            pattern_regex = '/'.join(src_arr)  # the globbing part is the rest of element that contain *
            pattern_regex = pattern_regex.replace('*', '.*')
            use_regex = True
            filtering_enabled = True
        else:
            pattern = '/'.join(src_arr)  # the globbing part is the rest of element that contain *
            use_regex = False
            filtering_enabled = True

    # check for valid (single) specifications delimiter
    count_tokens = collections.Counter(arg_source if isDstLocal else arg_target)
    if count_tokens[','] + count_tokens['@'] > 1:
        msg = f"At most one of >,< or >@< tokens used for copy specification can be present in the argument. The offender is: {''.join(count_tokens)}"
        return RET(64, '', msg)  # EX_USAGE /* command line usage error */

    if not isDownload: use_regex = True
    if use_regex:
        try:
            regex = re.compile(pattern_regex)
        except re.error:
            msg = "regex argument of -select or -name option is invalid!!"
            return RET(64, '', msg)  # EX_USAGE /* command line usage error */

    src = src_type = src_specs_remotes = None  # let's record specifications like disk=3,SE1,!SE2
    if isSrcLocal:
        src = expand_path_local(arg_source)
        if not os.path.exists(src):
            msg = "source does not exist (or is not accessible)"
            return RET(2, '', msg)  # ENOENT /* No such file or directory */
        src_type = pathtype_local(src)
        if src_type == 'd':
            isSrcDir = bool(True)
            if not arg_glob and not slashend_src: parent = parent + 1
    else:
        src_specs_remotes = specs_split.split(arg_source, maxsplit = 1)  # NO comma allowed in grid names (hopefully)
        src = src_specs_remotes.pop(0)  # first item is the file path, let's remove it; it remains disk specifications
        src = expand_path_grid(src)
        src_type = pathtype_grid(wb, src)
        if not src_type:
            msg = f"Could not check source argument type: {AlienSessionInfo['error']}"
            return RET(2, '', msg)  # ENOENT /* No such file or directory */
        if src_type == 'd': isSrcDir = bool(True)

    dst = dst_type = dst_specs_remotes = None  # let's record specifications like disk=3,SE1,!SE2
    if isDstLocal:
        dst = expand_path_local(arg_target)
        dst_type = pathtype_local(dst)
        if not dst_type:
            try:
                mk_path = Path(dst) if dst.endswith('/') else Path(dst).parent
                mk_path.mkdir(parents=True, exist_ok=True)
            except Exception:
                logging.error(traceback.format_exc())
                path_str = mk_path.as_posix()
                msg = f"Could not create local destination directory: {path_str}\ncheck log file {DEBUG_FILE}"
                return RET(42, '', msg)  # ENOMSG /* No message of desired type */
            dst_type = 'd'  # we just created it
        # if dst_type == 'd': isDstDir = bool(True)
    else:
        dst_specs_remotes = specs_split.split(arg_target, maxsplit = 1)  # NO comma allowed in grid names (hopefully)
        dst = dst_specs_remotes.pop(0)  # first item is the file path, let's remove it; it remains disk specifications
        dst = expand_path_grid(dst)
        dst_type = pathtype_grid(wb, dst)
        if not dst_type:
            mk_path = dst if dst.endswith('/') else Path(dst).parent.as_posix()
            ret_obj = SendMsg(wb, 'mkdir', ['-p', mk_path], opts = 'nomsg')
            retf_print(ret_obj, opts = 'noprint err')
            if ret_obj.exitcode != 0:
                msg = f"check log file {DEBUG_FILE}"
                return RET(42, '', msg)  # ENOMSG /* No message of desired type */
            dst_type = 'd'  # we just created it
        # if dst_type == 'd': isDstDir = bool(True)

    error_msg = ''  # container which accumulates the error messages
    # if src is directory, then create list of files coresponding with options
    isWrite = bool(False)
    if isDownload:  # src is GRID, we are DOWNLOADING from GRID directory
        specs = src_specs_remotes
        if isSrcDir:  # recursive download
            find_defaults = ['-a', '-s', src]
            if use_regex:
                find_defaults.insert(0, '-r')
                find_defaults.append(pattern_regex)
            else:
                find_defaults.append(pattern)
            find_args.extend(find_defaults)
            send_opts = 'nomsg' if not DEBUG else ''
            ret_obj = SendMsg(wb, 'find', find_args, opts = send_opts)
            src_list_files_dict = ret_obj.ansdict
            if ret_obj.exitcode != 0:
                msg = f"Find returned error when using: {find_args}\n{ret_obj.err}\nEnable debug with ALIENPY_DEBUG=1 and check {DEBUG_FILE} for detailed logging"
                return RET(42, '', msg)  # ENOMSG /* No message of desired type */
            if len(src_list_files_dict['results']) < 1:
                msg = f"No files found using: {find_args}\n{ret_obj.err}\nEnable debug with ALIENPY_DEBUG=1 and check {DEBUG_FILE} for detailed logging"
                return RET(42, '', msg)  # ENOMSG /* No message of desired type */
            for item in src_list_files_dict['results']:
                dst_filename = format_dst_fn(src, item['lfn'], dst, parent)
                if os.path.isfile(dst_filename) and not overwrite:
                    print(f'{dst_filename} exists, skipping..', flush = True)
                    continue
                tokens = getEnvelope_lfn(wb, lfn2file(item['lfn'], dst_filename), specs, isWrite)
                if 'answer' not in tokens or not tokens['answer'] or AlienSessionInfo['exitcode'] != 0:
                    error_msg = f"{error_msg}\n{tokens['lfn']} -> {AlienSessionInfo['error']}" if error_msg else f"{tokens['lfn']} -> {AlienSessionInfo['error']}"
                    continue
                copy_list.append(CopyFile(item['lfn'], dst_filename, isWrite, tokens['answer'], ''))
        else:
            if dst.endswith("/"): dst = dst[:-1] + setDst(src, parent)
            if os.path.isfile(dst) and not overwrite:
                msg = f'{dst} exists, skipping..'
                return RET(0, msg)  # Destination present we will not overwrite it
            tokens = getEnvelope_lfn(wb, lfn2file(src, dst), specs, isWrite)
            if 'answer' not in tokens or not tokens['answer'] or AlienSessionInfo['exitcode'] != 0:
                error_msg = f"{error_msg}\n{tokens['lfn']} -> {AlienSessionInfo['error']}" if error_msg else f"{tokens['lfn']} -> {AlienSessionInfo['error']}"
            else:
                copy_list.append(CopyFile(src, dst, isWrite, tokens['answer'], ''))
    else:  # src is LOCAL, we are UPLOADING from LOCAL directory
        isWrite = True
        specs = dst_specs_remotes
        if isSrcDir:  # recursive upload
            for root, dirs, files in os.walk(src):
                for file in files:
                    filepath = os.path.join(root, file)
                    if regex.search(filepath):
                        lfn = format_dst_fn(src, filepath, dst, parent)
                        lfn_exists = pathtype_grid(wb, lfn)
                        if lfn_exists:
                            if not overwrite:  # if the lfn is already present and not overwrite lets's skip the upload
                                print(f'{lfn} exists, skipping..', flush = True)
                                continue
                            # clear up the destination lfn
                            print(f'{lfn} exists, deleting..', flush = True)
                            ret_obj = SendMsg(wb, 'rm', ['-f', lfn], opts = 'nomsg')
                        tokens = getEnvelope_lfn(wb, lfn2file(lfn, filepath), specs, isWrite)
                        if 'answer' not in tokens or not tokens['answer'] or AlienSessionInfo['exitcode'] != 0:
                            error_msg = f"{error_msg}\n{tokens['lfn']} -> {AlienSessionInfo['error']}" if error_msg else f"{tokens['lfn']} -> {AlienSessionInfo['error']}"
                            continue
                        copy_list.append(CopyFile(filepath, lfn, isWrite, tokens['answer'], ''))
        else:
            if dst.endswith("/"): dst = dst[:-1] + setDst(src, parent)
            lfn_exists = pathtype_grid(wb, dst)
            if lfn_exists:
                if not overwrite: return RET(0, f'{dst} exists, skipping..')  # if the lfn is already present and not overwrite lets's skip the upload
                print(f'{dst} exists, deleting..', flush = True)  # clear up the destination lfn
                ret_obj = SendMsg(wb, 'rm', ['-f', dst], 'nomsg')
                retf_print(ret_obj, 'print')
            tokens = getEnvelope_lfn(wb, lfn2file(dst, src), specs, isWrite)
            if 'answer' not in tokens or not tokens['answer'] or AlienSessionInfo['exitcode'] != 0:
                error_msg = f"{error_msg}\n{tokens['lfn']} -> {AlienSessionInfo['error']}" if error_msg else f"{tokens['lfn']} -> {AlienSessionInfo['error']}"
            else:
                copy_list.append(CopyFile(src, dst, isWrite, tokens['answer'], ''))
    if error_msg:
        print(error_msg, file=sys.stderr, flush = True)


def makelist_xrdjobs(wb: websockets.client.WebSocketClientProtocol, copylist_lfns: list, copylist_xrd: list):
    """Process a list of lfns to XRootD copy jobs and add them to the list"""
    for cpfile in copylist_lfns:
        if not cpfile.isUpload:
            lfn = cpfile.src
            if not cpfile.token_request["results"]: continue
            dst = cpfile.dst
            size_4meta = cpfile.token_request['results'][0]['size']  # size SHOULD be the same for all replicas
            md5_4meta = cpfile.token_request['results'][0]['md5']  # the md5 hash SHOULD be the same for all replicas
            if retf_print(fileIsValid(dst, size_4meta, md5_4meta), 'noprint') == 0: continue  # destination exists and is valid

            # multiple replicas are downloaded to a single file
            is_zip = False
            file_in_zip = ''
            url_list_4meta = []
            for replica in cpfile.token_request['results']:
                url_components = replica['url'].rsplit('#', maxsplit = 1)
                if len(url_components) > 1:
                    is_zip = True
                    file_in_zip = url_components[1]
                # if is_pfn_readable(url_components[0]):  # it is a lot cheaper to check readability of replica than to try and fail a non-working replica
                url_list_4meta.append(url_components[0] + '?authz=' + replica['envelope'])

            if not url_list_4meta:
                print(f'Could not find working replicas of {lfn}', file=sys.stderr, flush = True)
                continue

            # Create the metafile based link
            meta_fn = make_tmp_fn(lfn, '.meta4', True)  # create a temporary uuid5 named file (the lfn can be retrieved from meta if needed)
            create_metafile(meta_fn, lfn, dst, size_4meta, md5_4meta, url_list_4meta)
            download_link = meta_fn
            if is_zip: download_link = f'{download_link}?xrdcl.unzip={file_in_zip}'
            copylist_xrd.append(CopyFile(download_link, dst, cpfile.isUpload, {}, lfn))  # we do not need the tokens in job list when downloading
        else:  # is upload
            src = cpfile.src
            lfn = cpfile.dst
            if not cpfile.token_request['results']: continue
            for request in cpfile.token_request['results']:
                copylist_xrd.append(CopyFile(src, f"{request['url']}?authz={request['envelope']}", cpfile.isUpload, request, lfn))


def DO_XrootdCp(wb: websockets.client.WebSocketClientProtocol, xrd_copy_command: Union[None, list] = None, printout: str = '') -> RET:
    """XRootD cp function :: process list of arguments for a xrootd copy command"""
    if not has_xrootd: return RET(1, "", 'DO_XrootdCp:: python XRootD module cannot be found, the copy process cannot continue')
    if xrd_copy_command is None: xrd_copy_command = []
    global AlienSessionInfo
    if not wb: return RET(107, "", 'DO_XrootdCp:: websocket not found')  # ENOTCONN /* Transport endpoint is not connected */

    if not xrd_copy_command or len(xrd_copy_command) < 2 or '-h' in xrd_copy_command or '-help' in xrd_copy_command:
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

    # xrdcp parameters (used by ALICE tests)
    # http://xrootd.org/doc/man/xrdcp.1.html
    # xrootd defaults https://github.com/xrootd/xrootd/blob/master/src/XrdCl/XrdClConstants.hh

    # Override the application name reported to the server.
    os.environ["XRD_APPNAME"] = "alien.py"

    # Number of connection attempts that should be made (number of available connection windows) before declaring a permanent failure.
    if not os.getenv('XRD_CONNECTIONRETRY'): os.environ["XRD_CONNECTIONRETRY"] = "3"

    # A time window for the connection establishment. A connection failure is declared if the connection is not established within the time window.
    # N.B.!!. If a connection failure happens earlier then another connection attempt will only be made at the beginning of the next window
    if not os.getenv('XRD_CONNECTIONWINDOW'): os.environ["XRD_CONNECTIONWINDOW"] = "10"

    # Default value for the time after which an error is declared if it was impossible to get a response to a request.
    if not os.getenv('XRD_REQUESTTIMEOUT'): os.environ["XRD_REQUESTTIMEOUT"] = "30"

    # Maximum time allowed for the copy process to initialize, ie. open the source and destination files.
    if not os.getenv('XRD_CPINITTIMEOUT'): os.environ["XRD_CPINITTIMEOUT"] = "90"  #

    # Maximum time allowed for a third-party copy operation to finish.
    if not os.getenv('XRD_CPTPCTIMEOUT'): os.environ["XRD_CPTPCTIMEOUT"] = "1800"  # this is the default

    # Time period after which an idle connection to a data server should be closed.
    if not os.getenv('XRD_DATASERVERTTL'): os.environ["XRD_DATASERVERTTL"] = "15"  # we have no reasons to keep idle connections

    # Time period after which an idle connection to a manager or a load balancer should be closed.
    if not os.getenv('XRD_LOADBALANCERTTL'): os.environ["XRD_LOADBALANCERTTL"] = "30"  # we have no reasons to keep idle connections

    # Resolution for the timeout events. Ie. timeout events will be processed only every XRD_TIMEOUTRESOLUTION seconds.
    if not os.getenv('XRD_TIMEOUTRESOLUTION'): os.environ["XRD_TIMEOUTRESOLUTION"] = "1"

    # If set the client tries first IPv4 address (turned off by default).
    if not os.getenv('XRD_PREFERIPV4'): os.environ["XRD_PREFERIPV4"] = "1"

    if '-f' in xrd_copy_command:
        overwrite = True
        xrd_copy_command.remove('-f')

    if '-P' in xrd_copy_command:
        posc = True
        xrd_copy_command.remove('-P')

    if '-cksum' in xrd_copy_command:
        cksum = True
        xrd_copy_command.remove('-cksum')

    # if '-tpc' in xrd_copy_command:
        # tpc = str('first')
        # xrd_copy_command.remove('-tpc')

    if '-y' in xrd_copy_command:
        y_idx = xrd_copy_command.index('-y')
        print("Ignored option! multiple source usage is known to break the files stored in zip files, so better to be ignored", flush = True)
        # sources = int(xrd_copy_command.pop(y_idx + 1))
        xrd_copy_command.pop(y_idx)

    if '-S' in xrd_copy_command:
        s_idx = xrd_copy_command.index('-S')
        streams = int(xrd_copy_command.pop(s_idx + 1))
        xrd_copy_command.pop(y_idx)
    elif os.getenv('XRD_SUBSTREAMSPERCHANNEL'):
        streams = int(os.getenv('XRD_SUBSTREAMSPERCHANNEL'))

    batch = 8  # a nice enough default
    if '-T' in xrd_copy_command:
        batch_idx = xrd_copy_command.index('-T')
        batch = int(xrd_copy_command.pop(batch_idx + 1))
        xrd_copy_command.pop(batch_idx)

    if '-chunks' in xrd_copy_command:
        chunks_nr_idx = xrd_copy_command.index('-chunks')
        chunks = int(xrd_copy_command.pop(chunks_nr_idx + 1))
        xrd_copy_command.pop(chunks_nr_idx)
    elif os.getenv('XRD_CPPARALLELCHUNKS'):
        chunks = int(os.getenv('XRD_CPPARALLELCHUNKS'))

    if '-chunksz' in xrd_copy_command:
        chksz_idx = xrd_copy_command.index('-chunksz')
        chunksize = int(xrd_copy_command.pop(chksz_idx + 1))
        xrd_copy_command.pop(chksz_idx)
    elif os.getenv('XRD_CPCHUNKSIZE'):
        chunksize = int(os.getenv('XRD_CPCHUNKSIZE'))

    # find options for recursive copy of directories
    find_args = []
    parent = int(0)
    if '-parent' in xrd_copy_command:
        parent_idx = xrd_copy_command.index('-parent')
        parent = int(xrd_copy_command.pop(parent_idx + 1))
        xrd_copy_command.pop(parent_idx)

    if '-a' in xrd_copy_command:
        find_args.append('-a')
        xrd_copy_command.remove('-a')

    if '-v' in xrd_copy_command:
        # print("Verbose mode not implemented, ignored")
        xrd_copy_command.remove('-v')

    if '-j' in xrd_copy_command:
        qid_idx = xrd_copy_command.index('-j')
        find_args.append('-j')
        find_args.append(xrd_copy_command.pop(qid_idx + 1))
        xrd_copy_command.pop(qid_idx)

    if '-l' in xrd_copy_command:
        return_nr_idx = xrd_copy_command.index('-l')
        find_args.append('-l')
        find_args.append(xrd_copy_command.pop(return_nr_idx + 1))
        xrd_copy_command.pop(return_nr_idx)

    if '-o' in xrd_copy_command:
        skip_nr_idx = xrd_copy_command.index('-o')
        find_args.append('-o')
        find_args.append(xrd_copy_command.pop(skip_nr_idx + 1))
        xrd_copy_command.pop(skip_nr_idx)

    pattern = '*'
    pattern_regex = '.*'  # default regex selection for find
    use_regex = False
    filtering_enabled = False

    if '-glob' in xrd_copy_command:
        select_idx = xrd_copy_command.index('-glob')
        pattern = xrd_copy_command.pop(select_idx + 1)
        xrd_copy_command.pop(select_idx)
        use_regex = False
        filtering_enabled = True

    if '-select' in xrd_copy_command:
        if filtering_enabled:
            msg = "Only one rule of selection can be used, either -select (full path match), -name (match on file name) or -glob (globbing)"
            return RET(22, '', msg)  # EINVAL /* Invalid argument */
        select_idx = xrd_copy_command.index('-select')
        pattern_regex = xrd_copy_command.pop(select_idx + 1)
        xrd_copy_command.pop(select_idx)
        use_regex = True
        filtering_enabled = True

    if '-name' in xrd_copy_command:
        if filtering_enabled:
            msg = "Only one rule of selection can be used, either -select (full path match), -name (match on file name) or -glob (globbing)"
            return RET(22, '', msg)  # EINVAL /* Invalid argument */
        name_idx = xrd_copy_command.index('-name')
        pattern_regex = xrd_copy_command.pop(name_idx + 1)
        xrd_copy_command.pop(name_idx)
        use_regex = True
        filtering_enabled = True

        pattern_regex = name2regex(pattern_regex)
        if not pattern_regex:
            msg = "No selection verbs were recognized! usage format is -name <attribute>_<string> where attribute is one of: begin, contain, ends, ext"
            return RET(22, '', msg)  # EINVAL /* Invalid argument */

    copy_lfnlist = []  # list of lfn copy tasks
    input_file = ''  # input file with <source, destination> pairs

    if '-input' in xrd_copy_command:
        input_idx = xrd_copy_command.index('-input')
        input_file = xrd_copy_command.pop(input_idx + 1)
        xrd_copy_command.pop(input_idx)
        if not os.path.isfile(input_file): return RET(1, '', f'Input file {input_file} not found')

        with open(input_file) as arglist_file:
            for line in arglist_file:
                if not line or ignore_comments_re.search(line) or emptyline_re.match(line): continue
                arglist = line.strip().split()
                if len(arglist) > 2:
                    print(f'Line skipped, it has more than 2 arguments => f{line.strip()}')
                    continue
                makelist_lfn(wb, arglist[0], arglist[1], find_args, parent, overwrite, pattern, pattern_regex, use_regex, filtering_enabled, copy_lfnlist)
    else:
        makelist_lfn(wb, xrd_copy_command[-2], xrd_copy_command[-1], find_args, parent, overwrite, pattern, pattern_regex, use_regex, filtering_enabled, copy_lfnlist)

    if not copy_lfnlist:
        msg = "No copy operations in list! enable the DEBUG mode for more info"
        logging.info(msg)
        return RET(2, '', msg)  # ENOENT /* No such file or directory */

    if DEBUG:
        logging.debug("We are going to copy these files:")
        for file in copy_lfnlist: logging.debug(file)

    # create a list of copy jobs to be passed to XRootD mechanism
    xrdcopy_job_list = []
    makelist_xrdjobs(wb, copy_lfnlist, xrdcopy_job_list)

    if not xrdcopy_job_list:
        msg = "No XRootD operations in list! enable the DEBUG mode for more info"
        logging.info(msg)
        return RET(2, '', msg)  # ENOENT /* No such file or directory */

    if DEBUG:
        logging.debug("XRootD copy jobs:")
        for file in xrdcopy_job_list: logging.debug(file)

    my_cp_args = XrdCpArgs(overwrite, batch, sources, chunks, chunksize, makedir, posc, hashtype, streams, cksum)
    # defer the list of url and files to xrootd processing - actual XRootD copy takes place
    copy_failed_list = XrdCopy(wb, xrdcopy_job_list, my_cp_args, printout)

    # hard to return a single exitcode for a copy process optionally spanning multiple files
    # we'll return SUCCESS if at least one lfn is confirmed, FAIL if not lfns is confirmed
    copy_jobs_nr = len(xrdcopy_job_list)
    copy_jobs_failed_nr = len(copy_failed_list)
    copy_jobs_success_nr = copy_jobs_nr - copy_jobs_failed_nr
    msg = f"Succesful copy jobs: {copy_jobs_success_nr}/{copy_jobs_nr}"
    return RET(0, msg) if copy_jobs_failed_nr < copy_jobs_nr else RET(1, '', msg)


if has_xrootd:
    class MyCopyProgressHandler(client.utils.CopyProgressHandler):
        def __init__(self):
            self.wb = None
            self.copy_failed_list = []  # record the tokens of succesfully uploaded files. needed for commit to catalogue
            self.jobs = int(0)
            self.job_list = []
            self.xrdjob_list = []
            self.printout = ''

        def begin(self, jobId, total, source, target):
            timestamp_begin = datetime.datetime.now().timestamp()
            if not ('quiet' in self.printout or 'silent' in self.printout):
                print("jobID: {0}/{1} >>> Start".format(jobId, total), flush = True)
            self.jobs = int(total)
            jobInfo = {'src': source, 'tgt': target, 'bytes_total': 0, 'bytes_processed': 0, 'start': timestamp_begin}
            self.job_list.insert(jobId - 1, jobInfo)
            if DEBUG: logging.debug("CopyProgressHandler.src: {0}\nCopyProgressHandler.dst: {1}\n".format(source, target))

        def end(self, jobId, results):
            results_message = results['status'].message
            results_status = results['status'].status
            results_errno = results['status'].errno
            results_code = results['status'].code
            status = PrintColor(COLORS.BIRed) + 'UNKNOWN' + PrintColor(COLORS.ColorReset)
            if results['status'].ok: status = PrintColor(COLORS.Green) + 'OK' + PrintColor(COLORS.ColorReset)
            if results['status'].error: status = PrintColor(COLORS.BRed) + 'ERROR' + PrintColor(COLORS.ColorReset)
            if results['status'].fatal: status = PrintColor(COLORS.BIRed) + 'FATAL' + PrintColor(COLORS.ColorReset)
            xrdjob = self.xrdjob_list[jobId - 1]  # joblist initilized when starting; we use the internal index to locate the job
            if not xrdjob.isUpload:
                if not os.getenv('ALIENPY_KEEP_META'): os.remove(xrdjob.src)  # remove the created metalink
            if results['status'].ok:
                deltaT = datetime.datetime.now().timestamp() - float(self.job_list[jobId - 1]['start'])
                speed = float(self.job_list[jobId - 1]['bytes_total'])/deltaT
                speed_str = str(GetHumanReadable(speed)) + '/s'
                if xrdjob.isUpload:  # isUpload
                    xrd_dst_url = str(self.job_list[jobId - 1]['tgt'])
                    link = urlparse(xrd_dst_url)
                    urltoken = next((param for param in str.split(link.query, '&') if 'authz=' in param), None).replace('authz=', '')  # extract the token from url
                    copyjob = next(job for job in self.xrdjob_list if job.token_request.get('url') in xrd_dst_url)
                    replica_dict = copyjob.token_request
                    perm = '644'
                    expire = '0'
                    ret_obj = commit(self.wb, urltoken, replica_dict['size'], copyjob.lfn, perm, expire, replica_dict['url'], replica_dict['se'], replica_dict['guid'], replica_dict['md5'])
                    if DEBUG: retf_print(ret_obj, 'debug')

                if not ('quiet' in self.printout or 'silent' in self.printout):
                    print("jobID: {0}/{1} >>> ERRNO/CODE/XRDSTAT {2}/{3}/{4} >>> STATUS {5} >>> SPEED {6} MESSAGE: {7}".format(jobId, self.jobs, results_errno, results_code, results_status, status, speed_str, results_message), flush = True)
            else:
                if xrdjob.isUpload:
                    self.copy_failed_list.append(xrdjob.token_request)
                    print(f"Failed upload: {xrdjob.token_request['file']} to {xrdjob.token_request['se']}, from {xrdjob.token_request['nSEs']} total replicas", flush = True)
                else:
                    self.copy_failed_list.append(xrdjob.lfn)
                    print(f"Failed download: {xrdjob.lfn}", flush = True)

        def update(self, jobId, processed, total):
            self.job_list[jobId - 1]['bytes_processed'] = processed
            self.job_list[jobId - 1]['bytes_total'] = total

        def should_cancel(self, jobId):
            return False


def XrdCopy(wb: websockets.client.WebSocketClientProtocol, job_list: list, xrd_cp_args: XrdCpArgs, printout: str = '') -> list:
    """XRootD copy command :: the actual XRootD copy process"""
    if not has_xrootd:
        print("XRootD not found", file=sys.stderr, flush = True)
        return []
    if not xrd_cp_args:
        print("cp arguments are not set, XrdCpArgs tuple missing", file=sys.stderr, flush = True)
        return []

    overwrite = xrd_cp_args.overwrite
    batch = xrd_cp_args.batch
    sources = xrd_cp_args.sources
    chunks = xrd_cp_args.chunks
    chunksize = xrd_cp_args.chunksize
    makedir = xrd_cp_args.makedir
    posc = xrd_cp_args.posc
    # hashtype = xrd_cp_args.hashtype
    streams = xrd_cp_args.streams
    cksum = xrd_cp_args.cksum

    if streams > 0:
        if streams > 15: streams = 15
        client.EnvPutInt('SubStreamsPerChannel', streams)

    cksum_mode = 'none'
    cksum_type = ''
    delete_invalid_chk = False
    if cksum:
        client.EnvPutInt('ZipMtlnCksum', 1)
        cksum_mode = 'end2end'
        cksum_type = 'auto'
        delete_invalid_chk = True

    handler = MyCopyProgressHandler()
    handler.wb = wb
    handler.xrdjob_list = job_list
    handler.printout = printout

    # get xrootd client version
    has_cksum = False
    xrd_ver_arr = client.__version__.split(".")
    if len(xrd_ver_arr) > 1:
        xrdver_major = xrd_ver_arr[0][1:] if xrd_ver_arr[0].startswith('v') else xrd_ver_arr[0]  # take out the v if present
        if xrdver_major.isdecimal() and int(xrdver_major) >= 5:
            has_cksum = True
        elif xrd_ver_arr[1].isdigit():
            xrdver_minor = int(xrd_ver_arr[1])
            # xrdver_patch = xrd_ver_arr[2]
            if xrdver_major == '4' and xrdver_minor > 12: has_cksum = True
        else:
            xrdver_minor = xrd_ver_arr[1]
            has_cksum = True  # minor version is not proper digit, it is assumed a version with this feature
    else:  # version is not of x.y.z form
        xrdver_git = xrd_ver_arr[0].split("-")
        if xrdver_git[0].isdecimal():
            xrdver_date = int(xrdver_git[0][1:])
            if xrdver_date > 20200408: has_cksum = True

    process = client.CopyProcess()
    process.parallel(int(batch))
    for copy_job in job_list:
        if DEBUG: logging.debug("\nadd copy job with\nsrc: {0}\ndst: {1}\n".format(copy_job.src, copy_job.dst))
        if has_cksum:
            process.add_job(copy_job.src, copy_job.dst, sourcelimit = sources, force = overwrite, posc = posc, mkdir = makedir, chunksize = chunksize, parallelchunks = chunks,
                            checksummode = cksum_mode, checksumtype = cksum_type, rmBadCksum = delete_invalid_chk)
        else:
            process.add_job(copy_job.src, copy_job.dst, sourcelimit = sources, force = overwrite, posc = posc, mkdir = makedir, chunksize = chunksize, parallelchunks = chunks)

    process.prepare()
    process.run(handler)
    return handler.copy_failed_list  # for upload jobs we must return the list of token for succesful uploads


def xrd_stat(pfn: str):
    if not has_xrootd:
        print('python XRootD module cannot be found, the copy process cannot continue')
        return None
    url_components = urlparse(pfn)
    endpoint = client.FileSystem(url_components.netloc)
    answer = endpoint.stat(url_components.path)
    return answer


def get_pfn_flags(pfn: str):
    answer = xrd_stat(pfn)
    if not answer[0].ok: return None
    return answer[1].flags


def is_pfn_readable(pfn: str) -> bool:
    flags = get_pfn_flags(pfn)
    if flags is None: return False
    return bool(flags & client.flags.StatInfoFlags.IS_READABLE)


def DO_pfnstatus(args: Union[list, None] = None) -> RET:
    global AlienSessionInfo
    if args is None: args = []
    if not args or '-h' in args or '-help' in args:
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
    x_bit_set = 1 if flags & client.flags.StatInfoFlags.X_BIT_SET else 0
    is_dir = 1 if flags & client.flags.StatInfoFlags.IS_DIR else 0
    other = 1 if flags & client.flags.StatInfoFlags.OTHER else 0
    offline = 1 if flags & client.flags.StatInfoFlags.OFFLINE else 0
    posc_pending = 1 if flags & client.flags.StatInfoFlags.POSC_PENDING else 0
    is_readable = 1 if flags & client.flags.StatInfoFlags.IS_READABLE else 0
    is_writable = 1 if flags & client.flags.StatInfoFlags.IS_WRITABLE else 0
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


def get_pfn_list(wb: websockets.client.WebSocketClientProtocol, lfn: str) -> list:
    if not wb: return []
    if not lfn: return []
    if pathtype_grid(wb, lfn) != 'f': return []
    ret_obj = SendMsg(wb, 'whereis', [lfn], opts = 'nomsg')
    retf_print(ret_obj, 'debug')
    return [str(item['pfn']) for item in ret_obj.ansdict['results']]


def DO_getSE(wb: websockets.client.WebSocketClientProtocol, args: list = None) -> RET:
    if not wb: return []
    if not args: args = []
    if '-h' in args or '-help' in args:
        msg = 'Command format: getSE <-id | -name | -srv> identifier_string\nReturn the specified property for the SE specified label'
        return RET(0, msg)

    ret_obj = SendMsg(wb, 'listSEs', [], 'nomsg')
    if ret_obj.exitcode != 0: return ret_obj

    arg_select = None
    if '-id' in args:
        args.remove('-id')
        arg_select = 'id'
    if '-name' in args:
        args.remove('-name')
        arg_select = 'name'
    if '-srv' in args:
        args.remove('-srv')
        arg_select = 'srv'

    if not args:
        se_list = [f"{se['seNumber']}\t{se['seName']}\t{se['endpointUrl'].replace('root://','')}" for se in ret_obj.ansdict["results"]]
        return RET(0, '\n'.join(se_list))

    def match_name(se: Union[dict, None] = None, name: str = '') -> bool:
        if se is None or not name: return False
        if name.isdecimal(): return name in se['seNumber']
        return (name.casefold() in se['seName'].casefold() or name.casefold() in se['seNumber'].casefold() or name.casefold() in se['endpointUrl'].casefold())

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


def get_lfn_meta(meta_fn: str) -> str:
    if not os.path.isfile(meta_fn): return ''
    import xml.dom.minidom
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
    if not ext: ext = '_' + str(os.getuid()) + '.alienpy_tmp'
    return TMPDIR + '/' + lfn2tmp_fn(lfn, uuid5) + ext


def get_lfn_name(tmp_name: str = '', ext: str = '') -> str:
    lfn = tmp_name.replace(ext, '') if ext else tmp_name.replace('_' + str(os.getuid()) + '.alienpy_tmp', '')
    return lfn.replace(TMPDIR + '/', '').replace("%%", "/")


def download_tmp(wb: websockets.client.WebSocketClientProtocol, lfn: str, overwrite: bool = False) -> str:
    """Download a lfn to a temporary file, it will return the file path of temporary"""
    global AlienSessionInfo
    tmpfile = make_tmp_fn(expand_path_grid(lfn))
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


def upload_tmp(wb: websockets.client.WebSocketClientProtocol, temp_file_name: str, upload_specs: str = '', dated_backup: bool = False) -> str:
    """Upload a temporary file: the original lfn will be renamed and the new file will be uploaded with the original lfn"""
    lfn = get_lfn_name(temp_file_name)  # lets recover the lfn from temp file name
    lfn_backup = lfn + "." + now_str() if dated_backup else lfn + "~"
    if not dated_backup:
        ret_obj = SendMsg(wb, 'rm', ['-f', lfn_backup])  # remove already present old backup; useless to pre-check
    ret_obj = SendMsg(wb, 'mv', [lfn, lfn_backup])  # let's create a backup of old lfn
    retf_print(ret_obj, 'debug')
    if retf_print(ret_obj) != 0: return ''
    tokens = getEnvelope_lfn(wb, lfn2file(lfn, temp_file_name), [upload_specs], isWrite = True)
    access_request = tokens['answer']
    replicas = access_request["results"][0]["nSEs"]
    if "disk:" not in upload_specs: upload_specs = "disk:" + replicas
    if upload_specs: upload_specs = "@" + upload_specs
    copycmd = "-f " + 'file:' + temp_file_name + " " + lfn + upload_specs
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


def DO_queryML(args: Union[list, None] = None) -> RET:
    """submit: process submit commands for local jdl cases"""
    global AlienSessionInfo
    if args is None: args = []
    if '-h' in args:
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
    row_format_list = ['{: <' + str(w) + '}' for w in max_value_size]
    row_format = "".join(row_format_list)

    msg = row_format.format(*keys)
    for row in ans_list:
        value_list = [row.get(key) for key in keys]
        msg = msg + "\n" + row_format.format(*value_list)
    return RET(AlienSessionInfo['exitcode'], msg, "")


def DO_submit(wb: websockets.client.WebSocketClientProtocol, args: Union[list, None] = None) -> RET:
    """submit: process submit commands for local jdl cases"""
    if not args or args is None: args = ['-h']
    if '-h' in args: return get_help_srv(wb, 'submit')
    if args[0].startswith("file:"):
        msg = ("Specifications as where to upload the jdl to be submitted and with what parameters are not yet defined"
               "Upload first the jdl to a suitable location (with a safe number of replicas) and then submit")
        return RET(0, msg)
    args[0] = expand_path_grid(args[0])
    return SendMsg(wb, 'submit', args)


def DO_ps(wb: websockets.client.WebSocketClientProtocol, args: Union[list, None] = None) -> RET:
    """ps : show and process ps output"""
    if args is None: args = []
    ret_obj = SendMsg(wb, 'ps', args)
    if '-trace' in args:
        nice_lines = [convert_time(str(msgline)) for item in ret_obj.ansdict['results'] for msgline in item['message'].split('\n')]
        return ret_obj._replace(out = '\n'.join(nice_lines))
    return ret_obj


def DO_cat(wb: websockets.client.WebSocketClientProtocol, args: Union[list, None] = None) -> RET:
    """cat lfn :: download lfn as a temporary file and cat"""
    if not args or args is None: args = ['-h']
    if '-h' in args: return get_help_srv(wb, 'cat')
    tmp = download_tmp(wb, args[-1])
    if tmp and os.path.isfile(tmp): return runShellCMD('cat ' + tmp)
    return RET(1, '', f'Could not download {args[-1]}')


def DO_less(wb: websockets.client.WebSocketClientProtocol, args: Union[list, None] = None) -> RET:
    """less lfn :: apply less on a downloaded lfn as a temporary file"""
    args.insert(0, '-noout')  # keep app open, do not terminate
    args.insert(0, 'less')
    return DO_run(wb, args, external = True)


def DO_more(wb: websockets.client.WebSocketClientProtocol, args: Union[list, None] = None) -> RET:
    """more lfn :: apply more on a downloaded lfn as a temporary file"""
    args.insert(0, '-noout')  # keep app open, do not terminate
    args.insert(0, 'more')
    return DO_run(wb, args, external = True)


def DO_pfn(wb: websockets.client.WebSocketClientProtocol, args: Union[list, None] = None) -> RET:
    if args is None: args = []
    if '-h' in args:
        msg = 'Command format : pfn [lfn]\nIt will print only the list of associtated pfns (simplified form of whereis)'
        return RET(0, msg)
    cmd = 'whereis'
    args.insert(0, '-r')
    ret_obj = SendMsg(wb, cmd, args, opts = 'nomsg')
    msg = '\n'.join(str(item['pfn']) for item in ret_obj.ansdict['results'] if 'pfn' in item).strip()
    return ret_obj._replace(out = msg)


def token(wb: websockets.client.WebSocketClientProtocol, args: Union[None, list] = None) -> int:
    """(Re)create the tokencert and tokenkey files"""
    if not wb: return 1
    if not args: args = []
    global AlienSessionInfo
    tokencert, tokenkey = get_files_token()

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


def token_regen(wb: websockets.client.WebSocketClientProtocol, args: Union[None, list] = None) -> websockets.client.WebSocketClientProtocol:
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


def DO_token(wb: websockets.client.WebSocketClientProtocol, args: Union[list, None] = None) -> RET:
    if args is None: args = []
    msg = "Print only command!!! Use >token-init< for token (re)generation, see below the arguments\n"
    ret_obj = SendMsg(wb, 'token', args, opts = 'nokeys')
    return ret_obj._replace(out = msg + ret_obj.out)


def DO_token_init(wb: websockets.client.WebSocketClientProtocol, args: Union[list, None] = None) -> RET:
    if args is None: args = []
    if len(args) > 0 and args[0] in ['-h', 'help', '-help']:
        ret_obj = SendMsg(wb, 'token', ['-h'], opts = 'nokeys')
        return ret_obj._replace(out = ret_obj.out.replace('usage: token', 'usage: token-init'))
    wb = token_regen(wb, args)
    tokencert, tokenkey = get_files_token()
    return CertInfo(tokencert)


def DO_edit(wb: websockets.client.WebSocketClientProtocol, args: Union[list, None] = None, editor: str = '') -> RET:
    """Edit a grid lfn; download a temporary, edit with the specified editor and upload the new file"""
    if not args or args is None: args = ['-h']
    if '-h' in args:
        msg = """Command format: edit lfn\nAfter editor termination the file will be uploaded if md5 differs
-datebck : the backup filename will be date based
N.B. EDITOR env var must be set or fallback will be mcedit (not checking if exists)"""
        return RET(0, msg)
    if not editor:
        editor = os.getenv('EDITOR')
        if not editor:
            print('EDITOR env variable not set, we will fallback to mcedit (no check if exists)')
            editor = 'mcedit -u'
    versioned_backup = False
    if '-datebck' in args:
        args.remove('-datebck')
        versioned_backup = True
    lfn = expand_path_grid(args[-1])  # assume that the last argument is the lfn
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
        ret_obj = runShellCMD(editor + ' ' + tmp, captureout = False)
        if ret_obj.exitcode != 0: return retf_print(ret_obj)
        md5_end = md5(tmp)
        if md5_begin != md5_end:
            uploaded_file = upload_tmp(wb, tmp, ','.join(specs), dated_backup = versioned_backup)
            os.remove(tmp)  # clean up the temporary file not matter if the upload was succesful or not
            return RET(0, f'Uploaded {uploaded_file}') if uploaded_file else RET(1, '', f'Error uploading {uploaded_file}')
        return RET(0)
    return RET(1, '', f'Error downloading {lfn}, editing could not be done.')


def DO_mcedit(wb: websockets.client.WebSocketClientProtocol, args: Union[list, None] = None) -> RET: return DO_edit(wb, args, editor = 'mcedit')


def DO_vi(wb: websockets.client.WebSocketClientProtocol, args: Union[list, None] = None) -> RET: return DO_edit(wb, args, editor = 'vi')


def DO_vim(wb: websockets.client.WebSocketClientProtocol, args: Union[list, None] = None) -> RET: return DO_edit(wb, args, editor = 'vim')


def DO_nano(wb: websockets.client.WebSocketClientProtocol, args: Union[list, None] = None) -> RET: return DO_edit(wb, args, editor = 'nano')


def DO_run(wb: websockets.client.WebSocketClientProtocol, args: Union[list, None] = None, external: bool = False) -> RET:
    """run shell_command lfn|alien: tagged lfns :: download lfn(s) as a temporary file and run shell command on the lfn(s)"""
    if args is None: args = []
    if not args: return RET(1, '', 'No shell command specified')
    if '-h' in args or len(args) == 1:
        msg_last = ('Command format: shell_command arguments lfn\n'
                    'N.B.!! the lfn must be the last element of the command!!\n'
                    'N.B.! The output and error streams will be captured and printed at the end of execution!\n'
                    'for working within application use <edit> or -noout argument\n'
                    'additiona arguments recognized independent of the shell command:\n'
                    '-force : will re-download the lfn even if already present\n'
                    '-noout : will not capture output, the actual application can be used')

        if external:
            ret_obj = runShellCMD(args[0] + ' -h')
            return ret_obj._replace(out = ret_obj.out + '\n' + msg_last)
        msg = ('Command format: run shell_command arguments lfn\n'
               'the lfn must be the last element of the command\n'
               'N.B.! The output and error streams will be captured and printed at the end of execution!\n'
               'for working within application use <edit>\n'
               'additiona arguments recognized independent of the shell command:\n'
               '-force : will re-download the lfn even if already present\n'
               '-noout : will not capture output, the actual application can be used')
        return RET(0, msg)

    overwrite = False
    if '-force' in args:
        args.remove('-force')
        overwrite = True
    capture_out = True
    if '-noout' in args:
        args.remove('-noout')
        capture_out = False

    list_of_lfns = [arg for arg in args if 'alien:' in arg]
    if not list_of_lfns: list_of_lfns = [args.pop(-1)]

    tmp_list = [download_tmp(wb, lfn, overwrite) for lfn in list_of_lfns]  # list of temporary downloads
    new_args = [arg for arg in args if arg not in list_of_lfns]  # command arguments without the files
    args = list(new_args)
    cmd = " ".join(args)
    files = " ".join(tmp_list)
    if tmp_list and all(os.path.isfile(tmp) for tmp in tmp_list):
        return runShellCMD(cmd + ' ' + files, capture_out)
    return RET(1, '', f'There was an error downloading the following files:\n{chr(10).join(tmp_list)}')


def DO_exec(wb: websockets.client.WebSocketClientProtocol,  args: Union[list, None] = None) -> RET:
    """exec lfn :: download lfn as a temporary file and executed in the shell"""
    if args is None: args = []
    if not args or '-h' in args or '-help' in args:
        msg = ('Command format: exec lfn list_of_arguments\n'
               'N.B.! The output and error streams will be captured and printed at the end of execution!\n'
               'for working within application use <edit>')
        return RET(0, msg)

    overwrite = False
    if '-force' in args:
        args.remove('-force')
        overwrite = True
    capture_out = True
    if '-noout' in args:
        args.remove('-noout')
        capture_out = False

    lfn = args.pop(0)  # the script to be executed
    opt_args = " ".join(args)
    tmp = download_tmp(wb, lfn, overwrite)
    if tmp and os.path.isfile(tmp):
        os.chmod(tmp, 0o700)
        return runShellCMD(f"{tmp + ' ' + opt_args if opt_args else tmp}", capture_out)
    return RET(1, '', f'There was an error downloading script: {lfn}')


def DO_syscmd(wb: websockets.client.WebSocketClientProtocol, cmd: str = '', args: Union[None, list, str] = None) -> RET:
    """run system command with all the arguments but all alien: specifications are downloaded to temporaries"""
    global AlienSessionInfo
    if args is None: args = []
    if type(args) == str: args = args.split()
    if not cmd: return RET(1, '', 'No system command specified!')
    new_arg_list = [download_tmp(wb, arg) if arg.startswith('alien:') else arg for arg in args]
    return runShellCMD(cmd + ' ' + ' '.join(new_arg_list))


def DO_find2(wb: websockets.client.WebSocketClientProtocol,  args: list) -> RET:
    if args is None: args = []
    if '-h' in args or '-help' in args:
        msg = (f'''Client-side implementation of find; it will use as default the regex option of server's find.
Command formant: find2 <options> <directory>
-select <pattern> : select only these files; {PrintColor(COLORS.BIGreen)}N.B. this is a REGEX applied to full path!!!{PrintColor(COLORS.ColorReset)} defaults to all ".*"
-name <pattern> : select only these files; {PrintColor(COLORS.BIGreen)}N.B. this is a REGEX applied to a directory or file name!!!{PrintColor(COLORS.ColorReset)} defaults to all ".*"
-name <verb>_string : where verb = begin|contain|ends|ext and string is the text selection criteria. verbs are aditive e.g.:
-name begin_myf_contain_run1_ends_bla_ext_root
{PrintColor(COLORS.BIRed)}N.B. the text to be filtered cannont have underline <_> within!!!{PrintColor(COLORS.ColorReset)}
-d  : return also the directories
-w[h] : long format, optionally human readable file sizes
-a : show hidden .* files
-j <queue_id> : filter files created by a certain job
-l <count> : limit the number of returned entries to at most the indicated value
-o <offset> : skip over the first <offset> results
        ''')
        return RET(0, msg)

    find_args = []
    if '-a' in args:
        find_args.append('-a')
        args.remove('-a')

    if '-r' in args:
        args.remove('-r')

    if '-d' in args:
        find_args.append('-d')
        args.remove('-d')

    if '-s' in args:
        args.remove('-s')

    if '-v' in args:
        # print("Verbose mode not implemented, ignored")
        args.remove('-v')

    if '-j' in args:
        qid_idx = args.index('-j')
        find_args.append('-j')
        find_args.append(args.pop(qid_idx + 1))
        args.pop(qid_idx)

    if '-l' in args:
        return_nr_idx = args.index('-l')
        find_args.append('-l')
        find_args.append(args.pop(return_nr_idx + 1))
        args.pop(return_nr_idx)

    if '-o' in args:
        skip_nr_idx = args.index('-o')
        find_args.append('-o')
        find_args.append(args.pop(skip_nr_idx + 1))
        args.pop(skip_nr_idx)

    pattern_regex = '.*'  # default regex selection for find
    filtering_enabled = False
    if '-select' in args:
        select_idx = args.index('-select')
        pattern_regex = args.pop(select_idx + 1)
        args.pop(select_idx)
        filtering_enabled = True

    if '-name' in args:
        if filtering_enabled: return RET(22, '', "Only one rule of selection can be used, either -select (full path match), -name (match on file name) or -glob (globbing)")  # EINVAL /* Invalid argument */
        name_idx = args.index('-name')
        pattern_regex = args.pop(name_idx + 1)
        args.pop(name_idx)
        filtering_enabled = True

        pattern_regex = name2regex(pattern_regex)
        if not pattern_regex: return RET(22, '', "No selection verbs were recognized! usage format is -name <attribute>_<string> where attribute is one of: begin, contain, ends, ext")  # EINVAL /* Invalid argument */

    try:
        re.compile(pattern_regex)
    except re.error:
        return RET(64, '', "regex argument of -select or -name option is invalid!!")  # EX_USAGE /* command line usage error */

    if len(args) > 1: return RET(1, '', f'Too many elements remained in arg list, it should be just the directory\nArg list: {args}')
    find_args.extend(['-r', '-s', expand_path_grid(args[0]), pattern_regex])
    return SendMsg(wb, 'find', find_args, opts = 'nokeys')


def runShellCMD(INPUT: str = '', captureout: bool = True) -> RET:
    """Run shell command in subprocess; if exists, print stdout and stderr"""
    if not INPUT: return RET(1, '', 'No command to be run provided')
    sh_cmd = re.sub(r'^!', '', INPUT)
    try:
        if captureout:
            args = sh_cmd
            shcmd = subprocess.run(args, encoding = 'utf-8', errors = 'replace', shell=True, stdout = subprocess.PIPE, stderr = subprocess.PIPE)
        else:
            args = shlex.split(sh_cmd)
            shcmd = subprocess.run(args, encoding = 'utf-8', errors = 'replace')
    except Exception as e:
        msg = 'Shell process threw this:\n{0}'.format(e)
        logging.error(msg)
        return RET(1, '', msg)
    return RET(shcmd.returncode, '' if shcmd.stdout is None else shcmd.stdout.strip(), '' if shcmd.stderr is None else shcmd.stderr.strip())


def DO_quota(wb: websockets.client.WebSocketClientProtocol, args: Union[None, list] = None) -> RET:
    """quota : put togheter both job and file quota"""
    if not args: args = []
    if '-h' in args:
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


def check_port(address: str, port: Union[str, int]) -> bool:
    """Check TCP connection to address:port"""
    s = socket.socket()  # Create a TCP socket
    is_open = False
    try:
        s.connect((address, int(port)))
        is_open = True
    except Exception:
        pass
    s.close()
    return is_open


def get_help(wb: websockets.client.WebSocketClientProtocol, cmd: str = '') -> RET:
    """Return the help option even for client-side commands"""
    if not cmd: return RET(1, '', 'No command specified for help')
    return ProcessInput(wb, cmd, ['-h'])


def get_help_srv(wb: websockets.client.WebSocketClientProtocol, cmd: str = '') -> RET:
    """Return the help option for server-side known commands"""
    if not cmd: return RET(1, '', 'No command specified for help request')
    return SendMsg(wb, cmd + ' -h')


def DO_help(wb: websockets.client.WebSocketClientProtocol, args: Union[list, None] = None) -> RET:
    global AlienSessionInfo
    if args is None: args = []
    if not args:
        msg = ('Project documentation can be found at:\n'
               'https://jalien.docs.cern.ch/\n'
               'https://gitlab.cern.ch/jalien/xjalienfs/blob/master/README.md\n'
               'the following commands are available:')
        nr = len(AlienSessionInfo['commandlist'])
        columns = 6
        for ln in range(0, nr, columns):
            if ln + 1 > nr: ln = nr - 1
            el_ln = AlienSessionInfo['commandlist'][ln:ln + columns]
            ln = [str(i).ljust(26) for i in el_ln]
            msg = msg + '\n' + ''.join(ln)
        return RET(0, msg)
    return get_help(wb, args.pop(0))


def DO_user(wb: websockets.client.WebSocketClientProtocol, args: Union[list, None] = None) -> RET:
    global AlienSessionInfo
    if args is None: args = []
    ret_obj = SendMsg(wb, 'user', args)
    if ret_obj.exitcode == 0 and 'homedir' in ret_obj.ansdict['results'][0]: AlienSessionInfo['alienHome'] = ret_obj.ansdict['results'][0]['homedir']
    return ret_obj


def DO_prompt(args: Union[list, None] = None) -> RET:
    """Add local dir and date information to the alien.py shell prompt"""
    global AlienSessionInfo
    if args is None: args = []
    if not args or '-h' in args:
        msg = "Toggle the following in the command prompt : <date> for date information and <pwd> for local directory"
        return RET(0, msg)

    if 'date' in args: AlienSessionInfo['show_date'] = (not AlienSessionInfo['show_date'])
    if 'pwd' in args: AlienSessionInfo['show_lpwd'] = (not AlienSessionInfo['show_lpwd'])
    return RET(0)


def get_list_entries(wb, lfn, fullpath: bool = False) -> list:
    """return a list of entries of the lfn argument, full paths if 2nd arg is True"""
    global AlienSessionInfo
    key = 'path' if fullpath else 'name'

    def cleanup_item(lfn):
        ret = re.sub(r"\/{2,}", "/", lfn)
        return re.sub(r"^\.\/", "", ret)

    ret_obj = SendMsg(wb, 'ls', ['-nomsg', '-F', lfn])
    return list(cleanup_item(item[key]) for item in ret_obj.ansdict['results']) if ret_obj.exitcode == 0 else []


def lfn_list(wb: websockets.client.WebSocketClientProtocol, lfn: str = ''):
    """Completer function : for a given lfn return all options for latest leaf"""
    if not wb: return []
    if not lfn: lfn = '.'  # AlienSessionInfo['currentdir']
    list_lfns = []
    lfn_path = Path(lfn)
    base_dir = lfn_path.parent.as_posix() if lfn_path.parent.as_posix() == '/' else lfn_path.parent.as_posix() + '/'
    name = lfn_path.name + '/' if lfn.endswith('/') else lfn_path.name

    def item_format(base_dir, name, item):
        # print(f'\nbase_dir: {base_dir} ; name: {name} ; item: {item}')
        if name.endswith('/') and name != '/':
            return name + item if base_dir == './' else base_dir + name + item
        return item if base_dir == './' else base_dir + item

    if lfn.endswith('/'):
        listing = get_list_entries(wb, lfn)
        list_lfns = [item_format(base_dir, name, item) for item in listing]
    else:
        listing = get_list_entries(wb, base_dir)
        list_lfns = [item_format(base_dir, name, item) for item in listing if item.startswith(name)]
    # print(f'\n{list_lfns}\n')
    return list_lfns


def wb_ping(wb: websockets.client.WebSocketClientProtocol) -> float:
    """Websocket ping function, it will return rtt in ms"""
    init_delta = float(-999.0)
    init_begin = datetime.datetime.now().timestamp()
    if IsWbConnected(wb):
        init_end = datetime.datetime.now().timestamp()
        init_delta = float((init_end - init_begin) * 1000)
        return init_delta
    return float(-1)


def DO_ping(wb: websockets.client.WebSocketClientProtocol, args: Union[list, None] = None) -> RET:
    """Command implementation for ping functionality"""
    if args is None: args = []
    if '-h' in args: return RET(0, "ping <count>\nwhere count is integer")

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


def get_files_cert() -> list:
    return (os.getenv('X509_USER_CERT', Path.home().as_posix() + '/.globus' + '/usercert.pem'), os.getenv('X509_USER_KEY', Path.home().as_posix() + '/.globus' + '/userkey.pem'))


def get_files_token() -> tuple:
    return os.getenv('JALIEN_TOKEN_CERT', TMPDIR + '/tokencert_' + str(os.getuid()) + '.pem'), os.getenv('JALIEN_TOKEN_KEY', TMPDIR + '/tokenkey_' + str(os.getuid()) + '.pem')


def create_ssl_context(use_usercert: bool = False) -> ssl.SSLContext:
    """Create SSL context using either the default names for user certificate and token certificate or X509_USER_{CERT,KEY} JALIEN_TOKEN_{CERT,KEY} environment variables"""
    global AlienSessionInfo
    # SSL SETTINGS
    cert = key = None  # vars for discovered credentials
    usercert, userkey = get_files_cert()
    tokencert, tokenkey = get_files_token()

    system_ca_path = '/etc/grid-security/certificates'
    alice_cvmfs_ca_path_lx = '/cvmfs/alice.cern.ch/etc/grid-security/certificates'
    alice_cvmfs_ca_path_macos = f'/Users/Shared{alice_cvmfs_ca_path_lx}'

    x509dir = os.getenv('X509_CERT_DIR') if os.path.isdir(str(os.getenv('X509_CERT_DIR'))) else ''
    x509file = os.getenv('X509_CERT_FILE') if os.path.isfile(str(os.getenv('X509_CERT_FILE'))) else ''

    capath_default = ''
    if x509dir:
        capath_default = x509dir
    elif os.path.exists(alice_cvmfs_ca_path_lx):
        capath_default = alice_cvmfs_ca_path_lx
    elif os.path.exists(alice_cvmfs_ca_path_macos):
        capath_default = alice_cvmfs_ca_path_macos
    else:
        if os.path.isdir(system_ca_path): capath_default = system_ca_path

    if not capath_default and not x509file:
        msg = "No CA location or files specified!!! Connection will not be possible!!"
        print(msg, file=sys.stderr, flush = True)
        logging.info(msg)
        sys.exit(2)
    if DEBUG:
        if x509file:
            logging.debug(f"CAfile = {x509file}")
        else:
            logging.debug(f"CApath = {capath_default}")

    if not use_usercert:  # if there is no explicit request for usercert
        if not os.path.isfile(tokencert) and 'BEGIN CERTIFICATE' in tokencert:  # and is not a file
            temp_cert = tempfile.NamedTemporaryFile(prefix = 'tokencert_', suffix = f'_{str(os.getuid())}.pem')
            temp_cert.write(tokencert.encode(encoding="ascii", errors="replace"))
            temp_cert.seek(0)
            tokencert = temp_cert.name  # temp file was created, let's give the filename to tokencert
        if not os.path.isfile(tokenkey) and 'PRIVATE KEY' in tokenkey:  # and is not a file
            temp_key = tempfile.NamedTemporaryFile(prefix = 'tokenkey_', suffix = f'_{str(os.getuid())}.pem')
            temp_key.write(tokenkey.encode(encoding="ascii", errors="replace"))
            temp_key.seek(0)
            tokenkey = temp_key.name  # temp file was created, let's give the filename to tokenkey

    if not use_usercert and IsValidCert(tokencert) and os.path.isfile(tokenkey):
        cert, key = tokencert, tokenkey
        AlienSessionInfo['use_usercert'] = False
    else:
        if not (os.path.exists(usercert) and os.path.exists(userkey)):
            msg = "User certificate files NOT FOUND!!! Connection will not be possible!!"
            print(msg, file=sys.stderr, flush = True)
            logging.info(msg)
            sys.exit(126)
        cert, key = usercert, userkey
        if not IsValidCert(cert):
            msg = f'Invalid user certificate!! Check the content of {cert}'
            print(msg, file=sys.stderr, flush = True)
            logging.info(msg)
            sys.exit(129)
        AlienSessionInfo['use_usercert'] = True

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
    try:
        ctx.set_ciphers('DEFAULT@SECLEVEL=1')  # Server uses only 80bit (sigh); set SECLEVEL only for newer than EL7
    except ssl.SSLError:
        pass
    ctx.options |= ssl.OP_NO_SSLv3
    ctx.verify_mode = ssl.CERT_REQUIRED  # CERT_NONE, CERT_OPTIONAL, CERT_REQUIRED
    ctx.check_hostname = False
    if x509file:
        ctx.load_verify_locations(cafile = x509file)
    else:
        ctx.load_verify_locations(capath = capath_default)
    ctx.load_cert_chain(certfile=cert, keyfile=key)

    if DEBUG: logging.debug(f"Cert = {cert} ; Key = {key}")
    return ctx


@syncify
async def wb_create(host: str = 'localhost', port: Union[str, int] = '0', path: str = '/', use_usercert: bool = False, localConnect: bool = False) -> Union[websockets.client.WebSocketClientProtocol, None]:
    """Create a websocket to wss://host:port/path (it is implied a SSL context)"""
    QUEUE_SIZE = int(2)  # maximum length of the queue that holds incoming messages
    MSG_SIZE = int(20 * 1024 * 1024)  # maximum size for incoming messages in bytes. The default value is 1 MiB. None disables the limit
    PING_TIMEOUT = int(os.getenv('ALIENPY_TIMEOUT', '20'))  # If the corresponding Pong frame isn’t received within ping_timeout seconds, the connection is considered unusable and is closed
    PING_INTERVAL = PING_TIMEOUT  # Ping frame is sent every ping_interval seconds
    CLOSE_TIMEOUT = int(10)  # maximum wait time in seconds for completing the closing handshake and terminating the TCP connection
    # https://websockets.readthedocs.io/en/stable/api.html#websockets.protocol.WebSocketCommonProtocol
    # we use some conservative values, higher than this might hurt the sensitivity to intreruptions

    wb = None
    ctx = None
    if localConnect:
        fHostWSUrl = 'ws://localhost/'
        logging.info(f"Request connection to : {fHostWSUrl}")
        socket_filename = TMPDIR + '/jboxpy_' + str(os.getuid()) + '.sock'
        try:
            wb = await websockets.client.unix_connect(socket_filename, fHostWSUrl, max_queue=QUEUE_SIZE, max_size=MSG_SIZE, ping_interval=PING_INTERVAL, ping_timeout=PING_TIMEOUT, close_timeout=CLOSE_TIMEOUT)
        except Exception as e:
            msg = 'Could NOT establish connection (local socket) to {0}\n{1}'.format(socket_filename, e)
            logging.error(msg)
            print(f'{msg}\nCheck the logfile: {DEBUG_FILE}', file=sys.stderr, flush = True)
            return None
    else:
        fHostWSUrl = 'wss://' + str(host) + ':' + str(port) + str(path)  # conection url
        ctx = create_ssl_context(use_usercert)  # will check validity of token and if invalid cert will be usercert
        logging.info(f"Request connection to : {host}:{port}{path}")

        socket_endpoint = None
        # https://async-stagger.readthedocs.io/en/latest/reference.html#async_stagger.create_connected_sock
        # AI_* flags --> https://linux.die.net/man/3/getaddrinfo
        try:
            if DEBUG:
                logging.debug(f"TRY ENDPOINT: {host}:{port}")
                init_begin = datetime.datetime.now().timestamp()
            if os.getenv('ALIENPY_NO_STAGGER'):
                socket_endpoint = socket.create_connection((host, int(port)))
            else:
                socket_endpoint = await async_stagger.create_connected_sock(host, int(port), async_dns=True, resolution_delay=0.050, detailed_exceptions=True)
            if DEBUG:
                init_delta = (datetime.datetime.now().timestamp() - init_begin) * 1000
                logging.debug(f"TCP SOCKET DELTA: {init_delta:.3f} ms")
        except Exception as e:
            msg = 'Could NOT establish connection (TCP socket) to {0}:{1}\n{2}'.format(host, port, e)
            logging.error(msg)
            print(f'{msg}\nCheck the logfile: {DEBUG_FILE}', file=sys.stderr, flush = True)
            return None

        if socket_endpoint:
            socket_endpoint_addr = socket_endpoint.getpeername()[0]
            socket_endpoint_port = socket_endpoint.getpeername()[1]
            logging.info(f"GOT SOCKET TO: {socket_endpoint_addr}")
            try:
                if DEBUG: init_begin = datetime.datetime.now().timestamp()
                deflateFact = websockets.extensions.permessage_deflate.ClientPerMessageDeflateFactory(compress_settings={'memLevel': 6},)
                wb = await websockets.connect(fHostWSUrl, sock = socket_endpoint, server_hostname = host, ssl = ctx, extensions=[deflateFact, ],
                                              max_queue=QUEUE_SIZE, max_size=MSG_SIZE, ping_interval=PING_INTERVAL, ping_timeout=PING_TIMEOUT, close_timeout=CLOSE_TIMEOUT)
                if DEBUG:
                    init_delta = (datetime.datetime.now().timestamp() - init_begin) * 1000
                    logging.debug(f"WEBSOCKET DELTA: {init_delta:.3f} ms")
            except Exception as e:
                msg = 'Could NOT establish connection (WebSocket) to {0}:{1}\n{2}'.format(socket_endpoint_addr, socket_endpoint_port, e)
                logging.error(msg)
                print(f'{msg}\nCheck the logfile: {DEBUG_FILE}', file=sys.stderr, flush = True)
                return None
        if wb: logging.info(f"CONNECTED: {wb.remote_address[0]}:{wb.remote_address[1]}")
    return wb


def wb_create_tryout(host: str = 'localhost', port: Union[str, int] = '0', path: str = '/', use_usercert: bool = False, localConnect: bool = False) -> Union[websockets.client.WebSocketClientProtocol, None]:
    """WebSocket creation with tryouts (configurable by env ALIENPY_CONNECT_TRIES and ALIENPY_CONNECT_TRIES_INTERVAL)"""
    wb = None
    nr_tries = 0
    init_begin = init_delta = None
    if TIME_CONNECT or DEBUG: init_begin = datetime.datetime.now().timestamp()
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
        if DEBUG: logging.debug(msg)
        if TIME_CONNECT: print(msg, flush = True)

    if wb and localConnect:
        pid_filename = TMPDIR + '/jboxpy_' + str(os.getuid()) + '.pid'
        writePidFile(pid_filename)
    return wb


def AlienConnect(token_args: Union[None, list] = None, use_usercert: bool = False, localConnect: bool = False) -> Union[websockets.client.WebSocketClientProtocol, None]:
    """Create a websocket connection to AliEn services either directly to alice-jcentral.cern.ch or trough a local found jbox instance"""
    jalien_server = os.getenv("ALIENPY_JCENTRAL", 'alice-jcentral.cern.ch')  # default value for JCENTRAL
    jalien_websocket_port = os.getenv("ALIENPY_JCENTRAL_PORT", '8097')  # websocket port
    jalien_websocket_path = '/websocket/json'
    jclient_env = f'{TMPDIR}/jclient_token_{str(os.getuid())}'

    # let's try to get a websocket
    wb = None
    if localConnect:
        wb = wb_create(localConnect = True)
    else:
        if not os.getenv("ALIENPY_JCENTRAL") and os.path.exists(jclient_env):  # If user defined ALIENPY_JCENTRAL the intent is to set and use the endpoint
            # lets check JBOX availability
            jalien_info = read_conf_file(jclient_env)
            if jalien_info:
                if is_my_pid(jalien_info['JALIEN_PID']) and check_port(jalien_info['JALIEN_HOST'], jalien_info['JALIEN_WSPORT']):
                    jalien_server, jalien_websocket_port = jalien_info['JALIEN_HOST'], jalien_info['JALIEN_WSPORT']

        wb = wb_create_tryout(jalien_server, str(jalien_websocket_port), jalien_websocket_path, use_usercert)

        # if we stil do not have a socket, then try to fallback to jcentral if we did not had explicit endpoint and jcentral was not already tried
        if wb is None and not os.getenv("ALIENPY_JCENTRAL") and jalien_server != 'alice-jcentral.cern.ch':
            jalien_server, jalien_websocket_port = 'alice-jcentral.cern.ch', '8097'
            wb = wb_create_tryout(jalien_server, str(jalien_websocket_port), jalien_websocket_path, use_usercert)

    if wb is None:
        msg = f'Check the logfile: {DEBUG_FILE}\nCould not get a websocket connection to {jalien_server}:{jalien_websocket_port}'
        logging.error(msg)
        print(msg, file=sys.stderr, flush = True)
        sys.exit(1)

    if AlienSessionInfo['use_usercert']: token(wb, token_args)  # if we connect with usercert then let get a default token
    return wb


def make_func_map_nowb():
    '''client side functions (new commands) that do not require connection to jcentral'''
    global AlienSessionInfo
    if AlienSessionInfo['cmd2func_map_nowb']: return
    AlienSessionInfo['cmd2func_map_nowb']['prompt'] = DO_prompt
    AlienSessionInfo['cmd2func_map_nowb']['token-info'] = DO_tokeninfo
    AlienSessionInfo['cmd2func_map_nowb']['token-destroy'] = DO_tokendestroy
    AlienSessionInfo['cmd2func_map_nowb']['cert-info'] = DO_certinfo
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


def make_func_map_client():
    '''client side functions (new commands) that do not require connection to jcentral'''
    global AlienSessionInfo
    if AlienSessionInfo['cmd2func_map_client']: return

    # client side function (overrides) with signature : (wb, args, opts)
    AlienSessionInfo['cmd2func_map_client']['cd'] = cd
    del AlienSessionInfo['cmd2func_map_srv']['cd']

    AlienSessionInfo['cmd2func_map_client']['cp'] = DO_XrootdCp
    del AlienSessionInfo['cmd2func_map_srv']['cp']

    AlienSessionInfo['cmd2func_map_client']['ping'] = DO_ping
    del AlienSessionInfo['cmd2func_map_srv']['ping']

    AlienSessionInfo['cmd2func_map_client']['ps'] = DO_ps
    del AlienSessionInfo['cmd2func_map_srv']['ps']

    AlienSessionInfo['cmd2func_map_client']['submit'] = DO_submit
    del AlienSessionInfo['cmd2func_map_srv']['submit']

    AlienSessionInfo['cmd2func_map_client']['token'] = DO_token
    del AlienSessionInfo['cmd2func_map_srv']['token']

    AlienSessionInfo['cmd2func_map_client']['user'] = DO_user
    del AlienSessionInfo['cmd2func_map_srv']['user']

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


def getSessionVars(wb: websockets.client.WebSocketClientProtocol):
    """Initialize the global session variables : cleaned up command list, user, home dir, current dir"""
    if not wb: return
    global AlienSessionInfo
    if not AlienSessionInfo['commandlist']:  # get the command list jsut once per session connection (a reconnection will skip this)
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
        AlienSessionInfo['commandlist'].extend([cmd for cmd in AlienSessionInfo['cmd2func_map_client']])  # add clien-side cmds to list
        AlienSessionInfo['commandlist'].extend([cmd for cmd in AlienSessionInfo['cmd2func_map_nowb']])  # add nowb cmds to list
        AlienSessionInfo['commandlist'].sort()

    # when starting new session prevdir is empty, if set then this is a reconnection
    if AlienSessionInfo['prevdir'] and (AlienSessionInfo['prevdir'] != AlienSessionInfo['currentdir']): cd(wb, AlienSessionInfo['prevdir'], 'log')


def InitConnection(token_args: Union[None, list] = None, use_usercert: bool = False, localConnect: bool = False) -> websockets.client.WebSocketClientProtocol:
    """Create a session to AliEn services, including session globals"""
    global AlienSessionInfo
    init_begin = init_delta = None
    if TIME_CONNECT or DEBUG: init_begin = datetime.datetime.now().timestamp()
    wb = AlienConnect(token_args, use_usercert, localConnect)
    if init_begin:
        init_delta = (datetime.datetime.now().timestamp() - init_begin) * 1000
        if DEBUG: logging.debug(f">>>   Time for websocket connection: {init_delta:.3f} ms")
        if TIME_CONNECT: print(f">>>   Time for websocket connection: {init_delta:.3f} ms", flush = True)

    if wb is not None: AlienSessionInfo['session_started'] = True
    # no matter if command or interactive mode, we need alienHome, currentdir, user and commandlist
    getSessionVars(wb)
    if init_begin:
        init_delta = (datetime.datetime.now().timestamp() - init_begin) * 1000
        if DEBUG: logging.debug(f">>>   Time for session connection: {init_delta:.3f} ms")
        if TIME_CONNECT: print(f">>>   Time for session connection: {init_delta:.3f} ms", flush = True)
    return wb


def ProcessInput(wb: websockets.client.WebSocketClientProtocol, cmd: str, args: Union[list, None] = None, shellcmd: Union[str, None] = None) -> RET:
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
        if not args or '-h' in args: return RET(0, 'Command format: time command arguments')
        cmd = args.pop(0)
        time_begin = datetime.datetime.now().timestamp()

    if cmd in AlienSessionInfo['cmd2func_map_nowb']:  # these commands do NOT need wb connection
        ret_obj = AlienSessionInfo['cmd2func_map_nowb'][cmd](args)
        retf_session_update(ret_obj)
        return ret_obj

    opts = ''  # let's proccess special server args
    if '-nokeys' in args:
        args.remove('-nokeys')
        opts = f'{opts} nokeys'
    if '-nomsg' in args:
        args.remove('-nomsg')
        opts = f'{opts} nomsg'
    if '-showkeys' in args:
        args.remove('-showkeys')
        opts = f'{opts} showkeys'
    if '-showmsg' in args:
        args.remove('-showmsg')
        opts = f'{opts} showmsg'

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
        shell_run = subprocess.run(shellcmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, input=ret_obj.out, encoding='ascii', shell=True)  # env=os.environ default is already the process env
        if msg_timing: shell_run.stdout = f'{shell_run.stdout}\n{msg_timing}'
        return RET(shell_run.returncode, shell_run.stdout, shell_run.stderr)

    if msg_timing: ret_obj = ret_obj._replace(out = f'{ret_obj.out}\n{msg_timing}')
    if ret_obj.ansdict and 'timing_ms' in ret_obj.ansdict['metadata']: ret_obj = ret_obj._replace(out = f"{ret_obj.out}\ntiming_ms = {ret_obj.ansdict['metadata']['timing_ms']}")
    return ret_obj


def ProcessCommandChain(wb: Union[websockets.client.WebSocketClientProtocol, None] = None, cmd_chain: str = '') -> int:
    global AlienSessionInfo, JSON_OUT, JSON_OUT_GLOBAL
    if not cmd_chain: return int(1)
    # translate aliases in place in the whole string
    if AlienSessionInfo['alias_cache']:
        for alias in AlienSessionInfo['alias_cache']: cmd_chain = cmd_chain.replace(alias, AlienSessionInfo['alias_cache'][alias])
    cmdline_list = [str(cmd).strip() for cmd in cmds_split.split(cmd_chain)]  # split commands on ; and \n

    ret_obj = None
    for cmdline in cmdline_list:
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
            print("AliEn command before the | token was not found")
            continue

        args = input_alien.strip().split()
        cmd = args.pop(0)

        print_opts = 'debug json' if JSON_OUT else 'debug'
        if '-json' in args or JSON_OUT_GLOBAL:
            args.remove('-json')
            JSON_OUT = True
            if 'json' not in print_opts: print_opts = f'print_opts {json}'

        if cmd in AlienSessionInfo['cmd2func_map_nowb']:
            ret_obj = AlienSessionInfo['cmd2func_map_nowb'][cmd](args)
        else:
            if wb is None: wb = InitConnection()  # we are doing the connection recovery and exception treatment in AlienConnect()
            args.insert(0, '-nokeys')  # Disable return of the keys. ProcessCommandChain is used for user-based communication so json keys are not needed
            ret_obj = ProcessInput(wb, cmd, args, pipe_to_shell_cmd)

        retf_session_update(ret_obj)  # Update the globals exitcode, out, err
        retf_print(ret_obj, print_opts)
        if cmd == 'cd': SessionSave()
        if not JSON_OUT_GLOBAL: JSON_OUT = False  # reset JSON_OUT if it's not globally enabled (env var or argument to alien.py)
    return ret_obj.exitcode


def JAlien(commands: str = '') -> int:
    """Main entry-point for interaction with AliEn"""
    global AlienSessionInfo, JSON_OUT
    import_aliases()
    wb = None
    make_func_map_nowb()  # add to cmd2func_map_nowb the functions that do not need wb session

    # Command mode interaction
    if commands: return ProcessCommandChain(wb, commands)

    # Start interactive mode
    wb = InitConnection()  # we are doing the connection recovery and exception treatment in AlienConnect()
    # Begin Shell-like interaction
    if has_readline:
        rl.parse_and_bind("tab: complete")
        rl.set_completer_delims(" ")

        def complete(text, state):
            prompt_line = rl.get_line_buffer()
            tokens = prompt_line.split()
            results = []
            if len(tokens) == 0:
                results = [x + " " for x in AlienSessionInfo['commandlist']]
            elif len(tokens) == 1 and not prompt_line.endswith(' '):
                results = [x + " " for x in AlienSessionInfo['commandlist'] if x.startswith(text)] + [None]
            else:
                results = lfn_list(wb, text) + [None]
            return results[state]
        rl.set_completer(complete)
        setupHistory()  # enable history saving

    print('Welcome to the ALICE GRID\nsupport mail: adrian.sevcenco@cern.ch\n', flush=True)
    if os.getenv('ALIENPY_PROMPT_DATE'): AlienSessionInfo['show_date'] = True
    if os.getenv('ALIENPY_PROMPT_CWD'): AlienSessionInfo['show_lpwd'] = True
    if not os.getenv('ALIENPY_NO_CWD_RESTORE'): SessionRestore(wb)
    while True:
        INPUT = ''
        prompt = f"AliEn[{AlienSessionInfo['user']}]:{AlienSessionInfo['currentdir']}"
        if AlienSessionInfo['show_date']: prompt = str(datetime.datetime.now().replace(microsecond=0).isoformat()) + " " + prompt
        if AlienSessionInfo['show_lpwd']: prompt = prompt + " " + "local:" + Path.cwd().as_posix()
        prompt = prompt + ' >'
        try:
            INPUT = input(prompt)
        except EOFError:
            exit_message()

        if not INPUT: continue
        ProcessCommandChain(wb, INPUT)


def setup_logging():
    MSG_LVL = logging.DEBUG if DEBUG else logging.INFO
    line_fmt = '%(levelname)s:%(asctime)s %(message)s'
    file_mode = 'a' if os.getenv('ALIENPY_DEBUG_APPEND', '') else 'w'
    logging.basicConfig(format = line_fmt, filename = DEBUG_FILE, filemode = file_mode, level = MSG_LVL)
    logger_wb = logging.getLogger('websockets')
    logger_wb.setLevel(MSG_LVL)


def main():
    signal.signal(signal.SIGINT, signal_handler)
    # signal.signal(sig, signal.SIG_DFL)  # register the default signal handler usage for a sig signal
    global JSON_OUT, ALIENPY_EXECUTABLE
    setup_logging()
    # at exit delete all temporary files
    atexit.register(cleanup_temp)

    ALIENPY_EXECUTABLE = os.path.realpath(sys.argv[0])
    exec_name = Path(sys.argv.pop(0)).name  # remove the name of the script(alien.py)

    if '-json' in sys.argv:
        sys.argv.remove('-json')
        JSON_OUT = True
        JSON_OUT_GLOBAL = True

    if len(sys.argv) > 0 and (sys.argv[0] == 'term' or sys.argv[0] == 'terminal' or sys.argv[0] == 'console'):
        import code
        term = code.InteractiveConsole(locals = globals())
        term.push('jalien = AliEn()')
        banner = 'Welcome to the ALICE GRID - Python interpreter shell\nsupport mail: adrian.sevcenco@cern.ch\nAliEn seesion object is >jalien< ; try jalien.help()'
        exitmsg = 'Exiting..'
        term.interact(banner, exitmsg)
        os._exit(int(AlienSessionInfo['exitcode']))

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
    except KeyboardInterrupt:
        print("Received keyboard intrerupt, exiting..")
        sys.exit(int(AlienSessionInfo['exitcode']))
    except Exception:
        print(f'''{PrintColor(COLORS.BIRed)}Exception encountered{PrintColor(COLORS.ColorReset)}! it will be logged to {DEBUG_FILE}
Please report the error and send the log file and "alien.py version" output to Adrian.Sevcenco@cern.ch
If the exception is reproductible including on lxplus, please create a detailed debug report this way:
ALIENPY_DEBUG=1 ALIENPY_DEBUG_FILE=log.txt your_command_line''', file=sys.stderr, flush = True)
        logging.error(traceback.format_exc())
        sys.exit(1)
    sys.exit(int(AlienSessionInfo['exitcode']))


def _cmd(what):
    sys.argv = [sys.argv[0]] + [what] + sys.argv[1:]
    main()


def cmd_cert_info(): _cmd('cert-info')


def cmd_token_info(): _cmd('token-info')


def cmd_token_destroy(): _cmd('token-destroy')


def cmd_token_init():
    print('INFO: JAliEn client automatically creates tokens, '
          'alien-token-init is deprecated')
    _cmd('token-init')


if __name__ == '__main__':
    main()
