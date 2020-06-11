#!/usr/bin/env python3

from typing import Union
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
import math
from typing import NamedTuple
import OpenSSL
import shlex
import argparse
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from enum import Enum
from urllib.parse import urlparse
import socket
import threading
import asyncio
import async_stagger
import websockets
from websockets.extensions import permessage_deflate

ALIENPY_VERSION_DATE = '20200611_101110'
ALIENPY_VERSION_STR = '1.1.1.post6'
ALIENPY_EXECUTABLE = ''

if sys.version_info[0] != 3 or sys.version_info[1] < 6:
    print("This script requires a minimum of Python version 3.6", flush = True)
    sys.exit(1)

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
        try:
            rl.read_history_file(histfile)
            h_len = rl.get_current_history_length()
        except FileNotFoundError:
            open(histfile, 'wb').close()
            h_len = 0
        rl.set_auto_history(True)
        atexit.register(rl.write_history_file, histfile)

    def saveHistory(prev_h_len, histfile):
        new_h_len = rl.get_current_history_length()
        prev_h_len = rl.get_history_length()
        rl.set_history_length(1000)
        rl.append_history_file(new_h_len - prev_h_len, histfile)


try:  # let's fail fast if the xrootd python bindings are not present
    from XRootD import client
    has_xrootd = True
except ImportError:
    has_xrootd = False


hasColor = False
if (hasattr(sys.stdout, "isatty") and sys.stdout.isatty()): hasColor = True

# environment debug variable
JSON_OUT = True if os.getenv('ALIENPY_JSON') else False
JSONRAW_OUT = True if os.getenv('ALIENPY_JSONRAW') else False
DEBUG = os.getenv('ALIENPY_DEBUG', '')
DEBUG_FILE = os.getenv('ALIENPY_DEBUG_FILE', Path.home().as_posix() + '/alien_py.log')
TIME_CONNECT = os.getenv('ALIENPY_TIMECONNECT', '')

# global session state;
AlienSessionInfo = {'alienHome': '', 'currentdir': '', 'commandlist': [], 'user': '', 'error': '', 'exitcode': 0, 'show_date': False, 'show_lpwd': False, 'templist': [], 'use_usercert': False, 'completer_cache': []}


def signal_handler(sig, frame):
    """Generig signal handler: just print the signal and exit"""
    print(f'\nCought signal {signal.Signals(sig).name}, let\'s exit')
    exit_message(int(AlienSessionInfo['exitcode']))
    # signal.signal(sig, signal.SIG_DFL)  # default signal handler usage (for sigint it does nothing)


def exit_message(exitcode: int = 0):
    print('Exit')
    sys.exit(exitcode)


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
    try:
        pong_waiter = await wb.ping()
        await pong_waiter
    except Exception as e:
        logging.debug(f"WB ping/pong failed!!!")
        logging.exception(e)
        return False
    return True


@syncify
async def wb_close(wb, code, reason):
    await wb.close(code = code, reason = reason)


@syncify
async def msg_proxy(websocket, path, use_usercert = False):
    # start client to upstream
    wb_jalien = AlienConnect(None, use_usercert)
    local_query = await websocket.recv()
    jalien_answer = await SendMsg(wb_jalien, local_query)
    await websocket.send(jalien_answer)


@syncify
async def __sendmsg(wb: websockets.client.WebSocketClientProtocol, json: str) -> str:
    await wb.send(json)
    result = await wb.recv()
    return result


def SendMsg(wb: websockets.client.WebSocketClientProtocol, cmdline: str, args: Union[None, list] = None, opts: str = '') -> Union[str, dict]:
    """Send a json message to the specified websocket; it will return the server answer"""
    if not wb:
        logging.info(f"SendMsg:: websocket not initialized")
        return '' if 'rawstr' in opts else {}
    if not args: args = []
    if '{"command":' in cmdline and '"options":' in cmdline:
        json = cmdline
    else:
        json = CreateJsonCommand(cmdline, args, opts)

    if not json:
        logging.info(f"SendMsg:: json message is empty or invalid")
        return '' if 'rawstr' in opts else {}
    if DEBUG:
        logging.debug(f"SEND COMMAND: {json}")
        init_begin = datetime.now().timestamp()
    nr_tries = int(0)
    result = None
    while result is None:
        if nr_tries > 3:
            msg = f"SendMsg:: {nr_tries - 1} communication errors!\nSent command: {json}"
            print(msg, file=sys.stderr, flush = True)
            logging.error(msg)
            break
        try:
            nr_tries += 1
            result = __sendmsg(wb, json)
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
        time.sleep(0.2)

    if DEBUG:
        init_delta = (datetime.now().timestamp() - init_begin) * 1000
        logging.debug(f"COMMAND SEND/RECV ROUNDTRIP: {init_delta:.3f} ms")

    if not result: return {}
    if 'rawstr' in opts: return result
    return GetDict(result, opts)


def CreateJsonCommand(cmdline: Union[str, dict], args: Union[None, list] = None, opts: str = '') -> str:
    """Return a json with command and argument list"""
    if type(cmdline) == dict:
        out_dict = cmdline.copy()
        if 'nomsg' in opts: out_dict["options"].insert(0, '-nomsg')
        if 'nokeys' in opts: out_dict["options"].insert(0, '-nokeys')
        return json.dumps(out_dict)

    if not args:
        tmp_list = cmdline.split()
        if len(tmp_list) == 1:
            args = []
            cmd = cmdline
        else:
            cmd = tmp_list.pop(0)
            args = tmp_list
    else:
        cmd = cmdline
    if 'nomsg' in opts: args.insert(0, '-nomsg')
    if 'nokeys' in opts: args.insert(0, '-nokeys')
    jsoncmd = {"command": cmd, "options": args}
    return json.dumps(jsoncmd)


def PrintDict(in_arg: Union[str, dict, list], opts: str = ''):
    """Print a dictionary in a nice format and optionaly send the string """
    if type(in_arg) == str:
        if 'rawstr' in opts:
            dict_str = in_arg
        else:
            try:
                in_arg = json.loads(in_arg)
            except Exception as e:
                print('PrintDict:: Could not load argument as json! For non-dictionaries try opts=\'rawstr\'', file=sys.stderr, flush = True)
                return

    dict_str = json.dumps(in_arg, sort_keys = True, indent = 4)
    if 'info' in opts: logging.info(dict_str)
    elif 'warn' in opts: logging.warning(dict_str)
    elif 'err' in opts: logging.error(dict_str)
    elif 'debug' in opts: logging.debug(dict_str)
    elif 'stderr' in opts: print(dict_str, file=sys.stderr, flush = True)
    else: print(dict_str, flush = True)


def GetMeta(result: dict, meta: str = '') -> Union[str, list]:
    if not result: return None
    if type(result) == dict and 'metadata' in result:  # these works only for AliEn responses
        meta_opts_list = None
        output = []
        if meta: meta_opts_list = meta.split()
        if 'cwd' in meta_opts_list: output.append(result["metadata"]["currentdir"])
        if 'user' in meta_opts_list: output.append(result["metadata"]["user"])
        if 'error' in meta_opts_list: output.append(result["metadata"]["error"])
        if 'exitcode' in meta_opts_list: output.append(result["metadata"]["exitcode"])
        if len(output) == 1:
            return output[0]
        else:
            return output
    else:
        return ''


def GetDict(result: Union[dict, list, str], opts: str = '') -> Union[None, dict, list]:
    """Convert server reply string to dict, update all relevant globals, do some filtering"""
    if not result: return None
    out_dict = None
    if type(result) == str:
        try:
            out_dict = json.loads(result)
        except Exception as e:
            print('PrintDict:: Could not load argument as json! For non-dictionaries try opts=\'rawstr\'', file=sys.stderr, flush = True)
            return None
    else:
        out_dict = result.copy()
    if type(out_dict) == dict and 'metadata' in out_dict:  # these works only for AliEn responses
        try:
            global AlienSessionInfo
            AlienSessionInfo['currentdir'] = out_dict["metadata"]["currentdir"]
            AlienSessionInfo['user'] = out_dict["metadata"]["user"]
            AlienSessionInfo['error'] = out_dict["metadata"]["error"]
            AlienSessionInfo['exitcode'] = int(out_dict["metadata"]["exitcode"])
            if int(AlienSessionInfo['exitcode']) != 0:
                err_msg = AlienSessionInfo['error']
                flags = ['log', 'err', 'debug']
                if any(flag in opts for flag in flags):
                    logging.error(f"{err_msg}")
                if 'print' in opts:
                    print(f'{err_msg}', file=sys.stderr, flush = True)
        except Exception as e:
            pass
        if 'nometa' in opts: del out_dict["metadata"]
        if 'results' in opts: out_dict = out_dict['results']
    return out_dict


class COLORS:
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


class AliEn:
    def __init__(self, opts = ''):
        self.wb = InitConnection()
        self.opts = opts

    def run(self, cmd, opts = ''):
        if not opts: opts = self.opts
        return SendMsg(self.wb, cmd, opts = opts)

    def ProcessMsg(self, cmd):
        command_list = cmd.split(";")
        exitcode = None
        for cmd in command_list: exitcode = ProcessInput(self.wb, cmd)
        return exitcode

    def wb(self):
        return self.wb

    def help(self):
        print(f'Methods of AliEn session:\n'
              f'.run(cmd, opts) : alias to SendMsg(cmd, opts)\n'
              f'.ProcessMsg(cmd_list) : alias to ProcessInput, it will have the same output as in the alien.py interaction\n'
              f'.wb() : return the session WebSocket to be used with other function within alien.py', flush = True)


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
    alias_file = os.path.join(os.path.expanduser("~"), ".alienpy_aliases")
    global AlienSessionInfo
    if os.path.exists(alias_file): return read_conf_file(alias_file)


def os_release() -> dict:
    return read_conf_file('/etc/os-release')


def pid_uid(pid: int) -> int:
    '''Return username of UID of process pid'''
    try:
        with open(f'/proc/{pid}/status') as proc_status:
            for line in proc_status:
                # Uid, Gid: Real, effective, saved set, and filesystem UIDs(GIDs)
                if line.startswith('Uid:'): return int((line.split()[1]))
    except Exception as e:
        return int(65537)


def is_my_pid(pid: int) -> bool:
    return True if pid_uid(int(pid)) == os.getuid() else False


def GetCWDFilename() -> str:
    return os.path.join(os.path.expanduser("~"), ".alienpy_cwd")


def RestoreCWD(wb: websockets.client.WebSocketClientProtocol):
    cwd = ''
    try:
        with open(GetCWDFilename()) as f:
            cwd = f.read()
    except Exception as e:
        logging.warning('RestoreCWD:: failed to read file')
        logging.exception(e)
    if cwd:
        resp = SendMsg(wb, 'cd ' + cwd, opts = 'log')


def StoreCWD():
    if not os.getenv('ALIENPY_NO_CWD_RESTORE'):
        try:
            with open(GetCWDFilename(), "w") as f:
                f.write(AlienSessionInfo["currentdir"])
        except Exception as e:
            logging.warning("StoreCWD:: failed to write file")
            logging.exception(e)


def unixtime2local(timestamp: Union[str, int]) -> str:
    """Convert unix time to a nice custom format"""
    utc_time = datetime.fromtimestamp(int(timestamp), timezone.utc)
    local_time = utc_time.astimezone()
    return str(local_time.strftime("%Y-%m-%d %H:%M:%S.%f%z"))  # (%Z)"))


def convert_time(str_line: str) -> str:
    """Convert the first 10 digit unix time like string from str argument to a nice time"""
    timestamp = re.findall(r"^(\d{10}) \[.*", str_line)
    if timestamp:
        nice_timestamp = f"{PrintColor(COLORS.BIGreen)}{unixtime2local(timestamp[0])}{PrintColor(COLORS.ColorReset)}"
        return str_line.replace(str(timestamp[0]), nice_timestamp)
    else:
        return ''


def DO_version():
    global AlienSessionInfo
    print(f'alien.py version: {ALIENPY_VERSION_STR}\n'
          f'alien.py version date: {ALIENPY_VERSION_DATE}\n'
          f'alien.py location: {os.path.realpath(__file__)}\n'
          f'script location: {ALIENPY_EXECUTABLE}\n'
          f'Interpreter: {os.path.realpath(sys.executable)}\n'
          f'Python version: {sys.version}', flush = True)
    if has_xrootd:
        print(f'XRootD version: {client.__version__}\nXRootD path: {client.__file__}', flush = True)
    else:
        print('XRootD not found', flush = True)
    AlienSessionInfo['exitcode'] = int(0)
    return AlienSessionInfo['exitcode']


def DO_certinfo(args: list = None):
    global AlienSessionInfo
    if not args: args = []
    cert_files = get_files_cert()
    if len(args) > 0 and (args[0] in ['-h', 'help', '-help']):
        print("Print user certificate information")
        AlienSessionInfo['exitcode'] = 0
        return AlienSessionInfo['exitcode']
    AlienSessionInfo['exitcode'] = CertInfo(cert_files[0])
    return AlienSessionInfo['exitcode']


def DO_tokeninfo(args: list = None):
    global AlienSessionInfo
    if not args: args = []
    token_files = get_files_token()
    tokencert = token_files[0]
    tokenkey = token_files[1]
    if len(args) > 0 and (args[0] in ['-h', 'help', '-help']):
        print("Print token certificate information")
        AlienSessionInfo['exitcode'] = 0
        return AlienSessionInfo['exitcode']

    if not os.path.isfile(tokencert):  # and is not a file
        temp_cert = tempfile.NamedTemporaryFile(prefix = 'tokencert_', suffix = '_' + str(os.getuid()) + '.pem')
        temp_cert.write(tokencert.encode(encoding="ascii", errors="replace"))
        temp_cert.seek(0)
        tokencert = temp_cert.name

    if os.path.exists(tokencert):
        AlienSessionInfo['exitcode'] = CertInfo(tokencert)
    else:
        print(f"Token >{tokencert}< not found/created", file=sys.stderr, flush = True)
        AlienSessionInfo['exitcode'] = 1
    return AlienSessionInfo['exitcode']


def DO_tokendestroy(args: list = None):
    global AlienSessionInfo
    if not args: args = []
    if len(args) > 0 and (args[0] in ['-h', 'help', '-help']):
        print("Delete the token{cert,key}.pem files")
        AlienSessionInfo['exitcode'] = 0
        return AlienSessionInfo['exitcode']
    token_files = get_files_token()
    tokencert = token_files[0]
    tokenkey = token_files[1]
    if os.path.exists(tokencert): os.remove(tokencert)
    if os.path.exists(tokenkey): os.remove(tokenkey)
    print("Token was destroyed! Re-connect for token re-creation.")
    AlienSessionInfo['exitcode'] = 0
    return AlienSessionInfo['exitcode']


def DO_exitcode():
    global AlienSessionInfo
    print(AlienSessionInfo['exitcode'])
    return int(0)


def xrdcp_help():
    print(f'''at least 2 arguments are needed : src dst
the command is of the form of (with the strict order of arguments): cp <args> src dst
where src|dst are local files if prefixed with file:// or file: or grid files otherwise
after each src,dst can be added comma separated specifiers in the form of: @disk:N,SE1,SE2,!SE3
where disk selects the number of replicas and the following specifiers add (or remove) storage endpoints from the received list
args are the following :
-h : print help
-f : replace destination file (if destination is local it will be replaced only if integrity check fails)
-P : enable persist on successful close semantic
-cksum : check hash sum of the file; for downloads the central catalogue md5 will be verified; for uploads (for new enough xrootds) a hash type will be negociated with remote and transfer will be validated
-y <nr_sources> : use up to the number of sources specified in parallel
-S <aditional TPC streams> : uses num additional parallel streams to do the transfer. (max = 15)
-chunks <nr chunks> : number of chunks that should be requested in parallel
-chunksz <bytes> : chunk size (bytes)
-T <nr_copy_jobs> : number of parralel copy jobs from a set (for recursive copy)

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
-o <offset> : skip first <offset> files found in the src directory (for recursive copy)''')


def getEnvelope_lfn(wb: websockets.client.WebSocketClientProtocol, lfn2file: lfn2file, specs: Union[None, list] = None, isWrite: bool = False) -> dict:
    """Query central services for the access envelope of a lfn, it will return a lfn:server answer with envelope pairs"""
    if not wb: return
    if not lfn2file: return {}
    lfn = lfn2file.lfn
    file = lfn2file.file
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
    result = SendMsg(wb, 'access', get_envelope_arg_list, opts = 'nomsg')
    replica_list = []
    for replica in result["results"]:
        replica_list.append(replica["se"])
    for replica in result["results"]:
        replica["SElist"] = ",".join(replica_list)
        replica["file"] = file
        replica["lfn"] = lfn
    return {"lfn": lfn, "answer": json.dumps(result)}


def getEnvelope(wb: websockets.client.WebSocketClientProtocol, lfn_list: list, specs: Union[None, list] = None, isWrite: bool = False) -> list:
    """Query central services for the access envelope of the list of lfns, it will return a list of lfn:server answer with envelope pairs"""
    if not wb: return
    access_list = []
    if not lfn_list: return access_list
    if not specs: specs = []
    for l2f in lfn_list:
        lfn_token = getEnvelope_lfn(wb, l2f, specs, isWrite)
        access_list.append(lfn_token)
    return access_list


def setDst(file: str = '', parent: int = 0) -> str:
    """For a fiven file path return the file path keeping the <parent> number of components"""
    p = Path(file)
    filename = p.parts[0]
    path_components = len(p.parts)
    if parent >= (path_components - 1): parent = path_components - 1 - 1  # IF parent >= number of components without filename THEN make parent = number of component without / and filename
    basedir = p.parents[parent].as_posix()
    if basedir == '/':
        return file
    else:
        return p.as_posix().replace(basedir, '', 1)


def expand_path_local(path: str) -> str:
    """Given a string representing a local file, return a full path after interpretation of HOME location, current directory, . and .. and making sure there are only single /"""
    exp_path = path
    if exp_path.startswith('file://'): exp_path = exp_path.replace("file://", "", 1)
    if exp_path.startswith('file:'): exp_path = exp_path.replace("file:", "", 1)
    exp_path = re.sub(r"^\~\/*", Path.home().as_posix() + "/", exp_path)
    if not exp_path.startswith('/'): exp_path = Path.cwd().as_posix() + "/" + exp_path
    tail_slash = True if exp_path.endswith("/") else False
    exp_path = os.path.normpath(exp_path)
    exp_path = os.path.realpath(exp_path)
    if tail_slash or os.path.isdir(exp_path): exp_path = exp_path + "/"
    return exp_path


def expand_path_grid(path: str) -> str:
    """Given a string representing a GRID file (lfn), return a full path after interpretation of AliEn HOME location, current directory, . and .. and making sure there are only single /"""
    exp_path = path
    if exp_path.startswith('alien://'): exp_path = exp_path.replace("alien://", "", 1)
    if exp_path.startswith('alien:'): exp_path = exp_path.replace("alien:", "", 1)
    exp_path = re.sub(r"^\/*\%ALIEN[\/\s]*", AlienSessionInfo['alienHome'], exp_path)  # replace %ALIEN token with user grid home directory
    if not exp_path.startswith('/'): exp_path = AlienSessionInfo['currentdir'] + "/" + exp_path  # if not full path add current directory to the referenced path
    tail_slash = True if exp_path.endswith("/") else False
    exp_path = os.path.normpath(exp_path)
    if tail_slash or os.path.isdir(exp_path): exp_path = exp_path + "/"
    return exp_path


def pathtype_grid(wb: websockets.client.WebSocketClientProtocol, path: str) -> str:
    """Query if a lfn is a file or directory, return f, d or empty"""
    if not wb: return ''
    if not path: return ''
    json_dict = SendMsg(wb, 'type', [path], opts = 'nomsg log')
    if int(AlienSessionInfo['exitcode']) != 0: return ''
    return str(json_dict['results'][0]["type"])[0]


def pathtype_local(path: str) -> str:
    """Query if a local path is a file or directory, return f, d or empty"""
    if not path: return ''
    p = Path(path)
    if p.is_dir(): return str('d')
    if p.is_file(): return str('f')
    return ''


def fileIsValid(file: str, size: Union[str, int], reported_md5: str) -> bool:
    """Check if the file path is consistent with the size and md5 argument. N.B.! the local file will be deleted with size,md5 not match"""
    if os.path.isfile(file):  # first check
        if int(os.stat(file).st_size) != int(size):
            os.remove(file)
            if DEBUG:
                print(f"Removed file (invalid size): {file}")
                logging.debug(f"Removed file (invalid size): {file}")
            return False
        if md5(file) != reported_md5:
            os.remove(file)
            if DEBUG:
                print(f"Removed file (invalid md5): {file}")
                logging.debug(f"Removed file (invalid md5): {file}")
            return False
        print(f"{file} --> TARGET VALID", flush = True)
        return True


def create_metafile(meta_filename: str, lfn: str, local_filename: str, size: Union[str, int], md5: str, replica_list: Union[None, list] = None):
    """Generate a meta4 xrootd virtual redirector with the specified location and using the rest of arguments"""
    if not replica_list: return
    published = str(datetime.now().replace(microsecond=0).isoformat())
    with open(meta_filename, 'w') as f:
        f.write('<?xml version="1.0" encoding="UTF-8"?>\n')
        f.write(' <metalink xmlns="urn:ietf:params:xml:ns:metalink">\n')
        f.write("   <published>{}</published>\n".format(published))
        f.write("   <file name=\"{}\">\n".format(local_filename))
        f.write("     <lfn>{}</lfn>\n".format(lfn))
        f.write("     <size>{}</size>\n".format(size))
        if md5: f.write("     <hash type=\"md5\">{}</hash>\n".format(md5))
        for url in replica_list:
            f.write("     <url><![CDATA[{}]]></url>\n".format(url))
        f.write('   </file>\n')
        f.write(' </metalink>\n')
        f.closed


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


def commit(wb: websockets.client.WebSocketClientProtocol, token: str, size: int, lfn: str, perm: str, expire: str, pfn: str, se: str, guid: str, md5sum: str) -> int:
    if not wb: return int(1)
    arg_list = [token, int(size), lfn, perm, expire, pfn, se, guid, md5sum]
    result_dict = SendMsg(wb, 'commit', arg_list, opts = 'log')
    if DEBUG: PrintDict(result_dict, 'debug')
    return int(AlienSessionInfo['exitcode'])


def GetHumanReadable(size, precision = 2):
    suffixes = ['B', 'KiB', 'MiB']
    suffixIndex = 0
    while size > 1024 and suffixIndex < 4:
        suffixIndex += 1  # increment the index of the suffix
        size = size/1024.0  # apply the division
    return "%.*f %s" % (precision, size, suffixes[suffixIndex])


def ProcessXrootdCp(wb: websockets.client.WebSocketClientProtocol, xrd_copy_command: Union[None, list] = None, printout: str = '') -> int:
    """XRootD cp function :: process list of arguments for a xrootd copy command"""
    if not has_xrootd:
        print('python XRootD module cannot be found, the copy process cannot continue')
        return int(1)

    global AlienSessionInfo
    if not wb: return int(107)  # ENOTCONN /* Transport endpoint is not connected */
    if (not xrd_copy_command) or len(xrd_copy_command) < 2 or xrd_copy_command == '-h':
        xrdcp_help()
        return int(64)  # EX_USAGE /* command line usage error */

    if not AlienSessionInfo:
        print('Session information like home and current directories needed', flush = True)
        return int(126)  # ENOKEY /* Required key not available */

    tmpdir = os.getenv('TMPDIR', '/tmp')

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

    cwd_grid_path = Path(AlienSessionInfo['currentdir'])
    home_grid_path = Path(AlienSessionInfo['alienHome'])

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
        print("Warning! multiple source usage is known to break the files stored in zip files, so it will be ignored in those cases", flush = True)
        sources = int(xrd_copy_command.pop(y_idx + 1))
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
        chunks_nr = int(xrd_copy_command.pop(chunks_nr_idx + 1))
        xrd_copy_command.pop(chunks_nr_idx)
    elif os.getenv('XRD_CPPARALLELCHUNKS'):
        chunks_nr = int(os.getenv('XRD_CPPARALLELCHUNKS'))

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
            print("Only one rule of selection can be used, either -select (full path match), -name (match on file name) or -glob (globbing)")
            return int(22)  # EINVAL /* Invalid argument */
        select_idx = xrd_copy_command.index('-select')
        pattern_regex = xrd_copy_command.pop(select_idx + 1)
        xrd_copy_command.pop(select_idx)
        use_regex = True
        filtering_enabled = True

    if '-name' in xrd_copy_command:
        if filtering_enabled:
            print("Only one rule of selection can be used, either -select (full path match), -name (match on file name) or -glob (globbing)")
            return int(22)  # EINVAL /* Invalid argument */
        name_idx = xrd_copy_command.index('-name')
        pattern_regex = xrd_copy_command.pop(name_idx + 1)
        xrd_copy_command.pop(name_idx)
        use_regex = True
        filtering_enabled = True

        translated_pattern_regex = '.*\\/'
        verbs = ('begin', 'contain', 'ends', 'ext')
        pattern_list = pattern_regex.split('_')
        if any(verb in pattern_regex for verb in verbs):
            if pattern_list.count('begin') > 1 or pattern_list.count('end') > 1 or pattern_list.count('ext') > 1:
                print('<begin>, <end>, <ext> verbs cannot appear more than once in the name selection')
                return int(64)  # EX_USAGE /* command line usage error */

            list_begin = []
            list_contain = []
            list_ends = []
            list_ext = []
            for idx, token in enumerate(pattern_list):
                if token == 'begin': list_begin.append(KV(token, pattern_list[idx + 1]))
                if token == 'contain': list_contain.append(KV(token, pattern_list[idx + 1]))
                if token == 'ends': list_ends.append(KV(token, pattern_list[idx + 1]))
                if token == 'ext': list_ext.append(KV(token, pattern_list[idx + 1]))

            for patt in list_begin: translated_pattern_regex = translated_pattern_regex + patt.val + '[^\\/]+'  # first string after the last slash (last match explude /)
            for patt in list_contain: translated_pattern_regex = translated_pattern_regex + '[^\\/]+' + patt.val + '[^\\/]+'
            for patt in list_ends:
                translated_pattern_regex = translated_pattern_regex + '[^\\/]+' + patt.val
                if list_ext:
                    translated_pattern_regex = translated_pattern_regex + '\\.' + list_ext[0].val
                else:
                    translated_pattern_regex = translated_pattern_regex + '\\.[^\\/]+'

            for path in list_ext:
                if not list_ends:  # we already added the ext in list_ends
                    translated_pattern_regex = translated_pattern_regex + '[^\\/]+' + '\\.' + list_ext[0].val

            pattern_regex = translated_pattern_regex
        else:
            print("No selection verbs were recognized! usage format is -name <attribute>_<string> where attribute is one of: begin, contain, ends, ext")

    isSrcDir = bool(False)
    isDstDir = bool(False)
    file_name = ''

    arg_source = xrd_copy_command[-2]
    arg_target = xrd_copy_command[-1]
    slashend_src = True if arg_source.endswith('/') else False
    slashend_dst = True if arg_target.endswith('/') else False

    isSrcLocal = None
    isDstLocal = None
    isDownload = None

    arg_err_msg = 'The operands cannot have the same type and need at least one specifier.\nUse any of "file:" and or "alien:" specifiers for any path arguments'

    if arg_source.startswith('file:'):
        if arg_target.startswith('file:'):
            print(arg_err_msg, file=sys.stderr, flush = True)
            return int(22)  # EINVAL /* Invalid argument */
        isSrcLocal = True
        isDstLocal = not isSrcLocal
        if arg_source.startswith('file://'):  arg_source = arg_source.replace("file://", "", 1)
        if arg_source.startswith('file:'):    arg_source = arg_source.replace("file:", "", 1)
    if arg_source.startswith('alien:'):
        if arg_target.startswith('alien:'):
            print(arg_err_msg, file=sys.stderr, flush = True)
            return int(22)  # EINVAL /* Invalid argument */
        isSrcLocal = False
        isDstLocal = not isSrcLocal
        if arg_source.startswith('alien://'): arg_source = arg_source.replace("alien://", "", 1)
        if arg_source.startswith('alien:'):   arg_source = arg_source.replace("alien:", "", 1)

    if isSrcLocal is None and arg_target.startswith('file:'):
        isSrcLocal = False
        isDstLocal = not isSrcLocal
        if arg_target.startswith('file://'):  arg_target = arg_target.replace("file://", "", 1)
        if arg_target.startswith('file:'):    arg_target = arg_target.replace("file:", "", 1)
    if isSrcLocal is None and arg_target.startswith('alien:'):
        isSrcLocal = True
        isDstLocal = not isSrcLocal
        if arg_target.startswith('alien://'): arg_target = arg_target.replace("alien://", "", 1)
        if arg_target.startswith('alien:'):   arg_target = arg_target.replace("alien:", "", 1)

    isDownload = isDstLocal
    if isSrcLocal is None:
        print(arg_err_msg, file=sys.stderr, flush = True)
        return int(22)  # EINVAL /* Invalid argument */
    if not isDownload: use_regex = True

    if use_regex:
        try:
            regex = re.compile(pattern_regex)
        except re.error:
            print("regex argument of -select or -name option is invalid!!", file=sys.stderr, flush = True)
            return int(64)  # EX_USAGE /* command line usage error */

    src = None
    src_type = None
    src_specs_remotes = None  # let's record specifications like disk=3,SE1,!SE2
    if isSrcLocal:
        src = expand_path_local(arg_source)
        src_type = pathtype_local(src)
        if src_type == 'd':
            isSrcDir = bool(True)
            if not slashend_src: parent = parent + 1
    else:
        src_specs_remotes = arg_source.split("@", maxsplit = 1)  # NO comma allowed in grid names (hopefully)
        src = src_specs_remotes.pop(0)  # first item is the file path, let's remove it; it remains disk specifications
        src = expand_path_grid(src)
        src_type = pathtype_grid(wb, src)
        if not src_type:
            error = AlienSessionInfo['error']
            print(f"Could not check source argument type: {error}", file=sys.stderr, flush = True)
            return int(42)  # ENOMSG /* No message of desired type */
        if src_type == 'd': isSrcDir = bool(True)

    dst = None
    dst_type = None
    dst_specs_remotes = None  # let's record specifications like disk=3,SE1,!SE2
    if isDstLocal:
        dst = expand_path_local(arg_target)
        dst_type = pathtype_local(dst)
        if not dst_type:
            try:
                mk_path = Path(dst) if dst.endswith('/') else Path(dst).parent
                mk_path.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                logging.error(traceback.format_exc())
                path_str = mk_path.as_posix()
                print(f"Could not create local destination directory: {path_str}\ncheck log file {DEBUG_FILE}", file=sys.stderr, flush = True)
                return int(42)  # ENOMSG /* No message of desired type */
            dst_type = 'd'  # we just created it
        if dst_type == 'd': isDstDir = bool(True)
    else:
        dst_specs_remotes = arg_target.split("@", maxsplit = 1)  # NO comma allowed in grid names (hopefully)
        dst = dst_specs_remotes.pop(0)  # first item is the file path, let's remove it; it remains disk specifications
        dst = expand_path_grid(dst)
        dst_type = pathtype_grid(wb, dst)
        if not dst_type:
            mk_path = dst if dst.endswith('/') else Path(dst).parent.as_posix()
            json_dict = SendMsg(wb, 'mkdir', ['-p', mk_path], opts = 'nomsg')
            if AlienSessionInfo['exitcode'] != 0:
                print(f"check log file {DEBUG_FILE}", file=sys.stderr, flush = True)
                return int(42)  # ENOMSG /* No message of desired type */
            dst_type = 'd'  # we just created it
        if dst_type == 'd': isDstDir = bool(True)

    # create a list of copy tasks
    copy_list = []
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
            src_list_files_dict = SendMsg(wb, 'find', find_args, opts = send_opts + ' print')
            if AlienSessionInfo['exitcode'] != 0:
                print(f"check log file {DEBUG_FILE}", file=sys.stderr, flush = True)
                return int(42)  # ENOMSG /* No message of desired type */
            for item in src_list_files_dict['results']:
                dst_filename = format_dst_fn(src, item['lfn'], dst, parent)
                if os.path.isfile(dst_filename) and not overwrite:
                    print(f'{dst_filename} exists, skipping..', flush = True)
                    continue
                tokens = getEnvelope_lfn(wb, lfn2file(item['lfn'], dst_filename), specs, isWrite)
                token_query = GetDict(tokens['answer'], 'print')
                if AlienSessionInfo['exitcode'] != 0:
                    lfn = tokens['lfn']
                    error = AlienSessionInfo['error']
                    msg = f"{lfn} -> {error}"
                    continue
                copy_list.append(CopyFile(item['lfn'], dst_filename, isWrite, token_query, ''))
        else:
            if dst.endswith("/"): dst = dst[:-1] + setDst(src, parent)
            if os.path.isfile(dst) and not overwrite:
                print(f'{dst} exists, skipping..', flush = True)
                return int(0)  # Destination present we will not overwrite it
            tokens = getEnvelope_lfn(wb, lfn2file(src, dst), specs, isWrite)
            token_query = GetDict(tokens['answer'], 'print')
            if AlienSessionInfo['exitcode'] != 0:
                lfn = tokens['lfn']
                error = AlienSessionInfo['error']
                msg = f"{lfn} -> {error}"
            else:
                copy_list.append(CopyFile(src, dst, isWrite, token_query, ''))
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
                            else:  # clear up the destination lfn
                                print(f'{lfn} exists, deleting..', flush = True)
                                json_dict = SendMsg(wb, 'rm', ['-f', lfn], opts = 'nomsg print')
                        tokens = getEnvelope_lfn(wb, lfn2file(lfn, filepath), specs, isWrite)
                        token_query = GetDict(tokens['answer'], 'print')
                        if AlienSessionInfo['exitcode'] != 0:
                            lfn = tokens['lfn']
                            error = AlienSessionInfo['error']
                            msg = f"{lfn} -> {error}"
                            continue
                        copy_list.append(CopyFile(filepath, lfn, isWrite, token_query, ''))
        else:
            if dst.endswith("/"): dst = dst[:-1] + setDst(src, parent)
            lfn_exists = pathtype_grid(wb, dst)
            if lfn_exists:
                if not overwrite:  # if the lfn is already present and not overwrite lets's skip the upload
                    print(f'{dst} exists, skipping..', flush = True)
                    return int(0)  # Destination present we will not overwrite it
                else:  # clear up the destination lfn
                    print(f'{dst} exists, deleting..', flush = True)
                    json_dict = SendMsg(wb, 'rm', ['-f', dst], 'nomsg print')
            tokens = getEnvelope_lfn(wb, lfn2file(dst, src), specs, isWrite)
            token_query = GetDict(tokens['answer'])
            if AlienSessionInfo['exitcode'] != 0:
                lfn = tokens['lfn']
                error = AlienSessionInfo['error']
                msg = f"{lfn} -> {error}"
            else:
                copy_list.append(CopyFile(src, dst, isWrite, token_query, ''))

    if not copy_list:
        msg = f"No copy operations in list! enable the DEBUG mode for more info"
        logging.info(msg)
        return int(2)  # ENOENT /* No such file or directory */

    if DEBUG:
        logging.debug("We are going to copy these files:")
        for file in copy_list: logging.debug(file)

    # create a list of copy jobs to be passed to XRootD mechanism
    xrdcopy_job_list = []
    for cpfile in copy_list:
        if isDownload:
            lfn = cpfile.src
            if not cpfile.token_request['results']: continue
            dst = cpfile.dst
            size_4meta = cpfile.token_request['results'][0]['size']  # size SHOULD be the same for all replicas
            md5_4meta = cpfile.token_request['results'][0]['md5']  # the md5 hash SHOULD be the same for all replicas
            if fileIsValid(dst, size_4meta, md5_4meta): continue  # destination exists and is valid

            # multiple replicas are downloaded to a single file
            is_zip = False
            file_in_zip = ''
            url_list_4meta = []
            for replica in cpfile.token_request['results']:
                url_components = replica['url'].rsplit('#', maxsplit = 1)
                if len(url_components) > 1:
                    is_zip = True
                    file_in_zip = url_components[1]
                if True:  # is_pfn_readable(url_components[0]):  # it is a lot cheaper to check readability of replica than to try and fail a non-working replica
                    url_list_4meta.append(url_components[0] + '?authz=' + replica['envelope'])

            if not url_list_4meta:
                print(f'Could not find working replicas of {lfn}', file=sys.stderr, flush = True)
                continue

            # Create the metafile based link
            meta_fn = make_tmp_fn(lfn, '.meta4', True)  # create a temporary uuid5 named file (the lfn can be retrieved from meta if needed)
            create_metafile(meta_fn, lfn, dst, size_4meta, md5_4meta, url_list_4meta)
            download_link = meta_fn
            if is_zip:
                sources = 1
                download_link = download_link + '?xrdcl.unzip=' + file_in_zip
            xrdcopy_job_list.append(CopyFile(download_link, dst, cpfile.isUpload, {}, lfn))  # we do not need the tokens in job list when downloading
        else:  # is upload
            src = cpfile.src
            lfn = cpfile.dst
            if not cpfile.token_request['results']: continue
            for request in cpfile.token_request['results']:
                complete_url = request['url'] + "?" + "authz=" + request['envelope']
                xrdcopy_job_list.append(CopyFile(src, complete_url, cpfile.isUpload, request, lfn))

    if not xrdcopy_job_list:
        msg = f"No XRootD operations in list! enable the DEBUG mode for more info"
        logging.info(msg)
        return int(2)  # ENOENT /* No such file or directory */

    if DEBUG:
        logging.debug("XRootD copy jobs:")
        for file in xrdcopy_job_list: logging.debug(file)

    my_cp_args = XrdCpArgs(overwrite, batch, sources, chunks, chunksize, makedir, posc, hashtype, streams, cksum)
    # defer the list of url and files to xrootd processing - actual XRootD copy takes place
    replica_list_upload_failed = XrdCopy(wb, xrdcopy_job_list, isDownload, my_cp_args, printout)

    # hard to return a single exitcode for a copy process optionally spanning multiple files
    # we'll return SUCCESS if at least one lfn is confirmed, FAIL if not lfns is confirmed
    return int(1) if replica_list_upload_failed else int(0)


if has_xrootd:
    class MyCopyProgressHandler(client.utils.CopyProgressHandler):
        def __init__(self):
            self.wb = None
            self.isDownload = bool(True)
            self.replica_list_upload_failed = []  # record the tokens of succesfully uploaded files. needed for commit to catalogue
            self.jobs = int(0)
            self.job_list = []
            self.xrdjob_list = []
            self.printout = ''

        def begin(self, jobId, total, source, target):
            timestamp_begin = datetime.now().timestamp()
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
            status = ''
            if results['status'].ok: status = PrintColor(COLORS.Green) + 'OK' + PrintColor(COLORS.ColorReset)
            if results['status'].error: status = PrintColor(COLORS.BRed) + 'ERROR' + PrintColor(COLORS.ColorReset)
            if results['status'].fatal: status = PrintColor(COLORS.BIRed) + 'FATAL' + PrintColor(COLORS.ColorReset)

            xrdjob = self.xrdjob_list[jobId - 1]  # joblist initilized when starting; we use the internal index to locate the job
            if self.isDownload and not os.getenv('ALIENPY_KEEP_META'): os.remove(xrdjob.src)  # remove the created metalink

            if not results['status'].ok:
                if self.isDownload:  # we have an failed replica upload
                    print(f"Failed download: {xrdjob.lfn}", flush = True)
                else:
                    self.replica_list_upload_failed.append(xrdjob.token_request)
                    print(f"Failed upload: {xrdjob.token_request['file']} to {xrdjob.token_request['se']}, {xrdjob.token_request['nSEs']} total replicas", flush = True)
                return

            speed_str = '0 B/s'
            if results['status'].ok:
                deltaT = datetime.now().timestamp() - float(self.job_list[jobId - 1]['start'])
                speed = float(self.job_list[jobId - 1]['bytes_total'])/deltaT
                speed_str = str(GetHumanReadable(speed)) + '/s'
                if not self.isDownload:  # isUpload
                    xrd_dst_url = str(self.job_list[jobId - 1]['tgt'])
                    link = urlparse(xrd_dst_url)
                    token = next((param for param in str.split(link.query, '&') if 'authz=' in param), None).replace('authz=', '')  # extract the token from url
                    copyjob = next(job for job in self.xrdjob_list if job.token_request.get('url') in xrd_dst_url)
                    replica_dict = copyjob.token_request
                    perm = '644'
                    expire = '0'
                    exitcode = commit(self.wb, token, replica_dict['size'], copyjob.lfn, perm, expire, replica_dict['url'], replica_dict['se'], replica_dict['guid'], replica_dict['md5'])

            if not ('quiet' in self.printout or 'silent' in self.printout):
                print("jobID: {0}/{1} >>> ERRNO/CODE/XRDSTAT {2}/{3}/{4} >>> STATUS {5} >>> SPEED {6} MESSAGE: {7}".format(jobId, self.jobs, results_errno, results_code, results_status, status, speed_str, results_message), flush = True)

        def update(self, jobId, processed, total):
            self.job_list[jobId - 1]['bytes_processed'] = processed
            self.job_list[jobId - 1]['bytes_total'] = total

        def should_cancel(self, jobId):
            return False


def XrdCopy(wb: websockets.client.WebSocketClientProtocol, job_list: list, isDownload: bool, xrd_cp_args: XrdCpArgs, printout: str = '') -> list:
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
    hashtype = xrd_cp_args.hashtype
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
    handler.isDownload = isDownload
    handler.wb = wb
    handler.xrdjob_list = job_list
    handler.printout = printout

    # get xrootd client version
    has_cksum = False
    xrd_ver_arr = client.__version__.split(".")
    if len(xrd_ver_arr) > 1:
        xrdver_major = xrd_ver_arr[0]
        if xrd_ver_arr[1].isdigit():
            xrdver_minor = int(xrd_ver_arr[1])
            # xrdver_patch = xrd_ver_arr[2]
            if xrdver_major == 'v4' and xrdver_minor > 12: has_cksum = True
        else:
            xrdver_minor = xrd_ver_arr[1]
            has_cksum = True  # minor version is not proper digit, it is assumed a version with this feature
    else:
        xrdver_git = xrd_ver_arr[0].split("-")
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
    return handler.replica_list_upload_failed  # for upload jobs we must return the list of token for succesful uploads


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
    if flags:
        return True if flags & client.flags.StatInfoFlags.IS_READABLE else False
    return False


def DO_pfnstatus(args: list = None):
    global AlienSessionInfo
    if not args: args = []
    if '-h' in args or '-help' in args:
        print('Command format: pfn_status <pfn>'
              'It will return all flags reported by the xrootd server', flush = True)
        return int(0)
    pfn = args.pop(0)
    answer = xrd_stat(pfn)
    response_stat = answer[0]
    response_statinfo = answer[1]
    if not response_stat.ok:
        print(f'{response_stat.message}; code/status: {response_stat.code}/{response_stat.status}', file=sys.stderr, flush = True)
        return int(response_stat.shellcode)
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
    print(f'''Size: {size}\n'''
          f'''Modification time: {modtime}\n'''
          f'''Executable bit: {x_bit_set}\n'''
          f'''Is directory: {is_dir}\n'''
          f'''Not a file or directory: {other}\n'''
          f'''File is offline (not on disk): {offline}\n'''
          f'''File opened with POSC flag, not yet successfully closed: {posc_pending}\n'''
          f'''Is readable: {is_readable}\n'''
          f'''Is writable: {is_writable}''')
    return int(response_stat.shellcode)


def get_pfn_list(wb: websockets.client.WebSocketClientProtocol, lfn: str):
    if not wb: return ''
    if not lfn: return ''
    type = pathtype_grid(wb, lfn)
    if type != 'f': return ''
    json_dict = SendMsg(wb, 'whereis', [lfn], opts = 'nomsg debug')
    pfn_list = [str(item['pfn']) for item in json_dict['results']]


def get_SE_id(wb: websockets.client.WebSocketClientProtocol, se_name: str) -> list:
    if not wb: return ''
    if not se_name: return ''
    json_dict = SendMsg(wb, 'listSEs', [], 'nomsg debug')
    if int(AlienSessionInfo['exitcode']): return ''
    return [se["seNumber"].strip() if re.search(se_name, str(se.values())) else '' for se in json_dict["results"]]


def get_SE_name(wb: websockets.client.WebSocketClientProtocol, se_name: str) -> list:
    if not wb: return ''
    if not se_name: return ''
    json_dict = SendMsg(wb, 'listSEs', [], 'nomsg debug')
    if int(AlienSessionInfo['exitcode']): return ''
    if se_name.isdecimal():
        return [se["seName"].strip() if se_name in se['seNumber'] else '' for se in json_dict["results"]]
    else:
        return [se["seName"].strip() if re.search(se_name, str(se.values())) else '' for se in json_dict["results"]]


def get_SE_srv(wb: websockets.client.WebSocketClientProtocol, se_name: str) -> list:
    if not wb: return ''
    if not se_name: return ''
    json_dict = SendMsg(wb, 'listSEs', [], 'nomsg debug')
    if int(AlienSessionInfo['exitcode']): return ''
    if se_name.isdecimal():
        return [urlparse(se["endpointUrl"]).netloc.strip() if se_name in se['seNumber'] else '' for se in json_dict["results"]]
    else:
        return [urlparse(se["endpointUrl"]).netloc.strip() if re.search(se_name, str(se.values())) else '' for se in json_dict["results"]]


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
    return os.getenv('TMPDIR', '/tmp') + '/' + lfn2tmp_fn(lfn, uuid5) + ext


def get_lfn_name(tmp_name: str = '', ext: str = '') -> str:
    lfn = tmp_name.replace(ext, '') if ext else tmp_name.replace('_' + str(os.getuid()) + '.alienpy_tmp', '')
    lfn = lfn.replace(os.getenv('TMPDIR', '/tmp') + '/', '')
    lfn = lfn.replace("%%", "/")
    return lfn


def download_tmp(wb: websockets.client.WebSocketClientProtocol, lfn: str, overwrite: bool = False) -> str:
    """Download a lfn to a temporary file, it will return the file path of temporary"""
    global AlienSessionInfo
    tmpfile = make_tmp_fn(expand_path_grid(lfn))
    if overwrite and os.path.isfile(tmpfile): os.remove(tmpfile)
    if tmpfile not in AlienSessionInfo['templist'] and not os.path.isfile(tmpfile):
        copycmd = "-f " + lfn + " " + 'file://' + tmpfile
        result = ProcessXrootdCp(wb, copycmd.split(), printout = 'silent')  # print only errors for temporary downloads
        AlienSessionInfo['templist'].append(tmpfile)
    return tmpfile


def upload_tmp(wb: websockets.client.WebSocketClientProtocol, temp_file_name: str, upload_specs: str = '') -> str:
    """Upload a temporary file: the original lfn will be renamed and the new file will be uploaded with the oirginal lfn"""
    lfn = get_lfn_name(temp_file_name)

    # lets recover the lfn from temp file name
    # let's create a backup of old lfn
    lfn_backup = lfn + "~"
    result = SendMsg(wb, 'rm', ['-f', lfn_backup], opts = 'log')
    result = SendMsg(wb, 'mv', [lfn, lfn_backup], opts = 'log')
    json_dict = GetDict(result)
    if json_dict["metadata"]["exitcode"] != '0':
        print(f"Could not create backup of lfn : {lfn}", file=sys.stderr, flush = True)
        return ''

    tokens = getEnvelope_lfn(wb, lfn2file(lfn, temp_file_name), [upload_specs], isWrite = True)
    access_request = GetDict(tokens['answer'])
    replicas = access_request["results"][0]["nSEs"]
    if "disk:" not in upload_specs: upload_specs = "disk:" + replicas
    if upload_specs: upload_specs = "@" + upload_specs
    copycmd = "-f " + 'file://' + temp_file_name + " " + lfn + upload_specs
    list_upload = ProcessXrootdCp(wb, copycmd.split())
    if list_upload == 0: return lfn
    result = SendMsg(wb, 'mv', [lfn_backup, lfn], opts = 'log')
    return ''


def DO_ps(wb: websockets.client.WebSocketClientProtocol, args: list) -> int:
    """ps : show and process ps output"""
    result = SendMsg(wb, 'ps', args, opts = 'log print')
    if JSON_OUT:  # print nice json for debug or json mode
        PrintDict(result)
        return int(AlienSessionInfo['exitcode'])
    if JSONRAW_OUT:  # print the raw byte stream received from the server
        PrintDict(result, opts = 'rawstr')
        return int(AlienSessionInfo['exitcode'])
    if int(AlienSessionInfo['exitcode']) != 0: return int(AlienSessionInfo['exitcode'])
    msg_str = '\n'.join(str(item['message']) for item in result['results'])
    if '-trace' in args:
        nice_lines = [convert_time(msgline) for msgline in msg_str.split('\n')]
        msg_str = '\n'.join(nice_lines)
    print(msg_str, flush = True)
    return int(AlienSessionInfo['exitcode'])


def DO_cat(wb: websockets.client.WebSocketClientProtocol, lfn: str) -> int:
    """cat lfn :: download lfn as a temporary file and cat"""
    lfn_path = expand_path_grid(lfn)
    tmp = make_tmp_fn(lfn_path)
    if tmp not in AlienSessionInfo['templist']:
        tmp = download_tmp(wb, lfn)
        AlienSessionInfo['templist'].append(tmp)
    if tmp and os.path.isfile(tmp): return runShellCMD('cat ' + tmp)


def DO_less(wb: websockets.client.WebSocketClientProtocol, lfn: str) -> int:
    """cat lfn :: download lfn as a temporary file and less"""
    lfn_path = expand_path_grid(lfn)
    tmp = make_tmp_fn(lfn_path)
    if tmp not in AlienSessionInfo['templist']:
        tmp = download_tmp(wb, lfn)
        AlienSessionInfo['templist'].append(tmp)
    if tmp and os.path.isfile(tmp): return runShellCMD('less ' + tmp, False)


def DO_more(wb: websockets.client.WebSocketClientProtocol, lfn: str) -> int:
    """cat lfn :: download lfn as a temporary file and more"""
    lfn_path = expand_path_grid(lfn)
    tmp = make_tmp_fn(lfn_path)
    if tmp not in AlienSessionInfo['templist']:
        tmp = download_tmp(wb, lfn)
        AlienSessionInfo['templist'].append(tmp)
    if tmp and os.path.isfile(tmp): return runShellCMD('more ' + tmp, False)


def DO_pfn(wb: websockets.client.WebSocketClientProtocol, args: list) -> int:
    cmd = 'whereis'
    args.insert(0, '-r')
    json_dict = SendMsg(wb, cmd, args, opts = 'nomsg print')
    output = '\n'.join(str(item['pfn']) for item in json_dict['results']).strip()
    print(output, flush = True)
    return AlienSessionInfo['exitcode']


def DO_edit(wb: websockets.client.WebSocketClientProtocol, lfn: str, editor: str = 'mcedit') -> int:
    """Edit a grid lfn; download a temporary, edit with the specified editor and upload the new file"""
    if editor == 'mcedit': editor = 'mc -c -e'
    editor = editor + " "
    specs = ''
    lfn_specs = lfn.split("@", maxsplit = 1)
    if len(lfn_specs) > 1:
        lfn = lfn_specs[0]
        specs = lfn_specs[1]
    lfn_path = expand_path_grid(lfn)
    tmp = download_tmp(wb, lfn)
    if tmp and os.path.isfile(tmp):
        md5_begin = md5(tmp)
        exitcode = runShellCMD(editor + tmp, False)
        md5_end = md5(tmp)
        if md5_begin != md5_end: upload_tmp(wb, tmp, specs)
        os.remove(tmp)  # clean up the temporary file not matter if the upload was succesful or not
        return exitcode
    else:
        print(f'There was an error downloading {lfn}, editing could not be done.', file=sys.stderr, flush = True)
        return int(1)


def DO_run(wb: websockets.client.WebSocketClientProtocol, args: list) -> int:
    """cat lfn :: download lfn as a temporary file and more"""
    if '-h' in args or '-help' in args:
        print('Command format: run <shell_command + arguments> lfn\n'
              'the lfn must be the last element of the command\n'
              'N.B.! The output and error streams will be captured and printed at the end of execution!\n'
              'for working within application use <edit>', flush = True)
        return int(0)
    lfn = args.pop(-1)
    cmd = " ".join(args)
    lfn_path = expand_path_grid(lfn)
    tmp = make_tmp_fn(lfn_path)
    if tmp not in AlienSessionInfo['templist']:
        tmp = download_tmp(wb, lfn)
        AlienSessionInfo['templist'].append(tmp)
    if tmp and os.path.isfile(tmp): return runShellCMD(cmd + ' ' + tmp)


def DO_exec(wb: websockets.client.WebSocketClientProtocol,  args: list) -> int:
    """cat lfn :: download lfn as a temporary file and more"""
    if '-h' in args or '-help' in args:
        print('Command format: exec lfn list_of_arguments\n'
              'N.B.! The output and error streams will be captured and printed at the end of execution!\n'
              'for working within application use <edit>', flush = True)
        return int(0)
    lfn = args.pop(0)
    opt_args = " ".join(args)
    lfn_path = expand_path_grid(lfn)
    tmp = make_tmp_fn(lfn_path)
    if tmp not in AlienSessionInfo['templist']:
        tmp = download_tmp(wb, lfn)
        AlienSessionInfo['templist'].append(tmp)
    os.chmod(tmp, 0o700)
    cmd = tmp + ' ' + opt_args if opt_args else tmp
    if tmp and os.path.isfile(tmp): return runShellCMD(cmd)


def DO_syscmd(wb: websockets.client.WebSocketClientProtocol, cmd: str = '', args: Union[None, list, str] = None) -> int:
    """run system command with all the arguments but all alien: specifications are downloaded to temporaries"""
    global AlienSessionInfo
    if args is None or not args or not cmd:
        AlienSessionInfo['exitcode'] = int(1)
        return AlienSessionInfo['exitcode']
    if type(args) == str: args = args.split()
    new_arg_list = [download_tmp(wb, arg) if arg.startswith('alien:') else arg for arg in args]
    return runShellCMD(cmd + ' ' + ' '.join(new_arg_list))


def DO_find2(wb: websockets.client.WebSocketClientProtocol,  args: list) -> int:
    if '-h' in args or '-help' in args:
        print(f'''-select <pattern> : select only these files; {PrintColor(COLORS.BIGreen)}N.B. this is a REGEX applied to full path!!!{PrintColor(COLORS.ColorReset)} defaults to all ".*"
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
        return int(0)

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

    pattern = '\\/.*'  # default regex selection for find
    if '-select' in args and '-name' in args:
        print("Only one rule of selection can be used, either -select (full path match) or -name (match on file name)")
        return int(22)  # EINVAL /* Invalid argument */

    if '-select' in args:
        select_idx = args.index('-select')
        pattern = args.pop(select_idx + 1)
        args.pop(select_idx)

    if '-name' in args:
        name_idx = args.index('-name')
        pattern = args.pop(name_idx + 1)
        args.pop(name_idx)

        translated_pattern = '.*\\/'
        verbs = ('begin', 'contain', 'ends', 'ext')
        pattern_list = pattern.split('_')
        if any(verb in pattern for verb in verbs):
            if pattern_list.count('begin') > 1 or pattern_list.count('end') > 1 or pattern_list.count('ext') > 1:
                print('<begin>, <end>, <ext> verbs cannot appear more than once in the name selection')
                return int(64)  # EX_USAGE /* command line usage error */

            list_begin = []
            list_contain = []
            list_ends = []
            list_ext = []
            for idx, token in enumerate(pattern_list):
                if token == 'begin': list_begin.append(KV(token, pattern_list[idx + 1]))
                if token == 'contain': list_contain.append(KV(token, pattern_list[idx + 1]))
                if token == 'ends': list_ends.append(KV(token, pattern_list[idx + 1]))
                if token == 'ext': list_ext.append(KV(token, pattern_list[idx + 1]))

            for patt in list_begin: translated_pattern = translated_pattern + patt.val + '[^\\/]+'  # first string after the last slash (last match explude /)
            for patt in list_contain: translated_pattern = translated_pattern + '[^\\/]+' + patt.val + '[^\\/]+'
            for patt in list_ends:
                translated_pattern = translated_pattern + '[^\\/]+' + patt.val
                if list_ext:
                    translated_pattern = translated_pattern + '\\.' + list_ext[0].val
                else:
                    translated_pattern = translated_pattern + '\\.[^\\/]+'

            for path in list_ext:
                if not list_ends:  # we already added the ext in list_ends
                    translated_pattern = translated_pattern + '[^\\/]+' + '\\.' + list_ext[0].val

            pattern = translated_pattern
        else:
            print("No selection verbs were recognized! usage format is -name <attribute>_<string> where attribute is one of: begin, contain, ends, ext")

    try:
        regex = re.compile(pattern)
    except re.error:
        print("regex argument of -select or -name option is invalid!!", file=sys.stderr, flush = True)
        return int(64)  # EX_USAGE /* command line usage error */

    if len(args) > 1:
        print('Too many elements remained in arg list, it should be just the directory')
        print(args)
        return int(1)
    find_args.extend(['-r', '-s', expand_path_grid(args[0]), pattern])
    result = SendMsg(wb, 'find', find_args, opts = 'nokeys')
    return ProcessReceivedMessage(result)


def runShellCMD(INPUT: str = '', captureout: bool = True) -> int:
    """Run shell command in subprocess; if exists, print stdout and stderr"""
    if not INPUT: return
    sh_cmd = re.sub(r'^!', '', INPUT)

    if captureout:
        args = sh_cmd
        shcmd_out = subprocess.run(args, env = os.environ, stdout = subprocess.PIPE, stderr = subprocess.PIPE, shell = True)
    else:
        args = shlex.split(sh_cmd)
        shcmd_out = subprocess.run(args, env = os.environ)

    if shcmd_out.stderr: print(shcmd_out.stderr.decode().strip(), file=sys.stderr, flush = True)
    if shcmd_out.stdout: print(shcmd_out.stdout.decode().strip(), file=sys.stdout, flush = True)
    return int(shcmd_out.returncode)


def DO_quota(wb: websockets.client.WebSocketClientProtocol, quota_args: Union[None, list] = None):
    """quota : put togheter both job and file quota"""
    if not quota_args: quota_args = []
    if len(quota_args) > 0:
        if quota_args[0] != "set":  # we asume that if 'set' is not used then the argument is a username
            user = quota_args[0]
            jquota_cmd = CreateJsonCommand('jquota -nomsg list ' + user)
            fquota_cmd = CreateJsonCommand('fquota -nomsg list ' + user)
        else:
            print('set functionality not implemented yet')
    else:
        user = AlienSessionInfo['user']
        jquota_cmd = CreateJsonCommand('jquota -nomsg list ' + user)
        fquota_cmd = CreateJsonCommand('fquota -nomsg list ' + user)

    jquota_dict = SendMsg(wb, jquota_cmd)
    fquota_dict = SendMsg(wb, fquota_cmd)

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

    print(f"""Quota report for user : {username}
Running time (last 24h) :\t{running_time:.2f}/{running_time_max:.2f}(h) --> {running_time_perc:.2f}% used
CPU Cost :\t\t\t{cpucost:.2f}/{cpucost_max:.2f}(h) --> {cpucost_perc:.2f}% used
ParallelJobs (nominal/max) :\t{pjobs_nominal}/{pjobs_max}
Unfinished jobs :\t\tMAX={unfinishedjobs_max}
Waiting :\t\t\t{waiting}
Storage size :\t\t\t{size_MiB:.2f}/{size_max_MiB:.2f} MiB --> {size_perc:.2f}%
Number of files :\t\t{files}/{files_max} --> {files_perc:.2f}%""")
    return int(0)


def check_port(address: str, port: Union[str, int]) -> bool:
    """Check TCP connection to address:port"""
    s = socket.socket()  # Create a TCP socket
    try:
        s.connect((address, int(port)))
    except Exception as e:
        # print(e)
        s.close()
        return False
    if s:
        s.close()
        return True


def get_help(wb, cmd):
    """Return the help option even for client-side commands"""
    ProcessInput(wb, cmd + ' -h')


def get_list_entries(wb, lfn, fullpath: bool = False) -> list:
    global AlienSessionInfo
    cache = AlienSessionInfo['completer_cache']
    """return a list of entries of the lfn argument, full paths if 2nd arg is True"""
    key = 'path' if fullpath else 'name'

    def cleanup_item(lfn):
        ret = re.sub(r"\/{2,}", "/", lfn)
        return re.sub(r"^\.\/", "", ret)

    entries_list = None
    ls_args = ['-nomsg', '-F']
    result_dict = SendMsg(wb, 'ls', ls_args + [lfn])
    if result_dict["metadata"]["exitcode"] != '0':
        entries_list = []
    else:
        entries_list = list(cleanup_item(item[key]) for item in result_dict['results'])
    return entries_list


def lfn_list(wb: websockets.client.WebSocketClientProtocol, lfn: str = ''):
    """Completer function : for a given lfn return all options for latest leaf"""
    if not wb: return
    if not lfn: lfn = '.'  # AlienSessionInfo['currentdir']
    lfn_list = []
    lfn_path = Path(lfn)
    base_dir = lfn_path.parent.as_posix() if lfn_path.parent.as_posix() == '/' else lfn_path.parent.as_posix() + '/'
    name = lfn_path.name + '/' if lfn.endswith('/') else lfn_path.name

    def item_format(base_dir, name, item):
        # print(f'\nbase_dir: {base_dir} ; name: {name} ; item: {item}')
        if name.endswith('/') and name != '/':
            return name + item if base_dir == './' else base_dir + name + item
        else:
            return item if base_dir == './' else base_dir + item
        return item

    if lfn.endswith('/'):
        listing = get_list_entries(wb, lfn)
        lfn_list = [item_format(base_dir, name, item) for item in listing]
    else:
        listing = get_list_entries(wb, base_dir)
        lfn_list = [item_format(base_dir, name, item) for item in listing if item.startswith(name)]
    # print(f'\n{lfn_list}\n')
    return lfn_list


def wb_ping(wb: websockets.client.WebSocketClientProtocol) -> float:
    """Websocket ping function, it will return rtt in ms"""
    init_delta = float(-999.0)
    init_begin = datetime.now().timestamp()
    status = IsWbConnected(wb)
    init_end = datetime.now().timestamp()
    init_delta = float((init_end - init_begin) * 1000)
    return init_delta


def DO_ping(wb: websockets.client.WebSocketClientProtocol, arg: str = ''):
    """Command implementation for ping functionality"""
    count = int(1)
    if not arg:
        count = int(3)
    elif arg.isdigit():
        count = int(arg)
        if count < 1: count = 1
    elif arg == '-h':
        print("ping <count>\nwhere count is integer")
    else:
        print("Unrecognized argument")
        return

    results = []
    for i in range(count):
        p = wb_ping(wb)
        results.append(p)

    rtt_min = min(results)
    rtt_max = max(results)
    rtt_avg = statistics.mean(results)
    rtt_stddev = statistics.stdev(results) if len(results) > 1 else 0.0
    endpoint = wb.remote_address[0]
    print(f"Websocket ping/pong(s) : {count} time(s) to {endpoint}\nrtt min/avg/max/mdev (ms) = {rtt_min:.3f}/{rtt_avg:.3f}/{rtt_max:.3f}/{rtt_stddev:.3f}", flush = True)


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
    utc_time = datetime.strptime(x509_notafter.decode("utf-8"), "%Y%m%d%H%M%SZ")
    time_notafter = int((utc_time - datetime(1970, 1, 1)).total_seconds())
    time_current  = int(datetime.now().timestamp())
    time_remaining = time_notafter - time_current
    return True if (time_remaining > 300) else False


def CertInfo(fname: str):
    """Print certificate information (subject, issuer, notbefore, notafter)"""
    try:
        with open(fname) as f:
            cert_bytes = f.read()
    except Exception:
        print(f"File >>>{fname}<<< not found", file=sys.stderr, flush = True)
        return int(2)  # ENOENT /* No such file or directory */

    try:
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_bytes)
    except Exception:
        print(f"Could not load certificate >>>{fname}<<<", file=sys.stderr, flush = True)
        return int(5)  # EIO /* I/O error */

    utc_time_notafter = datetime.strptime(x509.get_notAfter().decode("utf-8"), "%Y%m%d%H%M%SZ")
    utc_time_notbefore = datetime.strptime(x509.get_notBefore().decode("utf-8"), "%Y%m%d%H%M%SZ")
    issuer = '/%s' % ('/'.join(['%s=%s' % (k.decode("utf-8"), v.decode("utf-8")) for k, v in x509.get_issuer().get_components()]))
    subject = '/%s' % ('/'.join(['%s=%s' % (k.decode("utf-8"), v.decode("utf-8")) for k, v in x509.get_subject().get_components()]))
    print(f"DN >>> {subject}\nISSUER >>> {issuer}\nBEGIN >>> {utc_time_notbefore}\nEXPIRE >>> {utc_time_notafter}", flush = True)
    return int(0)


def get_files_cert() -> list:
    return (os.getenv('X509_USER_CERT', Path.home().as_posix() + '/.globus' + '/usercert.pem'), os.getenv('X509_USER_KEY', Path.home().as_posix() + '/.globus' + '/userkey.pem'))


def get_files_token() -> list:
    return (os.getenv('JALIEN_TOKEN_CERT', os.getenv('TMPDIR', '/tmp') + '/tokencert_' + str(os.getuid()) + '.pem'), os.getenv('JALIEN_TOKEN_KEY', os.getenv('TMPDIR', '/tmp') + '/tokenkey_' + str(os.getuid()) + '.pem'))


def create_ssl_context(use_usercert: bool = False) -> ssl.SSLContext:
    global AlienSessionInfo
    """Create SSL context using either the default names for user certificate and token certificate or X509_USER_{CERT,KEY} JALIEN_TOKEN_{CERT,KEY} environment variables"""
    # SSL SETTINGS
    cert_files = get_files_cert()
    token_files = get_files_token()
    tokencert = token_files[0]
    tokenkey = token_files[1]

    system_ca_path = '/etc/grid-security/certificates'
    alice_cvmfs_ca_path_lx = '/cvmfs/alice.cern.ch/etc/grid-security/certificates'
    alice_cvmfs_ca_path_macos = '/Users/Shared' + alice_cvmfs_ca_path_lx

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
        msg = "Not CA location or files specified!!! Connection will not be possible!!"
        print(msg, file=sys.stderr, flush = True)
        logging.info(msg)
        sys.exit(2)
    if DEBUG:
        if x509file:
            logging.debug(f"CAfile = {x509file}")
        else:
            logging.debug(f"CApath = {capath_default}")

    if not use_usercert:  # if there is no explicit request for usercert
        if not os.path.isfile(tokencert):  # and is not a file
            temp_cert = tempfile.NamedTemporaryFile(prefix = 'tokencert_', suffix = '_' + str(os.getuid()) + '.pem')
            temp_cert.write(tokencert.encode(encoding="ascii", errors="replace"))
            temp_cert.seek(0)
            tokencert = temp_cert.name  # temp file was created, let's give the filename to tokencert
        if not os.path.isfile(tokenkey):  # and is not a file
            temp_key = tempfile.NamedTemporaryFile(prefix = 'tokenkey_', suffix = '_' + str(os.getuid()) + '.pem')
            temp_key.write(tokenkey.encode(encoding="ascii", errors="replace"))
            temp_key.seek(0)
            tokenkey = temp_key.name  # temp file was created, let's give the filename to tokenkey

    if IsValidCert(tokencert) and not use_usercert:
        cert = tokencert
        key  = tokenkey
        AlienSessionInfo['use_usercert'] = False
    else:
        if not (os.path.exists(cert_files[0]) and os.path.exists(cert_files[1])):
            msg = f"User certificate files NOT FOUND!!! Connection will not be possible!!"
            print(msg, file=sys.stderr, flush = True)
            logging.info(msg)
            sys.exit(126)
        cert = cert_files[0]
        key  = cert_files[1]
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
    """https://websockets.readthedocs.io/en/stable/api.html#websockets.protocol.WebSocketCommonProtocol"""
    # we use some conservative values, higher than this might hurt the sensitivity to intreruptions

    wb = None
    ctx = None
    if localConnect:
        fHostWSUrl = 'ws://localhost/'
        logging.info(f"Request connection to : {fHostWSUrl}")
        socket_filename = os.getenv('TMPDIR', '/tmp') + '/jboxpy_' + str(os.getuid() + '.sock')
        try:
            wb = await websockets.client.unix_connect(socket_filename, fHostWSUrl, max_queue=QUEUE_SIZE, max_size=MSG_SIZE, ping_interval=PING_INTERVAL, ping_timeout=PING_TIMEOUT, close_timeout=CLOSE_TIMEOUT)
        except Exception as e:
            logging.debug(traceback.format_exc())
            msg = f"Could NOT create socket connection to local socket {socket_filename}"
            logging.error(msg)
            print(msg, file=sys.stderr, flush = True)
            print(f"Check the logfile: {DEBUG_FILE}", file=sys.stderr, flush = True)
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
                init_begin = datetime.now().timestamp()
            if os.getenv('ALIENPY_NO_STAGGER'):
                socket_endpoint = socket.create_connection((host, int(port)))
            else:
                socket_endpoint = await async_stagger.create_connected_sock(host, int(port), async_dns=True, resolution_delay=0.050, detailed_exceptions=True)
            if DEBUG:
                init_delta = (datetime.now().timestamp() - init_begin) * 1000
                logging.debug(f"TCP SOCKET DELTA: {init_delta:.3f} ms")
        except Exception as e:
            logging.debug(traceback.format_exc())
            logging.error(f"Could NOT create socket connection to {host}:{port}")
            return None

        if socket_endpoint:
            socket_endpoint_addr = socket_endpoint.getpeername()[0]
            socket_endpoint_port = socket_endpoint.getpeername()[1]
            logging.info(f"GOT SOCKET TO: {socket_endpoint_addr}")
            try:
                if DEBUG: init_begin = datetime.now().timestamp()
                deflateFact = permessage_deflate.ClientPerMessageDeflateFactory(server_max_window_bits=14, client_max_window_bits=14, compress_settings={'memLevel': 6},)
                wb = await websockets.connect(fHostWSUrl, sock = socket_endpoint, server_hostname = host, ssl = ctx, extensions=[deflateFact, ],
                                              max_queue=QUEUE_SIZE, max_size=MSG_SIZE, ping_interval=PING_INTERVAL, ping_timeout=PING_TIMEOUT, close_timeout=CLOSE_TIMEOUT)
                if DEBUG:
                    init_delta = (datetime.now().timestamp() - init_begin) * 1000
                    logging.debug(f"WEBSOCKET DELTA: {init_delta:.3f} ms")
            except Exception as e:
                logging.debug(traceback.format_exc())
                logging.error(f"Could NOT establish websocket connection to {socket_endpoint_addr}:{socket_endpoint_port}")
                return None
        if wb: logging.info(f"CONNECTED: {wb.remote_address[0]}:{wb.remote_address[1]}")
    return wb


def AlienConnect(token_args: Union[None, list] = None, use_usercert: bool = False, localConnect: bool = False) -> websockets.client.WebSocketClientProtocol:
    """Create a websocket connection to AliEn services either directly to alice-jcentral.cern.ch or trough a local found jbox instance"""
    jalien_websocket_port = os.getenv("ALIENPY_JCENTRAL_PORT", '8097')  # websocket port
    jalien_websocket_path = '/websocket/json'
    jalien_server = os.getenv("ALIENPY_JCENTRAL", 'alice-jcentral.cern.ch')  # default value for JCENTRAL
    jclient_env = os.getenv('TMPDIR', '/tmp') + '/jclient_token_' + str(os.getuid())

    # let's try to get a websocket
    wb = None
    nr_tries = 0
    init_begin = None
    init_delta = None
    if TIME_CONNECT or DEBUG: init_begin = datetime.now().timestamp()

    if localConnect:
        wb = wb_create(localConnect = True)
    else:
        if not os.getenv("ALIENPY_JCENTRAL") and os.path.exists(jclient_env):  # If user defined ALIENPY_JCENTRAL the intent is to set and use the endpoint
            # lets check JBOX availability
            jalien_info = read_conf_file(jclient_env)
            if jalien_info:
                if is_my_pid(jalien_info['JALIEN_PID']) and check_port(jalien_info['JALIEN_HOST'], jalien_info['JALIEN_WSPORT']):
                    jalien_server = jalien_info['JALIEN_HOST']
                    jalien_websocket_port = jalien_info['JALIEN_WSPORT']

        while wb is None:
            try:
                nr_tries += 1
                wb = wb_create(jalien_server, str(jalien_websocket_port), jalien_websocket_path, use_usercert)
            except Exception as e:
                logging.debug(traceback.format_exc())
            if not wb:
                if nr_tries + 1 > 3:
                    logging.debug(f"We tried on {jalien_server}:{jalien_websocket_port}{jalien_websocket_path} {nr_tries} times")
                    break
                time.sleep(1)

        # if we stil do not have a socket, then try to fallback to jcentral if we did not had explicit endpoint and jcentral was not already tried
        if not wb and not os.getenv("ALIENPY_JCENTRAL") and jalien_server != 'alice-jcentral.cern.ch':
            jalien_websocket_port = 8097
            jalien_server = 'alice-jcentral.cern.ch'
            nr_tries = 0
            while wb is None:
                try:
                    nr_tries += 1
                    wb = wb_create(jalien_server, str(jalien_websocket_port), jalien_websocket_path)
                except Exception as e:
                    logging.debug(traceback.format_exc())
                if not wb:
                    if nr_tries + 1 > 3:
                        logging.debug(f"Even {jalien_server}:{jalien_websocket_port}{jalien_websocket_path} failed for {nr_tries} times, giving up")
                        break
                    time.sleep(1)

    if not wb:
        print(f"Check the logfile: {DEBUG_FILE}", file=sys.stderr, flush = True)
        msg = "Could not get a websocket connection, exiting.."
        logging.error(msg)
        print(msg, file=sys.stderr, flush = True)
        sys.exit(1)
    if init_begin:
        init_delta = (datetime.now().timestamp() - init_begin) * 1000
        if DEBUG: logging.debug(f">>>   Endpoint total connecting time: {init_delta:.3f} ms")
        if TIME_CONNECT: print(f">>>   Endpoint total connecting time: {init_delta:.3f} ms", flush = True)

    if AlienSessionInfo['use_usercert']: token(wb, token_args)  # if we connect with usercert then let get a default token
    return wb


def token(wb: websockets.client.WebSocketClientProtocol, args: Union[None, list] = None):
    """(Re)create the tokencert and tokenkey files"""
    if not wb: return
    token_files = get_files_token()
    tokencert = token_files[0]
    tokenkey = token_files[1]

    global AlienSessionInfo
    if not args: args = []

    json_dict = SendMsg(wb, 'token', args, opts = 'nomsg print')

    tokencert_content = json_dict.get('results')[0].get('tokencert', '')
    if not tokencert_content:
        print("No token certificate returned", file=sys.stderr, flush = True)
        return int(AlienSessionInfo['exitcode'])

    tokenkey_content = json_dict.get('results')[0].get('tokenkey', '')
    if not tokenkey_content:
        print("No token key returned", file=sys.stderr, flush = True)
        return int(AlienSessionInfo['exitcode'])

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
    return int(AlienSessionInfo['exitcode'])


def token_regen(wb: websockets.client.WebSocketClientProtocol, args: Union[None, list] = None):
    global AlienSessionInfo
    if not AlienSessionInfo['use_usercert']:
        wb_close(wb, code = 1000, reason = 'Lets connect with usercert to be able to generate token')
        try:
            # we have to reconnect with the new token
            wb = InitConnection()
        except Exception as e:
            logging.debug(traceback.format_exc())

    # now we are connected with usercert, so we can generate token
    token(wb, args)
    # we have to reconnect with the new token
    wb_close(wb, code = 1000, reason = 'Re-initialize the connection with the new token')
    try:
        wb = InitConnection()
    except Exception as e:
        logging.debug(traceback.format_exc())
    return wb


def getSessionVars(wb: websockets.client.WebSocketClientProtocol):
    """Initialize the global session variables : cleaned up command list, user, home dir, current dir"""
    if not wb: return
    global AlienSessionInfo
    # get the command list
    AlienSessionInfo['commandlist'].clear()
    json_dict = SendMsg(wb, 'commandlist', [])
    # first executed commands, let's initialize the following (will re-read at each ProcessReceivedMessage)
    cmd_list = json_dict["results"][0]['message'].split()
    regex = re.compile(r'.*_csd$')
    AlienSessionInfo['commandlist'] = [i for i in cmd_list if not regex.match(i)]
    AlienSessionInfo['commandlist'].remove('jquota')
    AlienSessionInfo['commandlist'].remove('fquota')
    AlienSessionInfo['commandlist'].append('quota')
    AlienSessionInfo['commandlist'].append('prompt')
    AlienSessionInfo['commandlist'].append('token-init')
    AlienSessionInfo['commandlist'].append('token-info')
    AlienSessionInfo['commandlist'].append('token-destroy')
    AlienSessionInfo['commandlist'].append('cert-info')
    AlienSessionInfo['commandlist'].append('quit')
    AlienSessionInfo['commandlist'].append('exit')
    AlienSessionInfo['commandlist'].append('exitcode')
    AlienSessionInfo['commandlist'].append('pfn')
    AlienSessionInfo['commandlist'].append('logout')
    AlienSessionInfo['commandlist'].append('ll')
    AlienSessionInfo['commandlist'].append('la')
    AlienSessionInfo['commandlist'].append('lla')
    AlienSessionInfo['commandlist'].append('run')
    AlienSessionInfo['commandlist'].append('exec')
    AlienSessionInfo['commandlist'].append('getSE')
    AlienSessionInfo['commandlist'].append('version')
    AlienSessionInfo['commandlist'].append('pfn-status')
    AlienSessionInfo['commandlist'].append('find2')
    AlienSessionInfo['commandlist'].sort()
    AlienSessionInfo['user'] = json_dict['metadata']['user']

    # if we were intrerupted and re-connect than let's get back to the old currentdir
    if AlienSessionInfo['currentdir'] and (AlienSessionInfo['currentdir'] != json_dict['metadata']['currentdir']):
        tmp_res = SendMsg(wb, 'cd', [AlienSessionInfo['currentdir']])
    else:
        AlienSessionInfo['currentdir'] = json_dict["metadata"]["currentdir"]

    # if this is first query then current dir is alienHOME
    if not AlienSessionInfo['alienHome']: AlienSessionInfo['alienHome'] = AlienSessionInfo['currentdir']


def InitConnection(token_args: Union[None, list] = None, use_usercert: bool = False) -> websockets.client.WebSocketClientProtocol:
    """Create a session to AliEn services, including session globals"""
    socket_filename = os.getenv('TMPDIR', '/tmp') + '/jboxpy_' + str(os.getuid()) + '.sock'
    pid_filename = os.getenv('TMPDIR', '/tmp') + '/jboxpy_' + str(os.getuid()) + '.pid'
    init_begin = None
    init_delta = None
    wb = None
    if TIME_CONNECT or DEBUG: init_begin = datetime.now().timestamp()
    wb = AlienConnect(token_args, use_usercert)

    # no matter if command or interactive mode, we need alienHome, currentdir, user and commandlist
    getSessionVars(wb)
    if init_begin:
        init_delta = (datetime.now().timestamp() - init_begin) * 1000
        if DEBUG: logging.debug(f">>>   Time for session connection: {init_delta:.3f} ms")
        if TIME_CONNECT: print(f">>>   Time for session connection: {init_delta:.3f} ms", flush = True)
    return wb


def ProcessInput(wb: websockets.client.WebSocketClientProtocol, cmd_string: str, shellcmd: Union[str, None] = None, cmd_mode: bool = False):
    """Process a command line within shell or from command line mode input"""
    if not cmd_string: return
    global JSON_OUT, JSONRAW_OUT, AlienSessionInfo
    args = cmd_string.split(" ")
    cmd = args.pop(0)
    args[:] = [x for x in args if x.strip()]

    INI_JSONOUT_STATE = True  # enable per command json output only if was not per-session enabled at start
    if not (JSON_OUT or JSONRAW_OUT):
        INI_JSONOUT_STATE = False
        if '-json' in args:
            args.remove('-json')
            JSON_OUT = True
        if '-jsonraw' in args:
            args.remove('-jsonraw')
            JSONRAW_OUT = True

    # these commands do NOT need wb connection
    if cmd == 'version': return DO_version()
    if cmd == 'cert-info': return DO_certinfo(args)
    if cmd == 'token-info': return DO_tokeninfo(args)
    if cmd == 'token-destroy': return DO_tokendestroy(args)
    if cmd == 'exitcode': return DO_exitcode()
    if cmd == "pfn-status": return DO_pfnstatus(args)

    # make sure we have with whom to talk to; if not, lets redo the connection
    # we can consider any message/reply pair as atomic, we cannot forsee and treat the connection lost in the middle of reply
    # (if the end of message frame is not received then all message will be lost as it invalidated)
    if not IsWbConnected(wb): wb = InitConnection()

    if cmd == 'token':
        if len(args) > 0 and (args[0] in ['-h', 'help', '-help']):
            args[0] = '-h'
            print("Print only command!!! see below the arguments")

    if cmd == 'token-init':
        if len(args) > 0 and args[0] in ['-h', 'help', '-help']:
            cmd = 'token'
            args[0] = '-h'
            print("Use >token-init args< for token (re)creation, see below the arguments")
        else:
            wb = token_regen(wb, args)
            token_files = get_files_token()
            tokencert = token_files[0]
            tokenkey = token_files[1]
            if os.path.exists(tokencert) and os.path.exists(tokenkey):
                CertInfo(tokencert)
                AlienSessionInfo['exitcode'] = int(0)
            else:
                AlienSessionInfo['exitcode'] = int(1)
            return AlienSessionInfo['exitcode']

    if cmd == "ping":
        ping_arg = args[0] if len(args) > 0 else ''
        DO_ping(wb, ping_arg)
        return int(0)

    # implement a time command for measurement of sent/recv delay; for the commands above we do not use timing
    message_begin = None
    message_delta = None

    # first to be processed is the time token, it will start the timing and be removed from command
    if cmd == 'time':
        if not args:
            print("time precede the command that should be timed", flush = True)
            return int(64)  # EX_USAGE /* command line usage error */
        else:
            cmd = args.pop(0)
            message_begin = datetime.now().timestamp()

    # then we process the help commands
    if (cmd == "?") or (cmd == "-h") or (cmd.endswith('help')):
        if len(args) > 0:
            cmd = args.pop(0)
            args.clear()
            args.append('-h')
        else:
            print('Project documentation can be found at:\n'
                  'https://jalien.docs.cern.ch/\n'
                  'https://gitlab.cern.ch/jalien/xjalienfs/blob/master/README.md\n'
                  'the following commands are available:', flush = True)
            nr = len(AlienSessionInfo['commandlist'])
            columns = 6
            for ln in range(0, nr, columns):
                if ln + 1 > nr: ln = nr - 1
                el_ln = AlienSessionInfo['commandlist'][ln:ln + columns]
                ln = [str(i).ljust(26) for i in el_ln]
                print(''.join(ln), flush = True)
            AlienSessionInfo['exitcode'] = int(0)
            return AlienSessionInfo['exitcode']

    # intercept all commands that take a lfn as argument and proper expand it
    if cmd in ['cd', 'ls', 'stat', 'xrdstat', 'rm', 'rmdir', 'lfn2guid', 'whereis', 'pfn', 'type', 'chown', 'md5sum', 'mv', 'touch', 'whereis']:
        for i, arg in enumerate(args):
            if args[i][0] != '-': args[i] = expand_path_grid(args[i])

    if cmd == 'submit':  # submit have only first arg as lfn
        args[0] = expand_path_grid(args[0])

    if cmd == 'getSE':
        if not args or '-h' in args or '-help' in args:
            print('Command format: getSE <-id | -name | -srv> identifier_string', flush = True)
            return int(0)
        if args[0] == '-name':
            ans_list = get_SE_name(wb, args[1])
            print(" ".join(ans_list).strip())
            return int(0)
        if args[0] == '-id':
            ans_list = get_SE_id(wb, args[1])
            print(" ".join(ans_list).strip())
            return int(0)
        if args[0] == '-srv':
            ans_list = get_SE_srv(wb, args[1])
            print(" ".join(ans_list).strip())
            return int(0)

    if cmd == "ps":
        AlienSessionInfo['exitcode'] = DO_ps(wb, args)
        return AlienSessionInfo['exitcode']

    if cmd == "run":
        AlienSessionInfo['exitcode'] = DO_run(wb, args)
        return AlienSessionInfo['exitcode']

    if cmd == "exec":
        AlienSessionInfo['exitcode'] = DO_exec(wb, args)
        return AlienSessionInfo['exitcode']

    if cmd == "quota":
        AlienSessionInfo['exitcode'] = DO_quota(wb, args)
        return AlienSessionInfo['exitcode']

    if cmd == "find2":
        AlienSessionInfo['exitcode'] = DO_find2(wb, args)
        return AlienSessionInfo['exitcode']

    if cmd == "pfn":
        AlienSessionInfo['exitcode'] = DO_pfn(wb, args)
        return AlienSessionInfo['exitcode']

    if cmd == "cp":  # defer cp processing to ProcessXrootdCp
        AlienSessionInfo['exitcode'] = ProcessXrootdCp(wb, args)
        return AlienSessionInfo['exitcode']

    if cmd == "cat":
        if args[0] != '-h':
            AlienSessionInfo['exitcode'] = DO_cat(wb, args[0])
            return AlienSessionInfo['exitcode']

    if cmd == "less":
        if args[0] != '-h':
            AlienSessionInfo['exitcode'] = DO_less(wb, args[0])
            return AlienSessionInfo['exitcode']

    if cmd == "more":
        if args[0] != '-h':
            AlienSessionInfo['exitcode'] = DO_more(wb, args[0])
            return AlienSessionInfo['exitcode']

    if (cmd == 'mcedit' or cmd == 'vi' or cmd == 'nano' or cmd == 'vim'):
        if args[0] != '-h':
            DO_edit(wb, args[0], editor=cmd)
            return AlienSessionInfo['exitcode']

    if (cmd == 'edit' or cmd == 'sensible-editor'):
        EDITOR = os.getenv('EDITOR', '')
        if not EDITOR:
            print('No EDITOR variable set up!', file=sys.stderr, flush = True)
            return int(22)  # EINVAL /* Invalid argument */
        cmd = EDITOR
        if args[0] != '-h':
            DO_edit(wb, args[0], editor=cmd)
            return AlienSessionInfo['exitcode']

    if cmd not in AlienSessionInfo['commandlist']:
        return DO_syscmd(wb, cmd, args)

    # default to print / after directories
    if cmd == 'ls': args.insert(0, '-F')
    if cmd == 'll':
        cmd = 'ls'
        [args.insert(0, flag) for flag in ('-l', '-F')]
    if cmd == 'la':
        cmd = 'ls'
        [args.insert(0, flag) for flag in ('-a', '-F')]
    if cmd == 'lla':
        cmd = 'ls'
        [args.insert(0, flag) for flag in ('-a', '-l', '-F')]

    send_opt = 'nokeys'
    if DEBUG: send_opt = ''
    if JSON_OUT or JSONRAW_OUT: send_opt = 'rawstr'
    result = SendMsg(wb, cmd, args, opts = send_opt + ' print')
    if message_begin:
        message_delta = (datetime.now().timestamp() - message_begin) * 1000
        print(f">>>   Roundtrip for send/receive: {message_delta:.3f} ms", flush = True)
    if not INI_JSONOUT_STATE:
        JSON_OUT = False
        JSONRAW_OUT = False
    return int(ProcessReceivedMessage(result, shellcmd, cmd_mode))


def ProcessReceivedMessage(message: Union[dict, str], shellcmd: Union[str, None] = None, cmd_mode: bool = False):
    """Process the printing/formating of the received message from the server"""
    if not message: return int(61)  # ENODATA
    global AlienSessionInfo

    if JSON_OUT:  # print nice json for debug or json mode
        PrintDict(message)
        return int(AlienSessionInfo['exitcode'])
    if JSONRAW_OUT:  # print the raw byte stream received from the server
        PrintDict(message, opts = 'rawstr')
        return int(AlienSessionInfo['exitcode'])

    websocket_output = ''
    if message['results']:
        websocket_output = '\n'.join(str(item['message']) for item in message['results'])
        websocket_output.strip()
    if websocket_output:
        if shellcmd:
            shell_run = subprocess.run(shellcmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, input=websocket_output, encoding='ascii', shell=True, env=os.environ)
            stdout = shell_run.stdout
            if stdout: print(stdout, flush = True)
            stderr = shell_run.stderr
            if stderr: print(stderr, file=sys.stderr, flush = True)
        else:
            print(websocket_output, flush = True)
    return int(AlienSessionInfo['exitcode'])


def JAlien(commands: str = ''):
    """Main entry-point for interaction with AliEn"""
    global AlienSessionInfo
    aliases_dict = import_aliases()

    # Command mode interaction
    if commands:
        # translate aliases
        if aliases_dict:
            for alias in aliases_dict: commands = commands.replace(alias, aliases_dict[alias])
        cmds_tokens = commands.split(";")
        if len(cmds_tokens) == 1:
            args = commands.split(" ")
            cmd = args.pop(0)
            args[:] = [x for x in args if x.strip()]

            # FAST-PATH!! these commands do NOT need wb connection
            if cmd == 'version': return DO_version()
            if cmd == 'cert-info': return DO_certinfo(args)
            if cmd == 'token-info': return DO_tokeninfo(args)
            if cmd == 'token-destroy': return DO_tokendestroy(args)
            if cmd == 'exitcode': return DO_exitcode()
            if cmd == "pfn-status": return DO_pfnstatus(args)

        wb = InitConnection()  # we are doing the connection recovery and exception treatment in AlienConnect()
        for token in cmds_tokens: ProcessInput(wb, token, None, True)
        return int(AlienSessionInfo['exitcode'])  # return the exit code of the latest command

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
    if not os.getenv('ALIENPY_NO_CWD_RESTORE'): RestoreCWD(wb)
    if os.getenv('ALIENPY_PROMPT_DATE'): AlienSessionInfo['show_date'] = True
    if os.getenv('ALIENPY_PROMPT_CWD'): AlienSessionInfo['show_lpwd'] = True
    while True:
        INPUT = ''
        prompt = f"AliEn[{AlienSessionInfo['user']}]:{AlienSessionInfo['currentdir']}"
        if AlienSessionInfo['show_date']: prompt = str(datetime.now().replace(microsecond=0).isoformat()) + " " + prompt
        if AlienSessionInfo['show_lpwd']: prompt = prompt + " " + "local:" + Path.cwd().as_posix()
        prompt = prompt + ' >'

        try:
            INPUT = input(prompt)
        except EOFError:
            exit_message()

        if not INPUT: continue

        # translate aliases for each command
        if aliases_dict:
            for alias in aliases_dict: INPUT = INPUT.replace(alias, aliases_dict[alias])

        # if shell command, just run it and return
        if INPUT.startswith('!'):
            runShellCMD(INPUT)
            continue

        cmds_tokens = INPUT.split(";")
        for token in cmds_tokens:
            # process the input and take care of pipe to shell
            input_list = []
            pipe_to_shell_cmd = ''
            if "|" in str(token):  # if we have pipe to shell command
                input_split_pipe = token.split('|', maxsplit=1)  # split in before pipe (jalien cmd) and after pipe (shell cmd)
                if not input_split_pipe[0]:
                    print("You might wanted to run a shell comand with ! not a pipe from AliEn command to shell", flush = True)
                    runShellCMD(input_split_pipe[1])
                    continue
                else:
                    input_list = input_split_pipe[0].split()  # the list of arguments sent to websocket
                    pipe_to_shell_cmd = input_split_pipe[1]  # the shell command
                    pipe_to_shell_cmd.encode('ascii', 'unicode-escape')
            else:
                input_list = token.split()

            if input_list[0] == 'prompt':
                if len(input_list) > 1 and input_list[1] == 'date':
                    AlienSessionInfo['show_date'] = (not AlienSessionInfo['show_date'])
                elif len(input_list) > 1 and input_list[1] == 'pwd':
                    AlienSessionInfo['show_lpwd'] = (not AlienSessionInfo['show_lpwd'])
                else:
                    print("Toggle the following in the command prompt : <date> for date information and <pwd> for local directory", flush = True)
                input_list.clear()
                continue

            if input_list[0] == 'exit' or input_list[0] == 'quit' or input_list[0] == 'logout': exit_message()
            ProcessInput(wb, ' '.join(input_list), pipe_to_shell_cmd)
            if input_list[0] == 'cd': StoreCWD()


def setup_logging():
    MSG_LVL = logging.INFO
    if DEBUG: MSG_LVL = logging.DEBUG
    line_fmt = '%(levelname)s:%(asctime)s %(message)s'
    log = logging.basicConfig(format = line_fmt, filename = DEBUG_FILE, filemode = 'w', level = MSG_LVL)
    logger_wb = logging.getLogger('websockets')
    logger_wb.setLevel(MSG_LVL)


def main():
    signal.signal(signal.SIGINT, signal_handler)
    global JSON_OUT, JSONRAW_OUT, ALIENPY_EXECUTABLE
    setup_logging()
    # at exit delete all temporary files
    atexit.register(cleanup_temp)

    ALIENPY_EXECUTABLE = os.path.realpath(sys.argv[0])
    exec_name = Path(sys.argv.pop(0)).name  # remove the name of the script(alien.py)

    if '-json' in sys.argv:
        sys.argv.remove('-json')
        JSON_OUT = True
    if '-jsonraw' in sys.argv:
        sys.argv.remove('-jsonraw')
        JSONRAW_OUT = True

    if len(sys.argv) > 0 and (sys.argv[0] == 'term' or sys.argv[0] == 'terminal' or sys.argv[0] == 'console'):
        import code
        jalien = AliEn()
        term = code.InteractiveConsole(locals = globals())
        term.push('jalien = AliEn()')
        banner = f'Welcome to the ALICE GRID - Python interpreter shell\nsupport mail: adrian.sevcenco@cern.ch\nAliEn seesion object is >jalien< ; try jalien.help()'
        exitmsg = f'Exiting..'
        term.interact(banner, exitmsg)
        os._exit(int(AlienSessionInfo['exitcode']))

    verb = exec_name.replace('alien_', '') if exec_name.startswith('alien_') else ''
    if verb: sys.argv.insert(0, verb)
    cmd_string = ' '.join(sys.argv)
    try:
        JAlien(cmd_string)
    except KeyboardInterrupt:
        print("Received keyboard intrerupt, exiting..")
        sys.exit(int(AlienSessionInfo['exitcode']))
    except Exception as e:
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


def cmd_token_info(): _cmd('token-info')


def cmd_token_destroy(): _cmd('token-destroy')


def cmd_token_init():
    print('INFO: JAliEn client automatically creates tokens, '
          'alien-token-init is deprecated')
    _cmd('token-init')


if __name__ == '__main__':
    main()
