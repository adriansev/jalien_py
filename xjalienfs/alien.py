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
from typing import NamedTuple
import OpenSSL
import shlex
import argparse
import tempfile
import time
from datetime import datetime
from pathlib import Path
from enum import Enum
from urllib.parse import urlparse
import socket
import threading
import asyncio
import async_stagger
import websockets
from websockets.extensions import permessage_deflate

if sys.version_info[0] != 3 or sys.version_info[1] < 6:
    print("This script requires a minimum of Python version 3.6", flush = True)
    sys.exit(1)


def signal_handler(sig, frame):
    """Generig signal handler: just print the signal and exit"""
    print(f'\nCought signal {signal.Signals(sig).name}, let\'s exit')
    os._exit(int(AlienSessionInfo['exitcode']))


def exit_message(exitcode: int = 0):
    print('Exit')
    sys.exit(exitcode)


def start_asyncio():
    """Initialization of main thread that will keep the asyncio loop"""
    signal.signal(signal.SIGINT, signal_handler)
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
        to_cancel = asyncio.tasks.all_tasks(loop)
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


try:
    import readline as rl
    has_readline = True
except ImportError:
    try:
        import gnureadline as rl
        has_readline = True
    except ImportError:
        has_readline = False

try:  # let's fail fast if the xrootd python bindings are not present
    from XRootD import client
    has_xrootd = True
except ImportError:
    has_xrootd = False


hasColor = False
if (hasattr(sys.stdout, "isatty") and sys.stdout.isatty()): hasColor = True

# environment debug variable
JSON_OUT = os.getenv('ALIENPY_JSON', '')
JSONRAW_OUT = os.getenv('ALIENPY_JSONRAW', '')
DEBUG = os.getenv('ALIENPY_DEBUG', '')
DEBUG_FILE = os.getenv('ALIENPY_DEBUG_FILE', Path.home().as_posix() + '/alien_py.log')
TIME_CONNECT = os.getenv('ALIENPY_TIMECONNECT', '')

# global session state;
AlienSessionInfo = {'alienHome': '', 'currentdir': '', 'commandlist': [], 'user': '', 'error': '', 'exitcode': 0, 'show_date': False, 'show_lpwd': False, 'templist': [], 'use_usercert': False, 'completer_cache': []}


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
    overwrite: bool
    batch: int
    sources: int
    chunks: int
    chunksize: int
    makedir: bool
    posc: bool
    hashtype: str
    streams: int


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
            name, var = line.partition("=")[::2]
            var = re.sub(r"^\"", '', str(var.strip()))
            var = re.sub(r"\"$", '', var)
            DICT_INFO[name.strip()] = var
    return DICT_INFO


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


def PrintDict(dict: dict) -> str:
    """Print a dictionary in a nice format"""
    print(json.dumps(dict, sort_keys=True, indent=4), flush = True)


def GetDict(answer: str, print_err: str = '') -> Union[None, dict]:
    """Convert server reply string to dict, update all relevant globals"""
    global AlienSessionInfo
    if not answer: return None
    ans_dict = json.loads(answer)
    AlienSessionInfo['currentdir'] = ans_dict["metadata"]["currentdir"]
    AlienSessionInfo['user'] = ans_dict["metadata"]["user"]
    AlienSessionInfo['error'] = str(ans_dict["metadata"]["error"])
    AlienSessionInfo['exitcode'] = int(ans_dict["metadata"]["exitcode"])
    if int(AlienSessionInfo['exitcode']) != 0:
        err_msg = AlienSessionInfo['error']
        if 'log' in print_err:
            logging.info(f"{err_msg}")
        if 'debug' in print_err:
            logging.debug(f"{err_msg}")
        if 'print' in print_err:
            print(f'{err_msg}', file=sys.stderr, flush = True)
    return ans_dict


def xrdcp_help():
    print(f'''at least 2 arguments are needed : src dst
the command is of the form of (with the strict order of arguments):
cp args src dst
where src|dst are local files if prefixed with file:// or grid files otherwise
after each src,dst can be added comma separated specifiers in the form of: @disk:N,SE1,SE2,!SE3
where disk selects the number of replicas and the following specifiers add (or remove) storage endpoints from the received list
args are the following :
-h : print help
-f : replace any existing output file
-P : enable persist on successful close semantic
-y <nr_sources> : use up to the number of sources specified in parallel
-S <aditional TPC streams> : uses num additional parallel streams to do the transfer. The maximum value is 15. The default is 0 (i.e., use only the main stream).
-chunks <nr chunks> : number of chunks that should be requested in parallel
-chunksz <bytes> : chunk size (bytes)
-T <nr_copy_jobs> : number of parralel copy jobs from a set (for recursive copy)

for the recursive copy of directories the following options (of the find command) can be used:
-select <pattern> : select only these files to be copied; {PrintColor(COLORS.BIGreen)}N.B. this is a REGEX applied to full path!!!{PrintColor(COLORS.ColorReset)} defaults to all ".*"
-select all_<extension> : alias for selection of all files the have the specified extension e.g. all_root would select all files that have .root extension
-name <pattern> : select only these files to be copied; {PrintColor(COLORS.BIGreen)}N.B. this is a REGEX applied to a directory or file name!!!{PrintColor(COLORS.ColorReset)} defaults to all ".*"
-name all_<extension> : alias for selection of all files the have the specified extension e.g. all_root would select all files that have .root extension
-parent <parent depth> : in destination use this <parent depth> to add to destination ; defaults to 0
-a : copy also the hidden files .* (for recursive copy)
-j <queue_id> : select only the files created by the job with <queue_id>  (for recursive copy)
-l <count> : copy only <count> nr of files (for recursive copy)
-o <offset> : skip first <offset> files found in the src directory (for recursive copy)
''')


def getEnvelope(wb: websockets.client.WebSocketClientProtocol, lfn_list: list, specs: Union[None, list] = None, isWrite: bool = False) -> list:
    """Query central services for the access envelope of the list of lfns, it will return a list of lfn:server answer with envelope pairs"""
    if not wb: return
    access_list = []
    if not lfn_list: return access_list
    if not specs: specs = []
    access_type = 'read'
    if isWrite: access_type = 'write'
    for lfn in lfn_list:
        get_envelope_arg_list = [access_type, lfn]
        if not DEBUG: get_envelope_arg_list.insert(0, '-nomsg')
        if specs: get_envelope_arg_list.append(str(",".join(specs)))
        result = SendMsg(wb, 'access', get_envelope_arg_list)
        access_list.append({"lfn": lfn, "answer": result})
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
    exp_path = exp_path.replace("file://", "")  # there are only 2 cases : either file:// and the remainder is the path
    exp_path = exp_path.replace("file:", "")  # or just file: ; the unspoken contract is that no one will do file:/ + /full_local_path
    exp_path = re.sub(r"^\~\/*", Path.home().as_posix() + "/", exp_path)
    exp_path = re.sub(r"^\/*\.{2}[\/\s]", Path.cwd().parents[0].as_posix() + "/", exp_path)
    exp_path = re.sub(r"^\/*\.{1}[\/\s]", Path.cwd().as_posix() + "/", exp_path)
    if not exp_path.startswith('/'): exp_path = Path.cwd().as_posix() + "/" + exp_path
    exp_path = re.sub(r"\/{2,}", "/", exp_path)
    return exp_path


def expand_path_grid(path: str) -> str:
    """Given a string representing a GRID file (lfn), return a full path after interpretation of AliEn HOME location, current directory, . and .. and making sure there are only single /"""
    exp_path = path
    exp_path = re.sub(r"^\/*\%ALIEN[\/\s]*", AlienSessionInfo['alienHome'], exp_path)  # replace %ALIEN token with user grid home directory
    exp_path = re.sub(r"^\.{2}\/*$", Path(AlienSessionInfo['currentdir']).parents[0].as_posix(), exp_path)  # single .. to be replaced with parent of current dir
    if re.search(r"^\/*.*\.{2}\/*\/*", exp_path): exp_path = exp_path.replace("../", "")  # if .. is a within path just remove it
    exp_path = re.sub(r"^\.{1}\/*$", AlienSessionInfo['currentdir'], exp_path)
    if not exp_path.startswith('/'): exp_path = AlienSessionInfo['currentdir'] + "/" + exp_path  # if not full path add current directory to the referenced path
    exp_path = re.sub(r"\/{2,}", "/", exp_path)
    return exp_path


def pathtype_grid(wb: websockets.client.WebSocketClientProtocol, path: str) -> str:
    """Query if a lfn is a file or directory, return f, d or empty"""
    if not wb: return ''
    if not path: return ''
    result = SendMsg(wb, 'stat', ['-nomsg', path])
    json_dict = GetDict(result, print_err = 'debug')
    if int(AlienSessionInfo['exitcode']) != 0: return ''
    return str(json_dict['results'][0]["type"])


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


def ProcessXrootdCp(wb: websockets.client.WebSocketClientProtocol, xrd_copy_command: Union[None, list] = None) -> int:
    """XRootD cp function :: process list of arguments for a xrootd copy command"""
    global AlienSessionInfo
    if not wb: return int(107)  # ENOTCONN /* Transport endpoint is not connected */
    if (not xrd_copy_command) or len(xrd_copy_command) < 2 or xrd_copy_command == '-h':
        xrdcp_help()
        return int(64)  # EX_USAGE /* command line usage error */

    if not AlienSessionInfo:
        print('Session information like home and current directories needed', flush = True)
        return int(126)  # ENOKEY /* Required key not available */

    if not has_xrootd:
        print('python XRootD module cannot be found, the copy process cannot continue')
        return int(1)

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

    isSrcLocal = bool(False)
    isDstLocal = bool(False)
    isSrcDir = bool(False)
    isDstDir = bool(False)
    isDownload = bool(True)
    file_name = ''

    cwd_grid_path = Path(AlienSessionInfo['currentdir'])
    home_grid_path = Path(AlienSessionInfo['alienHome'])

    # xrdcp parameters (used by ALICE tests)
    # http://xrootd.org/doc/man/xrdcp.1.html
    # xrootd defaults https://github.com/xrootd/xrootd/blob/master/src/XrdCl/XrdClConstants.hh

    # Override the application name reported to the server.
    os.environ["XRD_APPNAME"] = "alien.py"

    # Default value for the time after which an error is declared if it was impossible to get a response to a request.
    if not os.getenv('XRD_REQUESTTIMEOUT'): os.environ["XRD_REQUESTTIMEOUT"] = "60"

    # A time window for the connection establishment. A connection failure is declared if the connection is not established within the time window.
    if not os.getenv('XRD_CONNECTIONWINDOW'): os.environ["XRD_CONNECTIONWINDOW"] = "15"

    # Number of connection attempts that should be made (number of available connection windows) before declaring a permanent failure.
    if not os.getenv('XRD_CONNECTIONRETRY'): os.environ["XRD_CONNECTIONRETRY"] = "4"

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

    # if '-tpc' in xrd_copy_command:
        # tpc = str('first')
        # xrd_copy_command.remove('-tpc')

    if '-y' in xrd_copy_command:
        y_idx = xrd_copy_command.index('-y')
        print("Warning! multiple source usage is known to break the files stored in zip files, so it will be ignored", flush = True)
        sources = int(xrd_copy_command.pop(y_idx + 1))
        xrd_copy_command.pop(y_idx + 1)
        xrd_copy_command.pop(y_idx)

    if '-S' in xrd_copy_command:
        s_idx = xrd_copy_command.index('-S')
        streams = int(xrd_copy_command.pop(s_idx + 1))
        xrd_copy_command.pop(y_idx)
    elif os.getenv('XRD_SUBSTREAMSPERCHANNEL'):
        streams = int(os.getenv('XRD_SUBSTREAMSPERCHANNEL'))

    batch_user_setup = False
    if '-T' in xrd_copy_command:
        batch_idx = xrd_copy_command.index('-T')
        batch = int(xrd_copy_command.pop(batch_idx + 1))
        batch_user_setup = True
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

    pattern = '.*'  # default regex selection for find
    if '-select' in xrd_copy_command and '-name' in xrd_copy_command:
        print("Only one rule of selection can be used, either -select (full path match) or -name (match on file name)")
        return int(22)  # EINVAL /* Invalid argument */

    if '-select' in xrd_copy_command:
        select_idx = xrd_copy_command.index('-select')
        pattern = xrd_copy_command.pop(select_idx + 1)
        xrd_copy_command.pop(select_idx)

    if '-name' in xrd_copy_command:
        name_idx = xrd_copy_command.index('-name')
        pattern = xrd_copy_command.pop(name_idx + 1)
        xrd_copy_command.pop(name_idx)
        if pattern.startswith('all_'):
            pattern = '\\/*.*\\.' + pattern.replace('all_', '', 1) + '$'
        else:
            pattern = '.*\\/' + pattern + '$'

    if ('-select' in xrd_copy_command or '-name' in xrd_copy_command) and pattern.startswith('all_'):
        pattern = '.*\\.' + pattern.replace('all_', '', 1) + '$'

    # list of src files and coresponding dst names
    src_filelist = []
    dst_filelist = []

    arg_source = xrd_copy_command[-2]
    arg_target = xrd_copy_command[-1]

    # clean up and prepare the paths to be used in the xrdcp command
    src = None
    src_type = None
    src_specs_remotes = None  # let's record specifications like disk=3,SE1,!SE2
    if arg_source.startswith('file:'):  # second to last argument (should be the source)
        isSrcLocal = True
        isDownload = False
        src = expand_path_local(arg_source)
        src_type = pathtype_local(src)
        if src_type == 'd': isSrcDir = bool(True)
    else:
        if arg_source.startswith('alien://'): arg_source = arg_source.replace("alien://", "")
        src_specs_remotes = arg_source.split("@", maxsplit = 1)  # NO comma allowed in grid names (hopefully)
        src = src_specs_remotes.pop(0)  # first item is the file path, let's remove it; it remains disk specifications
        src = expand_path_grid(src)
        src_type = pathtype_grid(wb, src)
        if not src_type:
            print("Could not determine the type of src argument.. is it missing?", file=sys.stderr, flush = True)
            return int(42)  # ENOMSG /* No message of desired type */
        if src_type == 'd': isSrcDir = bool(True)

    # For all download use a default of 8 simultaneous downloads;
    # the parralel uploads does not work yet because of return confirmations needed to commit writes to catalog
    if isDownload and not batch_user_setup: batch = 8

    dst = None
    dst_type = None
    dst_specs_remotes = None  # let's record specifications like disk=3,SE1,!SE2
    if arg_target.startswith('file:'):  # last argument (should be the destination)
        isDstLocal = True
        dst = expand_path_local(arg_target)
        dst_type = pathtype_local(dst)
        if dst_type == 'd': isDstDir = bool(True)
    else:
        isDownload = False
        if arg_target.startswith('alien://'): arg_target = arg_target.replace("alien://", "")
        dst_specs_remotes = arg_target.split("@", maxsplit = 1)  # NO comma allowed in grid names (hopefully)
        dst = dst_specs_remotes.pop(0)  # first item is the file path, let's remove it; it remains disk specifications
        dst = expand_path_grid(dst)
        dst_type = pathtype_grid(wb, dst)
        if not dst_type and src_type == 'f':
            # the destination is not present yet and because src is file then dst must be also file
            base_dir = Path(dst).parent.as_posix()
            result = SendMsg_str(wb, 'mkdir -p ' + base_dir)
            json_dict = json.loads(result)
            if json_dict["metadata"]["exitcode"] != '0':
                err = json_dict["metadata"]["error"]
                print(f"Could not create directory : {base_dir} !! --> {err}", file=sys.stderr, flush = True)
        if dst_type == 'd': isDstDir = bool(True)

    if isSrcLocal == isDstLocal:
        print("The operands cannot specify different source types: one must be local and one grid", file=sys.stderr, flush = True)
        return int(22)  # EINVAL /* Invalid argument */

    # if src is directory, then create list of files coresponding with options
    if isDownload:
        isWrite = bool(False)
        specs = src_specs_remotes
        if isSrcDir:  # src is GRID, we are DOWNLOADING from GRID directory
            find_args.extend(['-r', '-a', '-s', src, pattern])
            if not DEBUG: find_args.insert(0, '-nomsg')
            result = SendMsg(wb, 'find', find_args)
            src_list_files_dict = json.loads(result)
            for file in src_list_files_dict['results']:
                src_filelist.append(file['lfn'])
                src_path = Path(src)
                if parent > (len(src_path.parents) - 1): parent = len(src_path.parents) - 1  # make sure maximum parent var point to first dir in path
                src_root = src_path.parents[parent].as_posix()
                if src_root != '/':
                    file_relative_name = file['lfn'].replace(src_root, '')
                else:
                    file_relative_name = file['lfn']
                dst_file = dst + "/" + file_relative_name
                dst_file = re.sub(r"\/{2,}", "/", dst_file)
                dst_filelist.append(dst_file)
        else:
            src_filelist.append(src)
            if dst.endswith("/"): dst = dst[:-1] + setDst(src, parent)
            dst_filelist.append(dst)
    else:  # it is upload
        isWrite = bool(True)
        specs = dst_specs_remotes
        if isSrcDir:  # src is LOCAL, we are UPLOADING from LOCAL directory
            regex = re.compile(pattern)
            for root, dirs, files in os.walk(src):
                for file in files:
                    filepath = os.path.join(root, file)
                    if regex.search(filepath):
                        src_filelist.append(filepath)
                        src_path = Path(src)
                        if parent > (len(src_path.parents) - 1): parent = len(src_path.parents) - 1  # make sure maximum parent var point to first dir in path
                        src_root = src_path.parents[parent].as_posix()
                        if src_root != '/':
                            file_relative_name = filepath.replace(src_root, '')
                        else:
                            file_relative_name = filepath
                        dst_file = dst[:-1] + "/" + file_relative_name
                        dst_file = re.sub(r"\/{2,}", "/", dst_file)
                        dst_filelist.append(dst_file)
        else:
            src_filelist.append(src)
            if dst.endswith("/"): dst = dst[:-1] + setDst(src, parent)
            dst_filelist.append(dst)

    if DEBUG:
        logging.debug("We are going to copy these files:")
        for src_dbg, dst_dbg in zip(src_filelist, dst_filelist):
            logging.debug(f"src: {src_dbg}\ndst: {dst_dbg}\n")

    lfn_list = src_filelist if isDownload else dst_filelist
    envelope_list = getEnvelope(wb, lfn_list, specs, isWrite)

    # print errors
    errors_idx = []
    for item_idx, item in enumerate(envelope_list):
        lfn = item["lfn"]
        result = item["answer"]
        access_request = json.loads(result)
        error = access_request["metadata"]["error"]
        if error:
            errors_idx.append(item_idx)
            print(f"lfn: {lfn} --> {error}", flush = True)
        if DEBUG:
            logging.debug(f"lfn: {lfn}")
            logging.debug(json.dumps(access_request, sort_keys=True, indent=4))

    for i in reversed(errors_idx): envelope_list.pop(i)  # remove from list invalid lfns
    if not envelope_list:
        print("No lfns in envelope list after removing the invalid ones", file=sys.stderr)
        return int(2)  # ENOENT /* No such file or directory */

    url_list_src = []
    url_list_dst = []
    if isDownload:
        for item_idx, item in enumerate(envelope_list):
            lfn = item["lfn"]
            result = item["answer"]
            access_request = json.loads(result)
            if not access_request['results']: continue

            dst = dst_filelist[item_idx]
            size_4meta = access_request['results'][0]['size']  # size SHOULD be the same for all replicas
            md5_4meta = access_request['results'][0]['md5']  # the md5 hash SHOULD be the same for all replicas

            # ALWAYS check if exist and valid. There is no scenario where the download is required even if the md5sums match
            if fileIsValid(dst, size_4meta, md5_4meta): continue

            # multiple replicas are downloaded to a single file
            is_zip = False
            file_in_zip = ''
            url_list_4meta = []
            for server in access_request['results']:
                url_components = server['url'].rsplit('#', maxsplit = 1)
                if len(url_components) > 1:
                    is_zip = True
                    file_in_zip = url_components[1]
                complete_url = url_components[0] + '?authz=' + server['envelope']
                url_list_4meta.append(complete_url)

            url_list_dst.append({"url": dst})  # the local file destination
            src = src_filelist[item_idx]
            meta_fn = tmpdir + "/" + src.replace("/", "%%") + ".meta4"
            create_metafile(meta_fn, lfn, dst, size_4meta, md5_4meta, url_list_4meta)
            if is_zip:
                download_link = meta_fn + '?xrdcl.unzip=' + file_in_zip
            else:
                download_link = meta_fn
            url_list_src.append({"url": download_link})
    else:
        for item_idx, item in enumerate(envelope_list):
            src = src_filelist[item_idx]
            lfn = item["lfn"]
            result = item["answer"]
            access_request = json.loads(result)
            for server in access_request['results']:
                if not server: continue
                complete_url = server['url'] + "?" + "authz=" + server['envelope']
                url_list_dst.append({"url": complete_url})
                url_list_src.append({"url": src})

    if not (url_list_src or url_list_dst):
        if DEBUG: logging.debug("copy src/dst lists are empty, no copy process to be started")
        return int(0)  # no error to be reported as nothing happened

    if DEBUG:
        logging.debug("List of files:")
        for src_dbg, dst_dbg in zip(url_list_src, url_list_dst):
            logging.debug("src:{0}\ndst:{1}\n".format(src_dbg['url'], dst_dbg['url']))

    my_cp_args = XrdCpArgs(overwrite, batch, sources, chunks, chunksize, makedir, posc, hashtype, streams)
    # defer the list of url and files to xrootd processing - actual XRootD copy takes place
    token_list_upload_ok = XrdCopy(url_list_src, url_list_dst, isDownload, my_cp_args)

    if (not isDownload) and token_list_upload_ok:  # it was an upload job that had succesfull uploads
        for item_idx, item in enumerate(envelope_list):
            result = item["answer"]
            access_request = json.loads(result)
            src = src_filelist[item_idx]
            dst = dst_filelist[item_idx]
            # common values for all commit commands
            size = os.path.getsize(src)
            md5sum = md5(src)
            perm = '644'
            expire = '0'
            for token in token_list_upload_ok:  # for each succesful token
                for server in access_request['results']:  # go over all received servers
                    if token in server['envelope']:  # for the server that have the succesful uploaded token
                        exitcode = commit(wb, token, int(size), dst, perm, expire, server['url'], server['se'], server['guid'], md5sum)

    # hard to return a single exitcode for a copy process optionally spanning multiple files
    # we'll return SUCCESS if at least one lfn is confirmed, FAIL if not lfns is confirmed
    return int(0) if token_list_upload_ok else int(1)


def commit(wb: websockets.client.WebSocketClientProtocol, token: str, size: int, lfn: str, perm: str, expire: str, pfn: str, se: str, guid: str, md5sum: str) -> int:
    if not wb: return int(1)
    arg_list = [token, int(size), lfn, perm, expire, pfn, se, guid, md5sum]
    commit_results = SendMsg(wb, 'commit', arg_list)
    result_dict = GetDict(commit_results, print_err = 'debug')
    if DEBUG: logging.debug(json.dumps(result_dict, sort_keys=True, indent=4))
    return int(AlienSessionInfo['exitcode'])


def GetHumanReadable(size, precision = 2):
    suffixes = ['B', 'KiB', 'MiB']
    suffixIndex = 0
    while size > 1024 and suffixIndex < 4:
        suffixIndex += 1  # increment the index of the suffix
        size = size/1024.0  # apply the division
    return "%.*f %s" % (precision, size, suffixes[suffixIndex])


if has_xrootd:
    class MyCopyProgressHandler(client.utils.CopyProgressHandler):
        def __init__(self):
            self.isDownload = bool(True)
            self.token_list_upload_ok = []  # record the tokens of succesfully uploaded files. needed for commit to catalogue
            self.jobs = int(0)
            self.job_list = []
            self.sigint = False
            signal.signal(signal.SIGINT, self.catch)
            signal.siginterrupt(signal.SIGINT, False)

        def catch(self, signum, frame):
            self.sigint = True

        def begin(self, jobId, total, source, target):
            timestamp_begin = datetime.now().timestamp()
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

            speed_str = '0 B/s'
            if results['status'].ok:
                deltaT = datetime.now().timestamp() - float(self.job_list[jobId - 1]['start'])
                speed = float(self.job_list[jobId - 1]['bytes_total'])/deltaT
                speed_str = str(GetHumanReadable(speed)) + '/s'
                if self.isDownload:
                    meta_file = urlparse(str(self.job_list[jobId - 1]['src'])).path
                    import xml.dom.minidom
                    content = xml.dom.minidom.parse(meta_file)
                    lfn = content.getElementsByTagName('lfn')[0].firstChild.nodeValue
                    os.remove(meta_file)  # remove the created metalink
                    self.token_list_upload_ok.append(str(lfn))  # append on output list the downloaded lfn to be checked later
                else:  # isUpload
                    link = urlparse(str(self.job_list[jobId - 1]['tgt']))
                    token = next((param for param in str.split(link.query, '&') if 'authz=' in param), None).replace('authz=', '')  # extract the token from url
                    self.token_list_upload_ok.append(str(token))
            print("jobID: {0}/{1} >>> ERRNO/CODE/XRDSTAT {2}/{3}/{4} >>> STATUS {5} >>> SPEED {6} MESSAGE: {7}".format(jobId, self.jobs, results_errno, results_code, results_status, status, speed_str, results_message), flush = True)

        def update(self, jobId, processed, total):
            self.job_list[jobId - 1]['bytes_processed'] = processed
            self.job_list[jobId - 1]['bytes_total'] = total

        def should_cancel(self, jobId):
            return self.sigint


def XrdCopy(src: list, dst: list, isDownload: bool, xrd_cp_args: XrdCpArgs) -> list:
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

    process = client.CopyProcess()
    handler = MyCopyProgressHandler()
    process.parallel(int(batch))
    if streams > 0:
        if streams > 15: streams = 15
        client.EnvPutInt('SubStreamsPerChannel', streams)

    handler.isDownload = isDownload
    for url_src, url_dst in zip(src, dst):
        if DEBUG: logging.debug("\nadd copy job with\nsrc: {0}\ndst: {1}\n".format(url_src['url'], url_dst['url']))
        process.add_job(url_src["url"], url_dst["url"],
                        sourcelimit = sources,
                        force = overwrite,
                        posc = posc,
                        mkdir = makedir,
                        chunksize = chunksize,
                        parallelchunks = chunks
                        )
    process.prepare()
    process.run(handler)
    return handler.token_list_upload_ok  # for upload jobs we must return the list of token for succesful uploads


def make_tmp_fn(lfn: str = '') -> str:
    """make temporary file path string either random or based on grid lfn string"""
    ext = '_' + str(os.getuid()) + '.alienpy_tmp'
    if not lfn:
        return os.getenv('TMPDIR', '/tmp') + '/' + str(uuid.uuid4()) + ext
    return os.getenv('TMPDIR', '/tmp') + '/' + lfn.replace("/", '%%') + ext


async def download_tmp(wb: websockets.client.WebSocketClientProtocol, lfn: str) -> str:
    """Download a lfn to a temporary file, it will return the file path of temporary"""
    tmpfile = make_tmp_fn(expand_path_grid(lfn))
    copycmd = "-f " + lfn + " " + 'file://' + tmpfile
    result = ProcessXrootdCp(wb, copycmd.split())
    if result == 0:
        return tmpfile
    else:
        return ''


async def upload_tmp(wb: websockets.client.WebSocketClientProtocol, temp_file_name: str, upload_specs: str = '') -> str:
    """Upload a temporary file: the original lfn will be renamed and the new file will be uploaded with the oirginal lfn"""
    # lets recover the lfn from temp file name
    lfn = temp_file_name.replace('_' + str(os.getuid()) + '.alienpy_tmp', '')
    lfn = lfn.replace(os.getenv('TMPDIR', '/tmp') + '/', '')
    lfn = lfn.replace("%%", "/")

    envelope_list = getEnvelope(wb, [lfn], [upload_specs], isWrite = True)
    result = envelope_list[0]["answer"]
    access_request = json.loads(result)
    replicas = access_request["results"][0]["nSEs"]

    # let's create a backup of old lfn
    lfn_backup = lfn + "~"
    result = SendMsg(wb, 'rm', ['-f', lfn_backup])
    result = SendMsg(wb, 'mv', [lfn, lfn_backup])
    json_dict = json.loads(result)
    if json_dict["metadata"]["exitcode"] != '0':
        print(f"Could not create backup of lfn : {lfn}", file=sys.stderr, flush = True)
        return ''

    if "disk:" not in upload_specs:
        upload_specs = "disk:" + replicas

    if upload_specs: upload_specs = "@" + upload_specs
    copycmd = "-f " + 'file://' + temp_file_name + " " + lfn + upload_specs
    list_upload = ProcessXrootdCp(wb, copycmd.split())
    if list_upload == 0:
        return lfn
    else:
        result = SendMsg(wb, 'mv', [lfn_backup, lfn])
        return ''


def DO_cat(wb: websockets.client.WebSocketClientProtocol, lfn: str):
    """cat lfn :: download lfn as a temporary file and cat"""
    lfn_path = expand_path_grid(lfn)
    tmp = make_tmp_fn(lfn_path)
    if tmp in AlienSessionInfo['templist']:
        runShellCMD('cat ' + tmp)
    else:
        tmp = download_tmp(wb, lfn)
        if tmp:
            AlienSessionInfo['templist'].append(tmp)
            runShellCMD('cat ' + tmp)


def DO_less(wb: websockets.client.WebSocketClientProtocol, lfn: str):
    """cat lfn :: download lfn as a temporary file and less"""
    lfn_path = expand_path_grid(lfn)
    tmp = make_tmp_fn(lfn_path)
    if tmp in AlienSessionInfo['templist']:
        runShellCMD('less ' + tmp)
    else:
        tmp = download_tmp(wb, lfn)
        if tmp:
            AlienSessionInfo['templist'].append(tmp)
            runShellCMD('less ' + tmp)


def DO_more(wb: websockets.client.WebSocketClientProtocol, lfn: str):
    """cat lfn :: download lfn as a temporary file and more"""
    lfn_path = expand_path_grid(lfn)
    tmp = make_tmp_fn(lfn_path)
    if tmp in AlienSessionInfo['templist']:
        runShellCMD('more ' + tmp)
    else:
        tmp = download_tmp(wb, lfn)
        if tmp:
            AlienSessionInfo['templist'].append(tmp)
            runShellCMD('more ' + tmp)


def DO_quota(wb: websockets.client.WebSocketClientProtocol, quota_args: Union[None, list] = None):
    """quota : put togheter both job and file quota"""
    if not quota_args: quota_args = []
    if len(quota_args) > 0:
        if quota_args[0] != "set":  # we asume that if 'set' is not used then the argument is a username
            user = quota_args[0]
            jquota_cmd = CreateJsonCommand_str('jquota -nomsg list ' + user)
            fquota_cmd = CreateJsonCommand_str('fquota -nomsg list ' + user)
        else:
            print('set functionality not implemented yet')
    else:
        user = AlienSessionInfo['user']
        jquota_cmd = CreateJsonCommand_str('jquota -nomsg list ' + user)
        fquota_cmd = CreateJsonCommand_str('fquota -nomsg list ' + user)

    jquota = SendMsg_json(jquota_cmd)
    jquota_dict = json.loads(jquota)

    fquota = SendMsg_json(fquota_cmd)
    fquota_dict = json.loads(fquota)

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


def DO_edit(wb: websockets.client.WebSocketClientProtocol, lfn: str, editor: str = 'mcedit'):
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
    if tmp:
        md5_begin = md5(tmp)
        runShellCMD(editor + tmp, False)
        md5_end = md5(tmp)
        if md5_begin != md5_end: upload_tmp(wb, tmp, specs)
        # clean up the temporary file not matter if the upload was succesful or not
        os.remove(tmp)


def runShellCMD(INPUT: str = '', captureout: bool = True):
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


def CreateJsonCommand(cmd: str, options: Union[None, list] = None) -> str:
    """Return a json with command and argument list"""
    if not options: options = []
    jsoncmd = {"command": cmd, "options": options}
    if DEBUG: logging.debug(f'send json: {jsoncmd}')
    return json.dumps(jsoncmd)


def CreateJsonCommand_str(cmd: str) -> str:
    """Return a json by spliting the input string in first element(command) and the rest asa a list of arguments"""
    args = cmd.split(" ")
    command = args.pop(0)
    return CreateJsonCommand(command, args)


def get_help(wb, cmd):
    """Return the help option even for client-side commands"""
    ProcessInput(wb, cmd + ' -h')


def lfn_list(wb: websockets.client.WebSocketClientProtocol, lfn: str = ''):
    """Completer function : for a given lfn return all options for latest leaf"""
    if not wb: return
    if not lfn: lfn = AlienSessionInfo['currentdir']
    lfn = expand_path_grid(lfn)
    ls_args = ['-nokeys', '-F']
    lfn_list = []
    if lfn.endswith('/'):
        result = SendMsg(wb, 'ls', ls_args + [lfn])
        result_dict = json.loads(result)
        lfn_list = list(item['message'] for item in result_dict['results'])
    else:
        lfn_path = Path(lfn)
        base_dir = lfn_path.parent.as_posix()
        name = lfn_path.name
        result = SendMsg(wb, 'ls', ls_args + [base_dir])
        result_dict = json.loads(result)
        listing = list(item['message'] for item in result_dict['results'])
        lfn_list = [base_dir + '/' + item if base_dir != '/' else base_dir + item for item in listing if item.startswith(name)]
    return lfn_list


@syncify
async def IsWbConnected(wb: websockets.client.WebSocketClientProtocol) -> bool:
    """Check if websocket is connected with the protocol ping/pong"""
    try:
        pong_waiter = await wb.ping()
    except Exception as e:
        logging.debug(f"WB ping failed!!!")
        logging.exception(e)
        return False
    try:
        await pong_waiter
    except Exception as e:
        logging.debug(f"WB pong failed!!!")
        logging.exception(e)
        return False
    return True


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


@syncify
async def SendMsg_json(wb: websockets.client.WebSocketClientProtocol, json: str) -> str:
    """Send a json message to the specified websocket; it will return the server answer"""
    if not wb:
        logging.info(f"SendMsg_json:: websocket not initialized")
        return ''
    if not json:
        logging.info(f"SendMsg_json:: json message is empty or invalid")
        return ''
    if DEBUG:
        logging.debug(f"SEND COMMAND: {json}")
        init_begin = datetime.now().timestamp()
        logging.debug(f"COMMAND TIMESTAMP BEGIN: {init_begin}")

    try:
        await wb.send(json)
    except Exception as e:
        logging.exception(e)
        logging.debug("SendMsg_json:: error sending the message")
        print("SendMsg_json:: error sending the message", file=sys.stderr, flush = True)
        wb_status = IsWbConnected(wb)
        if not wb_status: wb = InitConnection()
        return ''

    try:
        result = await wb.recv()
    except Exception as e:
        logging.exception(e)
        logging.debug("SendMsg_json:: Websocket connection was closed while waiting the answer. Either network problem or ALIENPY_TIMEOUT should be set >20s")
        print("SendMsg_json:: Websocket connection was closed while waiting the answer. Either network problem or ALIENPY_TIMEOUT should be set >20s", file=sys.stderr, flush = True)
        wb_status = IsWbConnected(wb)
        if not wb_status: wb = InitConnection()
        return ''
    if DEBUG:
        init_end = datetime.now().timestamp()
        init_delta = (init_end - init_begin) * 1000
        logging.debug(f"COMMAND TIMESTAMP END: {init_end}")
        logging.debug(f"COMMAND SEND/RECV ROUNDTRIP: {init_delta:.3f} ms")
    return result


def SendMsg(wb: websockets.client.WebSocketClientProtocol, cmd: str, args: Union[None, list] = None) -> str:
    """Send a cmd/argument list message to the specified websocket; it will return the server answer"""
    if not args: args = []
    return SendMsg_json(wb, CreateJsonCommand(cmd, args))


def SendMsg_str(wb: websockets.client.WebSocketClientProtocol, cmd_line: str) -> str:
    """Send a cmd/argument list message to the specified websocket; it will return the server answer"""
    return SendMsg_json(wb, CreateJsonCommand_str(cmd_line))


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
    if (time_remaining > 300):
        return True
    else:
        return False


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


def create_ssl_context(use_usercert: bool = False) -> ssl.SSLContext:
    global AlienSessionInfo
    """Create SSL context using either the default names for user certificate and token certificate or X509_USER_{CERT,KEY} JALIEN_TOKEN_{CERT,KEY} environment variables"""
    # SSL SETTINGS
    usercert = os.getenv('X509_USER_CERT', Path.home().as_posix() + '/.globus' + '/usercert.pem')
    userkey = os.getenv('X509_USER_KEY', Path.home().as_posix() + '/.globus' + '/userkey.pem')
    tokencert_file = os.getenv('TMPDIR', '/tmp') + '/tokencert_' + str(os.getuid()) + '.pem'
    tokencert = os.getenv('JALIEN_TOKEN_CERT', tokencert_file)
    tokenkey_file = os.getenv('TMPDIR', '/tmp') + '/tokenkey_' + str(os.getuid()) + '.pem'
    tokenkey = os.getenv('JALIEN_TOKEN_KEY', tokenkey_file)
    system_ca_path = '/etc/grid-security/certificates'
    alice_cvmfs_ca_path = '/cvmfs/alice.cern.ch/etc/grid-security/certificates'
    x509dir = os.getenv('X509_CERT_DIR') if os.path.isdir(str(os.getenv('X509_CERT_DIR'))) else ''
    x509file = os.getenv('X509_CERT_FILE') if os.path.isfile(str(os.getenv('X509_CERT_FILE'))) else ''

    capath_default = ''
    if x509dir:
        capath_default = x509dir
    elif os.path.exists(alice_cvmfs_ca_path):
        capath_default = alice_cvmfs_ca_path
    else:
        if os.path.isdir(system_ca_path): capath_default = system_ca_path

    if not capath_default and not x509file:
        msg = "Not CA location or files specified!!! Connection will not be possible!!"
        print(msg, file=sys.stderr, flush = True)
        logging.info(msg)
        sys.exit(1)
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

    if IsValidCert(tokencert):
        cert = tokencert
        key  = tokenkey
        AlienSessionInfo['use_usercert'] = False
    else:
        if not (os.path.exists(usercert) and os.path.exists(userkey)):
            msg = f"User certificate files NOT FOUND!!! Connection will not be possible!!"
            print(msg, file=sys.stderr, flush = True)
            logging.info(msg)
            sys.exit(1)
        cert = usercert
        key  = userkey
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
                logging.debug(f"TCP SOCKET BEGIN: {init_begin}")
            if os.getenv('ALIENPY_NO_STAGGER'):
                socket_endpoint = socket.create_connection((host, int(port)))
            else:
                socket_endpoint = await async_stagger.create_connected_sock(host, int(port), async_dns=True, resolution_delay=0.050, detailed_exceptions=True)
            if DEBUG:
                init_end = datetime.now().timestamp()
                init_delta = (init_end - init_begin) * 1000
                logging.debug(f"TCP SOCKET END: {init_end}")
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
                if DEBUG:
                    init_begin = datetime.now().timestamp()
                    logging.debug(f"WEBSOCKET BEGIN: {init_begin}")

                deflateFact = permessage_deflate.ClientPerMessageDeflateFactory(server_max_window_bits=14, client_max_window_bits=14, compress_settings={'memLevel': 6},)
                wb = await websockets.connect(fHostWSUrl, sock = socket_endpoint, server_hostname = host, ssl = ctx, extensions=[deflateFact, ],
                                              max_queue=QUEUE_SIZE, max_size=MSG_SIZE, ping_interval=PING_INTERVAL, ping_timeout=PING_TIMEOUT, close_timeout=CLOSE_TIMEOUT)
                if DEBUG:
                    init_end = datetime.now().timestamp()
                    init_delta = (init_end - init_begin) * 1000
                    logging.debug(f"WEBSOCKET END: {init_end}")
                    logging.debug(f"WEBSOCKET DELTA: {init_delta:.3f} ms")
            except Exception as e:
                logging.debug(traceback.format_exc())
                logging.error(f"Could NOT establish websocket connection to {socket_endpoint_addr}:{socket_endpoint_port}")
                return None
        if wb: logging.info(f"CONNECTED: {wb.remote_address[0]}:{wb.remote_address[1]}")
    return wb


@syncify
async def msg_proxy(websocket, path, use_usercert = False):
    # start client to upstream
    wb_jalien = AlienConnect(None, use_usercert)
    local_query = await websocket.recv()
    jalien_answer = await SendMsg_json(wb_jalien, local_query)
    await websocket.send(jalien_answer)


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
    tokencert = os.getenv('JALIEN_TOKEN_CERT', os.getenv('TMPDIR', '/tmp') + '/tokencert_' + str(os.getuid()) + '.pem')
    tokenkey = os.getenv('JALIEN_TOKEN_KEY', os.getenv('TMPDIR', '/tmp') + '/tokenkey_' + str(os.getuid()) + '.pem')
    global AlienSessionInfo
    if not args: args = []
    args.insert(0, '-nomsg')

    answer = SendMsg(wb, 'token', args)
    json_dict = GetDict(answer, print_err = 'print')

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
        wb.close(code = 1000, reason = 'Lets connect with usercert to be able to generate token')
        try:
            # we have to reconnect with the new token
            wb = InitConnection()
        except Exception as e:
            logging.debug(traceback.format_exc())

    # now we are connected with usercert, so we can generate token
    token(wb, args)
    # we have to reconnect with the new token
    wb.close(code = 1000, reason = 'Re-initialize the connection with the new token')
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
    result = SendMsg(wb, 'commandlist', [])
    json_dict = json.loads(result)
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

    # make sure we have with whom to talk to; if not, lets redo the connection
    # we can consider any message/reply pair as atomic, we cannot forsee and treat the connection lost in the middle of reply
    # (if the end of message frame is not received then all message will be lost as it invalidated)
    if not IsWbConnected(wb): wb = InitConnection()

    global AlienSessionInfo
    args = cmd_string.split(" ")
    cmd = args.pop(0)
    args[:] = [x for x in args if x.strip()]

    usercert = os.getenv('X509_USER_CERT', Path.home().as_posix() + '/.globus' + '/usercert.pem')
    # userkey = os.getenv('X509_USER_KEY', Path.home().as_posix() + '/.globus' + '/userkey.pem')
    tokencert = os.getenv('JALIEN_TOKEN_CERT', os.getenv('TMPDIR', '/tmp') + '/tokencert_' + str(os.getuid()) + '.pem')
    tokenkey = os.getenv('JALIEN_TOKEN_KEY', os.getenv('TMPDIR', '/tmp') + '/tokenkey_' + str(os.getuid()) + '.pem')

    if cmd == 'cert-info':
        if len(args) > 0 and (args[0] in ['-h', 'help', '-help']):
            print("Print user certificate information")
            AlienSessionInfo['exitcode'] = 0
            return AlienSessionInfo['exitcode']
        AlienSessionInfo['exitcode'] = CertInfo(usercert)
        return AlienSessionInfo['exitcode']

    if cmd == 'token-info':
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

    if cmd == 'token-destroy':
        if len(args) > 0 and (args[0] in ['-h', 'help', '-help']):
            print("Delete the token{cert,key}.pem files")
            AlienSessionInfo['exitcode'] = 0
            return AlienSessionInfo['exitcode']
        if os.path.exists(tokencert): os.remove(tokencert)
        if os.path.exists(tokenkey): os.remove(tokenkey)
        if not cmd_mode:
            print("Token was destroyed! Exit and re-connect for token re-creation.")
        AlienSessionInfo['exitcode'] = 0
        return AlienSessionInfo['exitcode']

    if cmd == 'exitcode':
        print(AlienSessionInfo['exitcode'])
        return int(0)

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
    if (cmd == "?") or (cmd == "help"):
        if len(args) > 0:
            cmd = args.pop(0)
            args.clear()
            args.append('-h')
        else:
            print(' '.join(AlienSessionInfo['commandlist']), flush = True)
            AlienSessionInfo['exitcode'] = int(0)
            return AlienSessionInfo['exitcode']

    if cmd == "quota":
        DO_quota(wb, args)
        AlienSessionInfo['exitcode'] = int(0)
        return AlienSessionInfo['exitcode']

    # for commands that use lfns we need the current used paths and current directory content
    cwd_grid_path = Path(AlienSessionInfo['currentdir'])
    home_grid_path = Path(AlienSessionInfo['alienHome'])

    if cmd == "pfn":
        cmd = 'whereis'
        args.insert(0, '-r')
        result = SendMsg(wb, cmd, args)
        json_dict = json.loads(result)
        message = str(json_dict['results'][0]['message'])
        if message:
            arr = message.split()
            if 'archive' in arr: print('IS_ARCHIVED')
            [print(i) for i in arr if i.startswith('root:')]
        error = str(json_dict["metadata"]["error"])
        AlienSessionInfo['error'] = error
        AlienSessionInfo['exitcode'] = int(json_dict["metadata"]["exitcode"])
        if AlienSessionInfo['exitcode'] != 0: print(f'{error}', file=sys.stderr, flush = True)
        return AlienSessionInfo['exitcode']

    if cmd == "cp":  # defer cp processing to ProcessXrootdCp
        exitcode = ProcessXrootdCp(wb, args)
        AlienSessionInfo['exitcode'] = exitcode
        return AlienSessionInfo['exitcode']

    if cmd == "cat":
        if args[0] != '-h':
            DO_cat(wb, args[0])
            AlienSessionInfo['exitcode'] = int(0)
            return AlienSessionInfo['exitcode']

    if cmd == "less":
        if args[0] != '-h':
            DO_less(wb, args[0])
            return int(0)

    if (cmd == 'mcedit' or cmd == 'vi' or cmd == 'nano' or cmd == 'vim'):
        if args[0] != '-h':
            DO_edit(wb, args[0], editor=cmd)
            return int(0)

    if (cmd == 'edit' or cmd == 'sensible-editor'):
        EDITOR = os.getenv('EDITOR', '')
        if not EDITOR:
            print('No EDITOR variable set up!', file=sys.stderr, flush = True)
            return int(22)  # EINVAL /* Invalid argument */
        cmd = EDITOR
        if args[0] != '-h':
            DO_edit(wb, args[0], editor=cmd)
            return int(0)

    # default to print / after directories
    if cmd == 'ls': args.insert(0, '-F')
    if cmd == 'll':
        cmd = 'ls'
        args.insert(0, '-l')
        args.insert(0, '-F')

    if cmd == 'la':
        cmd = 'ls'
        args.insert(0, '-a')
        args.insert(0, '-F')

    if cmd == 'lla':
        cmd = 'ls'
        args.insert(0, '-a')
        args.insert(0, '-l')
        args.insert(0, '-F')

    if cmd == 'ls' or cmd == "stat" or cmd == "xrdstat" or cmd == "rm" or cmd == "lfn2guid":
        # or cmd == "find" # find expect pattern after lfn, and if pattern is . it will be replaced with current dir
        for i, arg in enumerate(args):
            if args[i][0] != '-': args[i] = expand_path_grid(args[i])

    if not (DEBUG or JSON_OUT or JSONRAW_OUT): args.insert(0, '-nokeys')
    result = SendMsg(wb, cmd, args)
    if message_begin:
        message_delta = (datetime.now().timestamp() - message_begin) * 1000
        print(f">>>   Roundtrip for send/receive: {message_delta:.3f} ms", flush = True)
    return int(ProcessReceivedMessage(result, shellcmd, cmd_mode))


def ProcessReceivedMessage(message: str = '', shellcmd: Union[str, None] = None, cmd_mode: bool = False):
    """Process the printing/formating of the received message from the server"""
    if not message: return int(61)  # ENODATA
    global AlienSessionInfo
    json_dict = GetDict(message, print_err = 'print')

    if JSON_OUT:  # print nice json for debug or json mode
        PrintDict(json_dict)
        return int(AlienSessionInfo['exitcode'])
    if JSONRAW_OUT:  # print the raw byte stream received from the server
        print(message, flush = True)
        return int(AlienSessionInfo['exitcode'])

    websocket_output = ''
    if json_dict['results']:
        websocket_output = '\n'.join(str(item['message']) for item in json_dict['results'])
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

def GetCWDFilename():
    tmp = os.getenv('TMPDIR', '/tmp')
    return os.path.join(tmp, "alienpy_cwd_{}".format(os.getuid()))

def RestoreCWD(wb):
    msg = "RestoreCWD:: failed to restore the curernt working directory: {}"

    try:
        cwd = ""
        with open(GetCWDFilename()) as f:
            cwd = f.read()

        resp = SendMsg(wb, 'cd', [cwd])
        GetDict(resp, print_err='log')

        if AlienSessionInfo['exitcode'] != 0:
            logging.warning(msg.format(cwd))
    except Exception as e:
        logging.warning(msg.format(cwd))
        logging.exception(e)


def StoreCWD(cwd):
    try:
        with open(GetCWDFilename(), "w") as f:
            f.write(cwd)
    except Exception as e:
        logging.warning("StoreCWD:: failed to store cwd")
        logging.exception(e)

def JAlien(commands: str = ''):
    """Main entry-point for interaction with AliEn"""
    global AlienSessionInfo
    wb = InitConnection()  # we are doing the connection recovery and exception treatment in AlienConnect()

    # Command mode interaction
    if commands:
        cmds_tokens = commands.split(";")
        for token in cmds_tokens: ProcessInput(wb, token, None, True)
        return int(AlienSessionInfo['exitcode'])  # return the exit code of the latest command

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
    RestoreCWD(wb)
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
            StoreCWD(AlienSessionInfo["currentdir"])


def main():
    global JSON_OUT, JSONRAW_OUT

    MSG_LVL = logging.INFO
    if DEBUG: MSG_LVL = logging.DEBUG
    log = logging.basicConfig(filename = DEBUG_FILE, filemode = 'w', level = MSG_LVL)
    logger_wb = logging.getLogger('websockets')
    logger_wb.setLevel(MSG_LVL)

    # at exit delete all temporary files
    atexit.register(cleanup_temp)

    exec_name = Path(sys.argv.pop(0)).name  # remove the name of the script(alien.py)
    verb = exec_name.replace('alien_', '') if exec_name.startswith('alien_') else ''
    if verb: sys.argv.insert(0, verb)
    if '-json' in sys.argv:
        sys.argv.remove('-json')
        JSON_OUT = 1
    if '-jsonraw' in sys.argv:
        sys.argv.remove('-jsonraw')
        JSONRAW_OUT = 1

    cmd_string = ' '.join(sys.argv)
    try:
        JAlien(cmd_string)
    except KeyboardInterrupt:
        print("Received keyboard intrerupt, exiting..")
        sys.exit(int(AlienSessionInfo['exitcode']))
    except Exception as e:
        print(f"Exception encountered, it will be logged to {DEBUG_FILE}", file=sys.stderr, flush = True)
        logging.error(traceback.format_exc())
        sys.exit(1)
    os._exit(int(AlienSessionInfo['exitcode']))


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
