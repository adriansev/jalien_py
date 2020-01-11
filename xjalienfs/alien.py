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
from typing import NamedTuple
import OpenSSL
import shlex
import argparse
# import tempfile
import time
from datetime import datetime
from pathlib import Path
from enum import Enum
from urllib.parse import urlparse
import socket
import asyncio
import async_stagger
import websockets

try:
    import readline
    has_readline = True
except ImportError:
    has_readline = False

try:  # let's fail fast if the xrootd python bindings are not present
    from XRootD import client
    has_xrootd = True
except ImportError:
    has_xrootd = False

if sys.version_info[0] != 3 or sys.version_info[1] < 6:
    print("This script requires a minimum of Python version 3.6", flush = True)
    sys.exit(1)

# environment debug variable
JSON_OUT = os.getenv('ALIENPY_JSON', '')
JSONRAW_OUT = os.getenv('ALIENPY_JSONRAW', '')
DEBUG = os.getenv('ALIENPY_DEBUG', '')
DEBUG_FILE = os.getenv('ALIENPY_DEBUG_FILE', Path.home().as_posix() + '/alien_py.log')
TIME_CONNECT = os.getenv('ALIENPY_TIMECONNECT', '')

# global session state;
AlienSessionInfo = {'alienHome': '', 'currentdir': '', 'cwd_list': [], 'commandlist': [], 'user': '', 'error': '', 'exitcode': '0', 'show_date': False, 'show_lpwd': False, 'templist': []}


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


def signal_handler(sig, frame):
    print('\nExit')
    sys.exit(0)


def exit_message(exitcode: int = 0):
    print('Exit')
    sys.exit(exitcode)


def xrdcp_help():
    print('''at least 2 arguments are needed : src dst
the command is of the form of (with the strict order of arguments):
cp args src dst
where src|dst are local files if prefixed with file:// or grid files otherwise
after each src,dst can be added comma separated arguments like: disk:N,SE1,SE2,!SE3
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
-select <pattern> : select only these files (AliEn find semantics) to be copied; defaults to all "."
-parent <parent depth> : in destination use this <parent depth> to add to destination ; defaults to 0
-a : copy also the hidden files .* (for recursive copy)
-j <queue_id> : select only the files created by the job with <queue_id>  (for recursive copy)
-l <count> : copy only <count> nr of files (for recursive copy)
-o <offset> : skip first <offset> files found in the src directory (for recursive copy)
''')


async def getEnvelope(wb: websockets.client.WebSocketClientProtocol, lfn_list: list = [], specs: list = [], isWrite: bool = False) -> list:
    """Query central services for the access envelope of the list of lfns, it will return a list of lfn:server answer with envelope pairs"""
    if not wb: return
    access_list = []
    if not lfn_list: return access_list
    access_type = 'read'
    if isWrite: access_type = 'write'
    for lfn in lfn_list:
        get_envelope_arg_list = [access_type, lfn]
        if not DEBUG: get_envelope_arg_list.insert(0, '-nomsg')
        if specs: get_envelope_arg_list.append(str(",".join(specs)))
        result = await SendMsg(wb, 'access', get_envelope_arg_list)
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
    exp_path = path.replace("file://", "")
    # exp_path_components = list(filter(None, exp_path.split("/")))
    exp_path = re.sub(r"^\~", Path.home().as_posix() + "/", exp_path)
    exp_path = re.sub(r"^\/*\.{2}", Path.cwd().parents[0].as_posix() + "/", exp_path)
    exp_path = re.sub(r"^\/*\.{1}", Path.cwd().as_posix() + "/", exp_path)
    if not exp_path.startswith('/'):
        exp_path = Path.cwd().as_posix() + "/" + exp_path
    exp_path = re.sub(r"\/{2,}", "/", exp_path)
    return exp_path


def expand_path_grid(path: str) -> str:
    """Given a string representing a GRID file (lfn), return a full path after interpretation of AliEn HOME location, current directory, . and .. and making sure there are only single /"""
    exp_path = re.sub(r"\/*\%ALIEN", AlienSessionInfo['alienHome'], path)
    exp_path = re.sub(r"^\/*\.{2}", Path(AlienSessionInfo['currentdir']).parents[0].as_posix(), exp_path)
    exp_path = re.sub(r"^\/*\.{1}", AlienSessionInfo['currentdir'], exp_path)
    if not exp_path.startswith('/'):
        exp_path = AlienSessionInfo['currentdir'] + "/" + exp_path
    exp_path = re.sub(r"\/{2,}", "/", exp_path)
    return exp_path


async def pathtype_grid(wb: websockets.client.WebSocketClientProtocol, path: str) -> str:
    """Query if a lfn is a file or directory, return f, d or NoValidType"""
    if not wb: return
    if not path: return
    result = await SendMsg(wb, 'stat', ['-nomsg', path])
    json_dict = json.loads(result)
    error = json_dict["metadata"]["error"]
    if error:
        if DEBUG: logging.debug(f"Stat cmd for {path} returned: {error}")
        return str("NoValidType")
    return str(json_dict['results'][0]["type"])


def pathtype_local(path: str) -> str:
    """Query if a local path is a file or directory, return f, d or NoValidType"""
    if not path: return ''
    p = Path(path)
    if p.is_dir(): return str('d')
    if p.is_file(): return str('f')
    return str("NoValidType")


def fileIsValid(file: str, size: Union[str, int], reported_md5: str) -> bool:
    """Check if the file path is consistent with the size and md5 argument. N.B.! the local file will be deleted with size,md5 not match"""
    if os.path.isfile(file):  # first check
        if int(os.stat(file).st_size) != int(size):
            os.remove(file)
            return False
        if md5(file) != reported_md5:
            os.remove(file)
            return False
        print(f"{file} --> TARGET VALID", flush = True)
        return True


def create_metafile(meta_filename: str, local_filename: str, size: Union[str, int], md5: str, replica_list: list = []):
    """Generate a meta4 xrootd virtual redirector with the specified location and using the rest of arguments"""
    published = str(datetime.now().replace(microsecond=0).isoformat())
    with open(meta_filename, 'w') as f:
        f.write('<?xml version="1.0" encoding="UTF-8"?>\n')
        f.write(' <metalink xmlns="urn:ietf:params:xml:ns:metalink">\n')
        f.write("   <published>{}</published>\n".format(published))
        f.write("   <file name=\"{}\">\n".format(local_filename))
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
            readline.read_history_file(histfile)
            h_len = readline.get_current_history_length()
        except FileNotFoundError:
            open(histfile, 'wb').close()
            h_len = 0
        readline.set_auto_history(True)
        atexit.register(readline.write_history_file, histfile)

    def saveHistory(prev_h_len, histfile):
        new_h_len = readline.get_current_history_length()
        prev_h_len = readline.get_history_length()
        readline.set_history_length(1000)
        readline.append_history_file(new_h_len - prev_h_len, histfile)


async def ProcessXrootdCp(wb: websockets.client.WebSocketClientProtocol, xrd_copy_command: list = []) -> int:
    """XRootD cp function :: process list of arguments for a xrootd copy command"""
    if not wb: return int(107)  # ENOTCONN /* Transport endpoint is not connected */
    if not AlienSessionInfo:
        print('Session information like home and current directories needed', flush = True)
        return int(126)  # ENOKEY /* Required key not available */

    if len(xrd_copy_command) < 2 or xrd_copy_command == '-h':
        xrdcp_help()
        return int(64)  # EX_USAGE /* command line usage error */

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
        sources = int(xrd_copy_command.pop(y_idx + 1))
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

    pattern = ''  # just a placeholder; if used in cmdline the user must do distinction between alien find pattern (download files from remote) and regex for local files (upload to remote)
    if '-select' in xrd_copy_command:
        select_idx = xrd_copy_command.index('-select')
        pattern = xrd_copy_command.pop(select_idx + 1)
        xrd_copy_command.pop(select_idx)

    # list of src files and coresponding dst names
    src_filelist = []
    dst_filelist = []

    # clean up and prepare the paths to be used in the xrdcp command
    src = None
    src_type = None
    src_specs_remotes = None  # let's record specifications like disk=3,SE1,!SE2
    if xrd_copy_command[-2].startswith('file:'):  # second to last argument (should be the source)
        isSrcLocal = True
        isDownload = False
        src = expand_path_local(xrd_copy_command[-2])
        src_type = pathtype_local(src)
        if src_type == 'd': isSrcDir = bool(True)
    else:
        src = expand_path_grid(xrd_copy_command[-2])
        src_specs_remotes = src.split(",", maxsplit = 1)
        src = src_specs_remotes.pop(0)  # first item is the file path, let's remove it; it remains disk specifications
        src_type = await pathtype_grid(wb, src)
        if src_type == "NoValidType":
            print("Could not determine the type of src argument.. is it missing?")
            return int(42)  # ENOMSG /* No message of desired type */
        if src_type == 'd': isSrcDir = bool(True)

    if not pattern and src_type == 'd':
        if isSrcLocal:
            pattern = '.*'
        else:
            pattern = '*'

    # For all download use a default of 8 simultaneous downloads;
    # the parralel uploads does not work yet because of return confirmations needed to commit writes to catalog
    if isDownload and not batch_user_setup: batch = 8

    dst = None
    dst_type = None
    dst_specs_remotes = None  # let's record specifications like disk=3,SE1,!SE2
    if xrd_copy_command[-1].startswith('file:'):  # last argument (should be the destination)
        isDstLocal = True
        dst = expand_path_local(xrd_copy_command[-1])
        dst_type = pathtype_local(dst)
        if dst_type == 'd': isDstDir = bool(True)
    else:
        isDownload = False
        dst = expand_path_grid(xrd_copy_command[-1])
        dst_specs_remotes = dst.split(",", maxsplit = 1)
        dst = dst_specs_remotes.pop(0)  # first item is the file path, let's remove it; it remains disk specifications
        dst_type = await pathtype_grid(wb, dst)
        if dst_type == "NoValidType" and src_type == 'f':
            # the destination is not present yet and because src is file then dst must be also file
            base_dir = Path(dst).parent.as_posix()
            result = await SendMsg_str(wb, 'mkdir -p ' + base_dir)
            json_dict = json.loads(result)
            if json_dict["metadata"]["exitcode"] != '0':
                err = json_dict["metadata"]["error"]
                print("Could not create directory : {base_dir} !! --> {err}")
        if dst_type == 'd': isDstDir = bool(True)

    if isSrcLocal == isDstLocal:
        print("The operands cannot specify different source types: one must be local and one grid", flush = True)
        return int(22)  # EINVAL /* Invalid argument */

    # if src is directory, then create list of files coresponding with options
    if isDownload:
        isWrite = bool(False)
        specs = src_specs_remotes
        if isSrcDir:  # src is GRID, we are DOWNLOADING from GRID directory
            find_args.append(src)
            find_args.append(pattern)
            if not DEBUG: find_args.insert(0, '-nomsg')
            result = await SendMsg(wb, 'find', find_args)
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
                    if regex.match(filepath):
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

    lfn_list = []
    if isDownload:
        lfn_list = src_filelist
    else:
        lfn_list = dst_filelist

    envelope_list = await getEnvelope(wb, lfn_list, specs, isWrite)

    # print errors
    errors_idx = []
    for item_idx, item in enumerate(envelope_list):
        lfn = item["lfn"]
        result = item["answer"]
        access_request = json.loads(result)
        if access_request["metadata"]["error"]:
            errors_idx.append(item_idx)
            error = access_request["metadata"]["error"]
            print(f"lfn: {lfn} --> {error}", flush = True)
        if DEBUG:
            logging.debug(f"lfn: {lfn}")
            logging.debug(json.dumps(access_request, sort_keys=True, indent=4))

    for i in reversed(errors_idx): envelope_list.pop(i)  # remove from list invalid lfns
    if not envelope_list:
        print("No lfns in envelope list after removing the invalid ones")
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
            create_metafile(meta_fn, dst, size_4meta, md5_4meta, url_list_4meta)
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
            lfn = dst
            size = os.path.getsize(src)
            md5sum = md5(src)
            perm = '644'
            expire = '0'
            for token in token_list_upload_ok:  # for each succesful token
                for server in access_request['results']:  # go over all received servers
                    if token in server['envelope']:  # for the server that have the succesful uploaded token
                        pfn = server['url']
                        se = server['se']
                        guid = server['guid']
                        # envelope size lfn perm expire pfn se guid md5
                        commit_args_list = [token, int(size), lfn, perm, expire, pfn, se, guid, md5sum]
                        commit_results = await SendMsg(wb, 'commit', commit_args_list)
                        if DEBUG: logging.debug(json.dumps(json.loads(commit_results), sort_keys=True, indent=4))

    # hard to return a single exitcode for a copy process optionally spanning multiple files
    # we'll return SUCCESS if at least one lfn is confirmed, FAIL if not lfns is confirmed
    if token_list_upload_ok:
        return int(0)
    else:
        return int(1)


def XrdCopy(src: list, dst: list, isDownload: bool, xrd_cp_args: XrdCpArgs) -> list:
    """XRootD copy command :: the actual XRootD copy process"""
    if not xrd_cp_args: return

    overwrite = xrd_cp_args.overwrite
    batch = xrd_cp_args.batch
    sources = xrd_cp_args.sources
    chunks = xrd_cp_args.chunks
    chunksize = xrd_cp_args.chunksize
    makedir = xrd_cp_args.makedir
    posc = xrd_cp_args.posc
    hashtype = xrd_cp_args.hashtype
    streams = xrd_cp_args.streams

    class MyCopyProgressHandler(client.utils.CopyProgressHandler):
        isDownload = bool(True)
        src = ''  # pass the source from begin to end
        dst = ''  # pass the target from begin to end
        token_list_upload_ok = []  # record the tokens of succesfully uploaded files. needed for commit to catalogue
        timestamp_begin = None
        total = None
        jobs = None
        job_list = []

        def begin(self, id, total, source, target):
            self.timestamp_begin = datetime.now().timestamp()
            print("jobID: {0}/{1} >>> Start".format(id, total), flush = True)
            self.src = source
            self.dst = target
            self.jobs = int(total)
            self.job_list.append(id)
            if DEBUG: logging.debug("CopyProgressHandler.src: {0}\nCopyProgressHandler.dst: {1}\n".format(self.src, self.dst))

        def end(self, jobId, results):
            results_message = results['status'].message
            results_status = results['status'].status
            results_errno = results['status'].errno
            results_code = results['status'].code
            status = ''
            if results['status'].ok: status = 'OK'
            if results['status'].error: status = 'ERROR'
            if results['status'].fatal: status = 'FATAL'

            if results['status'].ok:
                deltaT = datetime.now().timestamp() - self.timestamp_begin
                speed = self.total/deltaT
                bytes_s = 'bytes/s'
                kbytes_s = 'kB/s'
                mbytes_s = 'MB/s'
                unit = bytes_s
                if int(speed/1024) > 1:
                    speed = speed/1024
                    unit = kbytes_s
                if int(speed/(1024*1024)) > 1:
                    speed = speed/(1024*1024)
                    unit = mbytes_s
                print("jobID: {0}/{1} >>> STATUS: {2} ; SPEED = {3:.2f} {4} ; MESSAGE: {5}".format(jobId, self.jobs, status, speed, unit, results_message), flush = True)
                if self.isDownload:
                    os.remove(urlparse(str(self.src)).path)  # remove the created metalink
                    self.token_list_upload_ok.append(str(self.src))
                else:  # isUpload
                    link = urlparse(str(self.dst))
                    token = next((param for param in str.split(link.query, '&') if 'authz=' in param), None).replace('authz=', '')  # extract the token from url
                    self.token_list_upload_ok.append(str(token))
            else:
                print("jobID: {0}/{1} >>> STATUS: {2} ; ERRNO: {3} ; CODE: {4} ; MESSAGE: {5}".format(jobId, self.jobs, results_status, results_errno, results_code, results_message), flush = True)

        def update(self, jobId, processed, total):
            self.total = total
            # perc = float(processed)/float(total)
            # print("jobID: {0}/{1} >>> Completion = {2:.2f}".format(jobId, self.jobs, perc), flush = True)

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
    result = await ProcessXrootdCp(wb, copycmd.split())
    if result == 0: return tmpfile


async def upload_tmp(wb: websockets.client.WebSocketClientProtocol, temp_file_name: str, upload_specs: str = '') -> str:
    """Upload a temporary file: the original lfn will be renamed and the new file will be uploaded with the oirginal lfn"""
    # lets recover the lfn from temp file name
    lfn = temp_file_name.replace('_' + str(os.getuid()) + '.alienpy_tmp', '')
    lfn = lfn.replace(os.getenv('TMPDIR', '/tmp') + '/', '')
    lfn = lfn.replace("%%", "/")

    envelope_list = await getEnvelope(wb, [lfn])
    result = envelope_list[0]["answer"]
    access_request = json.loads(result)
    replicas = access_request["results"][0]["nSEs"]

    # let's create a backup of old lfn
    mod_time = f"{datetime.now():%Y%m%d_%H%M%S}"
    lfn_backup = lfn + "_" + mod_time
    result = await SendMsg(wb, 'mv', [lfn, lfn_backup])
    json_dict = json.loads(result)
    if json_dict["metadata"]["exitcode"] != '0':
        print("Could not create backup of lfn : {}", lfn)
        return 1

    if "disk:" not in upload_specs:
        upload_specs = "disk:" + replicas

    if upload_specs: lfn = lfn + "," + upload_specs
    copycmd = "-f " + 'file://' + temp_file_name + " " + lfn
    list_upload = await ProcessXrootdCp(wb, copycmd.split())
    if list_upload: return lfn


async def DO_cat(wb: websockets.client.WebSocketClientProtocol, lfn: str):
    """cat lfn :: download lfn as a temporary file and cat"""
    lfn_path = expand_path_grid(lfn)
    tmp = make_tmp_fn(lfn_path)
    if tmp in AlienSessionInfo['templist']:
        runShellCMD('cat ' + tmp)
    else:
        tmp = await download_tmp(wb, lfn)
        if tmp:
            AlienSessionInfo['templist'].append(tmp)
            runShellCMD('cat ' + tmp)


async def DO_less(wb: websockets.client.WebSocketClientProtocol, lfn: str):
    """cat lfn :: download lfn as a temporary file and less"""
    lfn_path = expand_path_grid(lfn)
    tmp = make_tmp_fn(lfn_path)
    if tmp in AlienSessionInfo['templist']:
        runShellCMD('less ' + tmp)
    else:
        tmp = await download_tmp(wb, lfn)
        if tmp:
            AlienSessionInfo['templist'].append(tmp)
            runShellCMD('less ' + tmp)


async def DO_more(wb: websockets.client.WebSocketClientProtocol, lfn: str):
    """cat lfn :: download lfn as a temporary file and more"""
    lfn_path = expand_path_grid(lfn)
    tmp = make_tmp_fn(lfn_path)
    if tmp in AlienSessionInfo['templist']:
        runShellCMD('more ' + tmp)
    else:
        tmp = await download_tmp(wb, lfn)
        if tmp:
            AlienSessionInfo['templist'].append(tmp)
            runShellCMD('more ' + tmp)


async def DO_quota(wb: websockets.client.WebSocketClientProtocol, quota_args: list):
    """quota : put togheter both job and file quota"""
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

    await wb.send(jquota_cmd)
    jquota = await wb.recv()
    jquota_dict = json.loads(jquota)

    await wb.send(fquota_cmd)
    fquota = await wb.recv()
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


async def DO_edit(wb: websockets.client.WebSocketClientProtocol, lfn: str, editor: str = 'mcedit'):
    """Edit a grid lfn; download a temporary, edit with the specified editor and upload the new file"""
    if editor == 'mcedit': editor = 'mc -c -e'
    editor = editor + " "
    lfn_path = expand_path_grid(lfn)
    tmp = make_tmp_fn(lfn_path)
    if tmp in AlienSessionInfo['templist']:
        runShellCMD(editor + tmp, False)
    else:
        tmp = await download_tmp(wb, lfn)
        if tmp:
            md5_begin = md5(tmp)
            AlienSessionInfo['templist'].append(tmp)
            runShellCMD(editor + tmp, False)
            md5_end = md5(tmp)
            if md5_begin != md5_end: await upload_tmp(wb, tmp, '')


def runShellCMD(INPUT: str = '', captureout: bool = True):
    """Run shell command in subprocess; if exists, print stdout and stderr"""
    if not INPUT: return
    sh_cmd = re.sub(r'^!', '', INPUT)

    if captureout:
        args = sh_cmd
        shcmd_out = subprocess.run(args, stdout = subprocess.PIPE, stderr = subprocess.PIPE, shell = True, env = os.environ)
    else:
        args = shlex.split(sh_cmd)
        shcmd_out = subprocess.run(args, env = os.environ)

    stdout = shcmd_out.stdout
    if stdout: print(stdout.decode(), flush = True)
    stderr = shcmd_out.stderr
    if stderr: print(stderr.decode(), flush = True)


def check_port(address: str, port: Union[str, int]) -> bool:
    """Check TCP connection to address:port"""
    import socket
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


def CreateJsonCommand(cmd: str, options: list = []) -> str:
    """Return a json with command and argument list"""
    jsoncmd = {"command": cmd, "options": options}
    if DEBUG: logging.debug(f'send json: {jsoncmd}')
    return json.dumps(jsoncmd)


def CreateJsonCommand_str(cmd: str) -> str:
    """Return a json by spliting the input string in first element(command) and the rest asa a list of arguments"""
    args = cmd.split(" ")
    command = args.pop(0)
    return CreateJsonCommand(command, args)


def PrintDict(dict: dict) -> str:
    """Print a dictionary in a nice format"""
    print(json.dumps(dict, sort_keys=True, indent=4), flush = True)


async def IsWbConnected(wb: websockets.client.WebSocketClientProtocol) -> bool:
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


async def SendMsg_json(wb: websockets.client.WebSocketClientProtocol, json: str) -> str:
    """Send a json message to the specified websocket; it will return the server answer"""
    if not wb:
        logging.debug(f"SendMsg_json:: websocket not initialized")
        return ''
    if not json:
        logging.debug(f"SendMsg_json:: json message is empty or invalid")
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
        print("SendMsg_json:: error sending the message")
        wb_status = await IsWbConnected(wb)
        if not wb_status: wb = await InitConnection()
        return ''

    try:
        result = await wb.recv()
    except Exception as e:
        logging.exception(e)
        logging.debug("SendMsg_json:: Websocket connection was closed while waiting the answer. Either network problem or ALIENPY_TIMEOUT should be set >20s")
        print("SendMsg_json:: Websocket connection was closed while waiting the answer. Either network problem or ALIENPY_TIMEOUT should be set >20s")
        wb_status = await IsWbConnected(wb)
        if not wb_status: wb = await InitConnection()
        return ''
    if DEBUG:
        init_end = datetime.now().timestamp()
        init_delta = (init_end - init_begin) * 1000
        logging.debug(f"COMMAND TIMESTAMP END: {init_end}")
        logging.debug(f"COMMAND SEND/RECV ROUNDTRIP: {init_delta:.3f} ms")
    return result


async def SendMsg(wb: websockets.client.WebSocketClientProtocol, cmd: str, args: list = []) -> str:
    """Send a cmd/argument list message to the specified websocket; it will return the server answer"""
    if not wb:
        logging.debug(f"SendMsg:: websocket is invalid")
        return ''
    if not cmd:
        logging.debug(f"SendMsg:: command is not specified")
        return ''
    result = await SendMsg_json(wb, CreateJsonCommand(cmd, args))
    return result


async def SendMsg_str(wb: websockets.client.WebSocketClientProtocol, cmd_line: str) -> str:
    """Send a cmd/argument list message to the specified websocket; it will return the server answer"""
    if not wb:
        logging.debug(f"SendMsg_str:: websocket is invalid")
        return ''
    if not cmd_line:
        logging.debug(f"SendMsg_str:: command line is not specified")
        return ''
    result = await SendMsg_json(wb, CreateJsonCommand_str(cmd_line))
    return result


async def AlienSession(cmd: str) -> dict:
    """Create a connection to AliEn central services, send a json message and return the decoded to dictionary message"""
    if not cmd:
        logging.debug(f"AlienSession:: cmd string is not specified")
        return None
    wb = await AlienConnect()
    if not wb:
        logging.debug(f"AlienSession:: websocket could not be aquired")
        return None
    result = await SendMsg_json(wb, json)
    return json.loads(result)


def AlienSendCmd(cmd):
    return asyncio.get_event_loop().run_until_complete(AlienSession(cmd))


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
        print(f"File >>>{fname}<<< not found", flush = True)
        return int(2)  # ENOENT /* No such file or directory */

    try:
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_bytes)
    except Exception:
        print(f"Could not load certificate >>>{fname}<<<", flush = True)
        return int(5)  # EIO /* I/O error */

    utc_time_notafter = datetime.strptime(x509.get_notAfter().decode("utf-8"), "%Y%m%d%H%M%SZ")
    utc_time_notbefore = datetime.strptime(x509.get_notBefore().decode("utf-8"), "%Y%m%d%H%M%SZ")
    issuer = '/%s' % ('/'.join(['%s=%s' % (k.decode("utf-8"), v.decode("utf-8")) for k, v in x509.get_issuer().get_components()]))
    subject = '/%s' % ('/'.join(['%s=%s' % (k.decode("utf-8"), v.decode("utf-8")) for k, v in x509.get_subject().get_components()]))
    print(f"DN >>> {subject}\nISSUER >>> {issuer}\nBEGIN >>> {utc_time_notbefore}\nEXPIRE >>> {utc_time_notafter}", flush = True)
    return int(0)


def create_ssl_context():
    """Create SSL context using either the default names for user certificate and token certificate or X509_USER_{CERT,KEY} JALIEN_TOKEN_{CERT,KEY} environment variables"""
    # SSL SETTINGS
    usercert = os.getenv('X509_USER_CERT', Path.home().as_posix() + '/.globus' + '/usercert.pem')
    userkey = os.getenv('X509_USER_KEY', Path.home().as_posix() + '/.globus' + '/userkey.pem')
    tokencert = os.getenv('JALIEN_TOKEN_CERT', os.getenv('TMPDIR', '/tmp') + '/tokencert_' + str(os.getuid()) + '.pem')
    tokenkey = os.getenv('JALIEN_TOKEN_KEY', os.getenv('TMPDIR', '/tmp') + '/tokenkey_' + str(os.getuid()) + '.pem')
    system_ca_path = '/etc/grid-security/certificates'
    alice_cvmfs_ca_path = '/cvmfs/alice.cern.ch/etc/grid-security/certificates'
    x509dir = ''
    if os.path.isdir(str(os.getenv('X509_CERT_DIR'))): x509dir = os.getenv('X509_CERT_DIR')
    x509file = ''
    if os.path.isfile(str(os.getenv('X509_CERT_FILE'))): x509file = os.getenv('X509_CERT_FILE')

    capath_default = ''
    if x509dir:
        capath_default = x509dir
    elif os.path.exists(alice_cvmfs_ca_path):
        capath_default = alice_cvmfs_ca_path
    else:
        if os.path.isdir(system_ca_path): capath_default = system_ca_path

    if not capath_default and not x509file:
        print("Not CA location or files specified!!! Connection will not be possible!!")
        sys.exit(1)
    if DEBUG:
        if x509file:
            logging.debug(f"CAfile = {x509file}")
        else:
            logging.debug(f"CApath = {capath_default}")

    # defaults
    cert = usercert
    key  = userkey

    if IsValidCert(tokencert):
        cert = tokencert
        key  = tokenkey

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
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


async def wb_create(host: str, port: Union[str, int], path: str) -> Union[websockets.client.WebSocketClientProtocol, None]:
    """Create a websocket to wss://host:port/path (it is implied a SSL context)"""
    QUEUE_SIZE = int(4)  # maximum length of the queue that holds incoming messages
    MSG_SIZE = int(16 * 1024 * 1024)  # maximum size for incoming messages in bytes. The default value is 1 MiB. None disables the limit
    PING_INTERVAL = int(10)  # Ping frame is sent every ping_interval seconds
    PING_TIMEOUT = int(os.getenv('ALIENPY_TIMEOUT', '20'))  # If the corresponding Pong frame isn’t received within ping_timeout seconds, the connection is considered unusable and is closed
    CLOSE_TIMEOUT = int(10)  # maximum wait time in seconds for completing the closing handshake and terminating the TCP connection
    """https://websockets.readthedocs.io/en/stable/api.html#websockets.protocol.WebSocketCommonProtocol"""
    # we use some conservative values, higher than this might hurt the sensitivity to intreruptions

    fHostWSUrl = 'wss://' + str(host) + ':' + str(port) + str(path)  # conection url
    ctx = create_ssl_context()  # will check validity of token and if invalid cert will be usercert

    if DEBUG: logging.debug(f"Request connection to : {host}:{port}{path}")

    socket_endpoint = None
    # https://async-stagger.readthedocs.io/en/latest/reference.html#async_stagger.create_connected_sock
    # AI_* flags --> https://linux.die.net/man/3/getaddrinfo
    try:
        if DEBUG:
            logging.debug(f"TRY ENDPOINT : {host}:{port}")
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

    websocket = None
    if socket_endpoint:
        try:
            if DEBUG:
                init_begin = datetime.now().timestamp()
                logging.debug(f"WEBSOCKET BEGIN: {init_begin}")
            websocket = await websockets.connect(fHostWSUrl, sock = socket_endpoint, server_hostname = host, ssl = ctx,
                                                 max_queue=QUEUE_SIZE, max_size=MSG_SIZE, ping_interval=PING_INTERVAL, ping_timeout=PING_TIMEOUT, close_timeout=CLOSE_TIMEOUT)
            if DEBUG:
                init_end = datetime.now().timestamp()
                init_delta = (init_end - init_begin) * 1000
                logging.debug(f"WEBSOCKET END: {init_end}")
                logging.debug(f"WEBSOCKET DELTA: {init_delta:.3f} ms")
        except Exception as e:
            logging.debug(traceback.format_exc())
    if websocket and DEBUG: logging.debug(f"GOT ENDPOINT: {socket_endpoint.getpeername()[0]}:{socket_endpoint.getpeername()[1]}")
    return websocket


async def AlienConnect() -> websockets.client.WebSocketClientProtocol:
    """Create a websocket connection to AliEn services either directly to alice-jcentral.cern.ch or trough a local found jbox instance"""
    jalien_websocket_port = 8097  # websocket port
    jalien_websocket_path = '/websocket/json'
    jalien_server = os.getenv("ALIENPY_JCENTRAL", 'alice-jcentral.cern.ch')  # default value for JCENTRAL

    jclient_env = os.getenv('TMPDIR', '/tmp') + '/jclient_token_' + str(os.getuid())

    if not os.getenv("ALIENPY_JCENTRAL") and os.path.exists(jclient_env):  # If user defined ALIENPY_JCENTRAL the intent is to set and use the endpoint
        # lets check JBOX availability
        jalien_info = {}
        with open(jclient_env) as myfile:
            for line in myfile:
                name, var = line.partition("=")[::2]
                jalien_info[name.strip()] = str(var.strip())

        if jalien_info:
            if check_port(jalien_info['JALIEN_HOST'], jalien_info['JALIEN_WSPORT']):
                jalien_server = jalien_info['JALIEN_HOST']
                jalien_websocket_port = jalien_info['JALIEN_WSPORT']

    # let's try to get a websocket
    websocket = None
    nr_tries = 0
    init_begin = None
    init_delta = None
    if TIME_CONNECT or DEBUG: init_begin = datetime.now().timestamp()
    while websocket is None:
        try:
            nr_tries += 1
            websocket = await wb_create(jalien_server, str(jalien_websocket_port), jalien_websocket_path)
        except Exception as e:
            logging.debug(traceback.format_exc())
        if not websocket:
            time.sleep(1)
            if nr_tries + 1 > 3:
                logging.debug(f"We tried on {jalien_server}:{jalien_websocket_port}{jalien_websocket_path} {nr_tries} times")
                break

    if jalien_server != 'alice-jcentral.cern.ch' and not websocket:  # we stil do not have a socket
        jalien_websocket_port = 8097
        jalien_server = 'alice-jcentral.cern.ch'
        nr_tries = 0
        while websocket is None:
            try:
                nr_tries += 1
                websocket = await wb_create(jalien_server, str(jalien_websocket_port), jalien_websocket_path)
            except Exception as e:
                logging.debug(traceback.format_exc())
            if not websocket:
                time.sleep(1)
                if nr_tries + 1 > 3:
                    logging.debug(f"Even {jalien_server}:{jalien_websocket_port}{jalien_websocket_path} failed for {nr_tries} times, giving up")
                    break

    if not websocket:
        logging.debug("Could not get a websocket connection, exiting..")
        sys.exit(1)
    if init_begin:
        init_delta = (datetime.now().timestamp() - init_begin) * 1000
        if DEBUG: logging.debug(f">>>   Endpoint total connecting time: {init_delta:.3f} ms")
        if TIME_CONNECT: print(f">>>   Endpoint total connecting time: {init_delta:.3f} ms", flush = True)

    await token(websocket)  # it will return if token is valid, if not it will request and write it to file
    # print(json.dumps(ssl_context.get_ca_certs(), sort_keys=True, indent=4), flush = True)
    return websocket


async def token(wb: websockets.client.WebSocketClientProtocol):
    """(Re)create the tokencert and tokenkey files"""
    if not wb: return
    tokencert = os.getenv('JALIEN_TOKEN_CERT', os.getenv('TMPDIR', '/tmp') + '/tokencert_' + str(os.getuid()) + '.pem')
    tokenkey = os.getenv('JALIEN_TOKEN_KEY', os.getenv('TMPDIR', '/tmp') + '/tokenkey_' + str(os.getuid()) + '.pem')

    # if the certificate used is not the token, then get one
    if IsValidCert(tokencert): return

    result = await SendMsg(wb, 'token', ['-nomsg'])
    json_dict = json.loads(result)

    tokencert_content = json_dict['results'][0]["tokencert"]
    tokenkey_content  = json_dict['results'][0]["tokenkey"]

    if os.path.isfile(tokencert): os.chmod(tokencert, 0o700)  # make it writeable
    with open(tokencert, "w") as tcert: print(f"{tokencert_content}", file=tcert)  # write the tokencert
    os.chmod(tokencert, 0o400)  # make it readonly

    if os.path.isfile(tokenkey): os.chmod(tokenkey, 0o700)  # make it writeable
    with open(tokenkey, "w") as tkey: print(f"{tokenkey_content}", file=tkey)  # write the tokenkey
    os.chmod(tokenkey, 0o400)  # make it readonly


async def getSessionVars(wb: websockets.client.WebSocketClientProtocol):
    """Initialize the global session variables : cleaned up command list, user, home dir, current dir"""
    if not wb: return
    global AlienSessionInfo
    # get the command list
    result = await SendMsg(wb, 'commandlist', [])
    json_dict = json.loads(result)
    # first executed commands, let's initialize the following (will re-read at each ProcessReceivedMessage)
    cmd_list = json_dict["results"][0]['message'].split()
    regex = re.compile(r'.*_csd$')
    AlienSessionInfo['commandlist'] = [i for i in cmd_list if not regex.match(i)]
    AlienSessionInfo['commandlist'].remove('jquota')
    AlienSessionInfo['commandlist'].remove('fquota')
    AlienSessionInfo['commandlist'].append('quota')
    AlienSessionInfo['commandlist'].append('prompt')
    AlienSessionInfo['commandlist'].append('token')
    AlienSessionInfo['commandlist'].append('certinfo')
    AlienSessionInfo['commandlist'].append('quit')
    AlienSessionInfo['commandlist'].append('exit')
    AlienSessionInfo['commandlist'].append('logout')
    AlienSessionInfo['commandlist'].sort()
    AlienSessionInfo['user'] = json_dict["metadata"]["user"]

    # if we were intrerupted and re-connect than let's get back to the old currentdir
    if AlienSessionInfo['currentdir'] and not AlienSessionInfo['currentdir'] == json_dict["metadata"]["currentdir"]:
        tmp_res = SendMsg(wb, 'cd', [AlienSessionInfo['currentdir']])
    AlienSessionInfo['currentdir'] = json_dict["metadata"]["currentdir"]
    if not AlienSessionInfo['alienHome']: AlienSessionInfo['alienHome'] = AlienSessionInfo['currentdir']  # this is first query so current dir is alienHOME


async def InitConnection() -> websockets.client.WebSocketClientProtocol:
    """Create a session to AliEn services, including session globals"""
    init_begin = None
    init_delta = None
    if TIME_CONNECT or DEBUG: init_begin = datetime.now().timestamp()
    wb = await AlienConnect()

    # no matter if command or interactive mode, we need alienHome, currentdir, user and commandlist
    if not AlienSessionInfo['commandlist']: await getSessionVars(wb)
    if init_begin:
        init_delta = (datetime.now().timestamp() - init_begin) * 1000
        if DEBUG: logging.debug(f">>>   Time for session connection: {init_delta:.3f} ms")
        if TIME_CONNECT: print(f">>>   Time for session connection: {init_delta:.3f} ms", flush = True)
    return wb


async def cwd_list(wb: websockets.client.WebSocketClientProtocol):
    """Save into global cwd_list the content of current directory"""
    if not wb: return
    result = await SendMsg(wb, 'ls', ['-nokeys', '-F'])
    result_dict = json.loads(result)
    AlienSessionInfo['cwd_list'] = list(item['message'] for item in result_dict['results'])


async def ProcessInput(wb: websockets.client.WebSocketClientProtocol, cmd_string: str, shellcmd: Union[str, None] = None):
    """Process a command line within shell or from command line mode input"""
    if not cmd_string: return
    global AlienSessionInfo
    args = cmd_string.split(" ")
    cmd = args.pop(0)

    cwd_grid_path = Path(AlienSessionInfo['currentdir'])
    home_grid_path = Path(AlienSessionInfo['alienHome'])
    await cwd_list(wb)  # content of grid current dir; it is used in expand_path_grid for paths without beggining /

    usercert = os.getenv('X509_USER_CERT', Path.home().as_posix() + '/.globus' + '/usercert.pem')
    # userkey = os.getenv('X509_USER_KEY', Path.home().as_posix() + '/.globus' + '/userkey.pem')
    tokencert = os.getenv('JALIEN_TOKEN_CERT', os.getenv('TMPDIR', '/tmp') + '/tokencert_' + str(os.getuid()) + '.pem')
    tokenkey = os.getenv('JALIEN_TOKEN_KEY', os.getenv('TMPDIR', '/tmp') + '/tokenkey_' + str(os.getuid()) + '.pem')

    # implement a time command for measurement of sent/recv delay
    message_begin = None
    message_delta = None

    # first to be processed is the time token, it will start the timing and be removed from command
    if cmd == 'time':
        if not args:
            print("time needs as argument a command", flush = True)
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

    if cmd == 'certinfo':
        AlienSessionInfo['exitcode'] = CertInfo(usercert)
        return AlienSessionInfo['exitcode']

    if cmd == 'token':
        if len(args) > 0 and args[0] == 'refresh':
            os.remove(tokencert)
            os.remove(tokenkey)
            try:
                wb = await InitConnection()
            except Exception as e:
                logging.debug(traceback.format_exc())
                wb = await InitConnection()
            AlienSessionInfo['exitcode'] = int(0)
            return AlienSessionInfo['exitcode']
        if not args or (len(args) > 0 and args[0] == 'info'):
            AlienSessionInfo['exitcode'] = CertInfo(tokencert)
            return AlienSessionInfo['exitcode']

    if cmd == "cp":  # defer cp processing to ProcessXrootdCp
        exitcode = await ProcessXrootdCp(wb, args)
        AlienSessionInfo['exitcode'] = exitcode
        return AlienSessionInfo['exitcode']

    if cmd == "quota":
        await DO_quota(wb, args)
        AlienSessionInfo['exitcode'] = int(0)
        return AlienSessionInfo['exitcode']

    if cmd == "cat":
        if args[0] != '-h':
            await DO_cat(wb, args[0])
            AlienSessionInfo['exitcode'] = int(0)
            return AlienSessionInfo['exitcode']

    if cmd == "less":
        if args[0] != '-h':
            await DO_less(wb, args[0])
            return int(0)

    if (cmd == 'mcedit' or cmd == 'vi' or cmd == 'nano' or cmd == 'vim'):
        if args[0] != '-h':
            await DO_edit(wb, args[0], editor=cmd)
            return int(0)

    if (cmd == 'edit' or cmd == 'sensible-editor'):
        EDITOR = os.getenv('EDITOR', '')
        if not EDITOR:
            print('No EDITOR variable set up!', flush = True)
            return int(22)  # EINVAL /* Invalid argument */
        cmd = EDITOR
        if args[0] != '-h':
            await DO_edit(wb, args[0], editor=cmd)
            return int(0)

    # default to print / after directories
    if cmd == 'ls': args.insert(0, '-F')

    if cmd == 'ls' or cmd == "stat" or cmd == "xrdstat" or cmd == "rm" or cmd == "lfn2guid":
        # or cmd == "find" # find expect pattern after lfn, and if pattern is . it will be replaced with current dir
        for i, arg in enumerate(args):
            if args[i][0] != '-':
                args[i] = expand_path_grid(args[i])
                args[i] = re.sub(r"\/{2,}", "/", args[i])

    if not (DEBUG or JSON_OUT or JSONRAW_OUT): args.insert(0, '-nokeys')
    result = await SendMsg(wb, cmd, args)
    if message_begin:
        message_delta = (datetime.now().timestamp() - message_begin) * 1000
        print(f">>>   Roundtrip for send/receive: {message_delta:.3f} ms", flush = True)
    return int(ProcessReceivedMessage(result, shellcmd))


def ProcessReceivedMessage(message: str = '', shellcmd: Union[str, None] = None):
    """Process the printing/formating of the received message from the server"""
    if not message: return int(61)  # ENODATA
    global AlienSessionInfo
    json_dict = json.loads(message)
    AlienSessionInfo['currentdir'] = json_dict["metadata"]["currentdir"]

    error = json_dict.get("metadata").get("error", '')
    AlienSessionInfo['error'] = error

    exitcode = json_dict.get("metadata").get("exitcode", '0')
    AlienSessionInfo['exitcode'] = exitcode

    if JSON_OUT:  # print nice json for debug or json mode
        print(json.dumps(json_dict, sort_keys=True, indent=4), flush = True)
        return int(exitcode)
    if JSONRAW_OUT:  # print the raw byte stream received from the server
        print(message, flush = True)
        return int(exitcode)

    if error and exitcode and (exitcode != "0"): print(f'exitcode: {exitcode} ; err: {error}', flush = True)

    websocket_output = '\n'.join(str(item['message']) for item in json_dict['results'])
    if not websocket_output:
        if not exitcode: exitcode = 61  # ENODATA
        return int(exitcode)

    if shellcmd:
        shell_run = subprocess.run(shellcmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, input=websocket_output, encoding='ascii', shell=True, env=os.environ)
        stdout = shell_run.stdout
        if stdout: print(stdout, flush = True)
        stderr = shell_run.stderr
        if stderr: print(stderr, flush = True)
    else:
        print(websocket_output, flush = True)

    return int(exitcode)


async def JAlien(commands: str = ''):
    """Main entry-point for interaction with AliEn"""
    global AlienSessionInfo

    wb = await InitConnection()  # we are doing the connection recovery and exception treatment in AlienConnect()

    # Command mode interaction
    if commands:
        cmds_tokens = commands.split(";")
        for token in cmds_tokens: await ProcessInput(wb, token, None)
        return int(AlienSessionInfo['exitcode'])

    # Begin Shell-like interaction
    if has_readline: setupHistory()  # enable history saving

    print('Welcome to the ALICE GRID\nsupport mail: adrian.sevcenco@cern.ch\n', flush=True)
    while True:
        signal.signal(signal.SIGINT, signal_handler)
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

            # make sure we have with whom to talk to; if not, lets redo the connection
            # we can consider any message/reply pair as atomic, we cannot forsee and treat the connection lost in the middle of reply
            # (if the end of message frame is not received then all message will be lost as it invalidated)
            try:
                ping = await wb.ping()
            except Exception as e:
                logging.debug(traceback.format_exc())
                wb = await InitConnection()

            await ProcessInput(wb, ' '.join(input_list), pipe_to_shell_cmd)


def main():
    global JSON_OUT, JSONRAW_OUT

    MSG_LVL = logging.ERROR
    if DEBUG: MSG_LVL = logging.DEBUG
    log = logging.basicConfig(filename = DEBUG_FILE, filemode = 'w', level = MSG_LVL)

    logger_wb = logging.getLogger('websockets')
    logger_wb.setLevel(MSG_LVL)

    # at exit delete all temporary files
    atexit.register(cleanup_temp)

    sys.argv.pop(0)  # remove the name of the script(alien.py)
    if '-json' in sys.argv:
        sys.argv.remove('-json')
        JSON_OUT = 1
    if '-jsonraw' in sys.argv:
        sys.argv.remove('-jsonraw')
        JSONRAW_OUT = 1

    cmd_string = ' '.join(sys.argv)
    asyncio.get_event_loop().run_until_complete(JAlien(cmd_string))
    os._exit(int(AlienSessionInfo['exitcode']))


if __name__ == '__main__':
    main()
