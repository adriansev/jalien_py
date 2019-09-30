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
from typing import NamedTuple
import OpenSSL
import shlex
import argparse
# import tempfile
from datetime import datetime
from pathlib import Path
from enum import Enum
from urllib.parse import urlparse
import asyncio
import websockets
# import websockets.speedups

try:
    import readline
    has_readline = True
except ImportError:
    has_readline = False

if sys.version_info[0] != 3 or sys.version_info[1] < 6:
    print("This script requires a minimum of Python version 3.6", flush = True)
    sys.exit(1)

# environment debug variable
DEBUG = os.getenv('ALIENPY_DEBUG', '')
DEBUG_WS = os.getenv('ALIENPY_DEBUG_WS', '')
XRDDEBUG = os.getenv('ALIENPY_XRDDEBUG', '')
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


async def getEnvelope(websocket, lfn_list = [], specs = [], isWrite = bool(False)):
    if not websocket: return
    access_list = []
    if not lfn_list: return access_list
    access_type = 'read'
    if isWrite: access_type = 'write'
    for lfn in lfn_list:
        get_envelope_arg_list = [access_type, lfn]
        if not DEBUG: get_envelope_arg_list.insert(0, '-nomsg')
        if specs: get_envelope_arg_list.append(str(",".join(specs)))
        await websocket.send(CreateJsonCommand('access', get_envelope_arg_list))
        result = await websocket.recv()
        access_list.append({"lfn": lfn, "answer": result})
    return access_list


def setDst(file = '', parent = 0):
    p = Path(file)
    filename = p.parts[0]
    if parent >= (len(p.parts) - 1): parent = len(p.parts) - 1 - 1
    basedir = p.parents[parent].as_posix()
    if basedir == '/':
        return file
    else:
        return p.as_posix().replace(p.parents[parent].as_posix(), '', 1)


def expand_path_local(path):
    exp_path = path.replace("file://", "")
    # exp_path_components = list(filter(None, exp_path.split("/")))
    exp_path = re.sub(r"^\~", Path.home().as_posix() + "/", exp_path)
    exp_path = re.sub(r"^\/*\.{2}", Path.cwd().parents[0].as_posix() + "/", exp_path)
    exp_path = re.sub(r"^\/*\.{1}", Path.cwd().as_posix() + "/", exp_path)
    if not exp_path.startswith('/'):
        exp_path = Path.cwd().as_posix() + "/" + exp_path
    exp_path = re.sub(r"\/{2,}", "/", exp_path)
    return exp_path


def expand_path_grid(path):
    exp_path = re.sub(r"\/*\%ALIEN", AlienSessionInfo['alienHome'], path)
    exp_path = re.sub(r"^\/*\.{2}", Path(AlienSessionInfo['currentdir']).parents[0].as_posix(), exp_path)
    exp_path = re.sub(r"^\/*\.{1}", AlienSessionInfo['currentdir'], exp_path)
    if not exp_path.startswith('/'):
        path_components = path.split("/")
        r = re.compile(path_components[0] + "\\/*")
        matches = list(filter(r.match, AlienSessionInfo['cwd_list']))
        if matches:
            exp_path = AlienSessionInfo['currentdir'] + "/" + exp_path
    exp_path = re.sub(r"\/{2,}", "/", exp_path)
    return exp_path


async def ProcessXrootdCp(websocket, xrd_copy_command = []):
    if not websocket: return int(107)  # ENOTCONN /* Transport endpoint is not connected */
    if not AlienSessionInfo:
        print('Session information like home and current directories needed', flush = True)
        return int(126)  # ENOKEY /* Required key not available */

    if len(xrd_copy_command) < 2 or xrd_copy_command == '-h':
        xrdcp_help()
        return int(64)  # EX_USAGE /* command line usage error */

    tmpdir = os.getenv('TMPDIR', '/tmp')

    # xrdcp parameters (used by ALICE tests)
    # http://xrootd.org/doc/man/xrdcp.1.html

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

    # Size of a single data chunk handled by xrdcp / XrdCl::CopyProcess.
    if not os.getenv('XRD_CPCHUNKSIZE'): os.environ["XRD_CPCHUNKSIZE"] = "128"

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
    streams = int(0)  # uses num additional parallel streams to do the transfer. The maximum value is 15. The default is 0 (i.e., use only the main stream).
    chunks = int(1)  # number of chunks that should be requested in parallel
    chunksize = int(4194304)  # chunk size for remote transfers
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

    if '-T' in xrd_copy_command:
        batch_idx = xrd_copy_command.index('-T')
        batch = int(xrd_copy_command.pop(batch_idx + 1))
        xrd_copy_command.pop(batch_idx)

    if '-chunks' in xrd_copy_command:
        chunks_nr_idx = xrd_copy_command.index('-chunks')
        chunks_nr = int(xrd_copy_command.pop(chunks_nr_idx + 1))
        xrd_copy_command.pop(chunks_nr_idx)

    if '-chunksz' in xrd_copy_command:
        chksz_idx = xrd_copy_command.index('-chunksz')
        chunksize = int(xrd_copy_command.pop(chksz_idx + 1))
        xrd_copy_command.pop(chksz_idx)

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

    pattern = '.*'  # default pattern
    if '-select' in xrd_copy_command:
        select_idx = xrd_copy_command.index('-select')
        pattern = xrd_copy_command.pop(select_idx + 1)
        xrd_copy_command.pop(select_idx)

    # list of src files and coresponding dst names
    src_filelist = []
    dst_filelist = []

    # clean up and prepare the paths to be used in the xrdcp command
    src = ''
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
        src_type = await pathtype_grid(websocket, src)
        if src_type == "NoValidType":
            print("Could not determine the type of src argument.. is it missing?")
            return int(42)  # ENOMSG /* No message of desired type */
        if src_type == 'd': isSrcDir = bool(True)

    dst = ''
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
        dst_type = await pathtype_grid(websocket, dst)
        if dst_type == "NoValidType":
            print("Could not determine the type of dst argument.. is it missing?")
            return int(42)  # ENOMSG /* No message of desired type */
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
            await websocket.send(CreateJsonCommand('find', find_args))
            result = await websocket.recv()
            src_list_files_dict = json.loads(result.encode('ascii', 'ignore'))
            for file in src_list_files_dict['results']:
                src_filelist.append(file['lfn'])
                src_path = Path(src)
                if parent > (len(src_path.parents) - 1): parent = len(src_path.parents) - 1  # make sure maximum parent var point to first dir in path
                src_root = src_path.parents[parent].as_posix()
                if src_root != '/':
                    file_relative_name = file['lfn'].replace(src_root, '')
                else:
                    file_relative_name = file['lfn']
                dst_file = dst + "/" + file_relative_name  # setDst(file['lfn'], parent)
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
            list = []
            for root, dirs, files in os.walk(src[:-1]):
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

    if XRDDEBUG:
        print("We are going to copy these files:", flush = True)
        for src_dbg, dst_dbg in zip(src_filelist, dst_filelist):
            print(f"src: {src_dbg}\ndst: {dst_dbg}\n", flush = True)

    lfn_list = []
    if isDownload:
        lfn_list = src_filelist
    else:
        lfn_list = dst_filelist

    envelope_list = await getEnvelope(websocket, lfn_list, specs, isWrite)

    # print errors
    errors_idx = []
    for item_idx, item in enumerate(envelope_list):
        lfn = item["lfn"]
        result = item["answer"]
        access_request = json.loads(result.encode('ascii', 'ignore'))
        if access_request["metadata"]["error"]:
            errors_idx.append(item_idx)
            error = access_request["metadata"]["error"]
            print(f"lfn: {lfn} --> {error}", flush = True)
        if XRDDEBUG:
            print(lfn, flush = True)
            print(json.dumps(access_request, sort_keys=True, indent=4), flush = True)

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
            access_request = json.loads(result.encode('ascii', 'ignore'))
            if not access_request['results']: continue

            dst = dst_filelist[item_idx]
            size_4meta = access_request['results'][0]['size']  # size SHOULD be the same for all replicas
            md5_4meta = access_request['results'][0]['md5']  # the md5 hash SHOULD be the same for all replicas

            # ALWAYS check if exist and valid. There is no scenario where the download is required even if the md5sums match
            if os.path.isfile(dst):  # first check
                if int(os.stat(dst).st_size) != int(size_4meta): os.remove(dst)
            if os.path.isfile(dst):  # if the existent file survived the size check
                if md5(dst) != md5_4meta: os.remove(dst)
            if os.path.isfile(dst):  # if the existent file survived the md5sum check
                print("File is already downloaded and size and md5 match the remote", flush = True)
                continue

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
            access_request = json.loads(result.encode('ascii', 'ignore'))
            for server in access_request['results']:
                if not server: continue
                complete_url = server['url'] + "?" + "authz=" + server['envelope']
                url_list_dst.append({"url": complete_url})
                url_list_src.append({"url": src})

    if XRDDEBUG:
        print("List of files:", flush = True)
        for src_dbg, dst_dbg in zip(url_list_src, url_list_dst):
            print("src:{0}\ndst:{1}\n".format(src_dbg['url'], dst_dbg['url']), flush = True)

    my_cp_args = XrdCpArgs(overwrite, batch, sources, chunks, chunksize, makedir, posc, hashtype, streams)

    if not (url_list_src or url_list_dst):
        print("copy src/dst lists are empty, no copy process to be started", flush = True)
        return int(2)  # ENOENT /* No such file or directory */
    # defer the list of url and files to xrootd processing - actual XRootD copy takes place
    token_list_upload_ok = XrdCopy(url_list_src, url_list_dst, isDownload, my_cp_args)

    if (not isDownload) and token_list_upload_ok:  # it was an upload job that had succesfull uploads
        for item_idx, item in enumerate(envelope_list):
            result = item["answer"]
            access_request = json.loads(result.encode('ascii', 'ignore'))
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
                        await websocket.send(CreateJsonCommand('commit', commit_args_list))
                        commit_results = await websocket.recv()  # useless return message
                        if XRDDEBUG: print(json.dumps(json.loads(commit_results), sort_keys=True, indent=4), flush = True)

    # hard to return a single exitcode for a copy process optionally spanning multiple files
    # we'll return SUCCESS if at least one lfn is confirmed, FAIL if not lfns is confirmed
    if token_list_upload_ok:
        return int(0)
    else:
        return int(1)


def XrdCopy(src, dst, isDownload = bool(True), xrd_cp_args = None):
    if not xrd_cp_args: return
    from XRootD import client

    overwrite = xrd_cp_args.overwrite
    batch = xrd_cp_args.batch
    sources = xrd_cp_args.sources
    chunks = xrd_cp_args.chunks
    chunksize = xrd_cp_args.chunksize
    makedir = xrd_cp_args.makedir
    posc = xrd_cp_args.posc
    hashtype = xrd_cp_args.hashtype
    streams = xrd_cp_args.streams

    def cursor_up(lines = 1):
        if lines < 1: lines = 1
        for k in range(lines):
            sys.stdout.write('\x1b[1A')
            sys.stdout.flush()

    def cursor_down(lines = 1):
        if lines < 1: lines = 1
        for k in range(lines):
            sys.stdout.write('\x1b[1B')
            sys.stdout.flush()

    def cursor_right(pos = 1):
        if pos < 1: pos = 1
        for k in range(pos):
            sys.stdout.write('\x1b[1C')
            sys.stdout.flush()

    def cursor_left(pos = 1):
        if pos < 1: pos = 1
        for k in range(pos):
            sys.stdout.write('\x1b[1D')
            sys.stdout.flush()

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
            if XRDDEBUG:
                print("CopyProgressHandler.src: {0}\nCopyProgressHandler.dst: {1}\n".format(self.src, self.dst), flush = True)

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
        if XRDDEBUG: print("\nadd copy job with\nsrc: {0}\ndst: {1}\n".format(url_src['url'], url_dst['url']), flush = True)
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


def create_metafile(meta_filename, local_filename, size, hash_val, replica_list = []):
    published = str(datetime.now().replace(microsecond=0).isoformat())
    with open(meta_filename, 'w') as f:
        f.write('<?xml version="1.0" encoding="UTF-8"?>\n')
        f.write(' <metalink xmlns="urn:ietf:params:xml:ns:metalink">\n')
        f.write("   <published>{}</published>\n".format(published))
        f.write("   <file name=\"{}\">\n".format(local_filename))
        f.write("     <size>{}</size>\n".format(size))
        if hash_val: f.write("     <hash type=\"md5\">{}</hash>\n".format(hash_val))
        for url in replica_list:
            f.write("     <url><![CDATA[{}]]></url>\n".format(url))
        f.write('   </file>\n')
        f.write(' </metalink>\n')
        f.closed


def make_tmp_fn(lfn = ''):
    ext = '_' + str(os.getuid()) + '.alienpy_tmp'
    if not lfn:
        return os.getenv('TMPDIR', '/tmp') + '/' + str(uuid.uuid4()) + ext
    return os.getenv('TMPDIR', '/tmp') + '/' + lfn.replace("/", '%%') + ext


async def download_tmp(websocket, lfn):
    tmpfile = make_tmp_fn(expand_path_grid(lfn))
    copycmd = "-f " + lfn + " " + 'file://' + tmpfile
    result = await ProcessXrootdCp(websocket, copycmd.split())
    if result == 0: return tmpfile


async def upload_tmp(websocket, temp_file_name, upload_specs = ''):
    # lets recover the lfn from temp file name
    lfn = temp_file_name.replace('_' + str(os.getuid()) + '.alienpy_tmp', '')
    lfn = lfn.replace(os.getenv('TMPDIR', '/tmp') + '/', '')
    lfn = lfn.replace("%%", "/")

    envelope_list = await getEnvelope(websocket, [lfn])
    result = envelope_list[0]["answer"]
    access_request = json.loads(result.encode('ascii', 'ignore'))
    replicas = access_request["results"][0]["nSEs"]

    # let's create a backup of old lfn
    mod_time = f"{datetime.now():%Y%m%d_%H%M%S}"
    lfn_backup = lfn + "_" + mod_time
    await websocket.send(CreateJsonCommand('mv', [lfn, lfn_backup]))
    result = await websocket.recv()
    json_dict = json.loads(result.lstrip().encode('ascii', 'ignore'))
    if json_dict["metadata"]["exitcode"] != '0':
        print("Could not create backup of lfn : {}", lfn)
        return 1

    if "disk:" not in upload_specs:
        upload_specs = "disk:" + replicas

    if upload_specs: lfn = lfn + "," + upload_specs
    copycmd = "-f " + 'file://' + temp_file_name + " " + lfn
    list_upload = await ProcessXrootdCp(websocket, copycmd.split())
    if list_upload: return lfn


async def DO_cat(websocket, lfn):
    lfn_path = expand_path_grid(lfn)
    tmp = make_tmp_fn(lfn_path)
    if tmp in AlienSessionInfo['templist']:
        runShellCMD('cat ' + tmp)
    else:
        tmp = await download_tmp(websocket, lfn)
        if tmp:
            AlienSessionInfo['templist'].append(tmp)
            runShellCMD('cat ' + tmp)


async def DO_less(websocket, lfn):
    lfn_path = expand_path_grid(lfn)
    tmp = make_tmp_fn(lfn_path)
    if tmp in AlienSessionInfo['templist']:
        runShellCMD('less ' + tmp)
    else:
        tmp = await download_tmp(websocket, lfn)
        if tmp:
            AlienSessionInfo['templist'].append(tmp)
            runShellCMD('less ' + tmp)


async def DO_more(websocket, lfn):
    lfn_path = expand_path_grid(lfn)
    tmp = make_tmp_fn(lfn_path)
    if tmp in AlienSessionInfo['templist']:
        runShellCMD('more ' + tmp)
    else:
        tmp = await download_tmp(websocket, lfn)
        if tmp:
            AlienSessionInfo['templist'].append(tmp)
            runShellCMD('more ' + tmp)


async def DO_edit(websocket, lfn, editor='mcedit'):
    if editor == 'mcedit': editor = 'mc -c -e'
    editor = editor + " "
    lfn_path = expand_path_grid(lfn)
    tmp = make_tmp_fn(lfn_path)
    if tmp in AlienSessionInfo['templist']:
        runShellCMD(editor + tmp, False)
    else:
        tmp = await download_tmp(websocket, lfn)
        if tmp:
            md5_begin = md5(tmp)
            AlienSessionInfo['templist'].append(tmp)
            runShellCMD(editor + tmp, False)
            md5_end = md5(tmp)
            if md5_begin != md5_end: await upload_tmp(websocket, tmp, '')


def cleanup_temp():
    if AlienSessionInfo['templist']:
        for f in AlienSessionInfo['templist']:
            if os.path.isfile(f): os.remove(f)


def md5(file):
    import hashlib
    BLOCKSIZE = 65536
    hasher = hashlib.md5()
    with open(file, 'rb') as f:
        buf = f.read(BLOCKSIZE)
        while len(buf) > 0:
            hasher.update(buf)
            buf = f.read(BLOCKSIZE)
    return hasher.hexdigest()


def signal_handler(sig, frame):
    print('\nExit')
    sys.exit(0)


def exit_message():
    print('\nExit')
    sys.exit(0)


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


def runShellCMD(INPUT = '', captureout = True):
    if not INPUT: return
    sh_cmd = re.sub(r'^!', '', INPUT)

    if captureout:
        args = sh_cmd
    else:
        args = shlex.split(sh_cmd)
    shcmd_out = subprocess.run(args, capture_output = captureout, shell = captureout, env=os.environ)

    stdout = shcmd_out.stdout
    if stdout: print(stdout.decode(), flush = True)
    stderr = shcmd_out.stderr
    if stderr: print(stderr.decode(), flush = True)


def CreateJsonCommand(command, options=[]):
    cmd_dict = {"command": command, "options": options}
    jcmd = json.dumps(cmd_dict)
    jcmd.encode('ascii', 'ignore')
    return jcmd


async def AlienSendCmd(wb = None, cmdline = ''):
    if not wb: return
    if not cmdline: return
    cmd_parts = cmdline.split(" ")
    cmd = cmd_parts.pop(0)
    await wb.send(CreateJsonCommand(cmd, cmd_parts))
    return await wb.recv()


def IsValidCert(fname):
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


def CertInfo(fname):
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
    # SSL SETTINGS
    usercert = os.getenv('X509_USER_CERT', Path.home().as_posix() + '/.globus' + '/usercert.pem')
    userkey = os.getenv('X509_USER_KEY', Path.home().as_posix() + '/.globus' + '/userkey.pem')
    tokencert = os.getenv('JALIEN_TOKEN_CERT', os.getenv('TMPDIR', '/tmp') + '/tokencert_' + str(os.getuid()) + '.pem')
    tokenkey = os.getenv('JALIEN_TOKEN_KEY', os.getenv('TMPDIR', '/tmp') + '/tokenkey_' + str(os.getuid()) + '.pem')

    capath_default = os.getenv('X509_CERT_DIR', '/etc/grid-security/certificates')
    if IsValidCert(tokencert):
        cert = tokencert
        key  = tokenkey
    else:
        cert = usercert
        key  = userkey

    ctx = ssl.SSLContext()
    # CERT_NONE, CERT_OPTIONAL, CERT_REQUIRED
    if os.getenv('ALIENPY_JBOX', ''):
        verify_mode = ssl.CERT_NONE
    else:
        verify_mode = ssl.CERT_REQUIRED
    ctx.verify_mode = verify_mode
    ctx.check_hostname = False
    ctx.load_verify_locations(capath = capath_default)
    ctx.load_verify_locations(capath = Path(usercert).parent)  # $HOME/.globus
    if os.getenv('ALIENPY_JBOX', ''):
        if Path(tokencert).exists() and IsValidCert(tokencert): ctx.load_verify_locations(cafile=tokencert)
        ctx.load_cert_chain(certfile=usercert, keyfile=userkey)
        # ctx.load_cert_chain(certfile=cert, keyfile=key)
    else:
        ctx.load_cert_chain(certfile=cert, keyfile=key)
    return ctx


async def AlienConnect():
    ssl_context = None
    if os.getenv('ALIENPY_JBOX', ''):
        jalien_server = 'localhost'
    else:
        jalien_server = 'alice-jcentral.cern.ch'

    jalien_websocket_port = 8097  # websocket port
    jalien_websocket_path = '/websocket/json'

    wb_protol = 'wss://'
    fHostWSUrl = wb_protol + jalien_server + ':' + str(jalien_websocket_port) + jalien_websocket_path

    if wb_protol == 'wss://': ssl_context = create_ssl_context()  # will check validity of token and if invalid cert will be usercert

    if DEBUG: print("Connecting to : ", fHostWSUrl, flush = True)
    """https://websockets.readthedocs.io/en/stable/api.html#websockets.protocol.WebSocketCommonProtocol"""
    # we use some conservative values, higher than this might hurt the sensitivity to intreruptions
    websocket = None
    try:
        websocket = await websockets.connect(fHostWSUrl, ssl=ssl_context, max_queue=4, max_size=16 * 1024 * 1024, ping_interval=50, ping_timeout=20, close_timeout=20)
    except websockets.exceptions.ConnectionClosedError:
        print("ConnectionError closed", flush = True)
    except websockets.exceptions.ConnectionClosed:
        print("Connection closed", flush = True)
    except Exception as e:
        logging.error(traceback.format_exc())

    if websocket:
        return websocket
    else:
        await AlienConnect()


async def InitConnection():
    usercert = os.getenv('X509_USER_CERT', Path.home().as_posix() + '/.globus' + '/usercert.pem')
    userkey = os.getenv('X509_USER_KEY', Path.home().as_posix() + '/.globus' + '/userkey.pem')
    tokencert = os.getenv('JALIEN_TOKEN_CERT', os.getenv('TMPDIR', '/tmp') + '/tokencert_' + str(os.getuid()) + '.pem')
    tokenkey = os.getenv('JALIEN_TOKEN_KEY', os.getenv('TMPDIR', '/tmp') + '/tokenkey_' + str(os.getuid()) + '.pem')
    # implement a time command for measurement of sent/recv delay
    init_begin = None
    init_delta = None
    if TIME_CONNECT:
        init_begin = datetime.now().timestamp()

    websocket = await AlienConnect()

    # if the certificate used is not the token, then get one
    if not IsValidCert(tokencert): await token(websocket, tokencert, tokenkey)

    # no matter if command or interactive mode, we need alienHome, currentdir, user and commandlist
    if not AlienSessionInfo['commandlist']: await getSessionVars(websocket)
    if init_begin:
        init_delta = datetime.now().timestamp() - init_begin
        print(">>>   Time for websocket initialization + sessionVars : {}".format(init_delta), flush = True)
    return websocket


async def token(websocket, tokencert, tokenkey):
    if not websocket: return
    await websocket.send(CreateJsonCommand('token', ['-nomsg']))
    result = await websocket.recv()
    json_dict = json.loads(result.lstrip().encode('ascii', 'ignore'))

    tokencert_content = json_dict['results'][0]["tokencert"]
    tokenkey_content  = json_dict['results'][0]["tokenkey"]

    if os.path.isfile(tokencert): os.chmod(tokencert, 0o700)  # make it writeable
    with open(tokencert, "w") as tcert: print(f"{tokencert_content}", file=tcert)  # write the tokencert
    os.chmod(tokencert, 0o400)  # make it readonly

    if os.path.isfile(tokenkey): os.chmod(tokenkey, 0o700)  # make it writeable
    with open(tokenkey, "w") as tkey: print(f"{tokenkey_content}", file=tkey)  # write the tokenkey
    os.chmod(tokenkey, 0o400)  # make it readonly


async def getSessionVars(websocket):
    if not websocket: return
    global AlienSessionInfo
    # get the command list to check validity of commands
    await websocket.send(CreateJsonCommand('commandlist'))
    result = await websocket.recv()
    json_dict = json.loads(result.lstrip().encode('ascii', 'ignore'))
    # first executed commands, let's initialize the following (will re-read at each ProcessReceivedMessage)
    cmd_list = json_dict["results"][0]['message'].split()
    regex = re.compile(r'.*_csd$')
    AlienSessionInfo['commandlist'] = [i for i in cmd_list if not regex.match(i)]
    AlienSessionInfo['commandlist'].sort()
    AlienSessionInfo['user'] = json_dict["metadata"]["user"]

    # if we were intrerupted and re-connect than let's get back to the old currentdir
    if AlienSessionInfo['currentdir'] and not AlienSessionInfo['currentdir'] == json_dict["metadata"]["currentdir"]:
        await websocket.send(CreateJsonCommand('cd', [AlienSessionInfo['currentdir']]))
    AlienSessionInfo['currentdir'] = json_dict["metadata"]["currentdir"]
    if not AlienSessionInfo['alienHome']: AlienSessionInfo['alienHome'] = AlienSessionInfo['currentdir']  # this is first query so current dir is alienHOME


async def cwd_list(websocket):
    if not websocket: return
    await websocket.send(CreateJsonCommand('ls', ['-nokeys', '-F']))
    result = await websocket.recv()
    result_dict = json.loads(result.lstrip().encode('ascii', 'ignore'))
    AlienSessionInfo['cwd_list'] = list(item['message'] for item in result_dict['results'])


async def pathtype_grid(websocket, path=''):
    if not websocket: return
    if not path: return
    await websocket.send(CreateJsonCommand('stat', ['-nomsg', path]))
    result = await websocket.recv()
    json_dict = json.loads(result.lstrip().encode('ascii', 'ignore'))

    error = json_dict["metadata"]["error"]
    if error:
        print(f"Stat cmd for {path} returned: {error}")
        return str("NoValidType")
    return str(json_dict['results'][0]["type"])


def pathtype_local(path=''):
    if not path: return
    p = Path(path)
    if p.is_dir(): return str('d')
    if p.is_file(): return str('f')
    return str('')


async def ProcessInput(websocket, cmd_string = '', shellcmd = None):
    if not cmd_string: return
    global AlienSessionInfo
    args = cmd_string.split(" ")
    cmd = args.pop(0)

    cwd_grid_path = Path(AlienSessionInfo['currentdir'])
    home_grid_path = Path(AlienSessionInfo['alienHome'])
    await cwd_list(websocket)  # let's start knowing what is the content of grid current dir

    usercert = os.getenv('X509_USER_CERT', Path.home().as_posix() + '/.globus' + '/usercert.pem')
    userkey = os.getenv('X509_USER_KEY', Path.home().as_posix() + '/.globus' + '/userkey.pem')
    tokencert = os.getenv('JALIEN_TOKEN_CERT', os.getenv('TMPDIR', '/tmp') + '/tokencert_' + str(os.getuid()) + '.pem')
    tokenkey = os.getenv('JALIEN_TOKEN_KEY', os.getenv('TMPDIR', '/tmp') + '/tokenkey_' + str(os.getuid()) + '.pem')

    # implement a time command for measurement of sent/recv delay
    message_begin = None
    message_delta = None

    if cmd == 'time':
        if not args:
            print("time needs as argument a command", flush = True)
            return int(64)  # EX_USAGE /* command line usage error */
        else:
            cmd = args.pop(0)
            message_begin = datetime.now().timestamp()

    if cmd == 'certinfo':
        AlienSessionInfo['exitcode'] = CertInfo(usercert)
        return AlienSessionInfo['exitcode']

    if cmd == 'token':
        if len(args) > 0 and args[0] == 'refresh':
            os.remove(tokencert)
            os.remove(tokenkey)
            try:
                websocket = await InitConnection()
            except Exception as e:
                logging.error(traceback.format_exc())
                websocket = await InitConnection()
            return int(0)
        if not args or (len(args) > 0 and args[0] == 'info'):
            AlienSessionInfo['exitcode'] = CertInfo(tokencert)
            return AlienSessionInfo['exitcode']

    if (cmd == "?") or (cmd == "help"):
        if len(args) > 0:
            cmd = args.pop(0)
            if cmd in AlienSessionInfo['commandlist']:
                args.clear()
                args.append('-h')
        else:
            print(' '.join(AlienSessionInfo['commandlist']), flush = True)
            return int(0)
    elif (cmd.startswith("cat")):
        if args[0] != '-h':
            await DO_cat(websocket, args[0])
            return int(0)
    elif (cmd.startswith("less")):
        if args[0] != '-h':
            await DO_less(websocket, args[0])
            return int(0)
    elif (cmd == 'mcedit' or cmd == 'vi' or cmd == 'nano' or cmd == 'vim'):
        if args[0] != '-h':
            await DO_edit(websocket, args[0], editor=cmd)
            return int(0)
    elif (cmd == 'edit' or cmd == 'sensible-editor'):
        EDITOR = os.getenv('EDITOR', '')
        if not EDITOR:
            print('No EDITOR variable set up!', flush = True)
            return int(22)  # EINVAL /* Invalid argument */
        cmd = EDITOR
        if args[0] != '-h':
            await DO_edit(websocket, args[0], editor=cmd)
            return int(0)
    elif cmd.startswith("cp"):  # defer cp processing to ProcessXrootdCp
        exitcode = await ProcessXrootdCp(websocket, args)
        AlienSessionInfo['exitcode'] = exitcode
        return int(exitcode)
    elif cmd == 'ls' or cmd == "stat" or cmd == "xrdstat" or cmd == "rm" or cmd == "lfn2guid":
        # or cmd == "find" # find expect pattern after lfn, and if pattern is . it will be replaced with current dir
        for i, arg in enumerate(args):
            args[i] = expand_path_grid(args[i])
            args[i] = re.sub(r"\/{2,}", "/", args[i])

    if not DEBUG: args.insert(0, '-nokeys')
    jsoncmd = CreateJsonCommand(cmd, args)  # make json with cmd and the list of arguments
    if DEBUG: print(f'send json: {jsoncmd}', flush = True)

    await websocket.send(jsoncmd)
    result = await websocket.recv()
    if message_begin:
        message_delta = datetime.now().timestamp() - message_begin
        print(">>>   Time for send/receive command : {}".format(message_delta), flush = True)
    return int(ProcessReceivedMessage(result, shellcmd))


def ProcessReceivedMessage(message='', shellcmd = None):
    if not message: return int(61)  # ENODATA
    global AlienSessionInfo
    json_dict = json.loads(message.lstrip().encode('ascii', 'ignore'))
    AlienSessionInfo['currentdir'] = json_dict["metadata"]["currentdir"]

    error = ''
    if 'error' in json_dict["metadata"]:
        error = json_dict["metadata"]["error"]
        AlienSessionInfo['error'] = error

    exitcode = '0'  # use a default value for cases where exitcode is missing
    if 'exitcode' in json_dict["metadata"]:
        exitcode = json_dict["metadata"]["exitcode"]
        AlienSessionInfo['exitcode'] = exitcode

    if DEBUG:
        print(json.dumps(json_dict, sort_keys=True, indent=4), flush = True)
        return int(exitcode)

    if error and exitcode and (exitcode != "0"): print(f'exitcode: {exitcode} ; err: {error}', flush = True)

    websocket_output = '\n'.join(str(item['message']) for item in json_dict['results'])
    if not websocket_output:
        if not exitcode: exitcode = 61  # ENODATA
        return int(exitcode)

    if shellcmd:
        # shlex.split(shellcmd)
        # shlex.quote(shellcmd)
        shell_run = subprocess.run(shellcmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, input=websocket_output, encoding='ascii', shell=True, env=os.environ)
        stdout = shell_run.stdout
        if stdout: print(stdout, flush = True)
        stderr = shell_run.stderr
        if stderr: print(stderr, flush = True)
    else:
        print(websocket_output, flush = True)

    return int(exitcode)


async def JAlien(commands = ''):
    global AlienSessionInfo

    try:
        websocket = await InitConnection()
    except Exception as e:
        logging.error(traceback.format_exc())
        websocket = await InitConnection()

    # Command mode interaction
    if commands:
        cmds_tokens = commands.split(";")
        for token in cmds_tokens: await ProcessInput(websocket, token, None)
        return int(AlienSessionInfo['exitcode'])

    # Begin Shell-like interaction
    if has_readline:
        setupHistory()  # enable history saving

    while True:
        signal.signal(signal.SIGINT, signal_handler)
        INPUT = ''
        prompt = f"AliEn[{AlienSessionInfo['user']}]:{AlienSessionInfo['currentdir']}"
        if AlienSessionInfo['show_date']: prompt = prompt + " " + str(datetime.now().replace(microsecond=0).isoformat())
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
                    print("Arguments supported are : <date> for date information and <pwd> for local directory", flush = True)
                input_list.clear()
                continue

            # make sure we have with whom to talk to; if not, lets redo the connection
            # we can consider any message/reply pair as atomic, we cannot forsee and treat the connection lost in the middle of reply
            # (if the end of message frame is not received then all message will be lost as it invalidated)
            try:
                ping = await websocket.ping()
            except Exception as e:
                logging.error(traceback.format_exc())
                websocket = await InitConnection()

            await ProcessInput(websocket, ' '.join(input_list), pipe_to_shell_cmd)


def main():
    # at exit delete all temporary files
    atexit.register(cleanup_temp)

    # Let's start the connection
    logger = logging.getLogger('websockets')
    logger.setLevel(logging.ERROR)
    if DEBUG_WS:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.ERROR)
    logger.addHandler(logging.StreamHandler())

    # args = sys.argv
    sys.argv.pop(0)  # remove the name of the script(alien.py)
    cmd_string = ' '.join(sys.argv)
    asyncio.get_event_loop().run_until_complete(JAlien(cmd_string))
    os._exit(int(AlienSessionInfo['exitcode']))


if __name__ == '__main__':
    main()

