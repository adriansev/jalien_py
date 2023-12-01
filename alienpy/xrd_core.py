"""alienpy:: XRootD mechanics"""

import os
import datetime
import sys
import zipfile
import traceback
from urllib.parse import urlparse
import logging
import re
from pathlib import Path
import shlex
import subprocess
import uuid
import time
import xml.dom.minidom as MD  # noqa: N812
from typing import Optional, Union

from .version import ALIENPY_VERSION_STR
from .setup_logging import DEBUG, DEBUG_FILE, print_err, print_out
from .data_structs import CommitInfo, CopyFile, RET, XrdCpArgs, lfn2file
from .global_vars import AlienSessionInfo, COLORS, REGEX_PATTERN_TYPE, specs_split
from .wb_api import SendMsg, retf_print
from .tools_nowb import (GetHumanReadableSize, PrintColor, common_path, create_metafile, deltat_ms_perf,
                         fileIsValid, fileline2list, format_dst_fn, get_arg, get_arg_value, get_hash_meta, get_lfn_key, get_lfn_name, get_size_meta,
                         is_help, is_int, list_files_local, make_tmp_fn, md5, name2regex, now_str, path_local_stat, path_writable_any, valid_regex, unixtime2local)
from .xrd_tools import commitFileList, expand_path_grid, extract_glob_pattern, lfn2fileTokens, list_files_grid, path_grid_stat, path_type, pathtype_grid, xrdcp_help


HAS_XROOTD = False
try:
    from XRootD import client as xrd_client  # type: ignore
    from XRootD.client.flags import QueryCode, OpenFlags, AccessMode, StatInfoFlags, AccessType
    HAS_XROOTD = True
except Exception:
    print("XRootD module could not be imported! Not fatal, but XRootD transfers will not work (or any kind of file access)\n Make sure you can do:\npython3 -c 'from XRootD import client as xrd_client'", file = sys.stderr, flush = True)


def _is_valid_xrootd() -> bool:
    if not HAS_XROOTD: return False
    xrd_ver_arr = xrd_client.__version__.split(".")
    _XRDVER_1 = _XRDVER_2 = None
    if len(xrd_ver_arr) > 1:
        _XRDVER_1 = xrd_ver_arr[0][1:] if xrd_ver_arr[0].startswith('v') else xrd_ver_arr[0]  # take out the v if present
        _XRDVER_2 = xrd_ver_arr[1]
        return int(_XRDVER_1) >= 5 and int(_XRDVER_2) > 2

    # version is not of x.y.z form, this is git based form
    xrdver_git = xrd_ver_arr[0].split("-")
    _XRDVER_1 = xrdver_git[0][1:] if xrdver_git[0].startswith('v') else xrdver_git[0]  # take out the v if present
    _XRDVER_2 = xrdver_git[1]
    return int(_XRDVER_1) > 20211113


# use only 5.3 versions and up - reference point
HAS_XROOTD = _is_valid_xrootd()
HAS_XROOTD_GETDEFAULT = False
if HAS_XROOTD:
    def XRD_EnvPut(key: str, value: str) -> bool:  # noqa: ANN001,ANN201
        """Sets the given key in the xrootd client environment to the given value.
        Returns false if there is already a shell-imported setting for this key, true otherwise
        """
        if not key or not value: return False
        return xrd_client.EnvPutInt(key, int(value)) if ( str(value).isdigit() or isinstance(value, int) ) else xrd_client.EnvPutString(key, str(value))

    def XRD_EnvGet(key: str) -> Union[None, int, str]:  # noqa: ANN001,ANN201
        """Get the value of the key from xrootd"""
        if not key: return None
        val = None
        val = xrd_client.EnvGetString(key)
        if not val:
            val = xrd_client.EnvGetInt(key)
        return val  # noqa: R504

    # Override the application name reported to the xrootd server.
    XRD_EnvPut('XRD_APPNAME', f'alien.py/{ALIENPY_VERSION_STR} xrootd/{xrd_client.__version__}')
    HAS_XROOTD_GETDEFAULT = hasattr(xrd_client, 'EnvGetDefault')


def xrd_config_init() -> None:
    """Initialize generic XRootD client vars/timeouts"""
    if not HAS_XROOTD: return
    # xrdcp parameters (used by ALICE tests)
    # http://xrootd.org/doc/man/xrdcp.1.html
    # https://xrootd.slac.stanford.edu/doc/xrdcl-docs/www/xrdcldocs.html#x1-100004.2
    # xrootd defaults https://github.com/xrootd/xrootd/blob/master/src/XrdCl/XrdClConstants.hh

    # Resolution for the timeout events. Ie. timeout events will be processed only every XRD_TIMEOUTRESOLUTION seconds.
    if not os.getenv('XRD_TIMEOUTRESOLUTION'): XRD_EnvPut('TimeoutResolution', int(1))  # let's check the status every 1s; default 15

    # Number of connection attempts that should be made (number of available connection windows) before declaring a permanent failure.
    if not os.getenv('XRD_CONNECTIONRETRY'): XRD_EnvPut('ConnectionRetry', int(5))  # default 5

    # A time window for the connection establishment. A connection failure is declared if the connection is not established within the time window.
    # N.B.!!. If a connection failure happens earlier then another connection attempt will only be made at the beginning of the next window
    if not os.getenv('XRD_CONNECTIONWINDOW'): XRD_EnvPut('ConnectionWindow', int(10))  # default 120

    # Default value for the time after which an error is declared if it was impossible to get a response to a request.
    # N.B.!!. This is the total time for the initialization dialogue!! see https://xrootd.slac.stanford.edu/doc/xrdcl-docs/www/xrdcldocs.html#x1-580004.3.6
    if not os.getenv('XRD_REQUESTTIMEOUT'): XRD_EnvPut('RequestTimeout', int(1200))  # default 1800

    # Default value for the time after which a connection error is declared (and a recovery attempted) if there are unfulfilled requests and there is no socket activity or a registered wait timeout.
    # N.B.!!. we actually want this timeout for failure on onverloaded/unresponsive server. see https://github.com/xrootd/xrootd/issues/1597#issuecomment-1064081574
    if not os.getenv('XRD_STREAMTIMEOUT'): XRD_EnvPut('StreamTimeout', int(60))  # default 60

    # Maximum time allowed for the copy process to initialize, ie. open the source and destination files.
    if not os.getenv('XRD_CPINITTIMEOUT'): XRD_EnvPut('CPInitTimeout', int(300))  # default 600

    # Time period after which an idle connection to a data server should be closed.
    if not os.getenv('XRD_DATASERVERTTL'): XRD_EnvPut('DataServerTTL', int(20))  # we have no reasons to keep idle connections

    # Time period after which an idle connection to a manager or a load balancer should be closed.
    if not os.getenv('XRD_LOADBALANCERTTL'): XRD_EnvPut('LoadBalancerTTL', int(30))  # we have no reasons to keep idle connections

    # If set the client tries first IPv4 address (turned off by default).
    if not os.getenv('XRD_PREFERIPV4'): XRD_EnvPut('PreferIPv4', int(1))

    # https://github.com/xrootd/xrootd/blob/v5.6.3/docs/man/xrdcp.1#L592
    # If set to 1, use the checksum available in a metalink file even if a file is being extracted from a ZIP archive.
    XRD_EnvPut('ZipMtlnCksum', int(1))

    # Preserve xattrs by default
    # XRD_EnvPut('PreserveXAttr', int(1))


def xrdfile_set_attr(uri: str = '', xattr_list: Optional[list] = None):
    """For a given URI (token included) set the xattrs"""
    if not HAS_XROOTD or not uri or not xattr_list: return None
    mode = OpenFlags.READ | OpenFlags.UPDATE | OpenFlags.WRITE
    with xrd_client.File() as f:
        status, response = f.open(uri, mode)
        print(status)
        print(respons)

        status, list_of_statuses = f.set_xattr(attrs = xattr_list)
        print(status)
        for s in list_of_statuses:
            print(s[0])
            print(s[1])


def makelist_lfn(wb, arg_source: str, arg_target: str, find_args: Optional[list] = None, copy_list: Optional[list] = None,
                 pattern: Union[None, REGEX_PATTERN_TYPE, str] = None, parent: int = 999,
                 overwrite: bool = False, is_regex: bool = False, strictspec: bool = False, httpurl: bool = False) -> RET:  # pylint: disable=unused-argument
    """Process a source and destination copy arguments and make a list of individual lfns to be copied"""
    isSrcDir = isSrcLocal = isDownload = specs = None  # make sure we set these to valid values later
    if find_args is None: find_args = []
    if copy_list is None or not isinstance(copy_list, list):
        print_out('makelist_lfn:: copy_list arguments is not a list!!')
        return RET()

    # lets extract the specs from both src and dst if any (to clean up the file-paths) and record specifications like disk=3,SE1,!SE2
    src_specs_remotes = specs_split.split(arg_source, maxsplit = 1)  # NO comma allowed in names (hopefully)
    arg_src = src_specs_remotes.pop(0)  # first item is the file path, let's remove it; it remains disk specifications
    src_specs = src_specs_remotes.pop(0) if src_specs_remotes else None  # whatever remains is the specifications

    dst_specs_remotes = specs_split.split(arg_target, maxsplit = 1)
    arg_dst = dst_specs_remotes.pop(0)
    dst_specs = dst_specs_remotes.pop(0) if dst_specs_remotes else None

    arg_src = re.sub(r"^\/*\%ALIEN[\/\s]*", AlienSessionInfo['alienHome'], arg_src)  # replace %ALIEN token with user grid home directory
    arg_dst = re.sub(r"^\/*\%ALIEN[\/\s]*", AlienSessionInfo['alienHome'], arg_dst)  # replace %ALIEN token with user grid home directory

    # lets process the pattern: extract it from src if is in the path globbing form
    src_glob = False
    if '*' in arg_src:  # we have globbing in src path
        src_glob = True
        arg_src, pattern = extract_glob_pattern(arg_src)
    else:  # pattern is specified by argument
        if isinstance(pattern, REGEX_PATTERN_TYPE):  # unlikely but supported to match signatures
            pattern = pattern.pattern  # We pass the regex pattern into command as string
            is_regex = True

        # it was explictly requested that pattern is regex
        if is_regex and isinstance(pattern, str) and valid_regex(pattern) is None:
            msg = f"makelist_lfn:: {pattern} failed to re.compile"
            logging.error(msg)
            return RET(64, '', msg)  # EX_USAGE /* command line usage error */

    slashend_src = arg_src.endswith('/')  # after extracting the globbing if present we record the slash
    # N.B.!!! the check will be wrong when the same relative path is present local and on grid
    # first let's check only prefixes
    src, src_type = path_type(arg_src)
    dst, dst_type = path_type(arg_dst)

    isSrcLocal = src_type == 'local'
    isDownload = not isSrcLocal
    if isSrcLocal:  # UPLOAD
        src_stat = path_local_stat(src)
        dst_stat = path_grid_stat(wb, dst)
    else:           # DOWNLOAD
        src_stat = path_grid_stat(wb, src)
        dst_stat = path_local_stat(dst)
        if not path_writable_any(dst_stat.path) and parent <= 1:
            return RET(2, '', f'no write permission/or missing in any component of {dst_stat.path}')

    if src_type == dst_type == 'grid':
        return RET(1, '', 'grid to grid copy is WIP; for the moment use two steps: download file and upload it; local src,dst should be ALWAYS prefixed with file:')
    if src_type == dst_type == 'local':
        return RET(1, '', 'for local copy use system command; within interactiv shell start a system command with "!"')

    if not src_stat.type: return RET(2, '', f'Specified source {src_stat.path} not found!')

    src = src_stat.path
    dst = dst_stat.path

    if not src: return RET(2, '', f'{arg_src} => {src} does not exist (or not accessible) on {src_type}')  # ENOENT /* No such file or directory */

    if slashend_src:
        if not src.endswith('/'): src = f"{src}/"  # recover the slash if lost
        if not dst.endswith('/'): dst = f"{dst}/"  # if src is dir, dst must be dir

    isSrcDir = src_stat.type == 'd'
    if isSrcDir and not src_glob and not slashend_src: parent = parent + 1  # cp/rsync convention: with / copy the contents, without it copy the actual dir

    # prepare destination locations
    if isDownload:
        mk_path = Path(dst) if dst.endswith('/') else Path(dst).parent  # if destination is file create it dir parent
        try:  # we can try anyway, this is like mkdir -p
            mk_path.mkdir(parents=True, exist_ok=True)
        except Exception:
            logging.error(traceback.format_exc())
            msg = f"Could not create local destination directory: {mk_path.as_posix()}\ncheck log file {DEBUG_FILE}"
            return RET(42, '', msg)  # ENOMSG /* No message of desired type */
    else:  # this is upload to GRID
        mk_path = dst if dst.endswith('/') else Path(dst).parent.as_posix()
        if not dst_stat.type:  # dst does not exists
            ret_obj = SendMsg(wb, 'mkdir', ['-p', mk_path], opts = 'nomsg')  # do it anyway, there is not point in checking before
            if retf_print(ret_obj, opts = 'noprint err') != 0: return ret_obj  # just return the mkdir result  # noqa: R504

    specs = src_specs if isDownload else dst_specs  # only the grid path can have specs
    specs_list = specs_split.split(specs) if specs else []

    if strictspec: print_out("Strict specifications were enabled!! Command may fail!!")
    if httpurl and isSrcLocal:
        print_out("httpurl option is ignored for uploads")
        httpurl = False

    error_msg = ''  # container which accumulates the error messages
    isWrite = not isDownload
    if isDownload:  # pylint: disable=too-many-nested-blocks  # src is GRID, we are DOWNLOADING from GRID location
        # to reduce the remote calls we treat files and directory on separate code-paths
        if src_stat.type == 'f':  # single file
            dst_filename = format_dst_fn(src, src, dst, parent)
            # if overwrite the file validity checking will do md5

            skip_file = retf_print(fileIsValid(dst_filename, src_stat.size, src_stat.mtime, src_stat.md5, shallow_check = not overwrite), opts = 'noerr') == 0
            if not skip_file:
                tokens = lfn2fileTokens(wb, lfn2file(src, dst_filename), specs_list, isWrite, strictspec, httpurl)
                if tokens and 'answer' in tokens:
                    copy_list.append(CopyFile(src, dst_filename, isWrite, tokens['answer'], src))
        else:  # directory to be listed
            results_list = list_files_grid(wb, src, pattern, is_regex, " ".join(find_args))
            if "results" not in results_list.ansdict or len(results_list.ansdict["results"]) < 1:
                msg = f"No files found with: find {' '.join(find_args) if find_args else ''}{' -r ' if is_regex else ''} -a -s {src} {pattern}"
                return RET(42, '', msg)  # ENOMSG /* No message of desired type */

            for lfn_obj in results_list.ansdict["results"]:  # make CopyFile objs for each lfn
                lfn = get_lfn_key(lfn_obj)
                dst_filename = format_dst_fn(src, lfn, dst, parent)
                # if overwrite the file validity checking will do md5
                skip_file = retf_print(fileIsValid(dst_filename, lfn_obj['size'], lfn_obj['ctime'], lfn_obj['md5'], shallow_check = not overwrite), opts = 'noerr') == 0
                if skip_file: continue  # destination exists and is valid, no point to re-download

                tokens = lfn2fileTokens(wb, lfn2file(lfn, dst_filename), specs_list, isWrite, strictspec, httpurl)
                if not tokens or 'answer' not in tokens: continue
                copy_list.append(CopyFile(lfn, dst_filename, isWrite, tokens['answer'], lfn))

    else:  # src is LOCAL, we are UPLOADING
        results_list = list_files_local(src, pattern, is_regex, " ".join(find_args))
        if "results" not in results_list.ansdict or len(results_list.ansdict["results"]) < 1:
            msg = f"No files found in: {src} /pattern: {pattern} /find_args: {' '.join(find_args)}"
            return RET(42, '', msg)  # ENOMSG /* No message of desired type */

        for file in results_list.ansdict["results"]:
            file_path = get_lfn_key(file)
            lfn = format_dst_fn(src, file_path, dst, parent)
            lfn_dst_stat = path_grid_stat(wb, lfn)  # check each destination lfn
            if lfn_dst_stat.type == 'f':  # lfn exists
                if not overwrite:
                    print_out(f'{lfn} exists, skipping..')
                    continue
                md5sum = md5(file_path)
                if md5sum == lfn_dst_stat.md5:
                    print_out(f'{lfn} exists and md5 match, skipping..')
                    continue
                print_out(f'{lfn} exists and md5 does not match, deleting..')  # we want to overwrite so clear up the destination lfn
                ret_obj = SendMsg(wb, 'rm', ['-f', lfn], opts = 'nomsg')

            tokens = lfn2fileTokens(wb, lfn2file(lfn, file_path), specs_list, isWrite, strictspec)
            if not tokens or 'answer' not in tokens: continue
            copy_list.append(CopyFile(file_path, lfn, isWrite, tokens['answer'], lfn))
    return RET(1, '', error_msg) if error_msg else RET(0)


def makelist_xrdjobs(copylist_lfns: list, copylist_xrd: list) -> None:
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
            AlienSessionInfo['templist'].append(metafile)
            if file_in_zip and 'ALIENPY_NOXRDZIP' not in os.environ: metafile = f'{metafile}?xrdcl.unzip={file_in_zip}'
            if DEBUG: print_out(f'makelist_xrdjobs:: {metafile}')
            copylist_xrd.append(CopyFile(metafile, cpfile.dst, cpfile.isUpload, {}, cpfile.src))  # we do not need the tokens in job list when downloading


def DO_XrootdCp(wb, xrd_copy_command: Optional[list] = None, printout: str = '', api_src: Optional[list] = None, api_dst: Optional[list] = None) -> RET:
    """XRootD cp function :: process list of arguments for a xrootd copy command"""
    if not HAS_XROOTD: return RET(1, "", 'DO_XrootdCp:: python XRootD module not found or lower than 5.3.3, the copy process cannot continue')

    if xrd_copy_command is None: xrd_copy_command = []
    if api_src is None: api_src = []
    if api_dst is None: api_dst = []

    if bool(api_src) ^ bool(api_dst): return RET(1, '', 'API _src,_dst used but only one is defined')
    if len(api_src) != len(api_dst): return RET(1, '', 'API _src,_dst used but not of equal lenght')

    if not wb: return RET(107, "", 'DO_XrootdCp:: websocket not found')  # ENOTCONN /* Transport endpoint is not connected */

    if is_help(xrd_copy_command):
        help_msg = xrdcp_help()
        return RET(0, help_msg)

    if (not api_src) and (len(xrd_copy_command) < 2):
        help_msg = xrdcp_help()
        return RET(22, '', f'\n{help_msg}')  # 22 /* Invalid argument */

    xrd_config_init()  # reset XRootD preferences to cp oriented settings

    # XRootD copy parameters
    # inittimeout: copy initialization timeout(int)
    # tpctimeout: timeout for a third-party copy to finish(int)
    # coerce: ignore file usage rules, i.e. apply `FORCE` flag to open() (bool)
    # :param checksummode: checksum mode to be used #:type    checksummode: string
    # :param checksumtype: type of the checksum to be computed  #:type    checksumtype: string
    # :param checksumpreset: pre-set checksum instead of computing it #:type  checksumpreset: string
    hashtype = str('md5')
    batch = int(1)   # from a list of copy jobs, start <batch> number of downloads
    streams = int(1)  # uses num additional parallel streams to do the transfer; use defaults from XrdCl/XrdClConstants.hh
    chunks = int(4)  # number of chunks that should be requested in parallel; use defaults from XrdCl/XrdClConstants.hh
    chunksize = int(8388608)  # chunk size for remote transfers; use defaults from XrdCl/XrdClConstants.hh
    overwrite = bool(False)  # overwrite target if it exists
    cksum = bool(False)
    timeout = int(0)
    rate = int(0)

    streams_arg = get_arg_value(xrd_copy_command, '-S')
    if streams_arg:
        if is_int(streams_arg):
            streams = min(abs(int(streams)), 15)
            if os.getenv('XRD_SUBSTREAMSPERCHANNEL'):
                print_out(f'Warning! env var XRD_SUBSTREAMSPERCHANNEL is set and will be overwritten with value: {streams}')
            XRD_EnvPut('SubStreamsPerChannel', streams)
    else:
        if not os.getenv('XRD_SUBSTREAMSPERCHANNEL'): XRD_EnvPut('SubStreamsPerChannel', streams)  # if no env customization, then use our defaults

    chunks_arg = get_arg_value(xrd_copy_command, '-chunks')
    if chunks_arg:
        if is_int(chunks_arg):
            chunks = abs(int(chunks_arg))
            if os.getenv('XRD_CPPARALLELCHUNKS'):
                print_out(f'Warning! env var XRD_CPPARALLELCHUNKS is set and will be overwritten with value: {chunks}')
            XRD_EnvPut('CPParallelChunks', chunks)
    else:
        if not os.getenv('XRD_CPPARALLELCHUNKS'): XRD_EnvPut('CPParallelChunks', chunks)

    chunksz_arg = get_arg_value(xrd_copy_command, '-chunksz')
    if chunksz_arg:
        if is_int(chunksz_arg):
            chunksize = abs(int(chunksz_arg))
            if os.getenv('XRD_CPCHUNKSIZE'):
                print_out(f'Warning! env var XRD_CPCHUNKSIZE is set and will be overwritten with value {chunksize}')
            XRD_EnvPut('CPChunkSize', chunksize)
    else:
        if not os.getenv('XRD_CPCHUNKSIZE'): XRD_EnvPut('CPChunkSize', chunksize)

    if get_arg(xrd_copy_command, '-noxrdzip'): os.environ["ALIENPY_NOXRDZIP"] = "nozip"

    timeout_arg = get_arg_value(xrd_copy_command, '-timeout')
    if timeout_arg:
        timeout = abs(int(timeout_arg))
        XRD_EnvPut('CPTimeout', timeout)

    rate_arg = get_arg_value(xrd_copy_command, '-ratethreshold')
    if rate_arg:
        rate = abs(int(rate_arg))
        XRD_EnvPut('XRateThreshold', rate)

    XRD_EnvPut('CpRetryPolicy', 'force')
    retry_arg = get_arg_value(xrd_copy_command, '-retry')
    if retry_arg:
        retry = abs(int(retry_arg))
        XRD_EnvPut('CpRetry', retry)

    _use_system_xrdcp = get_arg(xrd_copy_command, '-xrdcp')
    f_arg = get_arg(xrd_copy_command, '-f')
    if f_arg:
        print_out('No longer used flag! md5 verification of present destination is default; disable with -fastcheck')

    fastcheck = get_arg(xrd_copy_command, '-fastcheck') or get_arg(xrd_copy_command, '-skipmd5')
    overwrite = not fastcheck

    get_arg(xrd_copy_command, '-cksum')
    cksum = True

    dryrun = get_arg(xrd_copy_command, '-dryrun')

    tpc = 'none'
    if get_arg(xrd_copy_command, '-tpc'): tpc = 'first'
    if tpc != 'none': return RET(1, "", 'DO_XrootdCp:: TPC is not allowed!!')

    y_arg_val = get_arg_value(xrd_copy_command, '-y')
    # sources = int(y_arg_val)
    if y_arg_val: print_out("Ignored option! multiple source usage is known to break the files stored in zip files, so better to be ignored")

    batch = 8  # a nice enough default
    batch_arg = get_arg_value(xrd_copy_command, '-T')
    if batch_arg: batch = int(batch_arg)

    # options for envelope request
    strictspec = get_arg(xrd_copy_command, '-strictspec')
    httpurl = get_arg(xrd_copy_command, '-http')

    # keep this many path components into destination filepath
    parent = int(0)
    parent_arg = get_arg_value(xrd_copy_command, '-parent')
    if parent_arg: parent = int(parent_arg)

    # explicit specify a destination, the rest of arguments are source files
    dst_arg_specified = get_arg_value(xrd_copy_command, '-dst')

    # find options for recursive copy of directories
    find_args = []
    if get_arg(xrd_copy_command, '-v'): print_out("Verbose mode not implemented, ignored; enable debugging with ALIENPY_DEBUG=1")

    # find options not used or controlled
    get_arg(xrd_copy_command, '-a')
    get_arg(xrd_copy_command, '-s')
    get_arg(xrd_copy_command, '-c')
    get_arg(xrd_copy_command, '-w')
    get_arg(xrd_copy_command, '-wh')
    get_arg(xrd_copy_command, '-d')

    mindepth_arg = get_arg_value(xrd_copy_command, '-mindepth')
    if mindepth_arg: find_args.extend(['-mindepth', mindepth_arg])

    maxdepth_arg = get_arg_value(xrd_copy_command, '-maxdepth')
    if maxdepth_arg: find_args.extend(['-maxdepth', maxdepth_arg])

    minsize_arg = get_arg_value(xrd_copy_command, '-minsize')
    if minsize_arg: find_args.extend(['-minsize', minsize_arg])

    maxsize_arg = get_arg_value(xrd_copy_command, '-maxsize')
    if maxsize_arg: find_args.extend(['-maxsize', maxsize_arg])

    minctime_arg = get_arg_value(xrd_copy_command, '-min-ctime')
    if minctime_arg: find_args.extend(['-min-ctime', minctime_arg])

    maxctime_arg = get_arg_value(xrd_copy_command, '-max-ctime')
    if maxctime_arg: find_args.extend(['-max-ctime', maxctime_arg])

    exclude_str_arg = get_arg_value(xrd_copy_command, '-exclude')
    if exclude_str_arg: find_args.extend(['-exclude', exclude_str_arg])

    exclude_re_arg = get_arg_value(xrd_copy_command, '-exclude_re')
    if exclude_re_arg: find_args.extend(['-exclude_re', exclude_re_arg])

    user_arg = get_arg_value(xrd_copy_command, '-user')
    if user_arg: find_args.extend(['-user', user_arg])

    group_arg = get_arg_value(xrd_copy_command, '-group')
    if group_arg: find_args.extend(['-group', group_arg])

    jobid_arg = get_arg_value(xrd_copy_command, '-jobid')
    if jobid_arg: find_args.extend(['-jobid', jobid_arg])

    qid = get_arg_value(xrd_copy_command, '-j')
    if qid: find_args.extend(['-j', qid])

    files_limit = get_arg_value(xrd_copy_command, '-l')
    if files_limit: find_args.extend(['-l', files_limit])

    offset = get_arg_value(xrd_copy_command, '-o')
    if offset: find_args.extend(['-o', offset])

    ref_site = get_arg_value(xrd_copy_command, '-site')
    if ref_site: find_args.extend(['-S', ref_site])

    exclude_pattern = get_arg_value(xrd_copy_command, '-e')
    if exclude_pattern: find_args.extend(['-e', exclude_pattern])

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
                   f"The invalid pattern was: {pattern_regex}")
            return RET(22, '', msg)  # EINVAL /* Invalid argument */

    if use_regex: pattern = pattern_regex

    inputfile_arg = get_arg_value(xrd_copy_command, '-input')  # input file with <source, destination> pairs

    # Start of resolving src to dst pairs
    copy_lfnlist = []  # list of lfn copy tasks

    if api_src and api_dst:
        for src,dst in zip(api_src, api_dst):
            retobj = makelist_lfn(wb, arg_source = src, arg_target = dst,
                                  find_args = find_args, parent = parent,
                                  overwrite = overwrite, pattern = pattern,
                                  is_regex = use_regex, strictspec = strictspec, httpurl = httpurl, copy_list = copy_lfnlist)
            if retobj.exitcode != 0: print_err(retobj.err)  # if any error let's just return what we got  # noqa: R504
    elif inputfile_arg:
        cp_arg_list = fileline2list(inputfile_arg)
        if not cp_arg_list: return RET(1, '', f'Input file {inputfile_arg} not found or invalid content')
        for cp_line in cp_arg_list:
            cp_line_items = cp_line.strip().split()
            if len(cp_line_items) > 2:
                print_out(f'Line skipped, it has more than 2 arguments => f{cp_line.strip()}')
                continue
            retobj = makelist_lfn(wb, arg_source = cp_line_items[0], arg_target = cp_line_items[1],
                                  find_args = find_args, parent = parent,
                                  overwrite = overwrite, pattern = pattern,
                                  is_regex = use_regex, strictspec = strictspec, httpurl = httpurl, copy_list = copy_lfnlist)
            retf_print(retobj, "noout err")  # print error and continue with the other files
    elif dst_arg_specified:
        # the assumption is that every argument from arg list was removed and what remain is a list of sources
        common_root_path = common_path(xrd_copy_command)
        for src in xrd_copy_command:
            retobj = makelist_lfn(wb, arg_source = src, arg_target = f'{dst_arg_specified}/{src.replace(common_root_path, "")}',
                                  find_args = find_args, parent = parent,
                                  overwrite = overwrite, pattern = pattern,
                                  is_regex = use_regex, strictspec = strictspec, httpurl = httpurl, copy_list = copy_lfnlist)
            if retobj.exitcode != 0: print_err(retobj.err)  # if any error let's just return what we got  # noqa: R504
    else:
        if len(xrd_copy_command) < 2:
            return RET(1, '', 'Argument list invalid (less then 2 arguments)')
        src = xrd_copy_command[-2]
        dst = xrd_copy_command[-1]
        retobj = makelist_lfn(wb, arg_source = src, arg_target = dst,
                              find_args = find_args, parent = parent,
                              overwrite = overwrite, pattern = pattern,
                              is_regex = use_regex, strictspec = strictspec, httpurl = httpurl, copy_list = copy_lfnlist)
        if retobj.exitcode != 0: return retobj  # if any error let's just return what we got  # noqa: R504

    # at this point if any errors, the processing was already stopped
    if not copy_lfnlist: return RET(0, 'No copy jobs to be done!')

    if DEBUG:
        logging.debug("We are going to copy these files:")
        for f in copy_lfnlist: logging.debug(f)

    # create a list of copy jobs to be passed to XRootD mechanism
    xrdcopy_job_list = []
    makelist_xrdjobs(copy_lfnlist, xrdcopy_job_list)

    if not xrdcopy_job_list:
        msg = "No XRootD operations in list! enable the DEBUG mode for more info"
        logging.info(msg)
        return RET(2, '', msg)  # ENOENT /* No such file or directory */

    if DEBUG:
        logging.debug("XRootD copy jobs:")
        for f in xrdcopy_job_list: logging.debug(f)

    if dryrun:
        msg = ''
        for f in xrdcopy_job_list:
            c_msg = f'{f.src} -> {f.lfn} ({f.token_request["se"]})' if f.isUpload else f'{f.lfn} -> {f.dst}'
            msg = f'{msg}{c_msg}\n'
        return RET(0, msg)

    msg1 = msg2 = msg3 = msg_sum = ''
    copy_jobs_nr = copy_jobs_nr1 = copy_jobs_nr2 = 0
    copy_jobs_failed_nr = copy_jobs_failed_nr1 = copy_jobs_failed_nr2 = 0
    copy_jobs_success_nr = copy_jobs_success_nr1 = copy_jobs_success_nr2 = 0

    my_cp_args = XrdCpArgs(overwrite, batch, tpc, hashtype, cksum, timeout, rate)
    # defer the list of url and files to xrootd processing - actual XRootD copy takes place
    copy_failed_list = XrdCopy(wb, xrdcopy_job_list, my_cp_args, printout)  # if not _use_system_xrdcp else XrdCopy_xrdcp(xrdcopy_job_list, my_cp_args)
    copy_jobs_nr = len(xrdcopy_job_list)
    copy_jobs_failed_nr = len(copy_failed_list)
    copy_jobs_success_nr = copy_jobs_nr - copy_jobs_failed_nr
    msg1 = f"Succesful jobs (1st try): {copy_jobs_success_nr}/{copy_jobs_nr}" if not ('quiet' in printout or 'silent' in printout) else ''

    copy_failed_list2 = []
    if copy_failed_list:
        to_recover_list_try1 = []
        failed_lfns = {copy_job.lfn for copy_job in copy_failed_list if copy_job.isUpload}  # get which lfns had problems only for uploads
        for lfn in failed_lfns:  # process failed transfers per lfn
            failed_lfn_copy_jobs = [x for x in copy_failed_list if x.lfn == lfn]  # gather all failed copy jobs for one lfn
            failed_replica_nr = len(failed_lfn_copy_jobs)
            excluded_SEs_list = []
            for job in failed_lfn_copy_jobs:
                for se in job.token_request["SElist"]:
                    excluded_SEs_list.append(f'!{se}')
            excluded_SEs = ','.join(set(excluded_SEs_list))  # exclude already used SEs
            specs_list = f'disk:{failed_replica_nr},{excluded_SEs}'  # request N replicas (in place of failed ones), and exclude anything used

            job_file = failed_lfn_copy_jobs[0].token_request['file']
            job_lfn = failed_lfn_copy_jobs[0].token_request['lfn']
            job_isWrite = failed_lfn_copy_jobs[0].isUpload
            tokens_retry1 = lfn2fileTokens(wb, lfn2file(job_lfn, job_file), specs_list, job_isWrite, strictspec, httpurl)
            if not tokens_retry1 or 'answer' not in tokens_retry1: continue
            to_recover_list_try1.append(CopyFile(job_file, job_lfn, job_isWrite, tokens_retry1['answer'], job_lfn))

        if to_recover_list_try1:
            xrdcopy_job_list_2 = []
            makelist_xrdjobs(to_recover_list_try1, xrdcopy_job_list_2)
            copy_failed_list2 = XrdCopy(wb, xrdcopy_job_list_2, my_cp_args, printout)  # if not _use_system_xrdcp else XrdCopy_xrdcp(xrdcopy_job_list_2, my_cp_args)
            copy_jobs_nr1 = len(xrdcopy_job_list_2)
            copy_jobs_failed_nr1 = len(copy_failed_list2)
            copy_jobs_success_nr1 = copy_jobs_nr1 - copy_jobs_failed_nr1
            msg2 = f"Succesful jobs (2nd try): {copy_jobs_success_nr1}/{copy_jobs_nr1}" if not ('quiet' in printout or 'silent' in printout) else ''

    copy_failed_list3 = []
    if copy_failed_list2:
        to_recover_list_try2 = []
        failed_lfns2 = {copy_job.lfn for copy_job in copy_failed_list2 if copy_job.isUpload}  # get which lfns had problems only for uploads
        for lfn in failed_lfns2:  # process failed transfers per lfn
            failed_lfn_copy_jobs2 = [x for x in copy_failed_list2 if x.lfn == lfn]  # gather all failed copy jobs for one lfn
            failed_replica_nr = len(failed_lfn_copy_jobs2)
            excluded_SEs_list = []
            for job in failed_lfn_copy_jobs2:
                for se in job.token_request["SElist"]:
                    excluded_SEs_list.append(f'!{se}')
            excluded_SEs = ','.join(set(excluded_SEs_list))  # exclude already used SEs
            specs_list = f'disk:{failed_replica_nr},{excluded_SEs}'  # request N replicas (in place of failed ones), and exclude anything used

            job_file = failed_lfn_copy_jobs2[0].token_request['file']
            job_lfn = failed_lfn_copy_jobs2[0].token_request['lfn']
            job_isWrite = failed_lfn_copy_jobs2[0].isUpload
            tokens_retry2 = lfn2fileTokens(wb, lfn2file(job_lfn, job_file), specs_list, job_isWrite, strictspec, httpurl)
            if not tokens_retry2 or 'answer' not in tokens_retry2: continue
            to_recover_list_try2.append(CopyFile(job_file, job_lfn, job_isWrite, tokens_retry2['answer'], job_lfn))

        if to_recover_list_try2:
            xrdcopy_job_list_3 = []
            makelist_xrdjobs(to_recover_list_try2, xrdcopy_job_list_3)
            copy_failed_list3 = XrdCopy(wb, xrdcopy_job_list_3, my_cp_args, printout)  # if not _use_system_xrdcp else XrdCopy_xrdcp(xrdcopy_job_list_3, my_cp_args)
            copy_jobs_nr2 = len(xrdcopy_job_list_3)
            copy_jobs_failed_nr2 = len(copy_failed_list3)
            copy_jobs_success_nr2 = copy_jobs_nr2 - copy_jobs_failed_nr2
            msg3 = f'Succesful jobs (3rd try): {copy_jobs_success_nr2}/{copy_jobs_nr2}' if not ('quiet' in printout or 'silent' in printout) else ''

    # copy_jobs_failed_total = copy_jobs_failed_nr + copy_jobs_failed_nr1 + copy_jobs_failed_nr2
    copy_jobs_nr_total = copy_jobs_nr + copy_jobs_nr1 + copy_jobs_nr2
    copy_jobs_success_nr_total = copy_jobs_success_nr + copy_jobs_success_nr1 + copy_jobs_success_nr2
    # hard to return a single exitcode for a copy process optionally spanning multiple files
    # we'll return SUCCESS if at least one lfn is confirmed, FAIL if not lfns is confirmed
    msg_list = [msg1, msg2, msg3]
    if msg2 or msg3:
        msg_sum = f"Succesful jobs (total): {copy_jobs_success_nr_total}/{copy_jobs_nr_total}" if not ('quiet' in printout or 'silent' in printout) else ''
        msg_list.append(msg_sum)
    msg_all = '\n'.join(x.strip() for x in msg_list if x.strip())
    if 'ALIENPY_NOXRDZIP' in os.environ: os.environ.pop("ALIENPY_NOXRDZIP")
    return RET(0, msg_all) if copy_jobs_success_nr_total > 0 else RET(1, '', msg_all)


if HAS_XROOTD:
    class MyCopyProgressHandler(xrd_client.utils.CopyProgressHandler):
        """Custom ProgressHandler for XRootD copy process"""
        __slots__ = ('wb', 'copy_failed_list', 'jobs', 'job_list', 'xrdjob_list', 'succesful_writes', 'printout', 'debug')

        def __init__(self) -> None:
            self.wb = None
            self.copy_failed_list = []  # record the failed jobs
            self.jobs = int(0)
            self.job_list = []
            self.xrdjob_list = []
            self.succesful_writes = []
            self.printout = ''
            self.debug = False

        def begin(self, jobId, total, source, target) -> None:
            timestamp_begin = datetime.datetime.now().timestamp()
            if not ('quiet' in self.printout or 'silent' in self.printout):
                print_out(f'jobID: {jobId}/{total} >>> Start')
            self.jobs = int(total)
            xrdjob = self.xrdjob_list[jobId - 1]
            file_size = xrdjob.token_request['size'] if xrdjob.isUpload else get_size_meta(xrdjob.src)

            jobInfo = {'src': source, 'tgt': target, 'bytes_total': file_size, 'bytes_processed': 0, 'start': timestamp_begin}
            self.job_list.insert(jobId - 1, jobInfo)
            if self.debug: logging.debug('CopyProgressHandler.src: %s\nCopyProgressHandler.dst: %s\n', source, target)

        def end(self, jobId, results) -> None:
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
            job_status_info = f"jobID: {jobId}/{self.jobs} >>> STATUS {status}"

            deltaT = datetime.datetime.now().timestamp() - float(job_info['start'])
            if os.getenv('XRD_LOGLEVEL'):
                logging.debug('XRD copy job time:: %s -> %s', xrdjob.lfn, deltaT)
                logging.debug(results)

            if not xrdjob.isUpload and os.getenv('ALIENPY_KEEP_META'):
                meta_path, _, _ = str(xrdjob.src).partition("?")
                subprocess.run(shlex.split(f'cp -f {meta_path} {os.getcwd()}/'), check = False)  # nosec

            if results['status'].ok:
                speed = float(job_info['bytes_total']) / deltaT
                speed_str = f'{GetHumanReadableSize(speed)}/s'
                job_msg = f'{job_status_info} >>> SPEED {speed_str}'

                if xrdjob.isUpload:  # isUpload
                    md5 = results['sourceCheckSum'].replace('md5:','',1)
                    self.succesful_writes.append(CommitInfo(envelope = replica_dict['envelope'], size = replica_dict['size'], 
                                                            lfn = xrdjob.lfn, perm = '644', expire = '0',
                                                            pfn = replica_dict['url'], se = replica_dict['se'], guid = replica_dict['guid'], md5 = md5))
                    # Add xattrs to remote file
                    if 'ALIENPY_EXPERIMENTAL_XATTRS' in os.environ:
                        pfn_dir = urlparse(replica_dict['url']).path
                        xrdfile_set_attr(xrdjob.dst, [ ('xroot.alice.lfn', xrdjob.lfn), ('xroot.alice.md5', md5), ('xroot.alice.pfn', pfn_dir) ])
                else:  # isDownload
                    # NOXRDZIP was requested
                    if 'ALIENPY_NOXRDZIP' in os.environ and os.path.isfile(xrdjob.dst) and zipfile.is_zipfile(xrdjob.dst):
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

                if not ('quiet' in self.printout or 'silent' in self.printout): print_out(job_msg)
            else:
                self.copy_failed_list.append(xrdjob)
                codes_info = f">>> ERRNO/CODE/XRDSTAT {results['status'].errno}/{results['status'].code}/{results['status'].status}"
                xrd_resp_msg = results['status'].message
                failed_after = f'Failed after {deltaT}'
                if xrdjob.isUpload:
                    msg = f"{job_status_info} : {xrdjob.token_request['file']} to {xrdjob.token_request['se']}, {xrdjob.token_request['nSEs']} replicas\n{xrd_resp_msg}"
                else:
                    msg = f"{job_status_info} : {xrdjob.lfn}\n{xrd_resp_msg}"
                if DEBUG: msg = f'{msg}\n{failed_after}'
                logging.error('\n%s\n%s', codes_info, msg)
                print_err(msg)
                defined_reqtimeout = float(XRD_EnvGet('RequestTimeout'))
                if deltaT >= defined_reqtimeout:
                    print_err(f'Copy job duration >= RequestTimeout default setting ({defined_reqtimeout}); Contact developer for support.')


def XrdCopy(wb, job_list: list, xrd_cp_args: XrdCpArgs, printout: str = '') -> list:
    """XRootD copy command :: the actual XRootD copy process"""
    if not HAS_XROOTD:
        print_err("XRootD not found or lower than 5.3.3")
        return []
    if not xrd_cp_args:
        print_err("cp arguments are not set, XrdCpArgs tuple missing")
        return []

    # MANDATORY DEFAULTS, always used
    makedir = bool(True)  # create the parent directories when creating a file
    posc = bool(True)  # persist on successful close; Files are automatically deleted should they not be successfully closed.
    sources = int(1)  # max number of download sources; we (ALICE) do not rely on parallel multi-source downloads

    # passed arguments
    overwrite = xrd_cp_args.overwrite
    batch = xrd_cp_args.batch
    tpc = xrd_cp_args.tpc

    handler = MyCopyProgressHandler()
    handler.wb = wb
    handler.xrdjob_list = job_list
    handler.printout = printout
    handler.succesful_writes = []
    if DEBUG: handler.debug = True

    process = xrd_client.CopyProcess()
    process.parallel(int(batch))
    for copy_job in job_list:
        if DEBUG: logging.debug('\nadd copy job with\nsrc: %s\ndst: %s\n', copy_job.src, copy_job.dst)
        if copy_job.isUpload:
            cksum_mode = 'source'
            cksum_type = 'md5'
            cksum_preset = ''
        else:  # for downloads we already have the md5 value, lets use that
            cksum_mode = 'target'
            cksum_type, cksum_preset = get_hash_meta(copy_job.src)
            # If the remote file had no hash registered
            if not cksum_type or not cksum_preset:
                logging.error('COPY:: MD5 missing for %s', copy_job.lfn)
                cksum_mode = 'none'
                cksum_type = cksum_preset = ''

        delete_invalid_cksum = cksum_mode != 'none'  # if no checksumming mode, disable rmBadCksum
        if 'xrateThreshold' in process.add_job.__code__.co_varnames:
            process.add_job(copy_job.src, copy_job.dst, sourcelimit = sources, posc = posc, mkdir = makedir, force = overwrite, thirdparty = tpc,
                            checksummode = cksum_mode, checksumtype = cksum_type, checksumpreset = cksum_preset, rmBadCksum = delete_invalid_cksum,
                            retry = xrd_client.EnvGetInt('CpRetry'), cptimeout = xrd_client.EnvGetInt('CPTimeout'), xrateThreshold = xrd_client.EnvGetInt('XRateThreshold') )
        else:
            process.add_job(copy_job.src, copy_job.dst, sourcelimit = sources, posc = posc, mkdir = makedir, force = overwrite, thirdparty = tpc,
                            checksummode = cksum_mode, checksumtype = cksum_type, checksumpreset = cksum_preset, rmBadCksum = delete_invalid_cksum,
                            retry = xrd_client.EnvGetInt('CpRetry'), cptimeout = xrd_client.EnvGetInt('CPTimeout'), xrateThreashold = xrd_client.EnvGetInt('XRateThreshold') )

    process.prepare()
    process.run(handler)

    if handler.succesful_writes:  # if there were succesful uploads/remote writes, let's commit them to file catalogue
        ret_list = commitFileList(wb, handler.succesful_writes)
        for ret in ret_list: retf_print(ret, 'noout err')
    return handler.copy_failed_list  # lets see what failed and try to recover


# keep it commented until is needed - dead code for now
# def _xrdcp_sysproc(cmdline: str, timeout: Union[str, int, None] = None) -> RET:
#     """xrdcp stanalone system command"""
#     if not cmdline: return RET(1, '', '_xrdcp_sysproc :: no cmdline')  # type: ignore [call-arg]
#     if timeout is not None: timeout = int(timeout)
#     # --nopbar --posc
#     xrdcp_cmdline = f'xrdcp -N -P {cmdline}'
#     return runShellCMD(xrdcp_cmdline, captureout = True, do_shell = False, timeout = timeout)


# keep it commented until is needed - dead code for now
# def _xrdcp_copyjob(copy_job: CopyFile, xrd_cp_args: XrdCpArgs) -> int:  # , printout: str = ''
#     """xrdcp based task that process a copyfile and it's arguments"""
#     if not copy_job: return int(2)
#     # overwrite = xrd_cp_args.overwrite
#     # batch = xrd_cp_args.batch
#     # tpc = xrd_cp_args.tpc
#     # hashtype = xrd_cp_args.hashtype
#     # cksum = xrd_cp_args.cksum
#     timeout = xrd_cp_args.timeout
#     # rate = xrd_cp_args.rate
#     cmdline = f'{copy_job.src} {copy_job.dst}'
#     return retf_print(_xrdcp_sysproc(cmdline, timeout))

# keep it commented until is needed - dead code for now
# def XrdCopy_xrdcp(job_list: list, xrd_cp_args: XrdCpArgs) -> list:  # , printout: str = ''
#     """XRootD copy command :: the actual XRootD copy process"""
#     if not HAS_XROOTD:
#         print_err("XRootD not found or lower version thant 5.3.3")
#         return []
#     if not xrd_cp_args:
#         print_err("cp arguments are not set, XrdCpArgs tuple missing")
#         return []
#     # overwrite = xrd_cp_args.overwrite
#     # batch = xrd_cp_args.batch
#     # makedir = xrd_cp_args.makedir
#
#     # ctx = mp.get_context('forkserver')
#     # q = ctx.JoinableQueue()
#     # p = ctx.Process(target=_xrdcp_copyjob, args=(q,))
#     # p.start()
#     # print(q.get())
#     # p.join()
#     for copy_job in job_list:
#         if DEBUG: logging.debug('\nadd copy job with\nsrc: %s\ndst: %s\n', copy_job.src, copy_job.dst)
#         # xrdcp_cmd = f' {copy_job.src} {copy_job.dst}'
#         if DEBUG: print_out(copy_job)
#     return []


def xrd_response2dict(response_status: xrd_client.responses.XRootDStatus) -> dict:
    """Convert a XRootD response status answer to a dict"""
    if not response_status: return {}
    if not HAS_XROOTD:
        print_err('XRootD not present')
        return {}
    if not isinstance(response_status, xrd_client.responses.XRootDStatus):
        print_err('Invalid argument type passed to xrd_response2dict')
        return {}
    return {'status': response_status.status, 'code': response_status.code, 'errno': response_status.errno, 'message': response_status.message.strip(),
            'shellcode': response_status.shellcode, 'error': response_status.error, 'fatal': response_status.fatal, 'ok': response_status.ok}


def xrdfs_q_config(fqdn_port: str) -> dict:
    """Return a dictionary of xrdfs query config"""
    if not HAS_XROOTD:
        print_err('python XRootD module not found')
        return None
    endpoint = xrd_client.FileSystem(f'{fqdn_port}/?xrd.wantprot=unix')

    config_args_list = ['bind_max', 'chksum', 'pio_max', 'readv_ior_max', 'readv_iov_max', 'tpc', 'wan_port', 'wan_window', 'window', 'cms', 'role', 'sitename', 'version']
    config_dict = {}
    for cfg in config_args_list:
        q_status, response = endpoint.query(7, cfg, timeout = 5)  # get the config metrics
        status = xrd_response2dict(q_status)
        if status['ok']:
            response = response.decode('ascii').strip()
            val = 'NOT_SET' if cfg == response else response
            config_dict[cfg] = val
        else:
            print_err(f'Query error for {fqdn_port} : {status["message"]}')
            break
    return config_dict


def xrdfs_ping(fqdn_port: str):
    """Return a dictionary of xrdfs ping, it will contain ping_time_ms key"""
    if not HAS_XROOTD:
        print_err('python XRootD module not found')
        return None
    endpoint = xrd_client.FileSystem(f'{fqdn_port}/?xrd.wantprot=unix')
    result, _ = endpoint.ping(timeout = 2)  # ping the server 1st time to eliminate strange 1st time behaviour

    time_begin = time.perf_counter()
    result, _ = endpoint.ping(timeout = 2)  # ping the server
    ping_ms = deltat_ms_perf(time_begin)

    response_dict = xrd_response2dict(result)
    response_dict['ping_time_ms'] = float(ping_ms)
    return response_dict


def xrdfs_q_stats(fqdn_port: str, xml: bool = False, xml_raw: bool = False, compact: bool = False):
    if not HAS_XROOTD:
        print_err('python XRootD module not found')
        return {}
    endpoint = xrd_client.FileSystem(f'{fqdn_port}/?xrd.wantprot=unix')
    q_status, response = endpoint.query(1, 'a')  # get the stats (ALL)
    status = xrd_response2dict(q_status)
    if not status['ok']:
        print_err(f'xrdfs_q_stats:: query error to {fqdn_port} : {status["message"]}')
        return {}

    response = response.decode('ascii').strip().strip('\x00')
    # if xml is requested or xmltodict missing
    if xml:
        if xml_raw: return response
        xml_stats = MD.parseString(response)  # nosec B318:blacklist
        indent = '  '
        newl = '\n'
        if compact: indent = newl = ''
        return xml_stats.toprettyxml(indent = indent, newl = newl).replace('&quot;', '"')

    try:
        import xmltodict
    except Exception:
        print_err('Could not import xmltodict, cannot convert the xml output to a dict view. try -xml argument')
        return {}

    q_stats_dict_full = xmltodict.parse(response, attr_prefix = '')
    q_stats_dict = q_stats_dict_full.get('statistics')
    if not q_stats_dict: return {}

    old_stats = q_stats_dict.pop('stats')

    # it will mutate the input
    def convert_dict(input_dict: dict, head_key: str = 'id'):
        if isinstance(input_dict, dict) and head_key in input_dict:
            working_dict = dict(input_dict)
            key_name = working_dict.pop('id')
            new_dict = {key_name: working_dict}
            input_dict.clear()
            input_dict.update(new_dict)

    for id_entry in old_stats:
        convert_dict(id_entry)

    # to search for a recursive solution
    for i in old_stats:
        if 'oss' in i: convert_dict(i['oss']['paths']['stats'])

    merged_stats = {}
    for i in old_stats: merged_stats.update(i)
    q_stats_dict['stats'] = merged_stats
    return q_stats_dict


def xrd_statinfo2dict(response_statinfo: xrd_client.responses.StatInfo) -> dict:
    """Convert a XRootD StatInfo answer to a dict"""
    if not response_statinfo: return {}
    if not HAS_XROOTD:
        print_err('XRootD not present')
        return {}
    if not isinstance(response_statinfo, xrd_client.responses.StatInfo):
        print_err('Invalid argument type passed to xrd_statinfo2dict')
        return {}
    return {'size': response_statinfo.size, 'flags': response_statinfo.flags, 'modtime': response_statinfo.modtime, 'modtimestr': response_statinfo.modtimestr}


def xrdstat2dict(xrdstat: tuple) -> dict:
    """Convert a XRootD status answer to a dict"""
    if not xrdstat: return {}
    xrd_stat, xrd_info = xrdstat
    xrdstat_dict = xrd_response2dict(xrd_stat)
    xrdinfo_dict = xrd_statinfo2dict(xrd_info)
    return {**xrdstat_dict, **xrdinfo_dict}


def xrdfs_stat(pfn: str):
    if not HAS_XROOTD:
        print_err('python XRootD module not found')
        return None
    url_components = urlparse(pfn)
    endpoint = xrd_client.FileSystem(url_components.netloc)
    return endpoint.stat(f'{url_components.path}?xrd.wantprot=unix')


def xrdstat_flags2dict(flags: int) -> dict:
    """Convert the flags information of a XRootD file status to a dict"""
    return {'x_bit_set': bool(flags & xrd_client.flags.StatInfoFlags.X_BIT_SET),
            'is_dir': bool(flags & xrd_client.flags.StatInfoFlags.IS_DIR),
            'other': bool(flags & xrd_client.flags.StatInfoFlags.OTHER),
            'offline': bool(flags & xrd_client.flags.StatInfoFlags.OFFLINE),
            'is_readable': bool(flags & xrd_client.flags.StatInfoFlags.IS_READABLE),
            'is_writable': bool(flags & xrd_client.flags.StatInfoFlags.IS_WRITABLE),
            'posc_pending': bool(flags & xrd_client.flags.StatInfoFlags.POSC_PENDING),
            'backup_exists': bool(flags & xrd_client.flags.StatInfoFlags.BACKUP_EXISTS)}


def is_pfn_readable(pfn: str) -> bool:
    get_pfn_info = xrdstat2dict(xrdfs_stat(pfn))
    if 'flags' in get_pfn_info:
        pfn_flags = xrdstat_flags2dict(get_pfn_info['flags'])
        return pfn_flags['is_readable']
    return False


def get_pfn_list(wb, lfn: str) -> list:
    if not wb: return []
    if not lfn: return []
    if pathtype_grid(wb, lfn) != 'f': return []
    ret_obj = SendMsg(wb, 'whereis', [lfn], opts = 'nomsg')
    retf_print(ret_obj, 'debug')
    return [str(item['pfn']) for item in ret_obj.ansdict['results']]


def download_tmp(wb, lfn: str, overwrite: bool = False, verbose: bool = False) -> str:
    """Download a lfn to a temporary file, it will return the file path of temporary"""
    tmpfile = make_tmp_fn(expand_path_grid(lfn))
    if os.path.isfile(tmpfile):
        if overwrite:
            os.remove(tmpfile)
            if tmpfile in AlienSessionInfo['templist']: AlienSessionInfo['templist'].remove(tmpfile)
        else:
            if tmpfile not in AlienSessionInfo['templist']: AlienSessionInfo['templist'].append(tmpfile)
            return tmpfile

    if tmpfile in AlienSessionInfo['templist']: AlienSessionInfo['templist'].remove(tmpfile)  # just in case it is still in list
    ret_obj = DO_XrootdCp(wb, xrd_copy_command = ['-fastcheck'], api_src = [f'{lfn}'], api_dst = [f'file:{tmpfile}'], printout = 'silent')  # print only errors for temporary downloads

    if ret_obj.exitcode == 0 and os.path.isfile(tmpfile):
        AlienSessionInfo['templist'].append(tmpfile)
        return tmpfile
    if verbose: print_err(f'{ret_obj.err}')
    return ''


def upload_tmp(wb, temp_file_name: str, upload_specs: str = '', dated_backup: bool = False) -> str:
    """Upload a temporary file: the original lfn will be renamed and the new file will be uploaded with the original lfn"""
    lfn = get_lfn_name(temp_file_name)  # lets recover the lfn from temp file name
    lfn_backup = f'{lfn}.{now_str()}' if dated_backup else f'{lfn}~'
    if not dated_backup:
        ret_obj = SendMsg(wb, 'rm', ['-f', lfn_backup])  # remove already present old backup; useless to pre-check
    ret_obj = SendMsg(wb, 'mv', [lfn, lfn_backup])  # let's create a backup of old lfn
    if retf_print(ret_obj, 'debug') != 0: return ''
    tokens = lfn2fileTokens(wb, lfn2file(lfn, temp_file_name), [upload_specs], isWrite = True)
    access_request = tokens['answer']
    replicas = access_request["results"][0]["nSEs"]
    if "disk:" not in upload_specs: upload_specs = f'disk:{replicas}'
    if upload_specs: upload_specs = f'@{upload_specs}'

    ret_obj = DO_XrootdCp(wb, xrd_copy_command = ['-fastcheck'], api_src = [f'file:{temp_file_name}'], api_dst = [f'{lfn}{upload_specs}'])
    if ret_obj.exitcode == 0: return lfn
    ret_obj = SendMsg(wb, 'mv', [lfn_backup, lfn])  # if the upload failed let's move back the backup to original lfn name'
    retf_print(ret_obj, 'debug')
    return ''


if __name__ == '__main__':
    print('This file should not be executed!', file = sys.stderr, flush = True)
    sys.exit(95)
