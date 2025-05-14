"""alienpy:: Misc tooling functions (local, not-networked usage)"""

import ast
import atexit
import datetime
import json
import re
from typing import Any, Optional, Union
import logging
import multiprocessing as mp
import socket
import grp
import pwd
from pathlib import Path
import os
import time
import traceback
import uuid
import urllib.request as urlreq
import shutil
import shlex
import sys
import signal
import xml.etree.ElementTree as ET  # noqa: N817
import xml.dom.minidom as MD  # noqa: N812

from .data_structs import ALIEN_COLLECTION_EL, KV, RET, STAT_FILEPATH
from .global_vars import ALIENPY_FANCY_PRINT, AlienSessionInfo, COLORS, HAS_COLOR, REGEX_PATTERN_TYPE, TMPDIR, USER_HOME, emptyline_re, guid_regex, ignore_comments_re, lfn_prefix_re, rich_print_json
from .setup_logging import DEBUG, print_err, print_out
from .tools_shell import is_cmd, runShellCMD


NCPU = int(mp.cpu_count() * 0.8)  # use at most 80% of host CPUs


def PrintColor(color: str) -> str:
    """Disable color if the terminal does not have capability"""
    return color if HAS_COLOR else ''


def exit_message(code: int = 0, msg: str = '') -> None:
    """Exit with msg and with specified code"""
    print_out(msg if msg else 'Exit')
    sys.exit(code)


def signal_handler(sig, frame) -> None:  # pylint: disable=unused-argument
    """Generic signal handler: just print the signal and exit"""
    # https://stackoverflow.com/a/79497818/624734
    signal.signal(signalnum = sig, handler = signal.SIG_IGN)

    print_out(f"\nCaught signal {sig}, let\'s exit")

    # Send signal to all processes in the group
    os.killpg(0, sig)
    os._exit(int(AlienSessionInfo['exitcode']))


def is_float(arg: Union[str, float, None]) -> bool:
    if not arg: return False
    s = str(arg).replace('.', '', 1)
    if s[0] in ('-', '+'): return s[1:].isdigit()
    return s.isdigit()


def is_int(arg: Union[str, int, float, None]) -> bool:
    if not arg: return False
    s = str(arg)
    if s[0] in ('-', '+'): return s[1:].isdigit()
    return s.isdigit()


def time_unix2simple(time_arg: Union[str, int, None]) -> str:
    if not time_arg: return ''
    return datetime.datetime.fromtimestamp(float(time_arg)).replace(microsecond=0).isoformat().replace('T', ' ')


def time_str2unixmili(time_arg: Union[str, int, None]) -> int:
    if not time_arg:
        return int((datetime.datetime.utcnow() - datetime.datetime(1970, 1, 1)).total_seconds() * 1000)
    time_arg = str(time_arg)

    if time_arg.isdigit() or is_float(time_arg):
        if is_float(time_arg) and len(time_arg) == 10:
            return int(float(time_arg) * 1000)
        if time_arg.isdigit() and len(time_arg) == 13:
            return int(time_arg)
        return int(-1)

    # assume that this is a strptime arguments in the form of: time_str, format_str
    try:
        time_obj = ast.literal_eval(f'datetime.datetime.strptime({time_arg})')
        return int((time_obj - datetime.datetime(1970, 1, 1)).total_seconds() * 1000)
    except Exception:
        return int(-1)


def unixtime2local(timestamp: Union[str, int], decimals: bool = True) -> str:
    """Convert unix time to a nice custom format"""
    timestr = str(timestamp)
    if len(timestr) < 10: return ''
    micros = None
    millis = None
    time_decimals = ''
    if len(timestr) > 10:
        time_decimals = timestr[10:]
        if len(time_decimals) <= 3:
            time_decimals = float(time_decimals.ljust(3, '0')) * 1000
            millis = datetime.timedelta(milliseconds=int(time_decimals))
        else:
            time_decimals = float(time_decimals.ljust(6, '0')) *1000000
            micros = datetime.timedelta(microseconds=int(time_decimals))

    unixtime = timestr[:10]
    utc_time = datetime.datetime.fromtimestamp(int(unixtime), datetime.timezone.utc)
    local_time = utc_time.astimezone()
    if decimals and millis:
        return f'{(local_time + millis).strftime("%Y-%m-%d %H:%M:%S")}.{time_decimals}{local_time.strftime("%z")}'
    if decimals and micros:
        return (local_time + micros).strftime("%Y-%m-%d %H:%M:%S.%f%z")  # (%Z)"))
    return local_time.strftime("%Y-%m-%d %H:%M:%S%z")  # (%Z)"))


def convert_time(str_line: str, color: bool = True) -> str:
    """Convert the first 10 digit unix time like string from str argument to a nice time"""
    timestamp = re.findall(r"^(\d{10}) \[.*", str_line)
    if timestamp:
        nice_timestamp = f'{PrintColor(COLORS.BIGreen)}{unixtime2local(timestamp[0])}{PrintColor(COLORS.ColorReset)}' if color else unixtime2local(timestamp[0])
        return str_line.replace(str(timestamp[0]), nice_timestamp)
    return ''


def unquote_str(arg: str) -> str: return ast.literal_eval(arg) if isinstance(arg, str) else ''


def dequote(s: str) -> str:
    """Remove only 1 quotes in the string limits"""
    if (len(s) >= 2 and s[0] == s[-1]) and s.startswith(("'", '"')): return s[1:-1]
    return s


def is_guid(guid: str) -> bool:
    """Recognize a GUID format"""
    return bool(guid_regex.fullmatch(guid))  # identify if argument in an AliEn GUID


def run_function(function_name: str, *args, **kwargs):
    """Python code:: run some arbitrary function name (found in globals) with arbitrary arguments"""
    func = globals().get(function_name)
    return func(*args, *kwargs) if func else None  # run arbitrary function


def cursor_vertical(lines: int = 0) -> None:
    """Move the cursor up/down N lines"""
    if lines == 0: return
    out_char = '\x1b[1A'  # UP
    if lines < 0:
        out_char = '\x1b[1B'  # DOWN
        lines = abs(lines)
    sys.stdout.write(out_char * lines)
    sys.stdout.flush()


def cursor_horizontal(lines: int = 0) -> None:
    """Move the cursor left/right N lines"""
    if lines == 0: return
    out_char = '\x1b[1C'  # RIGHT
    if lines < 0:
        out_char = '\x1b[1D'  # LEFT
        lines = abs(lines)
    sys.stdout.write(out_char * lines)
    sys.stdout.flush()


def now_str() -> str: return str(datetime.datetime.now().strftime("%Y%m%d_%H%M%S"))


def deltat_ms(t0: Union[str, float, None] = None) -> str:
    """Return delta t in ms from a time start; if no argument it return a timestamp in ms"""
    now = datetime.datetime.now().timestamp()
    return f"{(now - float(t0)) * 1000:.3f}" if t0 else f"{now * 1000:.3f}"


def deltat_us(t0: Union[str, float, None] = None) -> str:
    """Return delta t in ms from a time start; if no argument it return a timestamp in ms"""
    now = datetime.datetime.now().timestamp()
    return f"{(now - float(t0)) * 1000000:.3f}" if t0 else f"{now * 1000000:.3f}"


def deltat_ms_perf(t0: Union[str, float, None] = None) -> str:
    """Return delta t in ms from a time start; if no argument it return a timestamp in ms"""
    if not t0: return ""
    return f"{(time.perf_counter() - float(t0)) * 1000:.3f}"


def deltat_us_perf(t0: Union[str, float, None] = None) -> str:
    """Return delta t in ms from a time start; if no argument it return a timestamp in ms"""
    if not t0: return ""
    return f"{(time.perf_counter() - float(t0)) * 1000000:.3f}"


def is_help(args: Union[str, list], clean_args: bool = False) -> bool:
    if not args: return False
    if isinstance(args, str): args = args.split()
    help_opts = ('-h', '--h', '-help', '--help')
    help_arg_present = any(opt in args for opt in help_opts)
    if help_arg_present and clean_args:
        for opt in help_opts: get_arg(args, opt)
    return help_arg_present


def read_conf_file(conf_file: str) -> dict:
    """Convert a configuration file with key = value format to a dict"""
    if not conf_file or not os.path.isfile(conf_file): return {}
    DICT_INFO = {}
    try:
        with open(conf_file, encoding="ascii", errors="replace") as rel_file:
            for line in rel_file:
                line, _, _ = line.partition('#')
                # name, var = line.rstrip().partition("=")[::2]
                name, _, var = line.rstrip().partition("=")
                var = re.sub(r"^\"", '', str(var.strip()))
                var = re.sub(r"\"$", '', var)
                DICT_INFO[name.strip()] = var
    except Exception:
        logging.error('Error reading the configuration file: %s', conf_file)
    return DICT_INFO


def file2list(input_file: str) -> list:
    """Parse a file and return a list of elements"""
    if not input_file or not os.path.isfile(input_file): return []
    file_list = []
    with open(input_file, encoding="ascii", errors="replace") as filecontent:
        for line in filecontent:
            if not line or ignore_comments_re.search(line) or emptyline_re.match(line): continue
            file_list.extend(line.strip().split())
    return file_list


def fileline2list(input_file: str) -> list:
    """Parse a file and return a list of file lines"""
    if not input_file or not os.path.isfile(input_file): return []
    file_list = []
    with open(input_file, encoding="ascii", errors="replace") as filecontent:
        for line in filecontent:
            if not line or ignore_comments_re.search(line) or emptyline_re.match(line): continue
            file_list.extend([line.strip()])
    return file_list


def os_release() -> dict:
    return read_conf_file('/etc/os-release')


def get_lfn_key(lfn_obj: dict) -> str:
    """get either lfn key or file key from a file description"""
    if not lfn_obj or not isinstance(lfn_obj, dict): return ''
    if "lfn" in lfn_obj: return lfn_obj["lfn"]
    if "file" in lfn_obj: return lfn_obj["file"]
    return ''


def pid_uid(pid: int) -> int:
    """Return username of UID of process pid"""
    uid = int(-1)
    try:
        with open(f'/proc/{pid}/status', encoding="ascii", errors="replace") as proc_status:
            for line in proc_status:
                # Uid, Gid: Real, effective, saved set, and filesystem UIDs(GIDs)
                if line.startswith('Uid:'):
                    line_elements = line.split()
                    uid = int(line_elements[1]) if len(line_elements) > 1 else -1
    except Exception:
        logging.error('Error getting uid of pid: %d', pid)
    return uid  # noqa: R504


def is_my_pid(pid: int) -> bool: return pid_uid(int(pid)) == os.getuid()


def writePidFile(filename: str) -> None:
    if not filename: return
    try:
        with open(filename, 'w', encoding="ascii", errors="replace") as f: f.write(str(os.getpid()))
    except Exception:
        logging.exception('Error writing the pid file: %s', filename)


def list_remove_item(target: list, item: str) -> None:
    """Remove all instances of item from list"""
    if not target: return
    target[:] = [el for el in target if el != item]


def get_arg(target: list, item: str) -> bool:
    """Remove inplace all instances of item from list and return True if found"""
    len_begin = len(target)
    list_remove_item(target, item)
    len_end = len(target)
    return len_begin != len_end


def get_arg_value(target: list, item: str) -> str:
    """Remove inplace all instances of item and item+1 from list and return item+1"""
    val = None
    idx_to_be_removed = []
    arg_list_size = len(target)
    # cannot get the value and remove from list in the same time
    for idx, x in enumerate(target):
        if x == item:
            # if current index (starts at 0) is greater then len - 1, just return
            if idx + 1 + 1 > arg_list_size: return val
            val = target[idx + 1]
            idx_to_be_removed.append(idx + 1)

    idx_to_be_removed.reverse()
    for idx in idx_to_be_removed: target.pop(idx)
    list_remove_item(target, item)
    return val  # noqa: R504


def get_arg_value_multiple(target: list, item: str) -> list:
    """Return the list af arguments values, for arguments used multiple times"""
    val_list = []
    idx_to_be_removed = []
    arg_list_size = len(target)
    # cannot get the value and remove from list in the same time
    for idx, x in enumerate(target):
        if x == item:
            # if current index (starts at 0) is greater then len - 1, just return
            if idx + 1 + 1 > arg_list_size: return val_list
            val_list.append(target[idx + 1])
            idx_to_be_removed.append(idx + 1)

    idx_to_be_removed.reverse()
    for idx in idx_to_be_removed: target.pop(idx)
    list_remove_item(target, item)
    return val_list  # noqa: R504


def get_arg_2values(target: list, item: str) -> tuple:
    """Remove inplace all instances of item, item+1 and item+2 from list and return item+1, item+2"""
    val1 = val2 = None
    idx_to_be_removed = []
    arg_list_size = len(target)
    for idx, x in enumerate(target):
        if x == item:
            # if current index (starts at 0) is greater then len - 2, just return
            if idx + 2 + 1 > arg_list_size: return val1, val2
            val2 = target[idx + 2]
            val1 = target[idx + 1]
            idx_to_be_removed.append(idx + 1)
            idx_to_be_removed.append(idx + 2)

    idx_to_be_removed.reverse()
    for idx in idx_to_be_removed: target.pop(idx)
    list_remove_item(target, item)
    return val1, val2


def get_arg_multiple(target: list, item: str) -> list:
    """Return list of all values for a given arg"""
    val = None
    values_list = []
    idx_to_be_removed = []
    arg_list_size = len(target)
    # cannot get the value and remove from list in the same time
    for idx, x in enumerate(target):
        if x == item:
            # if current index (starts at 0) is greater then len - 1, just return
            if idx + 1 + 1 > arg_list_size: return val
            values_list.append(target[idx + 1])
            idx_to_be_removed.append(idx + 1)

    idx_to_be_removed.reverse()
    for idx in idx_to_be_removed: target.pop(idx)
    list_remove_item(target, item)
    return values_list  # noqa: R504


def uid2name(uid: Union[str, int]) -> str:
    """Convert numeric UID to username"""
    try:
        user_info = pwd.getpwuid(int(uid))
        return user_info.pw_name
    except Exception:
        return str(uid)


def gid2name(gid: Union[str, int]) -> str:
    """Convert numeric GUI to group name"""
    try:
        group_info = grp.getgrgid(int(gid))
        return group_info.gr_name
    except Exception:
        return str(gid)


def GetHumanReadableSize(size_arg: Union[int, str], precision: int = 2) -> str:
    """Convert bytes to higher units"""
    if isinstance(size_arg, str): size_arg = int(size_arg)
    if size_arg == 0: return '0 B'
    size = float(size_arg)
    suffixes = ['B', 'KiB', 'MiB', 'GiB', 'TiB']
    suffixIndex = 0
    while size > 1024 and suffixIndex < 6:
        suffixIndex += 1  # increment the index of the suffix
        size = size / 1024.0  # apply the division
    return f'{size:.{precision}f} {suffixes[suffixIndex]}'


def check_ip_port(socket_object: tuple) -> bool:
    """Check connectivity to an address, port; address should be the tuple given by getaddrinfo"""
    if not socket_object: return False
    is_open = False
    # socket_object = (family, type, proto, canonname, sockaddr)
    with socket.socket(socket_object[0], socket_object[1], socket_object[2]) as s:  # Create a TCP socket
        s.settimeout(2)  # timeout 2s
        try:
            s.connect(socket_object[4])
            is_open = True
        except Exception as e:
            logging.error('check_ip_port:: error connecting to %s', str(socket_object[4]))
            if DEBUG: logging.exception(e)
    return is_open  # noqa: R504


def check_port(address: str, port: Union[str, int]) -> list:
    """Check TCP connection to fqdn:port"""
    try:
        ip_list = socket.getaddrinfo(address, int(port), proto = socket.IPPROTO_TCP)
    except Exception:
        print_out(f'check_port:: error getting address info for host: {address} ; port: {port}')
        return []
    return [(*sock_obj[-1], check_ip_port(sock_obj)) for sock_obj in ip_list]


def isReachable(address: str = 'alice-jcentral.cern.ch', port: Union[str, int] = 8097) -> bool:
    result_list = check_port(address, port)
    return any(ip[-1] for ip in result_list)


def exitcode(args: Optional[list] = None) -> None:  # pylint: disable=unused-argument
    """Return the latest global recorded exitcode"""
    if 'AlienSessionInfo' not in globals(): return RET()
    return RET(0, f"{AlienSessionInfo['exitcode']}", '')  # type: ignore [call-arg]


def valid_regex(regex_str: str) -> Optional[REGEX_PATTERN_TYPE]:
    """Validate a regex string and return a re.Pattern if valid"""
    regex = None
    try:
        regex = re.compile(regex_str.encode('unicode-escape').decode())  # try to no hit https://docs.python.org/3.6/howto/regex.html#the-backslash-plague
    except re.error:
        logging.error('regex validation failed:: %s', regex_str)
    return regex  # noqa: R504


def name2regex(pattern_regex: str = '') -> str:
    """Convert -name/-select argument of cp/find2 to regex form"""
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
    return translated_pattern_regex  # noqa: R504


def common_path(path_list: list) -> str:
    """Return common path of a list of paths"""
    if not path_list: return ''
    if not isinstance(path_list, list): return ''
    common = ''
    try:
        common = os.path.commonpath(path_list)
    except Exception:
        logging.exception('common_path:: exception')
    return common


def format_dst_fn(src_dir: str, src_file: str, dst: str, parent: int = 0, truncate_basepath: int = 0) -> str:
    """Return the destination filename given the source dir/name, destination directory and number of parents to keep"""
    # let's get destination file name (relative path with parent value)
    if src_dir != src_file:  # recursive operation
        total_relative_path = src_file.replace(src_dir, '', 1)
        src_dir_path = Path(src_dir)
        src_dir_parts = list(src_dir_path.parts)
        file_components = len(src_dir_parts)  # it's directory'

        if not src_dir.endswith('/'): src_dir_parts = src_dir_parts[:-1]

        if truncate_basepath > 0:
            # make sure to not truncate more the path components and account for initial / which is counted as a component
            truncate_basepath = min(truncate_basepath, file_components - 1)
            base_path_list = src_dir_parts[truncate_basepath + 1:]   # add 1 to account for initial / that does not count as path component
        else:
            parent = min(parent, file_components)  # make sure maximum parent var point to first dir in path
            base_path_list = src_dir_parts[(file_components - parent):]
        base_path = '/'.join(base_path_list).replace('//', '/')
        base_path = f'{base_path}/{total_relative_path}'

    else:
        src_file_path = Path(src_file)
        src_file_parts = list(src_file_path.parts)
        file_components = len(src_file_parts) - 1 # without last element which is the file

        if truncate_basepath > 0:
            # make sure to not truncate more the path components and account for initial / which is counted as a component
            truncate_basepath = min(truncate_basepath, file_components - 1)
            base_path_list = src_file_parts[truncate_basepath + 1:]   # add 1 to account for initial / that does not count as path component
        else:
            parent = min(parent, file_components)  # make sure maximum parent var point to first dir in path
            base_path_list = src_file_parts[(file_components - parent):]
        base_path = '/'.join(base_path_list).replace('//', '/')

    dst_file = f'{dst}/{base_path}' if dst.endswith('/') else dst
    return os.path.normpath(dst_file)


def setDst(file: str = '', parent: int = 0) -> str:
    """For a given file path return the file path keeping the <parent> number of components"""
    p = Path(file)
    path_components = len(p.parts)
    if parent >= (path_components - 1): parent = path_components - 1 - 1  # IF parent >= number of components without filename THEN make parent = number of component without / and filename
    basedir = p.parents[parent].as_posix()
    if basedir == '/': return file
    return p.as_posix().replace(basedir, '', 1)


def pathtype_local(path: str) -> str:
    """Query if a local path is a file or directory, return f, d or empty"""
    if not path: return ''
    p = Path(path)
    if p.is_dir(): return str('d')
    if p.is_file(): return str('f')
    return ''


def fileIsValid(filename: str, size: Union[str, int], lfn_mtime: Union[str, int], reported_md5: str, shallow_check: bool = False) -> RET:
    """Check if the file path is consistent with the size and md5 argument (source is remote lfn, target is local file); target will be removed if present and not match the source"""
    if os.path.isfile(filename):  # first check
        stat_info = os.stat(filename)
        local_file_mtime = int(stat_info.st_mtime * 1000)
        if int(stat_info.st_size) != int(size):
            os.remove(filename)
            return RET(9, '', f'{filename} : Removed (invalid size)')
        if int(lfn_mtime) > local_file_mtime:  # higher mtime --> newer file; if lfn(source) newer then local_file(destination) then remove destination
            os.remove(filename)
            return RET(9, '', f'{filename} : Removed (source/lfn newer than destination/local_file)')
        if shallow_check:  # file survived so far AND a check without md5 was requested
            os.utime(filename)  # validate the check by updating BOTH access and modified time
            return RET(0, f'{filename} --> TARGET VALID (size match, source/lfn older than destination/local_file)')
        if md5(filename) != reported_md5:
            os.remove(filename)
            return RET(9, '', f'{filename} : Removed (invalid md5)')
        os.utime(filename)  # validate the check by updateding BOTH access and modified time
        return RET(0, f'{filename} --> TARGET VALID (md5 match)')
    return RET(2, '', f'{filename} : No such file')  # ENOENT


def create_metafile(meta_filename: str, lfn: str, local_filename: str, size: Union[str, int], md5in: str, replica_list: Optional[list] = None) -> str:
    """Generate a meta4 xrootd virtual redirector with the specified location and using the rest of arguments"""
    if not (meta_filename and replica_list): return ''
    try:
        lfn = lfn.replace('<', '&lt;').replace('>', '&gt;').replace('&', '&amp;')
        local_filename = local_filename.replace('<', '&lt;').replace('>', '&gt;').replace('&', '&amp;')
        with open(meta_filename, 'w', encoding="ascii", errors="replace") as f:
            published = str(datetime.datetime.now().replace(microsecond=0).isoformat())
            f.write('<?xml version="1.0" encoding="UTF-8"?>\n')
            f.write(' <metalink xmlns="urn:ietf:params:xml:ns:metalink">\n')
            f.write(f'   <published>{published}</published>\n')
            f.write(f'   <file name="{local_filename}">\n')
            f.write(f'     <lfn>{lfn}</lfn>\n')
            f.write(f'     <size>{size}</size>\n')
            if md5in: f.write(f'     <hash type="md5">{md5in}</hash>\n')
            for url in replica_list:
                f.write(f'     <url><![CDATA[{url}]]></url>\n')
            f.write('   </file>\n')
            f.write(' </metalink>\n')
        return meta_filename
    except Exception:
        logging.error(traceback.format_exc())
        return ''


def get_lfn_meta(meta_fn: str) -> str:
    """Extract lfn value from metafile"""
    if 'meta4?' in meta_fn: meta_fn, _, _ = meta_fn.partition('?')
    if not os.path.isfile(meta_fn): return ''
    element_list = MD.parse(meta_fn).documentElement.getElementsByTagName('lfn')
    return element_list[0].firstChild.nodeValue if element_list else ''  # nosec B318:blacklist


def get_size_meta(meta_fn: str) -> int:
    """Extract size value from metafile"""
    if 'meta4?' in meta_fn: meta_fn, _, _ = meta_fn.partition('?')
    if not os.path.isfile(meta_fn): return int(-1)
    element_list = MD.parse(meta_fn).documentElement.getElementsByTagName('size')
    return int(element_list[0].firstChild.nodeValue) if element_list else -1  # nosec B318:blacklist


def get_hash_meta(meta_fn: str) -> tuple:
    """Extract hash value from metafile"""
    if 'meta4?' in meta_fn: meta_fn, _, _ = meta_fn.partition('?')
    if not os.path.isfile(meta_fn): return ('', '')
    element_list = MD.parse(meta_fn).documentElement.getElementsByTagName('hash')
    content = element_list[0] if element_list else None  # nosec B318:blacklist
    return (content.getAttribute('type'), content.firstChild.nodeValue) if content else (None, None)


def get_url_meta(meta_fn: str) -> list:
    """Extract url list from metafile"""
    if 'meta4?' in meta_fn: meta_fn, _, _ = meta_fn.partition('?')
    if not os.path.isfile(meta_fn): return ('', '')
    element_list = MD.parse(meta_fn).documentElement.getElementsByTagName('url')
    return [item.firstChild.nodeValue for item in element_list if item]


def md5(input_file: str) -> str:
    """Compute the md5 digest of the specified file"""
    if not path_readable(input_file): return '-1'
    from hashlib import md5 as hash_md5
    BLOCKSIZE = 65536

    hash_kwargs = {'usedforsecurity': False} if sys.version_info >= (3, 9) else {}
    hasher = hash_md5(**hash_kwargs)

    with open(input_file, 'rb', buffering = 0) as f:
        for chunk in iter(lambda: f.read(BLOCKSIZE), b''): hasher.update(chunk)
    return hasher.hexdigest()


def md5_mp(list_of_files: Optional[list] = None) -> list:
    """Compute md5 hashes in parallel; the results are guaranteed (by documentation) to be in the order of input list"""
    if not list_of_files: return []
    hash_list = []
    with mp.Pool(processes = NCPU) as pool: hash_list = pool.map(md5, list_of_files)
    return hash_list  # noqa: R504


def expand_path_local(path_arg: str, strict: bool = False) -> str:
    """Given a string representing a local file, return a full path after interpretation of HOME location, current directory, . and .. and making sure there are only single /"""
    if not path_arg: return ''
    exp_path = None
    path_arg = lfn_prefix_re.sub('', path_arg)  # lets remove any prefixes
    try:
        exp_path = Path(path_arg).expanduser().resolve(strict).as_posix()
    except Exception:
        return ''
    if (len(exp_path) > 1 and path_arg.endswith('/')) or os.path.isdir(exp_path): exp_path = f'{exp_path}/'
    return exp_path  # noqa: R504


def check_path_perm(filepath: str, mode: int) -> bool:
    """Resolve a file/path and check if mode is valid"""
    filepath = expand_path_local(filepath, True)
    if not filepath: return False
    if not mode: mode = os.F_OK
    return os.access(filepath, mode, follow_symlinks = True)


def path_readable(filepath: str = '') -> bool:
    """Resolve a file/path and check if it is readable"""
    return check_path_perm(filepath, os.R_OK)


def path_writable(filepath: str = '') -> bool:
    """Resolve a file/path and check if it is writable"""
    return check_path_perm(filepath, os.W_OK)


def path_writable_any(filepath: str = '') -> bool:
    """Return true if any path in hierarchy is writable (starting with the longest path)"""
    filepath = expand_path_local(filepath)  # do not use strict as the destination directory could not yet exists
    if not filepath: return False
    paths_list = [p.as_posix() for p in Path(filepath).parents]
    if Path(filepath).is_dir(): paths_list.insert(0, filepath)
    return any(path_writable(p) for p in paths_list)


def path_local_stat(path: str, do_md5: bool = False) -> STAT_FILEPATH:
    """Get full information on a local path"""
    norm_path = expand_path_local(path)
    if not os.path.exists(norm_path): return STAT_FILEPATH(norm_path)
    filetype = 'd' if os.path.isdir(norm_path) else 'f'
    statinfo = os.stat(norm_path)
    perm = oct(statinfo.st_mode)[-3:]  # noqa: BB001
    uid = uid2name(statinfo.st_uid)
    gid = gid2name(statinfo.st_gid)
    ctime = str(statinfo.st_ctime)  # metadata modification
    mtime = str(statinfo.st_mtime)  # content modification
    guid = ''
    size = str(statinfo.st_size)
    md5hash = ''
    if do_md5 and filetype == 'f': md5hash = md5(norm_path)
    return STAT_FILEPATH(norm_path, filetype, perm, uid, gid, ctime, mtime, guid, size, md5hash)


def list_files_local(search_dir: str, pattern: Union[None, REGEX_PATTERN_TYPE, str] = None, is_regex: bool = False, find_args: str = '') -> RET:
    """Return a list of files(local)(N.B! ONLY FILES) that match pattern found in dir"""
    if not search_dir: return RET(2, "", "No search directory specified")

    # let's process the pattern: extract it from src if is in the path globbing form
    regex = None
    is_single_file = False  # dir actually point to a file
    if '*' in search_dir:  # we have globbing in src path
        is_regex = False
        src_arr = search_dir.split("/")
        base_path_arr = []  # let's establish the base path
        for el in src_arr:
            if '*' not in el:
                base_path_arr.append(el)
            else:
                break
        for el in base_path_arr: src_arr.remove(el)  # remove the base path
        search_dir = '/'.join(base_path_arr) + '/'  # rewrite the source path without the globbing part
        pattern = '/'.join(src_arr)  # the globbing part is the rest of element that contain *
    else:  # pattern is specified by argument or not specified
        if pattern is None:
            if not search_dir.endswith('/'):  # this is a single file
                is_single_file = True
            else:
                pattern = '*'  # prefer globbing as default
        elif isinstance(pattern, REGEX_PATTERN_TYPE):  # unlikely but supported to match signatures
            regex = pattern
            is_regex = True
        elif is_regex and isinstance(pattern, str):  # it was explicitly requested that pattern is regex
            regex = valid_regex(pattern)
            if regex is None:
                msg = f'list_files_grid:: {pattern} failed to re.compile'
                logging.error(msg)
                return RET(-1, '', msg)

    directory = None  # resolve start_dir to an absolute_path
    try:
        directory = Path(search_dir).expanduser().resolve(strict = True).as_posix()
    except FileNotFoundError:
        return RET(2, '', f'{search_dir} not found')
    except RuntimeError:
        return RET(2, '', f'Loop encountered along the resolution of {search_dir}')

    filter_args_list = None
    if find_args: filter_args_list = find_args.split()  # for local files listing we have only filtering options

    file_list = None  # make a list of filepaths (that match a regex or a glob)
    if is_single_file:
        file_list = [directory]
    elif is_regex and regex:
        file_list = [os.path.join(root, f) for (root, _, files) in os.walk(directory) for f in files if regex.match(os.path.join(root, f))]
    else:
        file_list = [p.expanduser().resolve(strict = True).as_posix() for p in list(Path(directory).glob(f'**/{pattern}')) if p.is_file()]

    if not file_list:
        return RET(2, '', f"No files found in :: {directory} /pattern: {pattern} /find_args: {find_args}")

    # convert the file_list to a list of file properties dictionaries
    results_list = [file2file_dict(filepath) for filepath in file_list]

    results_list_filtered = []
    # items that pass the conditions are the actual/final results
    for found_lfn_dict in results_list:  # parse results to apply filters
        if not filter_file_prop(found_lfn_dict, directory, filter_args_list, regex): continue
        # at this point all filters were passed
        results_list_filtered.append(found_lfn_dict)

    if not results_list_filtered:
        return RET(2, '', f'No files passed the filters :: {directory} /pattern: {pattern} /find_args: {find_args}')

    ansdict = {"results": results_list_filtered}
    lfn_list = [get_lfn_key(lfn_obj) for lfn_obj in results_list_filtered]
    stdout = '\n'.join(lfn_list)
    return RET(0, stdout, '', ansdict)


def file_set_atime(path: str) -> None:
    """Set atime of file to now"""
    if not os.path.isfile(path): return
    file_stat = os.stat(path)
    os.utime(path, (datetime.datetime.now().timestamp(), file_stat.st_mtime))


def file2file_dict(fn: str) -> dict:
    """Take a string as path and return a dict with file properties"""
    try:
        file_path = Path(fn)
    except Exception:
        return {}
    try:
        file_name = file_path.expanduser().resolve(strict = True)
    except Exception:
        return {}
    if file_name.is_dir(): return {}

    return {'file': file_name.as_posix(), 'lfn': file_name.as_posix(), 'size': str(file_name.stat().st_size),
            'mtime': str(int(file_name.stat().st_mtime * 1000)), 'md5': md5(file_name.as_posix()),
            'owner': pwd.getpwuid(file_name.stat().st_uid).pw_name, 'gowner': gid2name(file_name.stat().st_gid)}


def filter_file_prop(f_obj: dict, base_dir: str, find_opts: Union[str, list, None], compiled_regex_list: Optional[list] = None) -> bool:
    """Return True if an file dict object pass the conditions in find_opts"""
    if not f_obj or not base_dir: return False
    if f_obj['lfn'].endswith('.'): return False

    if not find_opts and not compiled_regex_list: return True
    opts = find_opts.split() if isinstance(find_opts, str) else find_opts.copy()

    lfn = get_lfn_key(f_obj)
    if not base_dir.endswith('/'): base_dir = f'{base_dir}/'
    relative_lfn = lfn.replace(base_dir, '')  # it will have N directories depth + 1 file components

    # string/pattern exclusion
    exclude_str_list = get_arg_value_multiple(opts, '-exclude')
    for exclude_string in exclude_str_list:
        if exclude_string in relative_lfn:
            return False  # this is filtering out the string from relative lfn

    # regex based exclusion; we parse the already compiled regexes
    for compiled_regex in compiled_regex_list:
        match = compiled_regex.search(relative_lfn)
        if match: return False

    min_size = get_arg_value(opts, '-minsize')
    if min_size:
        if not min_size.isdigit() or min_size.startswith("-"):
            print_err(f'filter_file_prop::minsize arg not recognized: {" ".join(opts)}')
            return False
        if int(f_obj["size"]) < abs(int(min_size)): return False

    max_size = get_arg_value(opts, '-maxsize')
    if max_size:
        if not max_size.isdigit() or max_size.startswith("-"):
            print_err(f'filter_file_prop::maxsize arg not recognized: {" ".join(opts)}')
            return False
        if int(f_obj["size"]) > abs(int(max_size)): return False

    jobid = get_arg_value(opts, '-jobid')
    if jobid:
        if not jobid.isdigit() or jobid.startswith("-"):
            print_err(f'filter_file_prop::Missing argument in list:: {" ".join(opts)}')
            return False

        if "jobid" not in f_obj:
            print_err('filter_file_prop::jobid - could not find jobid information in file dictionary, selection failed!')
            return False
        if f_obj["jobid"] != jobid: return False

    user = get_arg_value(opts, '-user')
    if user:
        if not user.isalpha() or user.startswith("-"):
            print_err(f'filter_file_prop::Missing argument in list:: {" ".join(opts)}')
            return False
        if f_obj["owner"] != user: return False

    group = get_arg_value(opts, '-group')
    if group:
        if not group.isalpha() or group.startswith("-"):
            print_err(f'filter_file_prop::Missing argument in list:: {" ".join(opts)}')
            return False
        if f_obj["gowner"] != group: return False

    min_ctime = get_arg_value(opts, '-min-ctime')
    if min_ctime and min_ctime.startswith("-"):
        print_err(f'filter_file_prop::min-ctime arg not recognized: {" ".join(opts)}')
        return False

    max_ctime = get_arg_value(opts, '-max-ctime')
    if max_ctime and max_ctime.startswith("-"):
        print_err(f'filter_file_prop::max-ctime arg not recognized: {" ".join(opts)}')
        return False

    # the argument can be a string with a form like: '20.12.2016 09:38:42,76','%d.%m.%Y %H:%M:%S,%f'
    # see: https://docs.python.org/3.6/library/datetime.html#strftime-strptime-behavior
    if min_ctime or max_ctime:
        dict_time = f_obj.get("ctime", '')
        if not dict_time: dict_time = f_obj.get("mtime", '')
        if not dict_time or not dict_time.isdigit():
            print_err('filter_file_prop::min/max-ctime - could not find time information in file dictionary, selection failed!')
            return False
        if min_ctime:
            min_ctime = time_str2unixmili(min_ctime)
            if int(dict_time) < min_ctime: return False
        if max_ctime:
            max_ctime = time_str2unixmili(max_ctime)
            if int(dict_time) > max_ctime: return False

    min_depth = get_arg_value(opts, '-mindepth')
    if min_depth:
        if not min_depth.isdigit() or min_depth.startswith("-"):
            print_err(f'filter_file_prop::mindepth arg not recognized: {" ".join(opts)}')
            return False
        min_depth = abs(int(min_depth)) + 1  # add +1 for the always present file component of relative_lfn
        if len(relative_lfn.split('/')) < min_depth: return False

    max_depth = get_arg_value(opts, '-maxdepth')
    if max_depth:
        if not max_depth.isdigit() or max_depth.startswith("-"):
            print_err(f'filter_file_prop::maxdepth arg not recognized: {" ".join(opts)}')
            return False
        max_depth = abs(int(max_depth)) + 1  # add +1 for the always present file component of relative_lfn
        if len(relative_lfn.split('/')) > max_depth: return False

    return True


def lfn2tmp_fn(lfn: str = '', uuid5: bool = False) -> str:
    """make temporary file name that can be reconstructed back to the lfn"""
    if not lfn: return str(uuid.uuid4())
    if uuid5:
        return str(uuid.uuid5(uuid.NAMESPACE_URL, lfn))
    return lfn.replace("/", '%%')


def make_tmp_fn(lfn: str = '', ext: str = '', uuid5: bool = False) -> str:
    """make temporary file path string either random or based on grid lfn string"""
    if not ext: ext = f'_{str(os.getuid())}.alienpy_tmp'
    return f'{TMPDIR}/{lfn2tmp_fn(lfn, uuid5)}{ext}'


def get_lfn_name(tmp_name: str = '', ext: str = '') -> str:
    lfn = tmp_name.replace(ext, '') if ext else tmp_name.replace(f'_{str(os.getuid())}.alienpy_tmp', '')
    return lfn.replace(f'{TMPDIR}/', '').replace("%%", "/")


def file2xml_el(filepath: str) -> ALIEN_COLLECTION_EL:
    """Get a file and return an XML element structure"""
    if not filepath or not os.path.isfile(filepath): return ALIEN_COLLECTION_EL()
    p = Path(filepath).expanduser().resolve(strict = True)
    if p.is_dir(): return ALIEN_COLLECTION_EL()
    p_stat = p.stat()
    turl = f'file://{p.as_posix()}'
    return ALIEN_COLLECTION_EL(
        name = p.name, aclId = "", broken = "0", ctime = time_unix2simple(p_stat.st_ctime),
        dir = '', entryId = '', expiretime = '', gowner = p.group(), guid = '', guidtime = '', jobid = '', lfn = turl,
        md5 = md5(p.as_posix()), owner = p.owner(), perm = str(oct(p_stat.st_mode))[5:], replicated = "0",  # noqa: BB001
        size = str(p_stat.st_size), turl = turl, type = 'f')


def mk_xml_local(filepath_list: list) -> str:
    """Create AliEn collection XML output for local files"""
    xml_root = ET.Element('alien')
    collection = ET.SubElement(xml_root, 'collection', attrib={'name': 'tempCollection'})
    for idx, item in enumerate(filepath_list, start = 1):
        e = ET.SubElement(collection, 'event', attrib={'name': str(idx)})
        ET.SubElement(e, 'file', attrib = file2xml_el(lfn_prefix_re.sub('', item))._asdict())
    oxml = ET.tostring(xml_root, encoding = 'ascii')
    dom = MD.parseString(oxml)  # nosec B318:blacklist
    return dom.toprettyxml()


@atexit.register
def cleanup_temp() -> None:
    """Remove from disk all recorded temporary files"""
    if 'AlienSessionInfo' not in globals(): return
    if not AlienSessionInfo['templist']: return

    def rm_item(i: str = '') -> None:
        if not i: return
        if os.path.isfile(i): os.remove(i)
    for f in AlienSessionInfo['templist']: rm_item(f)
    AlienSessionInfo['templist'].clear()


def import_aliases() -> None:
    """Import defined aliases in the global session variable"""
    if 'AlienSessionInfo' not in globals(): return
    alias_file = os.path.join(os.path.expanduser("~"), ".alienpy_aliases")
    if os.path.exists(alias_file): AlienSessionInfo['alias_cache'] = read_conf_file(alias_file)


def convert_trace2dict(trace:str = '', nice_time: bool = True) -> dict:
    """Convert an JAliEn trace output to a somewhat usable dictionary"""
    trace_dict = { 'state': [], 'trace': [], 'proc': [], 'workdir': '', 'wn': '', 'queue': []}
    procfmt = []
    for line in trace.split('\n'):
        # do not use color
        nice_line = convert_time(str(line), False) if nice_time else line

        rez = nice_line.split('[state     ]: ')
        if len(rez) > 1:
            trace_dict['state'].append(' '.join(rez))
            continue
        rez = nice_line.split('[trace     ]: ')
        if len(rez) > 1:
            trace_dict['trace'].append(' '.join(rez))
            if 'Created workdir' in rez[1]:
                trace_dict['workdir'] = rez[1].split(': ')[1]  # noqa: BB001
            if 'Running JAliEn JobAgent' in rez[1]:
                rez_match = re.match(r'Running JAliEn JobAgent .* on ([\w.-]+)\.?', rez[1], re.IGNORECASE)
                trace_dict['wn'] = rez_match.group(1).strip(".")  # noqa: BB001
            if 'BatchId' in rez[1]:
                q_info = rez[1].replace('BatchId', '').strip()
                trace_dict['queue'].append(q_info)
            continue
        rez = nice_line.split('[proc      ]: ')
        if len(rez) > 1:
            trace_dict['proc'].append(' '.join(rez))
            continue
        rez = nice_line.split('[procfmt   ]: ')
        if len(rez) > 1:
            procfmt.append(' '.join(rez))
            continue
    trace_dict['proc'][0:0] = procfmt
    return trace_dict


def convert_jdl2dict(jdl:str = '') -> dict:
    """Convert an JAliEn jdl to a dictionary"""
    jdl_dict = {}
    for line in re.split(r';\s+', jdl):
        line = re.sub(r'\s+', ' ', line).strip()
        k, _, v = line.partition('=')
        v = v.replace('"', '').strip()
        if v.startswith('{') and v.endswith('}'):
            v = v.replace('{', '').replace('}', '').strip()
            v = v.split(', ')
            # list(map(str.strip, v))
            v[:] = [i.strip() for i in v]
        jdl_dict[k.strip()] = v
    return jdl_dict


def queryML(args: list = None) -> RET:
    """Query MonaLisa REST endpoint for information"""
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
    url = f'{alimon}{predicate}{type_default}'
    exitcode = stdout = stderr = ansdict = ansraw = None

    url_req = urlreq.Request(url)
    with urlreq.urlopen(url_req) as req:  # nosec
        ansraw = req.read().decode()
        exitcode = 0 if (req.getcode() == 200) else req.getcode()

    if type_default == type_json:
        stdout = stderr = ''
        ansdict = json.loads(ansraw)
    else:
        stdout, stderr = (ansraw, '') if exitcode == 0 else ('', ansraw)
    return RET(exitcode, stdout, stderr, ansdict)


def ccdb_json_cleanup(item_dict: dict) -> None:
    item_dict.pop('createTime', None)
    item_dict.pop('lastModified', None)
    item_dict.pop('id', None)  # replaced by ETag
    item_dict.pop('validFrom', None)
    item_dict.pop('validUntil', None)
    item_dict.pop('partName', None)

    item_dict.pop('initialValidity', None)  # replaced by InitialValidityLimit
    item_dict.pop('InitialValidityLimit', None)  # unclear use for this field

    item_dict.pop('MD5', None)  # replaced by Content-MD5
    item_dict.pop('fileName', None)  # replaced by Content-Disposition

    item_dict.pop('contentType', None)
    item_dict.pop('size', None)  # replaced by Content-Length

    # get and create the filename
    content_disposition = item_dict.pop('Content-Disposition')
    filename = content_disposition.replace('inline;filename=', '').replace('"', '')
    item_dict['filename'] = filename


def getCAcerts(custom_dir: str = '') -> RET:
    """Downloaf ALICE CA certificates to a given location (where certificates directory will be placed) or to the default ~/.globus/"""
    CERT_DIR = None
    if custom_dir:
        if os.path.isdir(custom_dir) and path_writable(custom_dir):
            CERT_DIR = custom_dir
        else:
            msg = f'Destination {custom_dir} was requested but not present or not writable!'
            return RET(1, '', msg)
    else:
        CERT_DIR = f'{USER_HOME}/.globus'

    if not os.path.isdir(CERT_DIR):
        return RET(1, '', f'Could not find the destination directory: {CERT_DIR}')
    if not is_cmd('git'):
        return RET(1, '', 'git command not available')
    if not is_cmd('rsync'):
        return RET(1, '', 'rsync command not available')

    CA_DIR = f'{CERT_DIR}/certificates'
    CA_DIR_TEMP = f'{CERT_DIR}/aliencas_temp'

    if os.path.isdir(CA_DIR_TEMP): shutil.rmtree(CA_DIR_TEMP, ignore_errors= True)
    Path(CA_DIR_TEMP).mkdir(parents = True, exist_ok = True)

    result = runShellCMD(f'git clone --single-branch --branch master --depth=1 https://github.com/alisw/alien-cas.git {CA_DIR_TEMP}', captureout = True, do_shell = True, timeout = 20)
    if result.exitcode != 0:
        return RET(1, '', 'Could not clone alien-cas repository!!!')
    shutil.rmtree(f'{CA_DIR_TEMP}/.git', ignore_errors= True)

    if os.path.isdir(CA_DIR): shutil.rmtree(CA_DIR, ignore_errors= True)
    Path(CA_DIR).mkdir(parents = True, exist_ok = True)

    result = runShellCMD(f'find {CA_DIR_TEMP} -type d -maxdepth 1 -mindepth 1 -exec rsync -av {{}}/ {CA_DIR} \\;', captureout = True, do_shell = True, timeout = 5)
    if result.exitcode != 0:
        return RET(1, '', 'Could not rsync content to destination!!!')
    shutil.rmtree(f'{CA_DIR_TEMP}', ignore_errors= True)

    # check if openssl rehash (openssl >= 1.1) present
    result = runShellCMD('openssl rehash 2>/dev/null', captureout = True, do_shell = True, timeout = 20)
    # if the command gives error that means that is present and return error due to bad arguments
    if result.exitcode == 1:
        result = runShellCMD(f'openssl rehash {CA_DIR}', captureout = True, do_shell = True, timeout = 20)
    else:
        if is_cmd('c_rehash'):
            result = runShellCMD(f'c_rehash {CA_DIR}', captureout = True, do_shell = True, timeout = 20)

    msg = f'Make sure to do "export X509_CERT_DIR={CA_DIR}" before the usage' if custom_dir else ''
    return RET(0, msg)


def CreateJsonCommand(cmdline: Union[str, dict], args: Optional[list] = None, opts: str = '', get_dict: bool = False) -> Union[str, dict]:
    """Return a json with command and argument list"""
    if not cmdline: return ''
    if args is None: args = []
    if isinstance(cmdline, dict):
        if 'command' not in cmdline or 'options' not in cmdline: return ''
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


def GetMeta(jalien_answer: dict) -> dict:
    """Return metadata of an JAliEn response"""
    if isinstance(jalien_answer, dict) and 'metadata' in jalien_answer: return jalien_answer['metadata']
    return {}


def GetResults(jalien_answer: dict) -> dict:
    """Return results of an JAliEn response"""
    if isinstance(jalien_answer, dict) and 'results' in jalien_answer: return jalien_answer['results']
    return {}


def PrintDict(in_arg: Union[str, dict, list, None] = None, compact: bool = False) -> None:
    """Print a dictionary in a nice format"""
    if not in_arg: return
    if isinstance(in_arg, str):
        try:
            in_arg = json.loads(in_arg)
        except Exception as e:
            print_err(f'PrintDict:: Could not load argument as json!\n{e!r}')
            return
    if isinstance(in_arg, (dict, list)):
        indent = None if compact else 2
        separators = (',', ':') if compact else None
        if ALIENPY_FANCY_PRINT:
            rich_print_json(data = in_arg)
        else:
            print_out(json.dumps(in_arg, sort_keys = True, indent = indent, separators = separators, skipkeys = False))


if __name__ == '__main__':
    print('This file should not be executed!', file = sys.stderr, flush = True)
    sys.exit(95)
