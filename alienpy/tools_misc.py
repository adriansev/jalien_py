'''alienpy:: Misc tooling functions'''

import ast
import sys
import datetime
import json
import re
from typing import Union
import socket
import time
import grp
import pwd
from .global_vars import *  # nosec PYL-W0614
from .setup_logging import print_out, print_err


def PrintColor(color: str) -> str:
    """Disable color if the terminal does not have capability"""
    return color if HAS_COLOR else ''


def exit_message(code: int = 0, msg = ''):
    """Exit with msg and with specied code"""
    print_out(msg if msg else 'Exit')
    sys.exit(code)


def signal_handler(sig, frame):  # pylint: disable=unused-argument
    """Generig signal handler: just print the signal and exit"""
    print_out(f"\nCought signal {sig}, let\'s exit")
    exit_message(int(AlienSessionInfo['exitcode']))


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

    # asume that this is a strptime arguments in the form of: time_str, format_str
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


def unquote_str(arg):
    if type(arg) is str: return ast.literal_eval(arg)
    return arg


def is_guid(guid: str) -> bool:
    """Recognize a GUID format"""
    return bool(guid_regex.fullmatch(guid))  # identify if argument in an AliEn GUID


def run_function(function_name: str, *args, **kwargs):
    """Python code:: run some arbitrary function name (found in globals) with arbitrary arguments"""
    return globals()[function_name](*args, *kwargs)  # run arbitrary function


def PrintDict(in_arg: Union[str, dict], compact: bool = False):
    """Print a dictionary in a nice format"""
    if isinstance(in_arg, str):
        try:
            in_arg = json.loads(in_arg)
        except Exception as e:
            print_err(f'PrintDict:: Could not load argument as json!\n{e!r}')
    if isinstance(in_arg, dict):
        indent = None if compact else 2
        separators = (',', ':') if compact else None
        print_out(json.dumps(in_arg, sort_keys = False, indent = indent, separators = separators))


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


def now_str() -> str: return str(datetime.datetime.now().strftime("%Y%m%d_%H%M%S"))


def deltat_ms(t0: Union[str, float, None] = None) -> str:
    """Return delta t in ms from a time start; if no argment it return a timestamp in ms"""
    now = datetime.datetime.now().timestamp()
    return f"{(now - float(t0)) * 1000:.3f}" if t0 else f"{now * 1000:.3f}"


def deltat_us(t0: Union[str, float, None] = None) -> str:
    """Return delta t in ms from a time start; if no argment it return a timestamp in ms"""
    now = datetime.datetime.now().timestamp()
    return f"{(now - float(t0)) * 1000000:.3f}" if t0 else f"{now * 1000000:.3f}"


def deltat_ms_perf(t0: Union[str, float, None] = None) -> str:
    """Return delta t in ms from a time start; if no argment it return a timestamp in ms"""
    if not t0: return ""
    return f"{(time.perf_counter() - float(t0)) * 1000:.3f}"


def deltat_us_perf(t0: Union[str, float, None] = None) -> str:
    """Return delta t in ms from a time start; if no argment it return a timestamp in ms"""
    if not t0: return ""
    return f"{(time.perf_counter() - float(t0)) * 1000000:.3f}"


def is_help(args: Union[str, list]) -> bool:
    if not args: return False
    if isinstance(args, str): args = args.split()
    help_opts = ('-h', '--h', '-help', '--help')
    return any(opt in args for opt in help_opts)


def read_conf_file(conf_file: str) -> dict:
    """Convert a configuration file with key = value format to a dict"""
    if not conf_file or not os.path.isfile(conf_file): return {}
    DICT_INFO = {}
    try:
        with open(conf_file, encoding="ascii", errors="replace") as rel_file:
            for line in rel_file:
                line = line.partition('#')[0].rstrip()
                name, var = line.partition("=")[::2]
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
                if line.startswith('Uid:'): uid = int((line.split()[1]))
    except Exception:
        logging.error('Error getting uid of pid: %d', pid)
    return uid  # noqa: R504


def is_my_pid(pid: int) -> bool: return bool(pid_uid(int(pid)) == os.getuid())


def writePidFile(filename: str):
    try:
        with open(filename, 'w', encoding="ascii", errors="replace") as f: f.write(str(os.getpid()))
    except Exception:
        logging.exception('Error writing the pid file: %s', filename)


def list_remove_item(target_list: list, item_list):
    """Remove all instances of item from list"""
    if not target_list: return
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
    return val  # noqa: R504


def get_arg_2values(target: list, item):
    """Remove inplace all instances of item, item+1 and item+2 from list and return item+1, item+2"""
    val1 = val2 = None
    for x in target:
        if x == item:
            val2 = target.pop(target.index(x) + 2)
            val1 = target.pop(target.index(x) + 1)
            target.pop(target.index(x))
    return val1, val2


def uid2name(uid: Union[str, int]) -> str:
    """Convert numeric UID to username"""
    return pwd.getpwuid(int(uid)).pw_name


def gid2name(gid: Union[str, int]) -> str:
    """Convert numeric GUI to group name"""
    try:
        group_info = grp.getgrgid(int(gid))
        return group_info.gr_name
    except Exception:
        return str(gid)


def GetHumanReadableSize(size, precision = 2):
    """Convert bytes to higher units"""
    suffixes = ['B', 'KiB', 'MiB', 'GiB']
    suffixIndex = 0
    while size > 1024 and suffixIndex < 5:
        suffixIndex += 1  # increment the index of the suffix
        size = size / 1024.0  # apply the division
    return f'{size:.{precision}f} {suffixes[suffixIndex]}'


def check_ip_port(socket_object: tuple) -> bool:
    """Check connectivity to an address, port; adress should be the tuple given by getaddrinfo"""
    if not socket_object: return False
    DEBUG = os.getenv('ALIENPY_DEBUG', '')
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
    except:
        print_out(f'check_port:: error getting address info for host: {address} ; port: {port}')
        return []
    return [(*sock_obj[-1], check_ip_port(sock_obj)) for sock_obj in ip_list]


def isReachable(address: str = 'alice-jcentral.cern.ch', port: Union[str, int] = 8097) -> bool:
    result_list = check_port(address, port)
    return any(ip[-1] for ip in result_list)


def exitcode(args: Union[list, None] = None):  # pylint: disable=unused-argument
    """Return the latest global recorded exitcode"""
    return RET(0, f"{AlienSessionInfo['exitcode']}", '')  # type: ignore [call-arg]


def valid_regex(regex_str: str) -> Union[None, REGEX_PATTERN_TYPE]:
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


def cleanup_temp(item: str = ''):
    """Remove from disk all recorded temporary files"""
    try:
        AlienSessionInfo
    except NameError:
        return
    if not AlienSessionInfo['templist']: return

    def rm_item(i: str = ''):
        if not i: return
        if os.path.isfile(i):
            AlienSessionInfo['templist'].remove(i)
            os.remove(i)
    if item:
        rm_item(item)
    else:
        for f in AlienSessionInfo['templist']: rm_item(f)


def import_aliases():
    """Import defined aliases in the global session variable"""
    try:
        AlienSessionInfo
    except NameError:
        return
    alias_file = os.path.join(os.path.expanduser("~"), ".alienpy_aliases")
    if os.path.exists(alias_file): AlienSessionInfo['alias_cache'] = read_conf_file(alias_file)


def convert_trace2dict(trace:str = '') -> dict:
    """Convert an JAliEn trace output to a somewhat usable dictionary"""
    trace_dict = { 'state': [], 'trace': [], 'proc': [], 'workdir': '', 'wn': '', 'queue': []}
    procfmt = []
    for line in trace.split('\n'):
        nice_line = convert_time(str(line))

        rez = nice_line.split('[state     ]: ')
        if len(rez) > 1:
            trace_dict['state'].append(' '.join(rez))
            continue
        rez = nice_line.split('[trace     ]: ')
        if len(rez) > 1:
            trace_dict['trace'].append(' '.join(rez))
            if 'Created workdir' in rez[1]:
                trace_dict['workdir'] = rez[1].split(': ')[1]
            if re.match('Running.*on.*', rez[1], re.IGNORECASE):
                trace_dict['wn'] = rez[1].split()[-1]
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
    jdl_dict = dict()
    for line in re.split(r';\s+', jdl):
        line = re.sub(r'\s+', ' ', line).strip()
        k, _, v = line.partition('=')
        v = v.replace('"', '').strip()
        if v.startswith('{') and v.endswith('}'):
            v = v.replace('{', '').replace('}', '').strip()
            v = v.split(', ')
            list(map(str.strip, v))
        jdl_dict[k.strip()] = v
    return jdl_dict


if __name__ == '__main__':
    print('This file should not be executed!', file = sys.stderr, flush = True)
    sys.exit(95)

