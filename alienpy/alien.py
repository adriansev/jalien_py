#!/usr/bin/env python3
"""Executable/module for interaction with GRID services of ALICE experiment"""

import os
import sys
if sys.version_info[0] < 3 or (sys.version_info[0] == 3 and sys.version_info[1] < 6):
    print("This packages requires a minimum of Python version 3.6", file = sys.stderr, flush = True)
    sys.exit(1)

import atexit
import collections
import datetime
import difflib
import json
import re
import signal
from pathlib import Path
import subprocess  # nosec
import logging
import shlex
import statistics
from typing import NamedTuple
from typing import Union
from typing import Optional
from typing import Callable
from typing import Iterator
import traceback
import time
import urllib.request as urlreq
from urllib.parse import urlparse
import xml.dom.minidom as MD  # nosec
import xml.etree.ElementTree as ET  # nosec

# External imports
try:
    import requests
except Exception:
    print("requests module could not be imported! Make sure you can do:\npython3 -c 'import requests'", file = sys.stderr, flush = True)
    sys.exit(1)

HAS_PPRINT = False
try:
    from rich.pretty import pprint
    HAS_PPRINT = True
except Exception:
    print("rich module could not be imported! Not fatal, but some pretty print features will not be available.\n Make sure you can do:\npython3 -c 'from rich.pretty import pprint'", file = sys.stderr, flush = True)

HAS_READLINE = False
try:
    import readline as rl  # type: ignore
    HAS_READLINE = True
except ImportError:
    try:
        import gnureadline as rl  # type: ignore  # mypy: no-redef
        HAS_READLINE = True
    except ImportError:
        pass


##################################################
#   GLOBAL POINTER TO WB CONNECTION  #############
ALIENPY_GLOBAL_WB = None
##################################################
##################################################
#   GLOBAL VARS
##################################################
ALIENPY_EXECUTABLE = ''

from .global_vars import *  # nosec PYL-W0614

##   START LOGGING BEFORE ANYTHING ELSE
from .setup_logging import print_out, print_err, setup_logging
setup_logging(DEBUG, DEBUG_FILE)

##   Data strucutures definitons
from .data_structs import *  # nosec PYL-W0614

##   VERSION STRINGS
from .version import *  # nosec PYL-W0614

##   SSL RELATED VARIABLES: TOKEN AND CERT NAMES
from .connect_ssl import TOKENCERT_NAME, TOKENKEY_NAME, TOKENCERT_VALID, TOKENKEY_VALID, USERCERT_VALID, USERKEY_VALID, CertInfo, CertVerify, CertKeyMatch

##   General misc functions library
from .tools_misc import *  # nosec PYL-W0614

# commands stack tools
from .tools_stackcmd import push2stack, deque_pop_pos

# shell related toold
from .tools_shell import *  # nosec PYL-W0614

# Session save
from .setup_cwd import SessionSave, SessionRestore

#########################
#   ASYNCIO MECHANICS
#########################
from .wb_api import *  # nosec PYL-W0614

# XRootD functions
from .xrd_core import *  # nosec PYL-W0614
# Global XRootD preferences
xrd_config_init()


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
    if not cmd: return RET(1)  # type: ignore [call-arg]
    if args is None: return RET(1)  # type: ignore [call-arg]
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
        return RET(1, '', help_msg)  # type: ignore [call-arg]

    sign = None
    position = None
    pos = None
    for arg in arg_list:
        if arg[0] == '+' or arg[0] == '-':
            sign = arg[0]
            if not arg[1:].isdecimal(): return RET(1, '', "-N | +N argument is invalid")  # type: ignore [call-arg]
            position = int(arg[1:])
            arg_list.remove(arg)
            pos = int(arg)

    if cmd == "dirs":
        if '-c' in arg_list:
            AlienSessionInfo['pathq'].clear()
            return RET(0)  # type: ignore [call-arg]
        if not arg_list: msg = ' '.join(AlienSessionInfo['pathq'])

        if position and sign:
            if position > len(AlienSessionInfo['pathq']) - 1: return RET(0)  # type: ignore [call-arg]
            if sign == "+":
                msg = AlienSessionInfo['pathq'][position]  # Nth position from top (last/top element have the index 0)
            if sign == "-":
                msg = AlienSessionInfo['pathq'][len(AlienSessionInfo['pathq']) - 1 - position]  # Nth position from last
        return RET(0, msg)  # type: ignore [call-arg]  # end of dirs

    if cmd == "popd":
        if position and sign:
            if position > len(AlienSessionInfo['pathq']) - 1: return RET(0)  # type: ignore [call-arg]
            deque_pop_pos(AlienSessionInfo['pathq'], pos)
            msg = " ".join(AlienSessionInfo['pathq'])
            return RET(0, msg)  # type: ignore [call-arg]

        if not arg_list:
            AlienSessionInfo['pathq'].popleft()
            if not do_not_cd: cd(wb, AlienSessionInfo['pathq'][0])  # cd to the new top of stack
        msg = " ".join(AlienSessionInfo['pathq'])
        return RET(0, msg)  # type: ignore [call-arg]  # end of popd

    if cmd == "pushd":
        if position and sign:
            if position > len(AlienSessionInfo['pathq']) - 1: return RET(0)  # type: ignore [call-arg]
            if sign == "+":
                AlienSessionInfo['pathq'].rotate(-1 * position)
                if not do_not_cd: cd(wb, AlienSessionInfo['pathq'][0], 'log')  # cd to the new top of stack
            if sign == "-":
                AlienSessionInfo['pathq'].rotate(-(len(AlienSessionInfo['pathq']) - 1 - position))
                if not do_not_cd: cd(wb, AlienSessionInfo['pathq'][0], 'log')  # cd to the new top of stack
            msg = " ".join(AlienSessionInfo['pathq'])
            return RET(0, msg)  # type: ignore [call-arg]  # end of +N|-N

        if not arg_list:
            if len(AlienSessionInfo['pathq']) < 2: return RET(0)  # type: ignore [call-arg]
            old_cwd = AlienSessionInfo['pathq'].popleft()
            new_cwd = AlienSessionInfo['pathq'].popleft()
            push2stack(old_cwd)
            push2stack(new_cwd)
            if not do_not_cd: cd(wb, AlienSessionInfo['pathq'][0], 'log')
            msg = " ".join(AlienSessionInfo['pathq'])
            return RET(0, msg)  # type: ignore [call-arg]  # end of +N|-N

        path = expand_path_grid(arg_list[0])
        if do_not_cd:
            cwd = AlienSessionInfo['pathq'].popleft()
            push2stack(path)
            push2stack(cwd)
        else:
            push2stack(path)
            cd(wb, AlienSessionInfo['pathq'][0], 'log')  # cd to the new top of stack
        msg = " ".join(AlienSessionInfo['pathq'])
        return RET(0, msg)  # type: ignore [call-arg]  # end of +N|-N
    return RET()  # type: ignore [call-arg]  # dummy return just in case cmd is not proper


def DO_version(args: Union[list, None] = None) -> RET:  # pylint: disable=unused-argument
    stdout = (f'alien.py version: {ALIENPY_VERSION_STR}\n'
              f'alien.py version date: {ALIENPY_VERSION_DATE}\n'
              f'alien.py version hash: {ALIENPY_VERSION_HASH}\n'
              f'alien.py location: {os.path.realpath(__file__)}\n'
              f'script location: {ALIENPY_EXECUTABLE}\n'
              f'Interpreter: {os.path.realpath(sys.executable)}\n'
              f'Python version: {sys.version}\n'
              'XRootD version: ')
    stdout = f'{stdout}{xrd_client.__version__}\nXRootD path: {xrd_client.__file__}' if HAS_XROOTD else f'{stdout}Not Found!'
    return RET(0, stdout, "")  # type: ignore [call-arg]


def DO_exit(args: Union[list, None] = None) -> Union[RET, None]:
    if args is None: args = []
    if len(args) > 0 and args[0] == '-h':
        msg = 'Command format: exit [code] [stderr|err] [message]'
        return RET(0, msg)  # type: ignore [call-arg]
    code = AlienSessionInfo['exitcode']
    msg = ''
    if len(args) > 0:
        if args[0].isdecimal(): code = args.pop(0)
        if args[0] == 'stderr' or args[0] == 'err': args.pop(0)
        msg = ' '.join(args).strip()
        if msg:
            if code == 0:
                print_out(msg)
            else:
                print_err(msg)
    sys.exit(int(code))


def DO_xrd_ping(wb, args: Union[list, None] = None) -> RET:
    global AlienSessionInfo
    if args is None: args = []
    if not args or is_help(args):
        msg = ('Command format: xrd_ping [-c count] fqdn[:port] | SE name | SE id\n'
               'It will use the XRootD connect/ping option to connect and return a RTT')
        return RET(0, msg)

    count_arg = get_arg_value(args, '-c')
    count = int(count_arg) if count_arg else 3

    sum_rez = []
    for se_name in args:
        ret_obj = DO_getSE(wb, ['-srv', se_name])
        if 'results' in ret_obj.ansdict: sum_rez.extend(ret_obj.ansdict['results'])

    # maybe user want to ping servers outside of ALICE redirectors list
    if not sum_rez:
        for arg in args: sum_rez.append({'seName': arg, 'endpointUrl': f'root://{arg}'})

    msg = f'XRootD ping(s): {count} time(s) to:'
    for se in sum_rez:
        se_name = se['seName']
        se_fqdn = urlparse(se['endpointUrl']).netloc

        results_list = []
        for _i in range(count): results_list.append(xrdfs_ping(se_fqdn))

        results = [res['ping_time_ms'] for res in results_list if res['ok']]
        if results:
            rtt_min = min(results)
            rtt_max = max(results)
            rtt_avg = statistics.mean(results)
            rtt_stddev = statistics.stdev(results) if len(results) > 1 else 0.0
            msg = f'{msg}\n{se_name : <32} rtt min/avg/max/mdev (ms) = {rtt_min:.3f}/{rtt_avg:.3f}/{rtt_max:.3f}/{rtt_stddev:.3f}'
        else:
            msg = f'{msg}\n{se_name : <32} {results_list[-1]["message"]}'

    return RET(0, msg)


def DO_xrd_config(wb, args: Union[list, None] = None) -> RET:
    global AlienSessionInfo
    if args is None: args = []
    if not args or is_help(args):
        msg = ('Command format: xrd_config [-v | -verbose] fqdn[:port] | SE name | SE id\n'
               'It will use the XRootD query config to get the current server properties\n'
               'verbose mode will print more about the server configuration')
        return RET(0, msg)
    verbose = get_arg(args, '-v') or get_arg(args, '-verbose')
    all_alice_sites = get_arg(args, '-a') or get_arg(args, '-all')

    sum_rez = []
    if all_alice_sites:
        ret_obj = DO_getSE(wb, ['-srv'])
        if 'results' in ret_obj.ansdict: sum_rez.extend(ret_obj.ansdict['results'])
    else:
        for se_name in args:
            ret_obj = DO_getSE(wb, ['-srv', se_name])
            if 'results' in ret_obj.ansdict: sum_rez.extend(ret_obj.ansdict['results'])

    # maybe user want to ping servers outside of ALICE redirectors list
    if not sum_rez:
        for arg in args: sum_rez.append({'seName': arg, 'endpointUrl': f'root://{arg}'})

    config_list = []
    msg_list = []
    for se in sum_rez:
        se_name = se['seName']
        se_fqdn = urlparse(se['endpointUrl']).netloc
        cfg = xrdfs_q_config(se_fqdn)
        if not cfg or 'sitename' not in cfg: continue
        cfg['seName'] = se_name  # xrootd 'sitename' could be undefined
        cfg['endpointUrl'] = se_fqdn
        if cfg['sitename'] == "NOT_SET" or not cfg['sitename']: cfg['sitename'] = se['seName']
        config_list.append(cfg)

        msg = f'Site/XrdVer: {cfg["sitename"] if cfg["sitename"] != "NOT_SET" or not cfg["sitename"] else cfg["seName"]}/{cfg["version"]} ; TPC status: {cfg["tpc"]} ; role: {cfg["role"]} ; CMS: {cfg["cms"]}'
        if verbose:
            msg = (f'{msg}\n'
                   f'Chksum type: {cfg["chksum"]} ; Bind max: {cfg["bind_max"]} ; PIO max: {cfg["pio_max"]} ; '
                   f'Window/WAN window: {cfg["window"]}/{cfg["wan_window"]} ; readv_{{ior,iov}}_max: {cfg["readv_ior_max"]}/{cfg["readv_iov_max"]}')

        msg_list.append(msg)

    results_dict = {'results': config_list}
    msg_all = '\n'.join(msg_list)
    return RET(0, msg_all, '', results_dict)


def DO_xrd_stats(wb, args: Union[list, None] = None) -> RET:
    global AlienSessionInfo
    if args is None: args = []
    if not args or is_help(args):
        msg = ('Command format: xrd_stats [ -xml | -xmlraw | -compact  ]  fqdn[:port] | SE name | SE id\n'
               'It will use the XRootD query stats option to get the server metrics\n'
               '-xml : print xml output (native to xrootd)\n'
               '-xmlraw : print rawxml output without any indentation\n'
               '-compact : print the most compact version of the output, with minimal white space\n')
        return RET(0, msg)
    compact = get_arg(args, '-compact')
    xml_out = get_arg(args, '-xml')
    xml_raw = get_arg(args, '-xmlraw')
    if xml_raw: xml_out = True
    all_alice_sites = get_arg(args, '-a') or get_arg(args, '-all')

    sum_rez = []
    if all_alice_sites:
        ret_obj = DO_getSE(wb, ['-srv'])
        if 'results' in ret_obj.ansdict: sum_rez.extend(ret_obj.ansdict['results'])
    else:
        for se_name in args:
            ret_obj = DO_getSE(wb, ['-srv', se_name])
            if 'results' in ret_obj.ansdict: sum_rez.extend(ret_obj.ansdict['results'])

    # maybe user want to ping servers outside of ALICE redirectors list
    if not sum_rez:
        for arg in args: sum_rez.append({'seName': arg, 'endpointUrl': f'root://{arg}'})

    stats_list = []
    msg_list = []
    for se in sum_rez:
        se_name = se['seName']
        se_fqdn = urlparse(se['endpointUrl']).netloc
        stats = xrdfs_q_stats(se_fqdn, xml = xml_out, xml_raw = xml_raw, compact = compact)
        if not stats: continue

        if xml_out:
            stats_list.append('XML output only, no json content')
            msg_list.append(f'{stats}')
            continue  # if plain xml output stop processing

        stats['seName'] = se_name  # xrootd 'sitename' could be undefined
        stats['endpointUrl'] = se_fqdn
        if stats['site'] == "NOT_SET" or not stats['site']: stats['site'] = se['seName']
        stats_list.append(stats)
        indent = None if compact else '  '
        separators = (',', ':') if compact else (', ', ': ')
        msg_list.append(json.dumps(stats, indent = indent, separators = separators).replace('\\"', ''))

    results_dict = {'results': stats_list}
    msg_all = '\n'.join(msg_list)
    exitcode = 1 if not results_dict else 0
    return RET(exitcode, msg_all, '', results_dict)


def DO_pfn(wb, args: Union[list, None] = None) -> RET:
    if args is None: args = []
    if is_help(args):
        msg = 'Command format : pfn [lfn]\nIt will print only the list of associated pfns (simplified form of whereis)'
        return RET(0, msg)
    args.insert(0, '-r')
    ret_obj = SendMsg(wb, 'whereis', args, opts = 'nomsg')
    msg = '\n'.join(str(item['pfn']) for item in ret_obj.ansdict['results'] if 'pfn' in item).strip()
    return ret_obj._replace(out = msg)


def DO_pfnstatus(wb, args: Union[list, None] = None) -> RET:
    global AlienSessionInfo
    if args is None: args = []
    if not args or is_help(args):
        msg = ('Command format: pfn_status <pfn>|<lfn>\n'
               'It will return all flags reported by the xrootd server - this is direct access to server\n'
               'pfn is identified by prefix root://; if missing the argument will be taken to be a lfn')
        return RET(0, msg)
    verbose = get_arg(args, '-v') or get_arg(args, '-verbose')
    pfn_list = []
    # create a list of all pfns to be queried
    for arg in args:
        if arg.startswith('root://'):
            pfn_list.append({'lfn': '', 'pfn': arg})
        else:
            # we assume that it's a lfn
            file_path = expand_path_grid(arg)
            pfns_ret = DO_pfn(wb, [file_path])
            pfn_list_found = [{'lfn': file_path, 'pfn': str(item['pfn'])} for item in pfns_ret.ansdict['results'] if 'pfn' in item]
            pfn_list.extend(pfn_list_found)

    msg_all = None
    dict_results = {"results": []}
    for pfn in pfn_list:
        get_pfn_info = xrdstat2dict(xrdfs_stat(pfn['pfn']))
        if 'flags' in get_pfn_info:
            pfn_flags = xrdstat_flags2dict(get_pfn_info['flags'])
            get_pfn_info.pop('flags')
        else:
            pfn_flags = {}

        pfn_info = {'lfn': pfn['lfn'], 'pfn': pfn['pfn'], **get_pfn_info, **pfn_flags}
        dict_results['results'].append(pfn_info)
        msg = None
        if pfn["lfn"]: msg = f'LFN: {pfn["lfn"]}\n'
        if pfn_info['ok']:
            # ( f'{msg if msg else ""}'
            msg = f'{msg if msg else ""}{pfn["pfn"]}\t\tSize: {pfn_info["size"]}\tR/W status:{int(pfn_info["is_readable"])}/{int(pfn_info["is_writable"])}\n'
            if verbose: msg = (f'{msg}'
                               f'IS DIR/OTHER/OFFLINE: {int(pfn_info["is_dir"])}/{int(pfn_info["other"])}/{int(pfn_info["offline"])}\t'
                               f'Modified: {pfn_info["modtimestr"]}\tPOSC pending: {int(pfn_info["posc_pending"])}\t\tBACKUP: {int(pfn_info["backup_exists"])}\n')
        else:
            msg = (f'{msg if msg else ""}'
                   f'{pfn["pfn"]}\t\tMessage: {pfn_info["message"]}\tStatus/Code/ErrNo:{pfn_info["status"]}/{pfn_info["code"]}/{pfn_info["errno"]}\n')

        msg_all = f'{msg_all if msg_all else ""}{msg}'

    return RET(0, msg_all, '', dict_results)


def DO_getSE(wb, args: list = None) -> RET:
    if not wb: return []
    if not args: args = []
    if is_help(args):
        msg = 'Command format: getSE <-id | -name | -srv> identifier_string\nReturn the specified property for the SE specified label'
        return RET(0, msg)

    ret_obj = SendMsg(wb, 'listSEs', [], 'nomsg')
    if ret_obj.exitcode != 0: return ret_obj

    arg_select = ''  # default return
    if get_arg(args, '-name'): arg_select = 'name'
    if get_arg(args, '-id'): arg_select = 'id'
    if get_arg(args, '-srv'): arg_select = 'srv'

    if not args:
        se_list = [f"{se['seNumber'] : <6}{se['seName'] : <32}{urlparse(se['endpointUrl']).netloc.strip()}" for se in ret_obj.ansdict["results"]]
        return RET(0, '\n'.join(se_list), '', ret_obj.ansdict)

    def match_name(se: Union[dict, None] = None, name: str = '') -> bool:
        if se is None or not name: return False
        if name.isdecimal(): return name in se['seNumber']
        return name.casefold() in se['seName'].casefold() or name.casefold() in se['seNumber'].casefold() or name.casefold() in se['endpointUrl'].casefold()

    se_name = args[-1].casefold()
    rez_list = []
    se_list = [se for se in ret_obj.ansdict["results"] if match_name(se, se_name)]
    if not se_list: return RET(1, '', f">{args[-1]}< label(s) not found in SE list")

    for se_info in se_list:
        srv_name = urlparse(se_info["endpointUrl"]).netloc.strip()
        if arg_select == 'name':
            rez_list.append(se_info['seName'])
        elif arg_select == 'srv':
            rez_list.append(srv_name)
        elif arg_select == 'id':
            rez_list.append(se_info['seNumber'])
        else:
            if se_name.isdecimal():
                rez_list.append(f"{se_info['seName'] : <32}{srv_name}")
            else:
                rez_list.append(f"{se_info['seNumber'] : <6}{se_info['seName'] : <32}{srv_name}")

    if not rez_list: return RET(1, '', f"Empty result when searching for: {args[-1]}")
    return RET(0, '\n'.join(rez_list), '', {'results': se_list})


def DO_getCE(wb, args: list = None) -> RET:
    if not wb: return []
    if not args: args = []
    if is_help(args):
        msg = 'Command format: getCE [-name string] [-host string] [-part string]>\nReturn the informations for the selection'
        return RET(0, msg)

    ret_obj = SendMsg(wb, 'listCEs', [], 'nomsg')
    if ret_obj.exitcode != 0: return ret_obj
    if 'results' not in ret_obj.ansdict: return RET(1, '', 'Could not get the list of CEs')
    ce_list_dict = ret_obj.ansdict['results']

    header = f'Name{" "*24}Host{" "*46}State{" "*3}Type{" "*6}R{" "*5}W{" "*5}TTL{" "*7}Partitions'
    if not args:
        ce_info = [f'{ce["ceName"].replace("ALICE::","") : <28}{ce["host"] : <50}{ce["status"] : <8}{ce["type"] : <10}{ce["maxRunning"] : <6}{ce["maxQueued"] : <6}{ce["TTL"] : <10}{ce["partitions"].strip(",")}' for ce in ce_list_dict]
        return RET(0, f"{header}\n{f'{os.linesep}'.join(ce_info)}", '', ce_list_dict)

    select_name = get_arg_value(args, '-name')
    select_host = get_arg_value(args, '-host')
    select_part = get_arg_value(args, '-part')

    def match_name(ce: Union[dict, None] = None, name: str = '') -> bool:
        if ce is None or not name: return False
        return name.casefold() in ce['ceName'].casefold()

    def match_host(ce: Union[dict, None] = None, host: str = '') -> bool:
        if ce is None or not host: return False
        return host.casefold() in ce['host'].casefold()

    def match_part(ce: Union[dict, None] = None, part: str = '') -> bool:
        if ce is None or not part: return False
        part_list = ce['partitions'].casefold().split(',')
        return part.casefold() in part_list

    select_list = []
    if select_name:
        select_list = [ce for ce in ce_list_dict if match_name(ce, select_name) ]

    if select_host:
        if select_list: ce_list_dict = select_list[:]
        select_list = [ce for ce in ce_list_dict if match_name(ce, select_host) ]

    if select_part:
        if select_list: ce_list_dict = select_list[:]
        select_list = [ce for ce in ce_list_dict if match_part(ce, select_part) ]

    if not select_list:
        return RET(0, 'Empty selection results')

    ce_info = [f'{ce["ceName"].replace("ALICE::","") : <28}{ce["host"] : <50}{ce["status"] : <8}{ce["type"] : <10}{ce["maxRunning"] : <6}{ce["maxQueued"] : <6}{ce["TTL"] : <10}{ce["partitions"].strip(",")}' for ce in select_list]
    return RET(0, f"{header}\n{f'{os.linesep}'.join(ce_info)}", '', select_list)


def DO_SEqos(wb, args: list = None) -> RET:
    if not wb: return RET()
    if not args or is_help(args):
        msg = 'Command format: SEqos <SE name>\nReturn the QOS tags for the specified SE (ALICE:: can be ommited and capitalization does not matter)'
        return RET(0, msg)
    sum_rez = []
    for se_name in args:
        ret_obj = DO_getSE(wb, [se_name])
        if 'results' in ret_obj.ansdict: sum_rez.extend(ret_obj.ansdict['results'])
    if not sum_rez: return RET(1, '', f'No SE information found! -> {" ".join(args)}')
    msg = None
    for se in sum_rez:
        msg = f'{msg if msg else ""}{se["seName"] : <32}{se["qos"]}\n'
    return RET(0, msg, '', {'results': sum_rez})


def DO_siteJobs(wb, args: list = None) -> RET:
    if not wb: return RET()
    if not args or is_help(args):
        msg = '''Command format: siteJobs <SITE ID> [ -id ] [ -running ] [ -status string] [ -user string ]
        Print jobs id or information for jobs associated with a site; use getCE command to identify site names'''
        return RET(0, msg)
    site_arg = args.pop(0)

    identified_site_names_obj = DO_getCE(wb, ['-name', site_arg])
    if not identified_site_names_obj.ansdict:
        return RET(1, '', f'No site names were identified by the label: {site_arg}')
    identified_site_names_list_dict = identified_site_names_obj.ansdict
    identified_site_names_list = [ce['ceName'] for ce in identified_site_names_list_dict]
    site_str = ','.join(identified_site_names_list)

    job_list_query = SendMsg(wb, 'ps', ['-s', site_str, '-a'], 'nomsg')
    if 'results' not in job_list_query.ansdict or not job_list_query.ansdict['results']: return job_list_query
    jobs_list_dict = job_list_query.ansdict['results']

    select_status = get_arg_value(args, '-status')
    select_user = get_arg_value(args, '-user')
    show_only_id = get_arg(args, '-id')
    show_only_running = get_arg(args, '-running') or get_arg(args, '-r')
    if show_only_running: select_status = 'RUNNING'

    def match_status(job: Union[dict, None] = None, status: str = '') -> bool:
        if job is None or not status: return False
        return status.casefold() in job['status'].casefold()

    def match_user(job: Union[dict, None] = None, user: str = '') -> bool:
        if job is None or not status: return False
        return user.casefold() in job['owner'].casefold()

    select_list = []
    if select_status:
        select_list = [job for job in jobs_list_dict if match_status(job, select_status) ]

    if select_user:
        if select_list: jobs_list_dict = select_list[:]
        select_list = [job for job in jobs_list_dict if match_user(job, select_user) ]

    if not select_list and (select_status or select_user): return RET(0, 'Selection(s) returned no match!')
    if not select_list: select_list = jobs_list_dict

    if show_only_id:
        id_list = [job['id '] for job in select_list]
        return RET(0, f'{os.linesep.join(id_list)}', '', select_list)

    header = f'JobID{" "*8}MasterJobID{" "*2}Status{" "*6}User{" "*10}Name'
    job_info = [f'{j["id"] : <13}{j["split"] : <13}{j["status"] : <12}{j["owner"] : <14}{j["name"]}' for j in select_list]
    return RET(0, f"{header}\n{f'{os.linesep}'.join(job_info)}", '', select_list)


def DO_jobInfo(wb, args: list = None) -> RET:
    if not wb: return RET()
    if not args or is_help(args):
        msg = '''Command format: jobInfo id1,id2,.. [ -trace ] [ -proc ]
        Print job information for specified ID(s)
        -trace will show the trace messages
        -proc will show the proc messages
        '''
        return RET(0, msg)

    show_trace = get_arg(args, '-trace')
    show_proc = get_arg(args, '-proc')
    show_jdl = get_arg(args, '-jdl')

    jobid = args.pop(0)
    job_info_query = SendMsg(wb, 'ps', ['-j', jobid, '-trace', '-jdl'], 'nomsg')
    if job_info_query.exitcode != 0 or 'results' not in job_info_query.ansdict or not job_info_query.ansdict['results']: return job_info_query
    job_info_list_dict = job_info_query.ansdict['results']

    job_list_messages = []
    header = f'JobID{" "*8}MasterJobID{" "*2}Status{" "*6}User{" "*10}Name'

    job_processed_list = []

    for j in job_info_list_dict:
        new_j = dict(j)
        new_j['trace'] = convert_trace2dict(j['trace'])
        new_j['jdl'] = convert_jdl2dict(j['jdl'])
        job_processed_list.append(new_j)

        if show_jdl:
            mod_jdl = json.dumps(new_j["jdl"], separators=(',', ':'))
            job_list_messages.append(f'{mod_jdl}\n')
        else:
            job_info = f'##################################################################\n{header}\n{j["id"] : <13}{j["split"] : <13}{j["status"] : <12}{j["owner"] : <14}{j["name"]}\n\n'
            machine_info = f'Machine info:\nWorkerNode: {new_j["trace"]["wn"]}\nWorkdir: {new_j["trace"]["workdir"]}\nLocal queue info:\n{f"{os.linesep}".join(new_j["trace"]["queue"])}\n\n'
            state_info = f'State info:\n{f"{os.linesep}".join(new_j["trace"]["state"])}\n\n'
            trace_info = f'Trace info:\n{f"{os.linesep}".join(new_j["trace"]["trace"])}\n\n'
            proc_info = f'Proc info:\n{f"{os.linesep}".join(new_j["trace"]["proc"])}\n\n'
            job_list_messages.append(f'{job_info}{machine_info}{state_info}{trace_info if show_trace else ""}{proc_info if show_proc else ""}')

    return RET(0, f'{os.linesep}'.join(job_list_messages), '', job_processed_list)


def queryML(args: list = None) -> RET:
    """submit: process submit commands for local jdl cases"""
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
    item_dict.pop('initialValidity', None)  # replaced by InitialValidityLimit
    item_dict.pop('MD5', None)  # replaced by Content-MD5
    item_dict.pop('fileName', None)  # replaced by Content-Disposition
    content_disposition = item_dict.pop('Content-Disposition')
    filename = content_disposition.replace('inline;filename=', '').replace('"', '')
    item_dict['filename'] = filename

    item_dict.pop('contentType', None)
    item_dict.pop('size', None)  # replaced by Content-Length
    item_dict.pop('Created', None)  #  no need (??) to be shown (mail2dev if needed)
    item_dict.pop('Content-Type', None)  #  useless for this application
    item_dict.pop('UploadedFrom', None)  #  useless for this application
    item_dict.pop('UploadedBy', None)  #  useless for this application
    item_dict.pop('partName', None)  #  useless for this application
    item_dict.pop('InitialValidityLimit', None)  #  unclear use for this field


def DO_ccdb_query(args: list = None) -> RET:
    """Query CCDB for object data"""
    if not args: return RET(2, '', 'empty query! Use at least a "/" as argument')

    if is_help(args):
        return RET(0, '''ccdb [-host FQDN] [-history] [-nicetime] QUERY
where query has the form of:
task name / detector name / start time [ / UUID]
or
task name / detector name / [ / time [ / key = value]* ]

-host: specify other ccdb server than alice-ccdb.cern.ch
-history: use browse to list the whole history of the object
-unixtime: print the unixtime
-get: download the specified object/objects - full path will be kept
-dst: set a specific destination for download
''' )

    headers = { 'user-agent': f'alien.py/{ALIENPY_VERSION_STR}', 'Accept': 'application/json', 'Accept-encoding': 'gzip, deflate', }  

    listing_type = 'browse/' if get_arg(args, '-history') else 'latest/'
    ccdb_default_host = 'http://alice-ccdb.cern.ch/'
    host_arg = get_arg_value(args, '-host')
    do_unixtime = get_arg(args, '-unixtime')
    do_compact = get_arg(args, '-compact')
    do_download = get_arg(args, '-get')

    dest_arg = get_arg_value(args, '-dst')
    if not dest_arg: dest_arg = '.'
    if not dest_arg.endswith('/'): dest_arg = f'{dest_arg}/'

    ccdb = host_arg if host_arg else ccdb_default_host
    if not ccdb.endswith('/'): ccdb = f'{ccdb}/'
    if not ccdb.startswith('http://') and not ccdb.startswith('https://'): ccdb = f'http://{ccdb}'

    if not args: return RET(2, '', 'empty query!')
    query_str = args[0]  # after removal of args assume the rest is the query

    q = requests.get(f'{ccdb}{listing_type}{query_str}', headers = headers, timeout = 5)
    q_dict = q.json()
    q_path = q_dict.pop('path')
    q_latest = q_dict.pop('latest')
    q_patternMatching = q_dict.pop('patternMatching')
    list(map(ccdb_json_cleanup, q_dict['objects']))

    if not do_unixtime:
        if 'validAt' in q_dict: q_dict['validAt'] = unixtime2local(q_dict['validAt'])
        for i in q_dict['objects']:
            i['Last-Modified'] = unixtime2local(i['Last-Modified'])
            i['Valid-From'] = unixtime2local(i['Valid-From'])
            i['Valid-Until'] = unixtime2local(i['Valid-Until'])

    dir_list = [f'{d}/' for d in q_dict['subfolders']]
    msg_dirs = f'{os.linesep}'.join(dir_list) if dir_list else ''

    from rich import print

    def get_alien_endpoint(obj):
        if not 'replicas' in obj: return ''
        for i in obj['replicas']:
            if i.startswith('alien'): return i

    header = f'Filename{" "*39}Type{" "*24}LastMod{" "*27}Valid'
    download_list = []
    dest_list = []
    msg_obj_list = []
    for q in q_dict['objects']:
        download_list.append(get_alien_endpoint(q))
        dest_list.append(f'file:{dest_arg}{q["path"]}/{q["filename"].replace("<","_").replace(">","_")}')
        msg_obj_list.append(f'{q["filename"]}    {q["ObjectType"]}    \"{q["Last-Modified"]}\"    \"{q["Valid-Until"]}\"')

    if do_download:
        return DO_XrootdCp(ALIENPY_GLOBAL_WB, xrd_copy_command = ['-parent', '99'], api_src = download_list, api_dst = dest_list)

    msg_obj = f'{os.linesep}'.join(msg_obj_list)
    if msg_obj: msg_obj = f'{header}\n{msg_obj}'
    msg = f'{msg_dirs}\n{msg_obj}'

    return RET(0, msg, '', q_dict)


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
        md5 = md5(p.as_posix()), owner = p.owner(), perm = str(oct(p_stat.st_mode))[5:], replicated = "0",
        size = str(p_stat.st_size), turl = turl, type = 'f')


def mk_xml_local(filepath_list: list):
    xml_root = ET.Element('alien')
    collection = ET.SubElement(xml_root, 'collection', attrib={'name': 'tempCollection'})
    for idx, item in enumerate(filepath_list, start = 1):
        e = ET.SubElement(collection, 'event', attrib={'name': str(idx)})
        ET.SubElement(e, 'file', attrib = file2xml_el(lfn_prefix_re.sub('', item))._asdict())
    oxml = ET.tostring(xml_root, encoding = 'ascii')
    dom = MD.parseString(oxml)  # nosec B318:blacklist
    return dom.toprettyxml()


def DO_2xml(wb, args: Union[list, None] = None) -> RET:
    if args is None: args = []
    if not args or is_help(args):
        central_help = SendMsg(wb, 'toXml', ['-h'], opts = 'nokeys')
        central_help_msg = central_help.out
        msg_local = ('\nAdditionally the client implements these options:'
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
    lfn_arg_list = None

    if lfn_filelist:  # a given file with list of files/lfns was provided
        if is_local:
            if do_append: return RET(1, '', 'toXml::local usage - appending to local xml is WIP, try without -a')
            if not os.path.exists(lfn_filelist): return RET(1, '', f'filelist {lfn_filelist} could not be found!!')
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
                    with open(output_file, 'w', encoding = "ascii", errors = "replace") as f: f.write(xml_coll)
                    return RET(0)
                except Exception as e:
                    logging.exception(e)
                    return RET(1, '', f'Error writing {output_file}')
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
                    with open(output_file, 'w', encoding = "ascii", errors = "replace") as f: f.write(ret_obj.out)
                    return RET(0)
                except Exception as e:
                    logging.exception(e)
                    return RET(1, '', f'Error writing {output_file}')
            return ret_obj
        return RET(1, '', 'Allegedly unreachable point in DO_2xml. If you see this, contact developer!')

    else:
        lfn_arg_list = args.copy()  # the rest of arguments are lfns
        if is_local:
            if do_append: return RET(1, '', 'toXml::local usage - appending to local xml is WIP, try without -a')
            lfn_list_obj_list = [file2file_dict(filepath) for filepath in lfn_arg_list]
            if not lfn_list_obj_list: return RET(1, '', f'Invalid list of files: {lfn_arg_list}')
            lfn_list = [get_lfn_key(lfn_obj) for lfn_obj in lfn_list_obj_list if get_lfn_key(lfn_obj)]
            xml_coll = mk_xml_local(lfn_list)
            if output_file:
                if output_file.startswith('alien:'):
                    return RET(1, '', 'For the moment upload the resulting file by hand in grid')
                output_file = lfn_prefix_re.sub('', output_file)
                with open(output_file, 'w', encoding = "ascii", errors = "replace") as f: f.write(xml_coll)
                return RET(0)
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
                    with open(output_file, 'w', encoding = "ascii", errors = "replace") as f: f.write(ret_obj.out)
                    return RET(0)
                except Exception as e:
                    logging.exception(e)
                    return RET(1, '', f'Error writing {output_file}')
            return ret_obj
        return RET(1, '', 'Allegedly unreachable point in DO_2xml. If you see this, contact the developer!')


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
    for t in types: get_arg(args, t)
    args.append('json')
    retobj = queryML(args)
    q_dict = retobj.ansdict

    if retobj.exitcode != 0: return RET(retobj.exitcode, '', f'Error getting query: {" ".join(args)}')
    ans_list = retobj.ansdict["results"]
    if len(ans_list) == 0: return RET(retobj.exitcode, f'queryML:: Empty answer from query: {" ".join(args)}')

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
    return RET(0, msg, '', q_dict)


def DO_submit(wb, args: Union[list, None] = None) -> RET:
    """submit: process submit commands for local jdl cases"""
    if not args or args is None: args = ['-h']
    if is_help(args): return get_help_srv(wb, 'submit')
    if args[0].startswith("file:"):
        msg = ("Specifications as where to upload the jdl to be submitted and with what parameters are not yet defined"
               "Upload first the jdl to a suitable location (with a safe number of replicas) and then submit")
        return RET(0, msg)
    args[0] = expand_path_grid(args[0])
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


def DO_lfn2uri(wb, args: Union[list, None] = None) -> RET:
    if args is None: args = []
    if is_help(args):
        msg = '''Command format : lfn2uri <lfn> <local_file?> [meta] [write|upload] [strict] [http]
It will print the URIs for lfn replicas
local_file : required only for write|upload URIs
meta : will write in current directory the metafile and will return the string to be used with xrdcp
write|upload : request tokens for writing/upload; incompatible with <meta> argument
strict : lfn specifications will be considered to be strict
http : URIs will be for http end-points of enabled SEs
'''
        return RET(0, msg)

    write_meta = get_arg(args, 'meta')
    strictspec = get_arg(args, 'strict')
    httpurl = get_arg(args, 'http')
    isWrite = get_arg(args, 'upload')
    if not isWrite: isWrite = get_arg(args, 'write')
    if isWrite and write_meta:
        return RET(1, '', 'meta argument is incompatible with uploading')
    if isWrite and len(args) < 2: return RET(1, '', 'for upload URIs two elements are required: lfn local_file')
    if len(args) < 1: return RET(1, '', 'at least one argument is neeeded: lfn')
    local_file = ''
    if len(args) > 1: local_file = args[1]
    lfn = args[0]
    lfn_components = specs_split.split(lfn, maxsplit = 1)  # NO comma allowed in grid names (hopefully)
    lfn = lfn_components[0]  # first item is the file path, let's remove it; it remains disk specifications
    if not isWrite: lfn = expand_path_grid(lfn)
    specs = ''
    if len(lfn_components) > 1: specs = lfn_components[1]
    if write_meta:
        out = lfn2meta(wb, lfn, local_file, specs, isWrite, strictspec, httpurl)
    else:
        out = lfn2uri(wb, lfn, local_file, specs, isWrite, strictspec, httpurl)
    if not out:
        return RET(1, '', f'Could not not create URIs for: {lfn}')
    return RET(0, out)


def token(wb, args: Union[None, list] = None) -> int:
    """(Re)create the tokencert and tokenkey files"""
    global AlienSessionInfo
    if not wb: return 1
    if not args: args = []

    ret_obj = SendMsg(wb, 'token', args, opts = 'nomsg')
    if ret_obj.exitcode != 0:
        logging.error('Token request returned error')
        return retf_print(ret_obj, 'err')
    tokencert_content = ret_obj.ansdict.get('results')[0].get('tokencert', '')
    tokenkey_content = ret_obj.ansdict.get('results')[0].get('tokenkey', '')
    if not tokencert_content or not tokenkey_content:
        logging.error('Token request valid but empty fields!!')
        return int(42)  # ENOMSG

    try:
        if path_readable(TOKENCERT_NAME):
            os.chmod(TOKENCERT_NAME, 0o600)  # make it writeable
            os.remove(TOKENCERT_NAME)
        with open(TOKENCERT_NAME, "w", encoding = "ascii", errors = "replace") as tcert: print(f"{tokencert_content}", file = tcert)  # write the tokencert
        os.chmod(TOKENCERT_NAME, 0o400)  # make it readonly
    except Exception:
        print_err(f'Error writing to file the aquired token cert; check the log file {DEBUG_FILE}!')
        logging.debug(traceback.format_exc())
        return 5  # EIO

    try:
        if path_readable(TOKENKEY_NAME):
            os.chmod(TOKENKEY_NAME, 0o600)  # make it writeable
            os.remove(TOKENKEY_NAME)
        with open(TOKENKEY_NAME, "w", encoding = "ascii", errors = "replace") as tkey: print(f"{tokenkey_content}", file = tkey)  # write the tokenkey
        os.chmod(TOKENKEY_NAME, 0o400)  # make it readonly
    except Exception:
        print_err(f'Error writing to file the aquired token key; check the log file {DEBUG_FILE}!')
        logging.debug(traceback.format_exc())
        return 5  # EIO

    return int(0)


def token_regen(wb, args: Union[None, list] = None):
    global AlienSessionInfo
    wb_usercert = None
    if not args: args = []
    if not AlienSessionInfo['use_usercert']:
        wb_close(wb, code = 1000, reason = 'Lets connect with usercert to be able to generate token')
        try:
            wb_usercert = InitConnection(wb, args, use_usercert = True)  # we have to reconnect with the new token
        except Exception:
            logging.debug(traceback.format_exc())
            return None  # we failed usercert connection

    # now we are connected with usercert, so we can generate token
    if token(wb_usercert, args) != 0: return wb_usercert
    # we have to reconnect with the new token
    wb_close(wb_usercert, code = 1000, reason = 'Re-initialize the connection with the new token')
    AlienSessionInfo['use_usercert'] = False
    wb_token_new = None
    try:
        wb_token_new = InitConnection(wb_token_new, args)
        __ = SendMsg(wb_token_new, 'pwd', [], opts = 'nokeys')  # just to refresh cwd
    except Exception:
        logging.exception('token_regen:: error re-initializing connection')
    return wb_token_new


def DO_token(wb, args: Union[list, None] = None) -> RET:
    if args is None: args = []
    msg = "Print only command!!! Use >token-init< for token (re)generation, see below the arguments\n"
    ret_obj = SendMsg(wb, 'token', args, opts = 'nokeys')
    return ret_obj._replace(out = f'{msg}{ret_obj.out}')


def DO_token_init(wb, args: Union[list, None] = None) -> RET:
    if args is None: args = []
    if len(args) > 0 and is_help(args):
        ret_obj = SendMsg(wb, 'token', ['-h'], opts = 'nokeys')
        return ret_obj._replace(out = ret_obj.out.replace('usage: token', 'INFO: token is automatically created, use this for token customization\nusage: token-init'))
    wb = token_regen(wb, args)
    return CertInfo(TOKENCERT_NAME)


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
    lfn = expand_path_grid(args[-1])  # assume that the last argument is the lfn
    # check for valid (single) specifications delimiter
    count_tokens = collections.Counter(lfn)
    if count_tokens[','] + count_tokens['@'] > 1:
        msg = f"At most one of >,< or >@< tokens used for copy specification can be present in the argument. The offender is: {''.join(count_tokens)}"
        return RET(64, '', msg)  # EX_USAGE /* command line usage error */

    specs = specs_split.split(lfn, maxsplit = 1)  # NO comma allowed in grid names (hopefully)
    lfn = specs.pop(0)  # first item is the file path, let's remove it; it remains disk specifications
    tmp = download_tmp(wb, lfn, overwrite = False, verbose = False)
    if tmp and os.path.isfile(tmp):
        md5_begin = md5(tmp)
        ret_obj = runShellCMD(f'{editor} {tmp}', captureout = False)
        if ret_obj.exitcode != 0: return ret_obj
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

    tmp_list = [download_tmp(wb, lfn, overwrite, verbose = True) for lfn in list_of_lfns]  # list of temporary downloads
    new_args = [arg for arg in args if arg not in list_of_lfns]  # command arguments without the files
    args = list(new_args)
    cmd = " ".join(args)
    files = " ".join(tmp_list)
    if tmp_list and all(os.path.isfile(tmp) for tmp in tmp_list):
        return runShellCMD(f'{cmd} {files}', capture_out, do_shell = True)
    return RET(1, '', f'There was an error downloading the following files:\n{chr(10).join(list_of_lfns)}')


def DO_exec(wb, args: Union[list, None] = None) -> RET:
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


def DO_find2(wb, args: Union[None, list, str] = None) -> RET:
    if args is None: args = []
    if isinstance(args, str):
        args = args.split() if args else []
    if is_help(args):
        msg_client = (f'''Client-side implementation of find, it contain the following helpers.
Command formant: find2 <options> <directory>
N.B. directory to be search for must be last element of command
-glob <globbing pattern> : this is the usual AliEn globbing format; {PrintColor(COLORS.BIGreen)}N.B. this is NOT a REGEX!!!{PrintColor(COLORS.ColorReset)} defaults to all "*"
-select <pattern>        : select only these files to be copied; {PrintColor(COLORS.BIGreen)}N.B. this is a REGEX applied to full path!!!{PrintColor(COLORS.ColorReset)}
-name <pattern>          : select only these files to be copied; {PrintColor(COLORS.BIGreen)}N.B. this is a REGEX applied to a directory or file name!!!{PrintColor(COLORS.ColorReset)}
-name <verb>_string      : where verb = begin|contain|ends|ext and string is the text selection criteria.
verbs are aditive  e.g. -name begin_myf_contain_run1_ends_bla_ext_root
{PrintColor(COLORS.BIRed)}N.B. the text to be filtered cannont have underline i.e >_< within!!!{PrintColor(COLORS.ColorReset)}

-exclude     string            : (client-side) exclude result containing this string
-exclude_re  pattern           : (client-side) exclude result matching this regex
-user    string                : (client-side) match the user
-group   string                : (client-side) match the group
-jobid   string                : (client-side) match the jobid
-minsize   / -maxsize    int   : (client-side) restrict results to min/max bytes (inclusive)
-mindepth  / -maxdepth   int   : (client-side) restrict results to min/max depth
-min-ctime / -max-ctime  int(unix time) : (client-side) restrict results age to min/max unix-time

The server options:''')
        srv_answ = get_help_srv(wb, 'find')
        msg_srv = srv_answ.out
        return RET(0, f'{msg_client}\n{msg_srv}')

    # clean up the options
    get_arg(args, '-v')
    get_arg(args, '-a')
    get_arg(args, '-s')
    get_arg(args, '-f')
    get_arg(args, '-d')
    get_arg(args, '-w')
    get_arg(args, '-wh')

    search_dir = args.pop()
    use_regex = False
    filtering_enabled = False

    pattern = None
    pattern_arg = get_arg_value(args, '-glob')
    if '*' in search_dir:  # we have globbing in path
        search_dir, pattern = extract_glob_pattern(search_dir)
        if not search_dir: search_dir = './'

    is_default_glob = False
    if not (pattern or pattern_arg):
        is_default_glob = True
        pattern = '*'  # default glob pattern
    if not pattern: pattern = pattern_arg  # if both present use pattern, otherwise pattern_arg
    filtering_enabled = not is_default_glob  # signal the filtering enabled only if explicit glob request was made

    search_dir = expand_path_grid(search_dir)

    pattern_regex = None
    select_arg = get_arg_value(args, '-select')
    if select_arg:
        if filtering_enabled:
            msg = 'Only one rule of selection can be used, either -select (full path match), -name (match on file name), -glob (globbing) or path globbing'
            return RET(22, '', msg)  # EINVAL /* Invalid argument */
        pattern_regex = select_arg
        use_regex = True
        filtering_enabled = True

    name_arg = get_arg_value(args, '-name')
    if name_arg:
        if filtering_enabled:
            msg = 'Only one rule of selection can be used, either -select (full path match), -name (match on file name), -glob (globbing) or path globbing'
            return RET(22, '', msg)  # EINVAL /* Invalid argument */
        use_regex = True
        filtering_enabled = True
        pattern_regex = name2regex(name_arg)
        if use_regex and not pattern_regex:
            msg = ("-name :: No selection verbs were recognized!"
                   "usage format is -name <attribute>_<string> where attribute is one of: begin, contain, ends, ext"
                   f"The invalid pattern was: {pattern_regex}")
            return RET(22, '', msg)  # EINVAL /* Invalid argument */

    if use_regex: pattern = pattern_regex  # -select, -name usage overwrites glob usage
    return list_files_grid(wb, search_dir = search_dir, pattern = pattern, is_regex = use_regex, find_args = args)


def DO_quota(wb, args: Union[None, list] = None) -> RET:
    """quota : put togheter both job and file quota"""
    if not args: args = []
    if is_help(args):
        msg = ("Client-side implementation that make use of server\'s jquota and fquota (hidden by this implementation)\n"
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

    running_time = float(jquota_dict['results'][0]["totalRunningTimeLast24h"]) / 3600
    running_time_max = float(jquota_dict['results'][0]["maxTotalRunningTime"]) / 3600
    running_time_perc = (running_time / running_time_max) * 100

    cpucost = float(jquota_dict['results'][0]["totalCpuCostLast24h"]) / 3600
    cpucost_max = float(jquota_dict['results'][0]["maxTotalCpuCost"]) / 3600
    cpucost_perc = (cpucost / cpucost_max) * 100

    unfinishedjobs_max = int(jquota_dict['results'][0]["maxUnfinishedJobs"])
    waiting = int(jquota_dict['results'][0]["waiting"])
    running = int(jquota_dict['results'][0]["running"])
    unfinishedjobs_perc = ((waiting + running) / unfinishedjobs_max) * 100

    pjobs_nominal = int(jquota_dict['results'][0]["nominalparallelJobs"])
    pjobs_max = int(jquota_dict['results'][0]["maxparallelJobs"])

    size = float(fquota_dict['results'][0]["totalSize"])
    size_MiB = size / (1024 * 1024)
    size_max = float(fquota_dict['results'][0]["maxTotalSize"])
    size_max_MiB = size_max / (1024 * 1024)
    size_perc = (size / size_max) * 100

    files = float(fquota_dict['results'][0]["nbFiles"])
    files_max = float(fquota_dict['results'][0]["maxNbFiles"])
    files_perc = (files / files_max) * 100

    msg = (f"""Quota report for user : {username}
Unfinished jobs(R + W / Max):\t\t{running} + {waiting} / {unfinishedjobs_max} --> {unfinishedjobs_perc:.2f}% used
Running time (last 24h) used/max:\t{running_time:.2f}/{running_time_max:.2f}(h) --> {running_time_perc:.2f}% used
CPU Cost (last 24h) used/max:\t\t{cpucost:.2f}/{cpucost_max:.2f}(h) --> {cpucost_perc:.2f}% used
ParallelJobs (nominal/max) :\t{pjobs_nominal}/{pjobs_max}
Storage size :\t\t\t{size_MiB:.2f}/{size_max_MiB:.2f} MiB --> {size_perc:.2f}%
Number of files :\t\t{files}/{files_max} --> {files_perc:.2f}%""")
    return RET(0, msg)


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
        stdout += f'{res[0]}:{res[1]}        {PrintColor(COLORS.BIGreen) + "OK" if res[-1] else PrintColor(COLORS.BIRed) + "FAIL"}{PrintColor(COLORS.ColorReset)}\n'
    return RET(0, stdout)


def get_help(wb, cmd: str = '') -> RET:
    """Return the help option even for client-side commands"""
    if not cmd: return RET(1, '', 'No command specified for help')
    return ProcessInput(wb, cmd, ['-h'])


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
            columns = os.get_terminal_size()[0] // column_width
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
    if ret_obj.exitcode != 0: return []
    return [item[key] for item in ret_obj.ansdict['results']]


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
    return list_lfns


def wb_ping(wb) -> float:
    """Websocket ping function, it will return rtt in ms"""
    init_begin = time.perf_counter()
    if IsWbConnected(wb):
        return float(deltat_ms_perf(init_begin))
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
    for _i in range(count):
        p = wb_ping(wb)
        results.append(p)

    rtt_min = min(results)
    rtt_max = max(results)
    rtt_avg = statistics.mean(results)
    rtt_stddev = statistics.stdev(results) if len(results) > 1 else 0.0
    endpoint = wb.remote_address[0]
    msg = (f'Websocket ping/pong(s) : {count} time(s) to {endpoint}\nrtt min/avg/max/mdev (ms) = {rtt_min:.3f}/{rtt_avg:.3f}/{rtt_max:.3f}/{rtt_stddev:.3f}')
    return RET(0, msg)


def DO_tokendestroy(args: Union[list, None] = None) -> RET:
    if args is None: args = []
    if len(args) > 0 and is_help(args): return RET(0, "Delete the token{cert,key}.pem files")
    if os.path.exists(TOKENCERT_VALID): os.remove(TOKENCERT_VALID)
    if os.path.exists(TOKENKEY_VALID): os.remove(TOKENKEY_VALID)
    return RET(0, "Token was destroyed! Re-connect for token re-creation.")


def DO_certinfo(args: Union[list, None] = None) -> RET:
    if args is None: args = []
    if len(args) > 0 and is_help(args): return RET(0, "Print user certificate information", "")
    return CertInfo(USERCERT_VALID)


def DO_tokeninfo(args: Union[list, None] = None) -> RET:
    if not args: args = []
    if len(args) > 0 and is_help(args): return RET(0, "Print token certificate information", "")
    return CertInfo(TOKENCERT_VALID)


def DO_certverify(args: Union[list, None] = None) -> RET:
    if args is None: args = []
    if len(args) > 0 and is_help(args): return RET(0, "Verify the user cert against the found CA stores (file or directory)", "")
    return CertVerify(USERCERT_VALID)


def DO_tokenverify(args: Union[list, None] = None) -> RET:
    if not args: args = []
    if len(args) > 0 and is_help(args): return RET(0, "Print token certificate information", "")
    return CertVerify(TOKENCERT_VALID)


def DO_certkeymatch(args: Union[list, None] = None) -> RET:
    if args is None: args = []
    if len(args) > 0 and is_help(args): return RET(0, "Check match of user cert with key cert", "")
    return CertKeyMatch(USERCERT_VALID, USERKEY_VALID)


def DO_tokenkeymatch(args: Union[list, None] = None) -> RET:
    if args is None: args = []
    if len(args) > 0 and is_help(args): return RET(0, "Check match of user token with key token", "")
    return CertKeyMatch(TOKENCERT_VALID, TOKENKEY_VALID)


def make_func_map_clean_server():
    """Remove from server list the client-side re-implementations"""
    global AlienSessionInfo
    del AlienSessionInfo['cmd2func_map_srv']['cd']
    list_remove_item(AlienSessionInfo['commandlist'], 'cd')

    del AlienSessionInfo['cmd2func_map_srv']['cp']
    list_remove_item(AlienSessionInfo['commandlist'], 'cp')

    del AlienSessionInfo['cmd2func_map_srv']['ping']
    list_remove_item(AlienSessionInfo['commandlist'], 'ping')

    del AlienSessionInfo['cmd2func_map_srv']['ps']
    list_remove_item(AlienSessionInfo['commandlist'], 'ps')

    del AlienSessionInfo['cmd2func_map_srv']['submit']
    list_remove_item(AlienSessionInfo['commandlist'], 'submit')

    del AlienSessionInfo['cmd2func_map_srv']['token']
    list_remove_item(AlienSessionInfo['commandlist'], 'token')

    del AlienSessionInfo['cmd2func_map_srv']['user']
    list_remove_item(AlienSessionInfo['commandlist'], 'user')

    del AlienSessionInfo['cmd2func_map_srv']['cat']
    list_remove_item(AlienSessionInfo['commandlist'], 'cat')

    del AlienSessionInfo['cmd2func_map_srv']['toXml']
    list_remove_item(AlienSessionInfo['commandlist'], 'toXml')


def make_func_map_nowb():
    """client side functions (new commands) that do not require connection to jcentral"""
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
    AlienSessionInfo['cmd2func_map_nowb']['version'] = DO_version
    AlienSessionInfo['cmd2func_map_nowb']['queryML'] = DO_queryML
    AlienSessionInfo['cmd2func_map_nowb']['exit'] = DO_exit
    AlienSessionInfo['cmd2func_map_nowb']['quit'] = DO_exit
    AlienSessionInfo['cmd2func_map_nowb']['logout'] = DO_exit
    AlienSessionInfo['cmd2func_map_nowb']['checkAddr'] = DO_checkAddr
    AlienSessionInfo['cmd2func_map_nowb']['ccdb'] = DO_ccdb_query


def make_func_map_client():
    """client side functions (new commands) that DO require connection to jcentral"""
    if AlienSessionInfo['cmd2func_map_client']: return

    # client side function (overrides) with signature : (wb, args, opts)
    AlienSessionInfo['cmd2func_map_client']['cd'] = cd
    AlienSessionInfo['cmd2func_map_client']['cp'] = DO_XrootdCp
    AlienSessionInfo['cmd2func_map_client']['ping'] = DO_ping
    AlienSessionInfo['cmd2func_map_client']['ps'] = DO_ps
    AlienSessionInfo['cmd2func_map_client']['submit'] = DO_submit
    AlienSessionInfo['cmd2func_map_client']['token'] = DO_token
    AlienSessionInfo['cmd2func_map_client']['user'] = DO_user
    AlienSessionInfo['cmd2func_map_client']['cat'] = DO_cat
    AlienSessionInfo['cmd2func_map_client']['toXml'] = DO_2xml

    # client side function (new commands) with signature : (wb, args)
    AlienSessionInfo['cmd2func_map_client']['quota'] = DO_quota
    AlienSessionInfo['cmd2func_map_client']['token-init'] = DO_token_init
    AlienSessionInfo['cmd2func_map_client']['pfn'] = DO_pfn
    AlienSessionInfo['cmd2func_map_client']['pfn-status'] = DO_pfnstatus
    AlienSessionInfo['cmd2func_map_client']['xrd_ping'] = DO_xrd_ping
    AlienSessionInfo['cmd2func_map_client']['xrd_config'] = DO_xrd_config
    AlienSessionInfo['cmd2func_map_client']['xrd_stats'] = DO_xrd_stats
    AlienSessionInfo['cmd2func_map_client']['run'] = DO_run
    AlienSessionInfo['cmd2func_map_client']['exec'] = DO_exec
    AlienSessionInfo['cmd2func_map_client']['getSE'] = DO_getSE
    AlienSessionInfo['cmd2func_map_client']['getCE'] = DO_getCE
    AlienSessionInfo['cmd2func_map_client']['siteJobs'] = DO_siteJobs
    AlienSessionInfo['cmd2func_map_client']['jobInfo'] = DO_jobInfo
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
    AlienSessionInfo['cmd2func_map_client']['lfn2uri'] = DO_lfn2uri


def getSessionVars(wb):
    """Initialize the global session variables : cleaned up command list, user, home dir, current dir"""
    global AlienSessionInfo
    if AlienSessionInfo['user']: return  # user session variable is already set, then return
    if not wb: return
    # get the command list just once per session connection (a reconnection will skip this)
    ret_obj = SendMsg(wb, 'commandlist', [])
    # first executed commands, let's initialize the following (will be re-read at each ProcessReceivedMessage)
    if not ret_obj.ansdict or 'results' not in ret_obj.ansdict:
        print_err("Start session:: could not get command list, let's exit.")
        sys.exit(1)
    csd_cmds_re = re.compile(r'.*_csd$')
    AlienSessionInfo['commandlist'] = [cmd["commandlist"] for cmd in ret_obj.ansdict["results"] if not csd_cmds_re.match(cmd["commandlist"])]

    # server commands, signature is : (wb, command, args, opts)
    for cmd in AlienSessionInfo['commandlist']: AlienSessionInfo['cmd2func_map_srv'][cmd] = SendMsg
    make_func_map_clean_server()

    make_func_map_nowb()  # GLOBAL!! add to the list of client-side no-connection implementations
    make_func_map_client()  # GLOBAL!! add to cmd2func_map_client the list of client-side implementations

    # these are aliases, or directly interpreted
    AlienSessionInfo['commandlist'].extend(['ll', 'la', 'lla'])
    AlienSessionInfo['commandlist'].extend(AlienSessionInfo['cmd2func_map_client'])  # add clien-side cmds to list
    AlienSessionInfo['commandlist'].extend(AlienSessionInfo['cmd2func_map_nowb'])    # add nowb cmds to list
    AlienSessionInfo['commandlist'] = sorted(set(AlienSessionInfo['commandlist']))


def InitConnection(wb = None, token_args: Union[None, list] = None, use_usercert: bool = False, localConnect: bool = False):
    """Create a session to AliEn services, including session globals and token regeneration"""
    global AlienSessionInfo, ALIENPY_GLOBAL_WB
    DEBUG = os.getenv('ALIENPY_DEBUG', '')
    wb = AlienConnect(wb, token_args, use_usercert, localConnect)
    ALIENPY_GLOBAL_WB = wb

    # NO MATTER WHAT BEFORE ENYTHING ELSE SESSION MUST BE INITIALIZED   !!!!!!!!!!!!!!!!
    if not AlienSessionInfo['session_started']:  # this is beggining of session, let's get session vars ONLY ONCE
        AlienSessionInfo['session_started'] = True
        session_begin = time.perf_counter() if (TIME_CONNECT or DEBUG) else None
        getSessionVars(wb)  # no matter if command or interactive mode, we need alienHome, currentdir, user and commandlist
        if session_begin:
            msg = f">>>   Time for session initialization: {deltat_us_perf(session_begin)} us"
            if DEBUG: logging.debug(msg)
            if TIME_CONNECT: print_out(msg)

    # this is a reconnection, make sure on the server we are in the last known current directory
    if AlienSessionInfo['currentdir']: cd(wb, AlienSessionInfo['currentdir'], 'log')

    # if usercert connection always regenerate token if connected with usercert
    if AlienSessionInfo['use_usercert'] and token(wb, token_args) != 0: print_err(f'The token could not be created! check the logfile {DEBUG_FILE}')
    return wb


def ProcessInput(wb, cmd: str, args: Union[list, None] = None, shellcmd: Union[str, None] = None) -> RET:
    """Process a command line within shell or from command line mode input"""
    global AlienSessionInfo
    if not cmd: return RET(1, '', 'ProcessInput:: Empty input')
    if args is None: args = []
    ret_obj = None

    # implement a time command for measurement of sent/recv delay; for the commands above we do not use timing
    time_begin = msg_timing = None
    if cmd == 'time':  # first to be processed is the time token, it will start the timing and be removed from command
        if not args or is_help(args): return RET(0, 'Command format: time command arguments')
        cmd = args.pop(0)
        time_begin = time.perf_counter()

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

    if cmd in AlienSessionInfo['cmd2func_map_nowb']:  # these commands do NOT need wb connection
        get_arg(args, '-nokeys')
        get_arg(args, '-nomsg')
        return AlienSessionInfo['cmd2func_map_nowb'][cmd](args)

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

    if time_begin: msg_timing = f">>>ProcessInput time: {deltat_ms_perf(time_begin)} ms"

    if cmd not in AlienSessionInfo['commandlist']:
        similar_list = difflib.get_close_matches(cmd, AlienSessionInfo['commandlist'])
        similar_cmds = None
        if similar_list: similar_cmds = ' '.join(similar_list)
        msg = f'WARNING! command >>> {cmd} <<< not in the list of known commands!'
        if similar_cmds: msg = f'{msg}\nSimilar commands: {similar_cmds}'
        print_err(msg)
    if ret_obj is None: return RET(1, '', f"NO RETURN from command: {cmd} {chr(32).join(args)}")

    if shellcmd:
        if ret_obj.exitcode != 0: return ret_obj
        if not ret_obj.out:
            return RET(1, '', f'Command >>>{cmd} {chr(32).join(args)}<<< do not have output but exitcode == 0')
        print_out(ret_obj.out)
        shell_run = subprocess.run(shellcmd, stdout = subprocess.PIPE, stderr = subprocess.PIPE, input = f'{ret_obj.out}\n', encoding = 'ascii', shell = True)  # pylint: disable=subprocess-run-check # env=os.environ default is already the process env  # nosec
        if msg_timing: shell_run.stdout = f'{shell_run.stdout}\n{msg_timing}'
        return RET(shell_run.returncode, shell_run.stdout, shell_run.stderr)

    if msg_timing: ret_obj = ret_obj._replace(out = f'{ret_obj.out}\n{msg_timing}')
    if ret_obj.ansdict and 'metadata' in ret_obj.ansdict and 'timing_ms' in ret_obj.ansdict['metadata']:
        ret_obj = ret_obj._replace(out = f"{ret_obj.out}\ntiming_ms = {ret_obj.ansdict['metadata']['timing_ms']}")
    return ret_obj


def ProcessCommandChain(wb = None, cmd_chain: str = '') -> int:
    global AlienSessionInfo, ALIENPY_GLOBAL_WB
    if not cmd_chain: return int(1)
    JSON_OUT_GLOBAL = os.getenv('ALIENPY_JSON_OUT_GLOBAL')

    # translate aliases in place in the whole string
    if AlienSessionInfo['alias_cache']:
        for alias, alias_value in AlienSessionInfo['alias_cache'].items(): cmd_chain = cmd_chain.replace(alias, alias_value)

    cmdline_list = [str(cmd).strip() for cmd in cmds_split.split(cmd_chain)]  # split commands on ; and \n

    # for each command, save exitcode and RET of the command
    for cmdline in cmdline_list:
        if not cmdline: continue
        if DEBUG: logging.info('>>> RUN COMMAND: %s', cmdline)
        if cmdline.startswith('!'):  # if shell command, just run it and return
            capture_out = True
            if '-noout' in cmdline:
                cmdline = cmdline.replace(' -noout', '')
                capture_out = False
            ret_obj = runShellCMD(cmdline, capture_out)
            AlienSessionInfo['exitcode'] = retf_print(ret_obj, 'debug')
            continue

        # process the input and take care of pipe to shell
        input_alien, __, pipe_to_shell_cmd = cmdline.partition(' | ')
        if not input_alien:
            print_out("AliEn command before the | token was not found")
            continue

        args = shlex.split(input_alien.strip())
        cmd = args.pop(0)

        # if globally enabled then enable per command OR if enabled for this command
        JSON_OUT_CMD = None
        if get_arg(args, '-json'):
            os.environ['ALIENPY_JSON_OUT'] = '1'
            JSON_OUT_CMD = '1'
        JSON_OUT = JSON_OUT_GLOBAL or JSON_OUT_CMD

        print_opts = 'debug'
        if JSON_OUT: print_opts = f'{print_opts} json'

        if cmd in AlienSessionInfo['cmd2func_map_nowb']:
            ret_obj = AlienSessionInfo['cmd2func_map_nowb'][cmd](args)
        else:
            if wb is None:
                # we are doing the connection recovery and exception treatment in AlienConnect()
                wb = InitConnection(wb, args, use_usercert = (cmd == 'token-init' and not is_help(args)))
                ALIENPY_GLOBAL_WB = wb
            args.append('-nokeys')  # Disable return of the keys. ProcessCommandChain is used for user-based communication so json keys are not needed
            ret_obj = ProcessInput(wb, cmd, args, pipe_to_shell_cmd)

        AlienSessionInfo['exitcode'] = retf_print(ret_obj, print_opts)  # save exitcode for easy retrieval
        if cmd == 'cd': SessionSave()

        # reset JSON_OUT if it's not globally enabled (env var or argument to alien.py)
        if not JSON_OUT_GLOBAL and 'ALIENPY_JSON_OUT' in os.environ: del os.environ['ALIENPY_JSON_OUT']
        
    return AlienSessionInfo['exitcode']


def setupHistory() -> None:
    """Setup up history mechanics for readline module"""
    if not HAS_READLINE: return
    histfile = os.path.join(os.path.expanduser("~"), ".alienpy_history")
    if not os.path.exists(histfile): Path(histfile).touch(exist_ok = True)
    rl.set_history_length(-1)  # unlimited history
    rl.read_history_file(histfile)

    def startup_hook() -> None: rl.append_history_file(1, histfile)  # before next prompt save last line
    rl.set_startup_hook(startup_hook)


def JAlien(commands: str = '') -> int:
    """Main entry-point for interaction with AliEn"""
    global AlienSessionInfo, ALIENPY_GLOBAL_WB
    import_aliases()

    # Command mode interaction
    if commands: return ProcessCommandChain(ALIENPY_GLOBAL_WB, commands)

    # Start interactive/shell mode
    ALIENPY_GLOBAL_WB = InitConnection()  # we are doing the connection recovery and exception treatment in AlienConnect()
    # Begin Shell-like interaction
    if HAS_READLINE:
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
                results = lfn_list(ALIENPY_GLOBAL_WB, text) + [None]
            return results[state]
        rl.set_completer(complete)
        setupHistory()  # enable history saving

    print_out('Welcome to the ALICE GRID\nsupport mail: adrian.sevcenco@cern.ch\n')
    if os.getenv('ALIENPY_PROMPT_DATE'): AlienSessionInfo['show_date'] = True
    if os.getenv('ALIENPY_PROMPT_CWD'): AlienSessionInfo['show_lpwd'] = True
    if not os.getenv('ALIENPY_NO_CWD_RESTORE'): SessionRestore(ALIENPY_GLOBAL_WB)

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
        AlienSessionInfo['exitcode'] = ProcessCommandChain(ALIENPY_GLOBAL_WB, INPUT)
    return AlienSessionInfo['exitcode']  # exit with the last command exitcode run in interactive mode


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

    @staticmethod
    def help():
        """Print help message"""
        print_out('Methods of AliEn session:\n'
                  '.run(cmd, opts) : alias to SendMsg(cmd, opts); It will return a RET object: named tuple (exitcode, out, err, ansdict)\n'
                  '.ProcessMsg(cmd_list) : alias to ProcessCommandChain, it will have the same output as in the alien.py interaction\n'
                  '.wb() : return the session WebSocket to be used with other function within alien.py')


###################################################
###   CODE TO BE RUN BEFORE MAIN STARTS
###################################################


###################################################
def main():
    global ALIENPY_EXECUTABLE, DEBUG, DEBUG_FILE
    signal.signal(signal.SIGINT, signal_handler)
    # signal.signal(sig, signal.SIG_DFL)  # register the default signal handler usage for a sig signal
    # at exit delete all temporary files
    atexit.register(cleanup_temp)

    ALIENPY_EXECUTABLE = os.path.realpath(sys.argv.pop(0))  # remove the name of the script
    if get_arg(sys.argv, '-json'): os.environ['ALIENPY_JSON_OUT_GLOBAL'] = '1'

    DEBUG_ARG = get_arg(sys.argv, '-debug')
    if DEBUG_ARG:
        os.environ['ALIENPY_DEBUG'] = '1'
        DEBUG = '1'

    DEBUGFILE_ARG = get_arg_value(sys.argv, '-debugfile')
    if DEBUGFILE_ARG:
        os.environ['ALIENPY_DEBUG_FILE'] = DEBUGFILE_ARG
        DEBUG_FILE = DEBUGFILE_ARG

    # start the logging
    setup_logging(bool(DEBUG), DEBUG_FILE)
    if DEBUG:
        print_out(f'Debug enabled, logfile is: {DEBUG_FILE}')
        ret_obj = DO_version()
        logging.debug('%s\n', ret_obj.out)

    arg_list_expanded = []
    for arg in sys.argv:
        for item in shlex.split(arg):
            arg_list_expanded.append(item)
    sys.argv = arg_list_expanded

    if len(sys.argv) > 0 and (sys.argv[0] == 'term' or sys.argv[0] == 'terminal' or sys.argv[0] == 'console'):
        import code
        term = code.InteractiveConsole(locals = globals())
        term.push('jalien = AliEn()')
        banner = 'Welcome to the ALICE GRID - Python interpreter shell\nsupport mail: adrian.sevcenco@cern.ch\nAliEn seesion object is >jalien< ; try jalien.help()'
        exitmsg = 'Exiting..'
        term.interact(banner, exitmsg)
        sys.exit(int(AlienSessionInfo['exitcode']))  # pylint: disable=protected-access

    exec_name = Path(ALIENPY_EXECUTABLE).name
    verb = exec_name.replace('alien_', '') if exec_name.startswith('alien_') else ''
    if verb: sys.argv.insert(0, verb)

    cmd_string = ''
    if len(sys.argv) > 0 and os.path.isfile(sys.argv[0]):
        with open(sys.argv[0], encoding="ascii", errors="replace") as input_file:
            cmd_string = input_file.read()
    else:
        cmd_string = ' '.join(sys.argv)

    try:
        sys.exit(JAlien(cmd_string))
    except KeyboardInterrupt:
        print_out("Received keyboard intrerupt, exiting..")
        sys.exit(1)
    except BrokenPipeError:
        # Python flushes standard streams on exit; redirect remaining output to devnull to avoid another BrokenPipeError at shutdown
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        sys.exit(1)  # Python exits with error code 1 on EPIPE
    except Exception:
        logging.exception("\n\n>>>   EXCEPTION   <<<", exc_info = True)
        logging.error("\n\n")
        print_err(f'''{PrintColor(COLORS.BIRed)}Exception encountered{PrintColor(COLORS.ColorReset)}! it will be logged to {DEBUG_FILE}
Please report the error and send the log file and "alien.py version" output to Adrian.Sevcenco@cern.ch
If the exception is reproductible including on lxplus, please create a detailed debug report this way:
ALIENPY_DEBUG=1 ALIENPY_DEBUG_FILE=log.txt your_command_line''')
        sys.exit(1)


def _cmd(what):
    sys.argv = [sys.argv[0]] + [what] + sys.argv[1:]
    main()


def cmd_cert_info(): _cmd('cert-info')


def cmd_token_info(): _cmd('token-info')


def cmd_token_destroy(): _cmd('token-destroy')


def cmd_token_init(): _cmd('token-init')


if __name__ == '__main__':
    main()
