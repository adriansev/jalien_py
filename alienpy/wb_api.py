"""alienpy::WEBSOCKET:: API for WebSocket communications"""

import sys
import os
import json
import re
import shlex
import logging
import traceback
from pathlib import Path
from typing import Callable, Optional, TYPE_CHECKING, Union
import time

try:
    import websockets.exceptions as wb_exceptions
except Exception:
    print("websockets module could not be imported! Make sure you can do:\npython3 -c 'import websockets.exceptions as wb_exceptions'", file = sys.stderr, flush = True)
    sys.exit(1)
from websockets import WebSocketClientProtocol

from .data_structs import RET
from .setup_logging import DEBUG, DEBUG_FILE, print_err, print_out
from .global_vars import ALIENPY_GLOBAL_WB, AlienSessionInfo, DEBUG_TIMING, TIME_CONNECT, TMPDIR, get_certs_names, SET_SITE
from .async_tools import syncify
from .wb_async import IsWbConnected, wb_close, wb_create, wb_sendmsg, wb_sendmsg_multi
from .tools_nowb import CreateJsonCommand, PrintDict, deltat_ms_perf, deltat_us_perf, isReachable, is_help, is_my_pid, path_readable, read_conf_file, writePidFile
from .tools_stackcmd import push2stack  # , deque_pop_pos


def wb_create_tryout(host: str, port: Union[str, int], path: str = '/', use_usercert: bool = False, localConnect: bool = False) -> WebSocketClientProtocol:
    """WebSocket creation with tryouts (configurable by env ALIENPY_CONNECT_TRIES and ALIENPY_CONNECT_TRIES_INTERVAL)"""
    wb = None
    nr_tries = 0
    connect_tries = int(os.getenv('ALIENPY_CONNECT_TRIES', '3'))
    connect_tries_interval = float(os.getenv('ALIENPY_CONNECT_TRIES_INTERVAL', '0.5'))

    init_begin = time.perf_counter() if (TIME_CONNECT or DEBUG) else None
    while wb is None:
        nr_tries += 1

        try:
            wb = wb_create(host, port, path, use_usercert, localConnect)
        except Exception:
            logging.exception('wb_create_tryout:: exception when wb_create')

        if not wb:
            if nr_tries >= connect_tries:
                logging.error('We tried on %s:%s%s %s times', host, port, path, nr_tries)
                break
            time.sleep(connect_tries_interval)

    if init_begin:
        fail_msg = 'trials ' if not wb else ''
        msg = f'>>>   Websocket {fail_msg}connecting time: {deltat_ms_perf(init_begin)} ms'
        if DEBUG: logging.debug(msg)
        if TIME_CONNECT: print_out(msg)

    # if local proxy process (a la JBox - but WIP)
    if localConnect and wb: writePidFile(f'{TMPDIR}/jboxpy_{os.getuid()}.pid')

    return wb


def AlienConnect(wb: Optional[WebSocketClientProtocol] = None, token_args: Optional[list] = None, use_usercert: bool = False, localConnect: bool = False) -> WebSocketClientProtocol:
    """Create a websocket connection to AliEn services either directly to alice-jcentral.cern.ch or trough a local found jbox instance"""
    if not token_args: token_args = []
    init_begin = time.perf_counter() if (TIME_CONNECT or DEBUG) else None

    SRV_DEFAULT = 'alice-jcentral.cern.ch'
    PORT_DEFAULT = '8097'

    jalien_server = os.getenv('ALIENPY_JCENTRAL', SRV_DEFAULT)  # default value for JCENTRAL
    jalien_websocket_port = os.getenv('ALIENPY_JCENTRAL_PORT', PORT_DEFAULT)  # websocket port
    jalien_websocket_path = '/websocket/json'
    jclient_env = f'{TMPDIR}/jclient_token_{str(os.getuid())}'

    # Prepare usage of destination specified by JBox env vars instead of jclient_token_
    JALIEN_HOST_ENV = os.getenv('JALIEN_HOST', '')
    JALIEN_WSPORT_ENV = os.getenv('JALIEN_WSPORT', PORT_DEFAULT)

    # If presentent with existing socket, let's try to close it
    if wb:
        _ = wb_close(wb, code = 1000, reason = 'Close previous websocket')
        wb = None

    # let's try to get a websocket
    if localConnect:
        wb = wb_create(localConnect = True)
    else:
        # First try the JBox connection details, first env vars then jclient_token_ file
        # N.B.!! ALIENPY_JCENTRAL env var have exclusive priority !! is present then the intent is to use the _THIS_ endpoint
        if not os.getenv("ALIENPY_JCENTRAL"):
            # we found env var JALIEN_HOST
            if JALIEN_HOST_ENV and isReachable(JALIEN_HOST_ENV, JALIEN_WSPORT_ENV):
                jalien_server, jalien_websocket_port = JALIEN_HOST_ENV, JALIEN_WSPORT_ENV
                logging.warning('AlienConnect:: JBox connection to %s:%s', jalien_server, jalien_websocket_port)
                wb = wb_create_tryout(jalien_server, jalien_websocket_port, jalien_websocket_path, use_usercert)

            # if either no JBox env vars or the wb creation failed let's check jalien_token_ file
            if wb is None and os.path.exists(jclient_env):
                jalien_info = read_conf_file(jclient_env)
                if jalien_info and 'JALIEN_PID' in jalien_info and is_my_pid(jalien_info['JALIEN_PID']):
                    jbox_host = jalien_info.get('JALIEN_HOST', 'localhost')
                    jbox_port = jalien_info.get('JALIEN_WSPORT', PORT_DEFAULT)
                    if isReachable(jbox_host, jbox_port):
                        jalien_server, jalien_websocket_port = jbox_host, jbox_port
                        logging.warning('AlienConnect:: JBox connection to %s:%s', jalien_server, jalien_websocket_port)
                        wb = wb_create_tryout(jalien_server, jalien_websocket_port, jalien_websocket_path, use_usercert)

        if wb is None:  # Either ALIENPY_JCENTRAL set or no wb so far
            wb = wb_create_tryout(jalien_server, jalien_websocket_port, jalien_websocket_path, use_usercert)

        # if ALIENPY_JCENTRAL is specified but no connection, treat this as hard error and exit
        if wb is None and os.getenv("ALIENPY_JCENTRAL"):
            msg = f'Check the logfile: {DEBUG_FILE}\nCould not connect to user specified ALIENPY_JCENTRAL: {jalien_server}:{jalien_websocket_port}\n'
            logging.error(msg)
            print_err(msg)
            sys.exit(107)  # ENOTCONN - Transport endpoint is not connected

        # if we still do not have a socket, then try to fallback to jcentral if not already tried
        if wb is None and jalien_server != SRV_DEFAULT:
            jalien_server, jalien_websocket_port = SRV_DEFAULT, PORT_DEFAULT
            wb = wb_create_tryout(jalien_server, jalien_websocket_port, jalien_websocket_path, use_usercert)

    if init_begin:
        msg = f">>>   AlienConnect::Time for connection: {deltat_ms_perf(init_begin)} ms"
        if DEBUG: logging.debug(msg)
        if TIME_CONNECT: print_out(msg)

    if wb is None:
        msg = f'Check the logfile: {DEBUG_FILE}\nCould not get a websocket connection to {jalien_server}:{jalien_websocket_port}'
        logging.error(msg)
        print_err(msg)
        sys.exit(107)  # ENOTCONN - Transport endpoint is not connected
    return wb


def InitConnection(wb: Optional[WebSocketClientProtocol] = None, token_args: Optional[list] = None, use_usercert: bool = False, localConnect: bool = False, cmdlist_func: Optional[Callable] = None) -> WebSocketClientProtocol:
    """Create a session to AliEn services, including session globals and token regeneration"""
    global ALIENPY_GLOBAL_WB

    wb = AlienConnect(wb, token_args, use_usercert, localConnect)  # Always valid, as the program will exit if connection could not be established
    ALIENPY_GLOBAL_WB = wb
    ## wb is guaranteed to be present as AlienConnect will bail out if not

    # is ALIEN_SITE env var is defined then pass this to central services
    if SET_SITE:
        rez = SendMsg(wb, 'setSite', [SET_SITE])
        logging.info(f'ALIEN_SITE :: {rez.out}')

    # NO MATTER WHAT BEFORE ANYTHING ELSE SESSION MUST BE INITIALIZED   !!!!!!!!!!!!!!!!
    if 'AlienSessionInfo' in globals():
        if not AlienSessionInfo['session_started']:  # this is beginning of session, let's get session vars ONLY ONCE
            AlienSessionInfo['session_started'] = True
            session_begin = time.perf_counter() if (TIME_CONNECT or DEBUG) else None

            ret_obj = SendMsg(wb, 'commandlist', [])  # it will automatically initialize user, currentdir, prevdir, alienHome (as each SendMsg does)
            if not ret_obj.ansdict or 'results' not in ret_obj.ansdict:
                print_err("Start session:: could not get command list, let's exit.")
                sys.exit(1)

            csd_cmds_re = re.compile(r'.*_csd$')
            AlienSessionInfo['commandlist'] = [cmd["commandlist"] for cmd in ret_obj.ansdict["results"] if not csd_cmds_re.match(cmd["commandlist"])]

            if session_begin:
                msg = f">>>   Time for session initialization: {deltat_ms_perf(session_begin)} ms"
                if DEBUG: logging.debug(msg)
                if TIME_CONNECT: print_out(msg)

        # construct command list with function in main module
        if cmdlist_func: cmdlist_func()

        # if this is a reconnection, make sure on the server we are in the last known current directory
        if AlienSessionInfo['currentdir']: cd(wb, AlienSessionInfo['currentdir'], 'log')

        # if usercert connection always regenerate token if connected with usercert
        if AlienSessionInfo['use_usercert'] and token(wb, token_args) != 0:
            print_err(f'The token could not be created! check the logfile {DEBUG_FILE}')

    return wb


def SendMsg(wb: WebSocketClientProtocol, cmdline: str, args: Optional[list] = None, opts: str = '') -> RET:
    """Send a json message to the specified websocket; it will return the server answer"""
    if not wb:
        msg = "SendMsg:: websocket not initialized"
        logging.info(msg)
        return RET(1, '', msg)  # type: ignore [call-arg]
    if not args: args = []
    JSON_OUT_GLOBAL = os.getenv('ALIENPY_JSON_OUT_GLOBAL')
    JSON_OUT = os.getenv('ALIENPY_JSON_OUT')

    time_begin = time.perf_counter() if DEBUG or DEBUG_TIMING else None

    if JSON_OUT_GLOBAL or JSON_OUT or DEBUG:  # if jsout output was requested, then make sure we get the full answer
        opts = opts.replace('-nokeys', '').replace('-nomsg', '').replace('nokeys', '').replace('nomsg', '')

    json_signature = ['{"command":', '"options":']
    # if already json format just use it as is; nomsg/nokeys will be passed to CreateJsonCommand
    jsonmsg = cmdline if all(x in cmdline for x in json_signature) else CreateJsonCommand(cmdline, args, opts)

    if not jsonmsg:
        logging.info("SendMsg:: json message is empty!")
        return RET(1, '', f"SendMsg:: empty json with args:: {cmdline} {' '.join(args)} /opts= {opts}")  # type: ignore [call-arg]

    if DEBUG:
        logging.debug(f"Called from: {sys._getframe().f_back.f_code.co_name}\n>>>   SEND COMMAND:: {jsonmsg}")  # pylint: disable=protected-access

    nr_tries = int(1)
    result = None
    while result is None:
        if nr_tries > 3: break
        nr_tries += 1
        try:
            result = wb_sendmsg(wb, jsonmsg)
        except Exception as e:
            logging.exception('SendMsg:: Error sending: %s\nBecause of %s', jsonmsg, e.__cause__)
            wb = AlienConnect(wb)
        if result is None: time.sleep(0.2)

    if time_begin: logging.debug('SendMsg::Result received: %s ms', deltat_ms_perf(time_begin))
    if not result:
        msg = f"SendMsg:: could not send command: {jsonmsg}\nCheck {DEBUG_FILE}"
        print_err(msg)
        logging.error(msg)
        return RET(70, '', 'SendMsg:: Empty result received from server')  # type: ignore [call-arg]  # ECOMM

    time_begin_decode = time.perf_counter() if DEBUG or DEBUG_TIMING else None
    ret_obj = retf_result2ret(result)
    if time_begin_decode: logging.debug('SendMsg::Result decoded: %s us', deltat_us_perf(time_begin_decode))
    return ret_obj  # noqa: R504


def SendMsgMulti(wb: WebSocketClientProtocol, cmds_list: list, opts: str = '') -> list:
    """Send a json message to the specified websocket; it will return the server answer"""
    if not wb:
        msg = "SendMsg:: websocket not initialized"
        logging.info(msg)
        return RET(1, '', msg)  # type: ignore [call-arg]
    if not cmds_list: return []
    JSON_OUT_GLOBAL = os.getenv('ALIENPY_JSON_OUT_GLOBAL')
    JSON_OUT = os.getenv('ALIENPY_JSON_OUT')

    time_begin = time.perf_counter() if DEBUG or DEBUG_TIMING else None

    if JSON_OUT_GLOBAL or JSON_OUT or DEBUG:  # if jsout output was requested, then make sure we get the full answer
        opts = opts.replace('-nokeys', '').replace('-nomsg', '').replace('nokeys', '').replace('nomsg', '')

    json_signature = ['{"command":', '"options":']
    json_cmd_list = []
    for cmd_str in cmds_list:
        # if already json format just use it as is; nomsg/nokeys will be passed to CreateJsonCommand
        jsonmsg = cmd_str if all(x in cmd_str for x in json_signature) else CreateJsonCommand(cmd_str, [], opts)
        json_cmd_list.append(jsonmsg)

    if DEBUG:
        logging.debug(f"Called from: {sys._getframe().f_back.f_code.co_name}\nSEND COMMAND:: {chr(32).join(json_cmd_list)}")  # pylint: disable=protected-access

    nr_tries = int(1)
    result_list = None
    while result_list is None:
        if nr_tries > 3: break
        nr_tries += 1
        try:
            result_list = wb_sendmsg_multi(wb, json_cmd_list)
        except wb_exceptions.ConnectionClosed as e:
            logging.exception('SendMsgMulti:: failure because of %s', e.__cause__)
            try:
                wb = AlienConnect(wb)
            except Exception:
                logging.exception('SendMsgMulti:: Could not recover connection when disconnected!!')
        except Exception:
            logging.exception('SendMsgMulti:: Abnormal connection status!!!')
        if result_list is None: time.sleep(0.2)

    if time_begin: logging.debug('SendMsg::Result received: %s ms', deltat_ms_perf(time_begin))
    if not result_list: return []
    time_begin_decode = time.perf_counter() if DEBUG or DEBUG_TIMING else None
    ret_obj_list = [retf_result2ret(result) for result in result_list]
    if time_begin_decode: logging.debug('SendMsg::Result decoded: %s ms', deltat_ms_perf(time_begin_decode))
    return ret_obj_list  # noqa: R504


def session_state_update(out_dict: dict) -> None:
    """Update global AlienSessionInfo with status of the latest command"""
    if 'AlienSessionInfo' in globals():  # update global state of session
        AlienSessionInfo['user'] = out_dict["metadata"]["user"]  # always update the current user
        current_dir = out_dict["metadata"]["currentdir"]

        # if this is first connection, current dir is alien home
        if not AlienSessionInfo['alienHome']: AlienSessionInfo['alienHome'] = current_dir

        # update the current current/previous dir status
        # previous/current have the meaning of before and after command execution
        prev_dir = AlienSessionInfo['currentdir']  # last known current dir
        if prev_dir != current_dir:
            AlienSessionInfo['currentdir'] = current_dir
            AlienSessionInfo['prevdir'] = prev_dir

        # update directory stack (pushd/popd/dirs)
        short_current_dir = current_dir.replace(AlienSessionInfo['alienHome'][:-1], '~')
        short_current_dir = short_current_dir[:-1]  # remove the last /
        if AlienSessionInfo['pathq']:
            if AlienSessionInfo['pathq'][0] != short_current_dir: AlienSessionInfo['pathq'][0] = short_current_dir
        else:
            push2stack(short_current_dir)


def retf_result2ret(result: Union[str, dict, None]) -> RET:
    """Convert AliEn answer dictionary to RET object"""
    if not result: return RET(61, '', 'Empty input')  # type: ignore [call-arg]
    out_dict = None
    if isinstance(result, str):
        try:
            out_dict = json.loads(result)
        except Exception as e:
            msg = f'retf_result2ret:: Could not load argument as json!\n{e!r}'
            logging.error(msg)
            return RET(22, '', msg)  # type: ignore [call-arg]
    elif isinstance(result, dict):
        out_dict = result
    else:
        msg = 'retf_result2ret:: Wrong type of argument'
        logging.error(msg)
        return RET(42, '', msg)  # type: ignore [call-arg]

    if 'metadata' not in out_dict or 'results' not in out_dict:  # these works only for AliEn responses
        msg = 'retf_results2ret:: Dictionary does not have AliEn answer format'
        logging.error(msg)
        return RET(42, '', msg)  # type: ignore [call-arg]

    session_state_update(out_dict)  # ALWAYS UPDATE GLOBAL STATE
    message_list = [str(item['message']) for item in out_dict['results'] if 'message' in item]
    output = '\n'.join(message_list)
    return RET(int(out_dict["metadata"]["exitcode"]), output.strip(), out_dict["metadata"]["error"], out_dict)  # type: ignore [call-arg]


def retf_print(ret_obj: RET, opts: str = '') -> int:
    """Process a RET object; it will return the exitcode
    opts content will steer the logging and message printing:
     - noprint : silence all stdout/stderr printing
     - noerr/noout : silence the respective messages
     - info/warn/err/debug : will log the stderr to that facility
     - json : will print just the json (if present)
    """
    if 'json' in opts:
        if ret_obj.ansdict:
            PrintDict(ret_obj.ansdict)
        else:
            print_err('This command did not return a json dictionary')
        return ret_obj.exitcode

    if ret_obj.exitcode != 0:
        if 'debug' in opts:
            logging.debug(ret_obj.err)
        elif 'info' in opts:
            logging.info(ret_obj.err)
        elif 'warn' in opts:
            logging.warning(ret_obj.err)
        else:
            logging.error(ret_obj.err)
        if ret_obj.err and not ('noerr' in opts or 'noprint' in opts): print_err(f'{ret_obj.err.strip()}')
    else:
        if ret_obj.out and not ('noout' in opts or 'noprint' in opts): print_out(f'{ret_obj.out.strip()}')
    return ret_obj.exitcode


def token(wb: WebSocketClientProtocol, args: Optional[list] = None) -> int:
    """(Re)create the tokencert and tokenkey files"""
    if not wb: return 1
    if not args: args = []
    certs_info = get_certs_names()
    _ = is_help(args, clean_args = True)

    ret_obj = SendMsg(wb, 'token', args, opts = 'nomsg')
    if ret_obj.exitcode != 0:
        logging.error('Token request returned error')
        return retf_print(ret_obj, 'err')
    tokencert_content = tokenkey_content = None
    ret_results = ret_obj.ansdict['results'] if ret_obj.ansdict and 'results' in ret_obj.ansdict else []
    if len(ret_results) > 0:
        tokencert_content = ret_results[0].get('tokencert', '')
        tokenkey_content = ret_results[0].get('tokenkey', '')
    if not tokencert_content or not tokenkey_content:
        logging.error('Token request valid but empty fields!!')
        return int(42)  # ENOMSG

    try:
        if path_readable(certs_info.token_cert):
            os.chmod(certs_info.token_cert, 0o600)  # make it writeable
            os.remove(certs_info.token_cert)
        with open(certs_info.token_cert, "w", encoding = "ascii", errors = "replace") as tcert: print(f"{tokencert_content}", file = tcert)  # write the tokencert
        os.chmod(certs_info.token_cert, 0o400)  # make it readonly
    except Exception:
        print_err(f'Error writing to file the acquired token cert; check the log file {DEBUG_FILE}!')
        logging.debug(traceback.format_exc())
        return 5  # EIO

    try:
        if path_readable(certs_info.token_key):
            os.chmod(certs_info.token_key, 0o600)  # make it writeable
            os.remove(certs_info.token_key)
        with open(certs_info.token_key, "w", encoding = "ascii", errors = "replace") as tkey: print(f"{tokenkey_content}", file = tkey)  # write the tokenkey
        os.chmod(certs_info.token_key, 0o400)  # make it readonly
    except Exception:
        print_err(f'Error writing to file the acquired token key; check the log file {DEBUG_FILE}!')
        logging.debug(traceback.format_exc())
        return 5  # EIO
    if 'AlienSessionInfo' in globals():
        AlienSessionInfo['token_cert'] = certs_info.token_cert
        AlienSessionInfo['token_key'] = certs_info.token_key
    return int(0)


def token_regen(wb: WebSocketClientProtocol, args: Optional[list] = None) -> WebSocketClientProtocol:
    """Do the disconnect, connect with user cert, generate token, re-connect with token procedure"""
    wb_usercert = None
    if not args: args = []

    if 'AlienSessionInfo' in globals() and not AlienSessionInfo['use_usercert']:
        _ = wb_close(wb, code = 1000, reason = 'Lets connect with usercert to be able to generate token')
        try:
            wb_usercert = InitConnection(wb, args, use_usercert = True)  # we have to reconnect with the new token
        except Exception:
            logging.debug(traceback.format_exc())
            return None  # we failed usercert connection

    # now we are connected with usercert, so we can generate token
    if token(wb_usercert, args) != 0: return wb_usercert
    # we have to reconnect with the new token
    _ = wb_close(wb_usercert, code = 1000, reason = 'Re-initialize the connection with the new token')
    if 'AlienSessionInfo' in globals(): AlienSessionInfo['use_usercert'] = False
    wb_token_new = None
    try:
        wb_token_new = InitConnection(wb_token_new, args)
        __ = SendMsg(wb_token_new, 'pwd', [], opts = 'nokeys')  # just to refresh cwd
    except Exception:
        logging.exception('token_regen:: error re-initializing connection')
    return wb_token_new


def cd(wb: WebSocketClientProtocol, args: Union[str, list, None] = None, opts: str = '') -> RET:
    """Override cd to add to home and to prev functions"""
    if args is None: args = []
    if isinstance(args, str): args = args.split()
    if is_help(args): return get_help_srv(wb, 'cd')
    if args:
        if args[0] == '-': args = [AlienSessionInfo['prevdir']]
        if 'nocheck' not in opts and AlienSessionInfo['currentdir'].rstrip('/') == args[0].rstrip('/'): return RET(0)  # type: ignore [call-arg]
    return SendMsg(wb, 'cd', args, opts)


def get_list_entries(wb: WebSocketClientProtocol, lfn: str = '', fullpath: bool = False) -> list:
    """return a list of entries of the lfn argument, full paths if 2nd arg is True"""
    if not lfn: return []
    key = 'path' if fullpath else 'name'
    ret_obj = SendMsg(wb, 'ls', ['-nomsg', '-a', '-F', os.path.normpath(lfn)])
    if ret_obj.exitcode != 0: return []
    return [item[key] for item in ret_obj.ansdict['results']]


def lfn_list(wb: WebSocketClientProtocol, lfn: str = '') -> list:
    """Completer function : for a given lfn return all options for latest leaf"""
    if not wb: return []
    if not lfn: lfn = '.'  # AlienSessionInfo['currentdir']
    lfn_path = Path(lfn)
    base_dir = '/' if lfn_path.parent.as_posix() == '/' else f'{lfn_path.parent.as_posix()}/'
    name = f'{lfn_path.name}/' if lfn.endswith('/') else lfn_path.name

    def item_format(base_dir: str, name: str, item: str) -> str:
        if name.endswith('/') and name != '/':
            return f'{name}{item}' if base_dir == './' else f'{base_dir}{name}{item}'
        return item if base_dir == './' else f'{base_dir}{item}'

    if lfn.endswith('/'):
        listing = get_list_entries(wb, lfn)
        return [item_format(base_dir, name, item) for item in listing]

    # we gave an initial name
    listing = get_list_entries(wb, base_dir)
    return [item_format(base_dir, name, item) for item in listing if item.startswith(name)]


def wb_ping(wb: WebSocketClientProtocol) -> float:
    """Websocket ping function, it will return rtt in ms"""
    init_begin = time.perf_counter()
    if IsWbConnected(wb):
        return float(deltat_ms_perf(init_begin))
    return float(-1)


def get_help_srv(wb: WebSocketClientProtocol, cmd: str = '') -> RET:
    """Return the help option for server-side known commands"""
    if not cmd: return RET(1, '', 'No command specified for help request')
    return SendMsg(wb, f'{cmd} -h')


class Msg:
    """Class to create json messages to be sent to server"""
    __slots__ = ('cmd', 'args', 'opts')

    def __init__(self, cmd: str = '', args: Union[str, list, None] = None, opts: str = '') -> None:
        self.cmd = cmd
        self.opts = opts
        if not args:
            self.args = []
        elif isinstance(args, str):
            self.args = shlex.split(args)
        elif isinstance(args, list):
            self.args = args.copy()

    def add_arg(self, arg: Union[str, list, None]) -> None:
        if not arg: return
        if isinstance(arg, str): self.args.extend(shlex.split(arg))
        if isinstance(arg, list): self.args.extend(arg)

    def msgdict(self) -> dict:
        return CreateJsonCommand(self.cmd, self.args, self.opts, True)

    def msgstr(self) -> str:
        return CreateJsonCommand(self.cmd, self.args, self.opts)

    def __call__(self) -> tuple:
        return (self.cmd, self.args, self.opts)

    def __bool__(self) -> bool:
        return bool(self.cmd)


@syncify
async def msg_proxy(websocket, use_usercert = False):
    """Proxy messages from a connection point to another"""
    wb_jalien = AlienConnect(None, use_usercert)
    local_query = await websocket.recv()
    jalien_answer = SendMsg(wb_jalien, local_query)
    await websocket.send(jalien_answer.ansdict)


if __name__ == '__main__':
    print('This file should not be executed!', file = sys.stderr, flush = True)
    sys.exit(95)
