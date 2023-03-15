"""WEBSOCKET:: API for WebSOcket communications"""

import os
import json

from .tools_misc import *
#from .setup_logging import *
from .wb_async import *
#from .global_vars import *
#from .setup_logging import *
from .tools_stackcmd import *


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


def CreateJsonCommand(cmdline: Union[str, dict], args: Union[None, list] = None, opts: str = '', get_dict: bool = False) -> Union[str, dict]:
    """Return a json with command and argument list"""
    if args is None: args = []
    if isinstance(cmdline, dict):
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


def SendMsg(wb, cmdline: str, args: Union[None, list] = None, opts: str = '') -> Union[RET, str]:
    """Send a json message to the specified websocket; it will return the server answer"""
    if not wb:
        msg = "SendMsg:: websocket not initialized"
        logging.info(msg)
        return '' if 'rawstr' in opts else RET(1, '', msg)  # type: ignore [call-arg]
    if not args: args = []
    time_begin = time.perf_counter() if DEBUG or DEBUG_TIMING else None
    if JSON_OUT_GLOBAL or JSON_OUT or DEBUG:  # if jsout output was requested, then make sure we get the full answer
        opts = opts.replace('nokeys', '').replace('nomsg', '')

    json_signature = ['{"command":', '"options":']
    # if already json format just use it as is; nomsg/nokeys will be passed to CreateJsonCommand
    jsonmsg = cmdline if all(x in cmdline for x in json_signature) else CreateJsonCommand(cmdline, args, opts)

    if not jsonmsg:
        logging.info("SendMsg:: json message is empty!")
        return '' if 'rawstr' in opts else RET(1, '', f"SendMsg:: empty json with args:: {cmdline} {' '.join(args)} /opts= {opts}")  # type: ignore [call-arg]

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
            wb = InitConnection()
        if result is None: time.sleep(0.2)

    if time_begin: logging.debug('SendMsg::Result received: %s ms', deltat_ms_perf(time_begin))
    if not result:
        msg = f"SendMsg:: could not send command: {jsonmsg}\nCheck {DEBUG_FILE}"
        print_err(msg)
        logging.error(msg)
        return RET(70, '', 'SendMsg:: Empty result received from server')  # type: ignore [call-arg]  # ECOMM  

    if 'rawstr' in opts: return result
    time_begin_decode = time.perf_counter() if DEBUG or DEBUG_TIMING else None
    ret_obj = retf_result2ret(result)
    if time_begin_decode: logging.debug('SendMsg::Result decoded: %s us', deltat_us_perf(time_begin_decode))
    return ret_obj  # noqa: R504


def SendMsgMulti(wb, cmds_list: list, opts: str = '') -> list:
    """Send a json message to the specified websocket; it will return the server answer"""
    if not wb:
        msg = "SendMsg:: websocket not initialized"
        logging.info(msg)
        return '' if 'rawstr' in opts else RET(1, '', msg)  # type: ignore [call-arg]
    if not cmds_list: return []
    time_begin = time.perf_counter() if DEBUG or DEBUG_TIMING else None
    if JSON_OUT_GLOBAL or JSON_OUT or DEBUG:  # if jsout output was requested, then make sure we get the full answer
        opts = opts.replace('nokeys', '').replace('nomsg', '')

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
                wb = InitConnection()
            except Exception:
                logging.exception('SendMsgMulti:: Could not recover connection when disconnected!!')
        except Exception:
            logging.exception('SendMsgMulti:: Abnormal connection status!!!')
        if result_list is None: time.sleep(0.2)

    if time_begin: logging.debug('SendMsg::Result received: %s ms', deltat_ms(time_begin))
    if not result_list: return []
    if 'rawstr' in opts: return result_list
    time_begin_decode = time.perf_counter() if DEBUG or DEBUG_TIMING else None
    ret_obj_list = [retf_result2ret(result) for result in result_list]
    if time_begin_decode: logging.debug('SendMsg::Result decoded: %s ms', deltat_ms(time_begin_decode))
    return ret_obj_list  # noqa: R504


def wb_create_tryout(host: str, port: Union[str, int], path: str = '/', use_usercert: bool = False, localConnect: bool = False):
    """WebSocket creation with tryouts (configurable by env ALIENPY_CONNECT_TRIES and ALIENPY_CONNECT_TRIES_INTERVAL)"""
    wb = None
    nr_tries = 0
    init_begin = None
    if TIME_CONNECT or DEBUG: init_begin = time.perf_counter()
    connect_tries = int(os.getenv('ALIENPY_CONNECT_TRIES', '3'))
    connect_tries_interval = float(os.getenv('ALIENPY_CONNECT_TRIES_INTERVAL', '0.5'))

    while wb is None:
        nr_tries += 1
        try:
            wb = wb_create(host, str(port), path, use_usercert, localConnect)
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

    if wb and localConnect:
        pid_filename = f'{TMPDIR}/jboxpy_{os.getuid()}.pid'
        writePidFile(pid_filename)
    return wb


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
            json_out = json.dumps(ret_obj.ansdict, sort_keys = True, indent = 3)
            if DEBUG: logging.debug(json_out)
            print_out(json_out)
        else:
            print_err('This command did not return a json dictionary')
        return ret_obj.exitcode

    if ret_obj.exitcode != 0:
        if 'info' in opts: logging.info(ret_obj.err)
        if 'warn' in opts: logging.warning(ret_obj.err)
        if 'err' in opts: logging.error(ret_obj.err)
        if 'debug' in opts: logging.debug(ret_obj.err)
        if ret_obj.err and not ('noerr' in opts or 'noprint' in opts):
            print_err(f'{ret_obj.err.strip()}')
    else:
        if ret_obj.out and not ('noout' in opts or 'noprint' in opts):
            print_out(f'{ret_obj.out.strip()}')
    return ret_obj.exitcode


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
    else:
        out_dict = result.copy()

    if 'metadata' not in out_dict or 'results' not in out_dict:  # these works only for AliEn responses
        msg = 'retf_results2ret:: Dictionary does not have AliEn answer format'
        logging.error(msg)
        return RET(52, '', msg)  # type: ignore [call-arg]

    session_state_update(out_dict)
    message_list = [str(item['message']) for item in out_dict['results'] if 'message' in item]
    output = '\n'.join(message_list)
    return RET(int(out_dict["metadata"]["exitcode"]), output.strip(), out_dict["metadata"]["error"], out_dict)  # type: ignore [call-arg]


def session_state_update (out_dict: dict) -> None:
    """Update global AlienSessionInfo with status of the latest command"""
    global AlienSessionInfo
    if AlienSessionInfo:  # update global state of session
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


def AlienConnect(token_args: Union[None, list] = None, use_usercert: bool = False, localConnect: bool = False):
    """Create a websocket connection to AliEn services either directly to alice-jcentral.cern.ch or trough a local found jbox instance"""
    if not token_args: token_args = []
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
            if jalien_info and 'JALIEN_PID' in jalien_info and is_my_pid(jalien_info['JALIEN_PID']):
                jbox_host = jalien_info.get('JALIEN_HOST', 'localhost')
                jbox_port = jalien_info.get('JALIEN_WSPORT', '8097')
                if isReachable(jbox_host, jbox_port):
                    jalien_server, jalien_websocket_port = jbox_host, jbox_port
                    logging.warning('AlienConnect:: JBox connection to %s:%s', jalien_server, jalien_websocket_port)

        wb = wb_create_tryout(jalien_server, str(jalien_websocket_port), jalien_websocket_path, use_usercert)

        # if we stil do not have a socket, then try to fallback to jcentral if we did not had explicit endpoint and jcentral was not already tried
        if wb is None and not os.getenv("ALIENPY_JCENTRAL") and jalien_server != 'alice-jcentral.cern.ch':
            jalien_server, jalien_websocket_port = 'alice-jcentral.cern.ch', '8097'
            wb = wb_create_tryout(jalien_server, jalien_websocket_port, jalien_websocket_path, use_usercert)

    if wb is None:
        msg = f'Check the logfile: {DEBUG_FILE}\nCould not get a websocket connection to {jalien_server}:{jalien_websocket_port}'
        logging.error(msg)
        print_err(msg)
        sys.exit(107)  # ENOTCONN - Transport endpoint is not connected

    return wb


if __name__ == '__main__':
    print('This file should not be executed!', file = sys.stderr, flush = True)
    sys.exit(95)
    
    
    
    
