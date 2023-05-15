"""WEBSOCKET:: API for WebSOcket communications"""

import os
import json
import shlex

from .global_vars import *  # nosec PYL-W0614
from .tools_nowb import *  # nosec PYL-W0614
from .wb_async import *  # nosec PYL-W0614
from .tools_stackcmd import push2stack
from .setup_logging import print_out, print_err
from .wb_api_tools import *

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


def AlienConnect(wb = None, token_args: Union[None, list] = None, use_usercert: bool = False, localConnect: bool = False):
    """Create a websocket connection to AliEn services either directly to alice-jcentral.cern.ch or trough a local found jbox instance"""
    if not token_args: token_args = []
    init_begin = time.perf_counter() if (TIME_CONNECT or DEBUG) else None

    jalien_server = os.getenv("ALIENPY_JCENTRAL", 'alice-jcentral.cern.ch')  # default value for JCENTRAL
    jalien_websocket_port = os.getenv("ALIENPY_JCENTRAL_PORT", '8097')  # websocket port
    jalien_websocket_path = '/websocket/json'
    jclient_env = f'{TMPDIR}/jclient_token_{str(os.getuid())}'

    # If presentent with existing socket, let's try to close it
    if wb: wb_close(wb, code = 1000, reason = 'Close previous websocket')

    # let's try to get a websocket
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


def SendMsg(wb, cmdline: str, args: Union[None, list] = None, opts: str = '') -> Union[RET, str]:
    """Send a json message to the specified websocket; it will return the server answer"""
    if not wb:
        msg = "SendMsg:: websocket not initialized"
        logging.info(msg)
        return '' if 'rawstr' in opts else RET(1, '', msg)  # type: ignore [call-arg]
    if not args: args = []
    JSON_OUT_GLOBAL = os.getenv('ALIENPY_JSON_OUT_GLOBAL')
    JSON_OUT = os.getenv('ALIENPY_JSON_OUT')

    time_begin = time.perf_counter() if DEBUG or DEBUG_TIMING else None

    if JSON_OUT_GLOBAL or JSON_OUT:  
        opts = opts.replace('-nokeys', '').opts.replace('nokeys', '')
        if 'nomsg' not in opts: opts = f'{opts} nomsg'

    # if DEBUG then make sure we get the full answer
    if DEBUG:
        opts = opts.replace('-nokeys', '').replace('-nomsg', '').replace('nokeys', '').replace('nomsg', '')

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
            wb = AlienConnect(wb)
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
    JSON_OUT_GLOBAL = os.getenv('ALIENPY_JSON_OUT_GLOBAL')
    JSON_OUT = os.getenv('ALIENPY_JSON_OUT')

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
                wb = AlienConnect(wb)
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
    
    
    
    

