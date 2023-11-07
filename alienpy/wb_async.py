"""WEBSOCKET:: main async functions"""

import os
import sys
import socket
import logging
import time
from typing import Optional, TYPE_CHECKING, Union

try:
    import websockets.client as wb_client
    import websockets.exceptions as wb_exceptions
    import websockets.version as wb_version
    from websockets.extensions import permessage_deflate as _wb_permessage_deflate
except Exception:
    print("websockets module could not be imported! Make sure you can do:\npython3 -c 'import websockets.client as wb_client'", file = sys.stderr, flush = True)
    sys.exit(1)
from websockets import WebSocketClientProtocol

if not os.getenv('ALIENPY_NO_STAGGER'):
    try:
        import async_stagger  # type: ignore
    except Exception:
        print("async_stagger module could not be imported! Make sure you can do:\npython3 -c 'import async_stagger'", file = sys.stderr, flush = True)
        sys.exit(1)

from .version import ALIENPY_VERSION_STR
from .global_vars import DEBUG, DEBUG_FILE, DEBUG_TIMING, TMPDIR
from .tools_nowb import deltat_ms_perf
from .setup_logging import print_err
from .connect_ssl import create_ssl_context, renewCredFilesInfo
from .async_tools import start_asyncio, syncify


#########################
#   ASYNCIO MECHANICS
#########################
# Let's start the asyncio main thread
start_asyncio()


@syncify
async def wb_create(host: str = 'localhost', port: Union[str, int] = '8097', path: str = '/', use_usercert: bool = False, localConnect: bool = False) -> Optional[WebSocketClientProtocol]:
    """Create a websocket to wss://host:port/path (it is implied a SSL context)"""
    if not host:
        msg = 'wb_create:: provided host argument is empty'
        print_err(msg)
        logging.error(msg)
        return None
    if not port or not str(port).isdigit() or abs(int(port)) > 65535:
        msg = 'wb_create:: provided port argument is empty, 0 or invalid integer'
        print_err(msg)
        logging.error(msg)
        return None
    port = str(abs(int(port)))  # make sure the port argument is positive

    QUEUE_SIZE = int(128)  # maximum length of the queue that holds incoming messages
    MSG_SIZE = None  # int(20 * 1024 * 1024)  # maximum size for incoming messages in bytes. The default value is 1 MiB. None disables the limit
    PING_TIMEOUT = int(os.getenv('ALIENPY_TIMEOUT', '20'))  # If the corresponding Pong frame isn’t received within ping_timeout seconds, the connection is considered unusable and is closed
    PING_INTERVAL = PING_TIMEOUT  # Ping frame is sent every ping_interval seconds
    CLOSE_TIMEOUT = int(10)  # maximum wait time in seconds for completing the closing handshake and terminating the TCP connection
    # https://websockets.readthedocs.io/en/stable/api.html#websockets.protocol.WebSocketCommonProtocol
    # we use some conservative values, higher than this might hurt the sensitivity to intreruptions

    wb = None
    ctx = None
    #  client_max_window_bits = 12,  # tomcat endpoint does not allow anything other than 15, so let's just choose a mem default towards speed
    deflateFact = _wb_permessage_deflate.ClientPerMessageDeflateFactory(compress_settings={'memLevel': 4})
    headers_list = [('User-Agent', f'alien.py/{ALIENPY_VERSION_STR} websockets/{wb_version.version}')]
    if localConnect:
        fHostWSUrl = 'ws://localhost/'
        logging.info('Request connection to : %s', fHostWSUrl)
        socket_filename = f'{TMPDIR}/jboxpy_{str(os.getuid())}.sock'
        try:
            wb = await wb_client.unix_connect(socket_filename, fHostWSUrl,
                                              max_queue = QUEUE_SIZE, max_size = MSG_SIZE,
                                              ping_interval = PING_INTERVAL, ping_timeout = PING_TIMEOUT,
                                              close_timeout = CLOSE_TIMEOUT, extra_headers = headers_list)
        except Exception as e:
            msg = f'Could NOT establish connection (local socket) to {socket_filename}\n{e!r}'
            logging.error(msg)
            print_err(f'{msg}\nCheck the logfile: {DEBUG_FILE}')
            return None
    else:
        fHostWSUrl = f'wss://{host}:{port}{path}'  # conection url

        # create/refresh the definitions of cert files
        certs_info = renewCredFilesInfo()

        # Check the presence of user certs and bailout before anything else
        if not certs_info.token_cert and not certs_info.user_cert:
            print_err(f'No valid user certificate or token found!! check {DEBUG_FILE} for further information and contact the developer if the information is not clear.')
            sys.exit(126)

        try:
            ctx = create_ssl_context(use_usercert,
                                     user_cert = certs_info.user_cert, user_key = certs_info.user_key,
                                     token_cert = certs_info.token_cert, token_key = certs_info.token_key)
        except Exception as e:
            msg = f'Could NOT create SSL context with cert files:\n{certs_info.user_cert} ; {certs_info.user_key}\n{certs_info.token_cert} ; {certs_info.token_key}\n{e!r}'
            logging.error(msg)
            print_err(f'{msg}\nCheck the logfile: {DEBUG_FILE}')
            return None

        if not ctx:
            msg = f'Could NOT create SSL context with cert files:\n{certs_info.user_cert} ; {certs_info.user_key}\n{certs_info.token_cert} ; {certs_info.token_key}'
            logging.error(msg)
            print_err(f'{msg}\nCheck the logfile: {DEBUG_FILE}')
            return None

        logging.info('Request connection to: %s:%s%s', host, port, path)

        socket_endpoint = None
        # https://async-stagger.readthedocs.io/en/latest/reference.html#async_stagger.create_connected_sock
        # AI_* flags --> https://linux.die.net/man/3/getaddrinfo
        init_begin_socket = None
        try:
            if DEBUG:
                logging.debug('TRY ENDPOINT: %s:%s', host, port)
                init_begin_socket = time.perf_counter()
            if os.getenv('ALIENPY_NO_STAGGER'):
                socket_endpoint = socket.create_connection((host, int(port)))
            else:
                socket_endpoint = await async_stagger.create_connected_sock(host, int(port), async_dns = True, delay = 0, resolution_delay = 0.050, detailed_exceptions = True)
            if init_begin_socket:
                logging.debug('TCP SOCKET DELTA: %s ms', deltat_ms_perf(init_begin_socket))
        except Exception as e:
            msg = f'Could NOT establish connection (TCP socket) to {host}:{port}\n{e!r}'
            logging.error(msg)
            print_err(f'{msg}\nCheck the logfile: {DEBUG_FILE}')
            return None

        if socket_endpoint:
            socket_endpoint_addr = socket_endpoint.getpeername()[0]
            socket_endpoint_port = socket_endpoint.getpeername()[1]
            logging.info('GOT SOCKET TO: %s:%s', socket_endpoint_addr, socket_endpoint_port)
            try:
                init_begin_wb = None
                if DEBUG: init_begin_wb = time.perf_counter()
                wb = await wb_client.connect(fHostWSUrl, sock = socket_endpoint, server_hostname = host, ssl = ctx, extensions=[deflateFact],
                                             max_queue=QUEUE_SIZE, max_size=MSG_SIZE,
                                             ping_interval=PING_INTERVAL, ping_timeout=PING_TIMEOUT,
                                             close_timeout=CLOSE_TIMEOUT, extra_headers=headers_list)

                if init_begin_wb:
                    logging.debug('WEBSOCKET DELTA: %s ms', deltat_ms_perf(init_begin_wb))

            except wb_exceptions.InvalidStatusCode as e:
                msg = f'Invalid status code {e.status_code} connecting to {socket_endpoint_addr}:{socket_endpoint_port}\n{e!r}'
                logging.error(msg)
                print_err(f'{msg}\nCheck the logfile: {DEBUG_FILE}')
                if int(e.status_code) == 401:
                    print_err('The status code indicate that your certificate is not authorized.\nCheck the correct certificate registration into ALICE VO')
                    sys.exit(129)
                return None
            except Exception as e:
                msg = f'Could NOT establish connection (WebSocket) to {socket_endpoint_addr}:{socket_endpoint_port}\n{e!r}'
                logging.error(msg)
                print_err(f'{msg}\nCheck the logfile: {DEBUG_FILE}')
                return None
        if wb: logging.info('CONNECTED: %s:%s', wb.remote_address[0], wb.remote_address[1])
    return wb


@syncify
async def IsWbConnected(wb: WebSocketClientProtocol) -> bool:
    """Check if websocket is connected with the protocol ping/pong"""
    time_begin = time.perf_counter() if DEBUG_TIMING else None
    if DEBUG:
        logging.info('Called from: %s', sys._getframe().f_back.f_code.co_name)  # pylint: disable=protected-access
    try:
        pong_waiter = await wb.ping()
        await pong_waiter
    except Exception:
        logging.exception('WB ping/pong failed!!!')
        return False
    if time_begin: logging.error('>>>IsWbConnected time = %s ms', deltat_ms_perf(time_begin))
    return True


@syncify
async def wb_close(wb: WebSocketClientProtocol, code, reason):
    """Send close to websocket"""
    try:
        await wb.close(code = code, reason = reason)
    except Exception:  # nosec
        pass


@syncify
async def wb_sendmsg(wb: WebSocketClientProtocol, jsonmsg: str) -> str:
    """The low level async function for send/receive"""
    time_begin = time.perf_counter() if DEBUG_TIMING else None
    await wb.send(jsonmsg)
    result = await wb.recv()
    if time_begin: logging.debug('>>>__sendmsg time = %s ms', deltat_ms_perf(time_begin))
    return result  # noqa: R504


@syncify
async def wb_sendmsg_multi(wb: WebSocketClientProtocol, jsonmsg_list: list) -> list:
    """The low level async function for send/receive multiple messages once"""
    if not jsonmsg_list: return []
    time_begin = time.perf_counter() if DEBUG_TIMING else None
    for msg in jsonmsg_list: await wb.send(msg)

    result_list = []
    for _i in range(len(jsonmsg_list)):
        result = await wb.recv()
        result_list.append(result)

    if time_begin: logging.debug('>>>__sendmsg time = %s ms', deltat_ms_perf(time_begin))
    return result_list


if __name__ == '__main__':
    print('This file should not be executed!', file = sys.stderr, flush = True)
    sys.exit(95)
