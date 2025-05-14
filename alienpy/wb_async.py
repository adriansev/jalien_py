"""alienpy::WEBSOCKET:: main async functions"""

import os
import sys
import socket
import logging
import time
import functools
from importlib.metadata import version
from typing import Optional, TYPE_CHECKING, Union

try:
    from websockets.asyncio.client import connect as wb_connect
    from websockets.asyncio.client import unix_connect as wb_connect_unix
    import websockets.exceptions as wb_exceptions
    from websockets.version import version as wb_version
    from websockets.extensions import permessage_deflate as _wb_permessage_deflate
except Exception:
    print("websockets module could not be imported! Make sure you can do:\npython3 -c 'import websockets.client as wb_client'", file = sys.stderr, flush = True)
    sys.exit(1)
from websockets import WebSocketClientProtocol

ASYNC_STAGGER_PRESENT = False
if not os.getenv('ALIENPY_NO_STAGGER'):
    try:
        import async_stagger  # type: ignore
        ASYNC_STAGGER_PRESENT = True
    except Exception:
        print("async_stagger module not found! Parallel connection to FQDN aliases will be disabled! Make sure you can do:\npython3 -c 'import async_stagger'", file = sys.stderr, flush = True)


from .version import ALIENPY_VERSION_STR
from .setup_logging import DEBUG, DEBUG_FILE, print_err
from .data_structs import CertsInfo
from .global_vars import DEBUG_TIMING, TMPDIR, PLATFORM_ID, AlienSessionInfo
from .tools_nowb import deltat_ms_perf
from .connect_ssl import create_ssl_context, renewCredFilesInfo
from .async_tools import start_asyncio, syncify


PYTHON_VERSION = f'{sys.version_info[0]}.{sys.version_info[1]}.{sys.version_info[2]}'
USER_AGENT = f'alienpy/{ALIENPY_VERSION_STR} websockets/{wb_version} Python/{PYTHON_VERSION} {PLATFORM_ID}'

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

    # https://websockets.readthedocs.io/en/stable/reference/asyncio/client.html#
    # https://websockets.readthedocs.io/en/stable/reference/sync/client.html
    QUEUE_SIZE = int(128)  # maximum length of the queue that holds incoming messages
    MSG_SIZE = None  # int(20 * 1024 * 1024)  # maximum size for incoming messages in bytes. The default value is 1 MiB. None disables the limit
    PING_TIMEOUT = int(os.getenv('ALIENPY_TIMEOUT', '20'))  # If the corresponding Pong frame isn’t received within ping_timeout seconds, the connection is considered unusable and is closed
    PING_INTERVAL = PING_TIMEOUT  # Ping frame is sent every ping_interval seconds
    OPEN_TIMEOUT = int(5)  # Timeout for opening the connection in seconds
    CLOSE_TIMEOUT = int(10)  # maximum wait time in seconds for completing the closing handshake and terminating the TCP connection
    # https://websockets.readthedocs.io/en/stable/api.html#websockets.protocol.WebSocketCommonProtocol
    # we use some conservative values, higher than this might hurt the sensitivity to intreruptions

    wb = None
    ctx = None
    # Compressiont settings given by https://docs.python.org/3/library/zlib.html#zlib.compressobj
    # client_max_window_bits = 12,  # tomcat endpoint does not allow anything other than 15, so let's just choose a mem default towards speed
    deflateFact = _wb_permessage_deflate.ClientPerMessageDeflateFactory(compress_settings={'memLevel': 8, 'level': 7})
    headers_list = None # [('User-Agent', USER_AGENT)]
    if localConnect:
        fHostWSUrl = 'ws://localhost/'
        logging.info('Request connection to : %s', fHostWSUrl)
        socket_filename = f'{TMPDIR}/jboxpy_{str(os.getuid())}.sock'
        try:
            wb = await wb_connect_unix(socket_filename, fHostWSUrl,
                                       max_queue = QUEUE_SIZE, max_size = MSG_SIZE,
                                       ping_interval = PING_INTERVAL, ping_timeout = PING_TIMEOUT,
                                       open_timeout = OPEN_TIMEOUT, close_timeout = CLOSE_TIMEOUT,
                                       user_agent_header = USER_AGENT, extra_headers = headers_list)
        except Exception as e:
            msg = f'Could NOT establish connection (local socket) to {socket_filename}\n{sys.exc_info()}'
            logging.error(msg)
            print_err(f'{msg}\nCheck the logfile: {DEBUG_FILE}')
            return None
    else:
        fHostWSUrl = f'wss://{host}:{port}{path}'  # connection url

        # Check the content of AlienSessionInfo for values of cert and token files
        certs_info = None
        if 'AlienSessionInfo' in globals() and AlienSessionInfo['token_cert'] and AlienSessionInfo['token_key'] and AlienSessionInfo['user_cert'] and AlienSessionInfo['user_key']:
            certs_info = CertsInfo(AlienSessionInfo['user_cert'], AlienSessionInfo['user_key'], AlienSessionInfo['token_cert'], AlienSessionInfo['token_key'])
        else:
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

            if ASYNC_STAGGER_PRESENT:
                # async_stagger requires Python 3.11 or later from v0.4.0 onwards. Please use v0.3.1 for Python 3.6 - 3.10.
                _ASYNC_STAGGER_VER_LIST = version('async_stagger').split('.')
                if int(_ASYNC_STAGGER_VER_LIST[0]) == 0 and int(_ASYNC_STAGGER_VER_LIST[1]) < 4:
                    stagger_args = { "async_dns": True, "resolution_delay": 0.050, "detailed_exceptions": True }  # [skipcq]
                else:
                    my_resolver = functools.partial(async_stagger.resolvers.concurrent_resolver, first_addr_family_count = 3, resolution_delay = 0.050, raise_exc_group = True)
                    stagger_args = { "resolver": my_resolver, "raise_exc_group": True }  # [skipcq]

                socket_endpoint = await async_stagger.create_connected_sock(host, int(port), delay = 0, **stagger_args) # [skipcq]

            else:
                socket_endpoint = socket.create_connection((host, int(port)))

            if init_begin_socket:
                logging.debug('TCP SOCKET DELTA: %s ms', deltat_ms_perf(init_begin_socket))
        except Exception as e:
            msg = f'Could NOT establish connection (TCP socket) to {host}:{port}\n{e!r}'
            logging.error(msg)
            print_err(f'{msg}\nCheck the logfile: {DEBUG_FILE}')
            return None

        if socket_endpoint:
            peer_info = socket_endpoint.getpeername()
            socket_endpoint_addr = None
            socket_endpoint_port = None
            if peer_info:
                socket_endpoint_addr = peer_info[0]
                socket_endpoint_port = peer_info[1]
            else:
                msg = f'Could NOT get peer information for {host}:{port}! This should be not reached, contact support!'
                logging.error(msg)
                print_err(f'{msg}\nCheck the logfile: {DEBUG_FILE}')
                return None
            logging.info('GOT SOCKET TO: %s:%s', socket_endpoint_addr, socket_endpoint_port)
            try:
                init_begin_wb = None
                if DEBUG: init_begin_wb = time.perf_counter()
                wb = await wb_connect(fHostWSUrl, sock = socket_endpoint, server_hostname = host, ssl = ctx, extensions = [deflateFact],
                                      max_queue = QUEUE_SIZE, max_size = MSG_SIZE,
                                      ping_interval = PING_INTERVAL, ping_timeout = PING_TIMEOUT,
                                      open_timeout = OPEN_TIMEOUT, close_timeout = CLOSE_TIMEOUT,
                                      user_agent_header = USER_AGENT, additional_headers = headers_list)

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

    if wb:
        logging.info('CONNECTED: %s:%s', wb.remote_address[0], wb.remote_address[1])
        if init_begin_wb: logging.debug('WEBSOCKET DELTA: %s ms', deltat_ms_perf(init_begin_wb))
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
    result_list = []
    time_begin = time.perf_counter() if DEBUG_TIMING else None
    nr_messages = len(jsonmsg_list)

    # send pipelined messages
    for msg in jsonmsg_list: await wb.send(msg)

    # receive and add to result_list the incoming messages
    for _i in range(nr_messages): result_list.append(await wb.recv())

    if time_begin: logging.debug('>>>__sendmsg time = %s ms', deltat_ms_perf(time_begin))
    return result_list


if __name__ == '__main__':
    print('This file should not be executed!', file = sys.stderr, flush = True)
    sys.exit(95)
