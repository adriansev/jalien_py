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


from .setup_logging import DEBUG, DEBUG_FILE, print_err
from .data_structs import CertsInfo, SSLctxException
from .global_vars import DEBUG_TIMING, TMPDIR, AlienSessionInfo, USER_AGENT, ALIENPY_ADDRESS_FAMILY
from .tools_nowb import deltat_ms_perf
from .connect_ssl import make_connection_ctx
from .async_tools import start_asyncio, syncify


#########################
#   ASYNCIO MECHANICS
#########################
# Let's start the asyncio main thread
start_asyncio()


def wb_process_exception(exp):
    raise exp


async def create_socket(host: str = 'localhost', port: Union[str, int] = '8097', path: str = '/') -> Optional[socket.socket]:
    '''Create a TCP socket to be later upgraded to a WebSocket connection; by default Happy-EyeBalls will be used'''
    logging.info('Request connection to: %s:%s%s', host, port, path)
    socket_endpoint = None

    PROTO = socket.IPPROTO_TCP
    socket.setdefaulttimeout(0.3)  # 300 milisec should be a good timeout for socket creation

    init_begin_socket = None
    if DEBUG:
        logging.debug('TRY ENDPOINT: %s:%s', host, port)
        init_begin_socket = time.perf_counter()

    # https://async-stagger.readthedocs.io/en/latest/reference.html#async_stagger.create_connected_sock
    # AI_* flags --> https://linux.die.net/man/3/getaddrinfo

    if ASYNC_STAGGER_PRESENT:
        # async_stagger requires Python 3.11 or later from v0.4.0 onwards. Please use v0.3.1 for Python 3.6 - 3.10.
        _ASYNC_STAGGER_VER_LIST = version('async_stagger').split('.')
        if int(_ASYNC_STAGGER_VER_LIST[0]) == 0 and int(_ASYNC_STAGGER_VER_LIST[1]) < 4:
            stagger_args = { "async_dns": True, "resolution_delay": 0.050, "detailed_exceptions": True }  # [skipcq]
        else:
            # https://async-stagger.readthedocs.io/en/latest/reference.html#async_stagger.resolvers.concurrent_resolver
            my_resolver = functools.partial(async_stagger.resolvers.concurrent_resolver,
                                            family = ALIENPY_ADDRESS_FAMILY, proto = PROTO,
                                            first_addr_family_count = 3, resolution_delay = 0.05, raise_exc_group = True)
            stagger_args = { "resolver": my_resolver, "raise_exc_group": True }  # [skipcq]

        try:
            socket_endpoint = await async_stagger.create_connected_sock(host, port, family = ALIENPY_ADDRESS_FAMILY, proto = PROTO,
                                                                        delay = 0, **stagger_args) # [skipcq]
        except Exception as e:
            msg = f'Could NOT establish connection (TCP socket)(async_stagger) to {host}:{port}\n{e!r}\n'
            logging.error(msg)
            print_err(f'{msg}\nCheck the logfile: {DEBUG_FILE}')
            return None

    else:
        resolved_addr_list = socket.getaddrinfo(host, port, family = ALIENPY_ADDRESS_FAMILY, proto = PROTO)
        for addr in resolved_addr_list:
            try:
                socket_endpoint = socket.create_connection((addr[-1][0], addr[-1][1]))
                break
            except Exception as e:
                msg = f'Could NOT establish connection (TCP socket)(socket.create_connection) to {host}:{port}\n{e!r}\n'
                logging.error(msg)

    if init_begin_socket:
        logging.debug('TCP SOCKET DELTA: %s ms', deltat_ms_perf(init_begin_socket))

    if not socket_endpoint:
        msg = f'Invalid socket to {host}:{port}!'
        logging.error(msg)
        print_err(f'{msg}\nCheck the logfile: {DEBUG_FILE}')
        return None

    peer_name = socket_endpoint.getpeername()
    logging.info('GOT SOCKET TO: %s:%s', peer_name[0], peer_name[1])
    return socket_endpoint


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

    headers_list = None # [('User-Agent', USER_AGENT)]
    wb = None

    # Connection to a local UNIX socket
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
        return wb

    try:
        ctx = make_connection_ctx(use_usercert)
    except Exception as e:
        msg = 'wb_async::wb_create:: Exception creating SSL context'
        logging.error(msg)
        print_err(f'{msg}\nCheck the logfile: {DEBUG_FILE}')
        logging.exception(f'>>> wb_async::wb_create:: Exception creating SSL context\n{e}\n', stack_info = True)
        raise SSLctxException('wb_async::wb_create SSL ctx not present!!!')

    socket_endpoint = await create_socket(host, port, path)
    if not socket_endpoint:
        return None
    peer_name = socket_endpoint.getpeername()
    socket_endpoint_addr, socket_endpoint_port = peer_name[0], peer_name[1]

    # Compression settings given by https://docs.python.org/3/library/zlib.html#zlib.compressobj
    # client_max_window_bits = 12,  # tomcat endpoint does not allow anything other than 15, so let's just choose a mem default towards speed
    deflateFact = _wb_permessage_deflate.ClientPerMessageDeflateFactory(compress_settings={'memLevel': 8, 'level': 7})

    # we are doing a normal TCP/IP connect
    fHostWSUrl = f'wss://{host}:{port}{path}'  # connection url
    init_begin_wb = None
    if DEBUG: init_begin_wb = time.perf_counter()

    try:
        wb = await wb_connect(fHostWSUrl, sock = socket_endpoint, server_hostname = host, ssl = ctx, extensions = [deflateFact],
                              max_queue = QUEUE_SIZE, max_size = MSG_SIZE,
                              ping_interval = PING_INTERVAL, ping_timeout = PING_TIMEOUT,
                              open_timeout = OPEN_TIMEOUT, close_timeout = CLOSE_TIMEOUT,
                              user_agent_header = USER_AGENT, additional_headers = headers_list)

    except wb_exceptions.InvalidStatus as e:
        msg = f'Invalid status code {e.response.status_code} connecting to {socket_endpoint_addr}:{socket_endpoint_port}'
        print_err(f'{msg}\nCheck the logfile: {DEBUG_FILE}')
        logging.error(f'{msg}\n{e!r}')
        if int(e.response.status_code) == 401:
            print_err('The status code indicate that your certificate is not authorized!!!\nCheck the certificate registration into ALICE VO')
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
    '''Check if websocket is connected with the protocol ping/pong'''
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
    '''Send close to websocket'''
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
