#!/bin/env python3

import os
import sys
import signal
import ssl
import socket
import pathlib
import json
import logging
import pprint
import inspect
from enum import Enum
from optparse import OptionParser
import asyncio
import websockets
# import websockets.speedups


pp = pprint.PrettyPrinter(indent=4)

# declare the token variables
fHost = str('')
fPort = int(0)
fUser = str('')
fGridHome = str('')
fPasswd = str('')
fDebug = int(0)
fPID = int(0)
fWSPort = 8097  # websocket port

# other user oriented variables
homedir = os.getenv('HOME', '~')
tmpdir = os.getenv('TMPDIR', '/tmp')
fUser = os.getenv('alien_API_USER', os.getenv('LOGNAME', 'USER'))

j_trusts_dir = homedir + '/.j/trusts/'
j_capath = os.getenv('X509_CERT_DIR', j_trusts_dir)

# let get the token file name
UID = os.getuid()
token_filename = '/tmp/jclient_token_' + str(UID)


# user cert locations
user_globus = homedir + '/.globus'
usercert = user_globus + '/usercert.pem'
userkey = user_globus + '/userkey.pem'
user_proxy = '/tmp' + '/x509up_u' + str(UID)

usercertpath = os.getenv('X509_USER_CERT', usercert)
userkeypath = os.getenv('X509_USER_KEY', userkey)

# token certificate
tokencert = '/tmp' + "/tokencert.pem"
tokencertpath = os.getenv('JALIEN_TOKEN_CERT', tokencert)

tokenkey = '/tmp' + "/tokenkey.pem"
tokenkeypath = os.getenv('JALIEN_TOKEN_KEY', tokenkey)

tokenlock = tmpdir + '/jalien_token.lock'

cert = None
key = None

# Web socket static variables
# websocket = None  # global websocket name
fHostWS = ''
fHostWSUrl = ''

# Websocket endpoint to be used
# server_central = 'alice-jcentral.cern.ch'
server_central = '137.138.99.145'
ws_path = '/websocket/json'

# server_central = 'demos.kaazing.com'
# ws_path = '/echo'

server_local = '127.0.0.1'
default_server = server_local


def signal_handler(sig, frame):
    print('\nYou pressed Ctrl+C!')
    sys.exit(0)


def token_parse(token_file):
    global fHost, fPort, fUser, fGridHome, fPasswd, fDebug, fPID, fWSPort
    with open(token_file) as myfile:
        for line in myfile:
            name, var = line.partition("=")[::2]
            if (name == "Host"): fHost = str(var.strip())
            if (name == "Port"): fPort = int(var.strip())
            if (name == "User"): fUser = str(var.strip())
            if (name == "Home"): fGridHome = str(var.strip())
            if (name == "Passwd"): fPasswd = str(var.strip())
            if (name == "Debug"): fDebug = int(var.strip())
            if (name == "PID"): fPID = int(var.strip())
            if (name == "WSPort"): fWSPort = int(var.strip())


def ws_endpoint_detect():
    global fHost, fWSPort, token_filename
    global default_server, server_local, server_central
    global cert, key
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex((server_local, fWSPort))
    if result == 0:
        default_server = server_local
        cert = tokencertpath
        key = tokenkeypath
        token_parse(token_filename)
    else:
        cert = usercertpath
        key = userkeypath
        default_server = server_central
        fHost = default_server
        fPort = 8098
        fWSPort = 8097
        fPasswd = ''


def create_ssl_context():
    global cert, key
    # ssl related options
    ctx = ssl.SSLContext()
    verify_mode = ssl.CERT_REQUIRED  # CERT_NONE, CERT_OPTIONAL, CERT_REQUIRED
    ctx.verify_mode = verify_mode
    ctx.check_hostname = False
    ctx.load_verify_locations(capath='/etc/grid-security/certificates/')
    ctx.load_verify_locations(capath=user_globus)
    alienca = user_globus + '/AliEn-CA.pem'
    ctx.load_verify_locations(cafile=alienca)
    ctx.load_verify_locations(cafile=user_proxy)
    ctx.load_cert_chain(certfile=cert, keyfile=key)
#    ctx.load_cert_chain(certfile=user_proxy, keyfile=key)
    return ctx


def CreateJsonCommand(command, options=[]):
    cmd_dict = {"command": command, "options": options}
    jcmd = json.dumps(cmd_dict)
    jcmd.encode('ascii', 'ignore')
    return jcmd


def ProcessReceivedMessage(message=''):
    print("Received< ", str(message))


async def Command(cmd, args=[]):
    global websocket, fHostWS, fHostWSUrl, ws_path
    ws_endpoint_detect()
    # fHostWS = 'wss://' + default_server + ':' + str(fWSPort)
    fHostWS = 'ws://' + default_server
    fHostWSUrl = fHostWS + ws_path
    print("Prepare to connect : ", fHostWSUrl)
    if str(fHostWSUrl).startswith("wss://"):
        ssl_context = create_ssl_context()
    else:
        ssl_context = None
    async with websockets.connect(fHostWSUrl, ssl=ssl_context) as websocket:
        json_cmd = CreateJsonCommand(cmd, args)
        # pp.pprint(fHostWSUrl)
        # pp.pprint(json_cmd)
        await websocket.send(json_cmd)
        print(f"Sent> {json_cmd}")
        # result = await websocket.recv()
        # print("Received< ", result)


async def Shell():
    global websocket, fHostWS, fHostWSUrl, ws_path
    ws_endpoint_detect()
    fHostWS = 'wss://' + default_server + ':' + str(fWSPort)
    # fHostWS = 'wss://' + default_server
    fHostWSUrl = fHostWS + ws_path
    print("Prepare to connect : ", fHostWSUrl)
    if str(fHostWSUrl).startswith("wss://"):
        ssl_context = create_ssl_context()
    else:
        ssl_context = None
    async with websockets.connect(fHostWSUrl, ssl=ssl_context) as websocket:
        while True:
            signal.signal(signal.SIGINT, signal_handler)
            INPUT = input("JalienShPy Cmd: ")
            input_json = CreateJsonCommand(INPUT)
            await websocket.send(input_json)
            # pp.pprint(websocket.__dict__.keys())
            result = await websocket.recv()
            result.encode('ascii', 'ignore')
            print("JalienShPy Ans: ", result)


async def ProcessMessages():
    global websocket
    async for message in websocket:
        await ProcessReceivedMessage(message)


if __name__ == '__main__':
    # Let's start the connection
    logger = logging.getLogger('websockets')
    logger.setLevel(logging.DEBUG)
    logger.addHandler(logging.StreamHandler())

    # ProcessMessages()
    # asyncio.get_event_loop().run_until_complete(Command(cmd='pwd'))
    asyncio.get_event_loop().run_until_complete(Shell())



