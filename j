#!/bin/env python3

import os
import ssl
import asyncio
import socket
import websockets
# import websocket
import pathlib
from enum import Enum


class CatalogType(Enum):
    kFailed = -1
    kFile = 0
    kDirectory = 1
    kCollection = 2


class OutType(Enum):
    kSTDOUT = 0
    kSTDERR = 1
    kOUTPUT = 2
    kENVIR = 3


# let's just use the same names as in TJAlien.h

fWSPort = 8097  # websocket port

server_central = 'alice-jcentral.cern.ch'
server_local = 'localhost'
default_server = ''

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
result = sock.connect_ex(('127.0.0.1',fWSPort))
if result == 0:
    default_server = server_local
else:
    default_server = server_central

ws_path = "/websocket/json"
fHost = 'wss://' + default_server + ':' + fWSPort
fHostUrl = fHost + ws_path





sUsercert = ''  # location of user certificate
sUserkey = ''   # location of user private key

# Load certificate
homedir = os.getenv('HOME', '~')      # local home directory
tmpdir = os.getenv('TMPDIR', '/tmp')  # tmp directory

tokencert = tmpdir + "/tokencert.pem"
tokenkey = tmpdir + "/tokenkey.pem"

tokencertpath = os.getenv('JALIEN_TOKEN_CERT', tokencert)  # if JALIEN_TOKEN_CERT is not defined then use the generic tmp one
tokenkeypath = os.getenv('JALIEN_TOKEN_KEY', tokenkey)     # if JALIEN_TOKEN_KEY is not defined then use the generic tmp one


ssl = ssl.create_default_context()
ssl.check_hostname = False
ssl.verify_mode = ssl.CERT_REQUIRED
# ssl.verify_mode = ssl.CERT_OPTIONAL
# ssl.verify_mode = ssl.CERT_NONE
ssl.load_cert_chain(tokencertpath, tokenkeypath)

# ______________________________________________________________________________
@asyncio.coroutine
def MakeWebsocketConnection(certpath, keypath):
    # Create the connection to JBox using the parameters read from the token
    # returns true if the connection was established
    print("JAlien :: Connecting to Server {fHost:s}".format(fHost))
    url = fHost + ws_path
    ws = yield from websockets.connect(url, ssl=ssl)















