#!/bin/env python3

import os
import ssl
import pathlib
import socket
import asyncio
import enum
import json
from enum import Enum

# websocket component for python
import websockets


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

default_server = 'alice-jcentral.cern.ch'
local_server = 'localhost'

fPort = 8098
fWSPort = 8097  # websocket port
fHost = 'wss://' + local_server + ':' + fWSPort
sUsercert = ''  # location of user certificate
sUserkey = ''   # location of user private key
ws_path = "/websocket/json"


# Certificats and authentication
# Load certificate
homedir = os.getenv('HOME', '~')      # local home directory
tmpdir = os.getenv('TMPDIR', '/tmp')  # tmp directory

tokencert = tmpdir + "/tokencert.pem"
tokenkey = tmpdir + "/tokenkey.pem"

# if JALIEN_TOKEN_CERT is not defined then use the generic tmp one
tokencertpath = os.getenv('JALIEN_TOKEN_CERT', tokencert)
# if JALIEN_TOKEN_KEY is not defined then use the generic tmp one
tokenkeypath = os.getenv('JALIEN_TOKEN_KEY', tokenkey)

#        std::string usercert = sUsercert.Data()[0] != '\0' ? sUsercert.Data() : homedir + "/.globus/usercert.pem";
#        std::string userkey = sUserkey.Data()[0] != '\0' ? sUserkey.Data() : homedir + "/.globus/userkey.pem";
#        std::string usercertpath = std::getenv("X509_USER_CERT") ? : usercert.c_str();
#        std::string userkeypath = std::getenv("X509_USER_KEY") ? : userkey.c_str();





# Define SSL options and context
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















