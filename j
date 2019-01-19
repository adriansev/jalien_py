#!/bin/env python3

import os
import sys
import ssl
import socket
import pathlib
from enum import Enum
from optparse import OptionParser
from twisted.python import log
from twisted.internet import reactor, ssl
from autobahn.twisted.websocket import WebSocketClientFactory, \
    WebSocketClientProtocol, \
    connectWS


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


class JalienProtocol(WebSocketClientProtocol):
    def ConnectionMessage(self):
        self.sendMessage("Jalien connection open".encode('utf8'))

    def onOpen(self):
        self.ConnectionMessage()

    def onMessage(self, payload, isBinary):
        if isBinary:
            print("Binary message received: {0} bytes".format(len(payload)))
        else:
            print("Text message received: {0}".format(payload.decode('utf8')))


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
usercert = homedir + '/.globus/usercert.pem'
usercertpath = os.getenv('X509_USER_CERT', usercert)

userkey = homedir + '/.globus/userkey.pem'
userkeypath = os.getenv('X509_USER_KEY', userkey)

# token certificate
tokencert = tmpdir + "/tokencert.pem"
tokencertpath = os.getenv('JALIEN_TOKEN_CERT', tokencert)

tokenkey = tmpdir + "/tokenkey.pem"
tokenkeypath = os.getenv('JALIEN_TOKEN_KEY', tokenkey)

tokenlock = tmpdir + '/jalien_token.lock'

# Web socket static variables
ws_path = '/websocket/json'
fHostUrl = ''

# Websocket endpoint to be used
server_central = 'alice-jcentral.cern.ch'
server_local = 'localhost'
default_server = server_local


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
    token_parse(token_filename)
    global fHost, fHostUrl
    global default_server, server_local, server_central, ws_path
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex(('127.0.0.1', fPort))
    port = int(0)
    if result == 0:
        default_server = server_local
        port = fPort
    else:
        default_server = server_central
        port = fWSPort

    fHost = 'wss://' + default_server + ':' + str(port)
    fHostUrl = fHost + ws_path


def MakeWebsocketConnection(certpath, keypath):
    ws_endpoint_detect()
    factory = WebSocketClientFactory(fHost)
    factory.protocol = JalienProtocol

    if factory.isSecure:
        ctx_factory = ssl.ClientContextFactory()
        ctx = ctx_factory.getContext()
        ctx.check_hostname = False
        ctx.load_client_ca(certpath)
    else:
        ctx_factory = None

    connectWS(factory, ctx_factory)
    reactor.run()


def ConnectJBox(certpath, keypath):
    token_parse(token_filename)
    global fHost, fPort, fWSPort, fPasswd
    if (fHost == ''):  # if there is no connection
        fHost = default_server
        fPort = 8098
        fWSPort = 8097
        fPasswd = ''
    MakeWebsocketConnection(certpath, keypath)






# CreateJsonCommand(TString *command, TList *opt)
if __name__ == '__main__':

# Let's start the connection
    log.startLogging(sys.stdout)

    token_parse(token_filename)
    if (fHost == ''):  # if there is no connection
        fHost = default_server
        fPort = 8098
        fWSPort = 8097
        fPasswd = ''

    ws_endpoint_detect()
    factory = WebSocketClientFactory(fHost)
    factory.protocol = JalienProtocol

    if factory.isSecure:
        ctx_factory = ssl.ClientContextFactory()
        ctx = ctx_factory.getContext()
        ctx.check_hostname = False
        ctx.load_client_ca(usercertpath)
    else:
        ctx_factory = None

    connectWS(factory, ctx_factory)
    reactor.run()



#    ConnectJBox(usercertpath, userkeypath)



#sys.exit()




















