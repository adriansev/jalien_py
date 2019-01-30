#!/bin/env python3

import os
import sys
import signal
import socket
import ssl
import OpenSSL
import json
import logging
from pathlib import Path
from enum import Enum
import asyncio
import websockets
# import websockets.speedups

DEBUG = os.getenv('JALIENPY_DEBUG', '')

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
userproxy = '/tmp' + '/x509up_u' + str(UID)

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

# jalien_py internal vars
currentdir = ''
commandlist = ''
site = ''

def signal_handler(sig, frame):
    print('\nExit')
    sys.exit(0)


def exit_message():
    print('\nExit')
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
    #ctx.load_cert_chain(certfile=cert, keyfile=key)
    #ctx.load_cert_chain(certfile=userproxy)
    ctx.load_cert_chain(certfile=tokencert, keyfile=tokenkey)

    return ctx


def CreateJsonCommand(command, options=[]):
    cmd_dict = {"command": command, "options": options}
    jcmd = json.dumps(cmd_dict)
    jcmd.encode('ascii', 'ignore')
    return jcmd


def ProcessReceivedMessage(message=''):
    if not message: return
    message.encode('ascii', 'ignore')
    json_dict = json.loads(message)
    if 'metadata' in json_dict:
        del json_dict['metadata']
    print(json.dumps(json_dict, sort_keys=True, indent=4))



async def JAlienConnect(jsoncmd = ''):
    global websocket, fHostWS, fHostWSUrl, ws_path, currentdir, commandlist
    ws_endpoint_detect()
    fHostWS = 'wss://' + default_server + ':' + str(fWSPort)
    fHostWSUrl = fHostWS + ws_path
    if str(fHostWSUrl).startswith("wss://"):
        ssl_context = create_ssl_context()
    else:
        ssl_context = None

    if DEBUG: print("Connecting to : ", fHostWSUrl)
    async with websockets.connect(fHostWSUrl, ssl=ssl_context) as websocket:
        tokencert_content = ''
        #    try:
        #        tokencert_content = json_dict["results"]
        #        print(type(tokencert_content))
        #    except KeyError:
        #        tokencert_content = ''
        #    print(tokencert_content)
        #    json_dict_token = { tokencert: json_dict[tokencert] for tokencert in 'tokencert' }
        #print("JalienShPy Ans: ", message)

        if not commandlist:
            # get the command list to check validity of commands
            await websocket.send(CreateJsonCommand('commandlist'))
            result = await websocket.recv()
            result = result.lstrip()
            json_dict_list = json.loads("[{}]".format(result.replace('}{', '},{')))
            json_dict = json_dict_list[-1]
            commandlist = json_dict["results"][0]["message"]

        # command mode
        if jsoncmd:
            signal.signal(signal.SIGINT, signal_handler)
            await websocket.send(jsoncmd)
            result = await websocket.recv()
            ProcessReceivedMessage(result)

        # interactive/shell mode
        else:
            while True:
                signal.signal(signal.SIGINT, signal_handler)
                # get the current directory, command list is already present
                await websocket.send(CreateJsonCommand('commandlist'))
                result = await websocket.recv()
                result = result.lstrip()
                json_dict_list = json.loads("[{}]".format(result.replace('}{', '},{')))
                json_dict = json_dict_list[-1]
                currentdir = json_dict["metadata"]["currentdir"]
                site = json_dict["metadata"]["site"]

                INPUT =''
                try:
                    INPUT = input(f"jsh:{site}: {currentdir} > ")
                except EOFError:
                    exit_message()

                if not INPUT: continue
                input_list = INPUT.split()
                cmd = input_list[0]
                input_list.pop(0)
                jsoncmd = CreateJsonCommand(cmd, input_list)
                if DEBUG: print(jsoncmd)
                await websocket.send(jsoncmd)
                result = await websocket.recv()
                result = result.lstrip()
                json_dict_list = json.loads("[{}]".format(result.replace('}{', '},{')))
                json_dict = json_dict_list[-1]
                result = json.dumps(json_dict)
                ProcessReceivedMessage(result)


if __name__ == '__main__':
    # Let's start the connection
    logger = logging.getLogger('websockets')
    logger.setLevel(logging.ERROR)
    # logger.setLevel(logging.DEBUG)
    logger.addHandler(logging.StreamHandler())

    cmd=''
    args=sys.argv

    if len(args) > 1 :
        args.pop(0)  # remove script name from arg list
        cmd = args[0]
        args.pop(0)  # ALSO remove command from arg list - remains only command args or empty

    if cmd:
        jsoncmd = CreateJsonCommand(cmd, args)
        if DEBUG: print(jsoncmd)
        asyncio.get_event_loop().run_until_complete(JAlienConnect(jsoncmd))
    else:
        asyncio.get_event_loop().run_until_complete(JAlienConnect())



