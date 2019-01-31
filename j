#!/bin/env python3

import os
import sys
import signal
import socket
from datetime import datetime
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

# Steering output
json_output = bool(False)
json_meta_output = bool(False)

# other user oriented variables
homedir = os.getenv('HOME', '~')
tmpdir = os.getenv('TMPDIR', '/tmp')
fUser = os.getenv('alien_API_USER', os.getenv('LOGNAME', 'USER'))

# let get the token file name
UID = os.getuid()

# SSL SETTINGS
cert = None
key = None
capath_default = os.getenv('X509_CERT_DIR', '/etc/grid-security/certificates')

# user cert locations
userproxy = '/tmp' + '/x509up_u' + str(UID)

user_globus_dir = homedir + '/.globus'
usercert_default = user_globus_dir + '/usercert.pem'
userkey_default = user_globus_dir + '/userkey.pem'

usercert = os.getenv('X509_USER_CERT', usercert_default)
userkey = os.getenv('X509_USER_KEY', userkey_default)

# token certificate
tokencert_default = '/tmp' + "/tokencert.pem"
tokenkey_default = '/tmp' + "/tokenkey.pem"
tokencert = os.getenv('JALIEN_TOKEN_CERT', tokencert_default)
tokenkey = os.getenv('JALIEN_TOKEN_KEY', tokenkey_default)


# Web socket static variables
fWSPort = 8097  # websocket port
fHostWS = ''
fHostWSUrl = ''

# Websocket endpoint to be used
# server_central = 'alice-jcentral.cern.ch'
server_central = '137.138.99.145'
ws_path = '/websocket/json'
default_server = server_central

# jalien_py internal vars
fGridHome = str('')
currentdir = ''
commandlist = ''
site = ''


def signal_handler(sig, frame):
    print('\nExit')
    sys.exit(0)


def exit_message():
    print('\nExit')
    sys.exit(0)


def IsValidCert(fname):
    try:
        with open(fname) as f:
            cert_bytes = f.read()
    except Exception:
        return False

    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_bytes)
    x509_notafter = x509.get_notAfter()
    utc_time = datetime.strptime(x509_notafter.decode("utf-8"), "%Y%m%d%H%M%SZ")
    time_notafter = int((utc_time - datetime(1970, 1, 1)).total_seconds())
    time_current  = int(datetime.now().timestamp())
    time_remaining = time_notafter - time_current
    if (time_remaining > 300):
        return True
    else:
        return False


def create_ssl_context():
    global cert, key
    # ssl related options
    if IsValidCert(tokencert):
        cert = tokencert
        key  = tokenkey
    else:
        cert = usercert
        key = userkey

    ctx = ssl.SSLContext()
    verify_mode = ssl.CERT_REQUIRED  # CERT_NONE, CERT_OPTIONAL, CERT_REQUIRED
    ctx.verify_mode = verify_mode
    ctx.check_hostname = False
    ctx.load_verify_locations(capath=capath_default)
    ctx.load_verify_locations(capath=user_globus_dir)
    ctx.load_cert_chain(certfile=cert, keyfile=key)
    return ctx


def CreateJsonCommand(command, options=[]):
    cmd_dict = {"command": command, "options": options}
    jcmd = json.dumps(cmd_dict)
    jcmd.encode('ascii', 'ignore')
    return jcmd


def ProcessReceivedMessage(message=''):
    global json_output, json_meta_output
    if not message: return
    message.encode('ascii', 'ignore')
    json_dict = json.loads(message)
    if not json_meta_output:
        if 'metadata' in json_dict:
            del json_dict['metadata']

    if json_output:
        print(json.dumps(json_dict, sort_keys=True, indent=4))
    else:
        for item in json_dict['results']:
            print(item['message'])


async def JAlienConnect(jsoncmd = ''):
    global websocket, fHostWS, fHostWSUrl, ws_path, currentdir, commandlist
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

    script_name = sys.argv[0]
    if '_json' in script_name: json_output = bool(True)
    if '_json_all' in script_name: json_meta_output = bool(True)

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



