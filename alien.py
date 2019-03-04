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
getToken = bool(False)
tokencert_default = tmpdir + "/tokencert.pem"
tokenkey_default = tmpdir + "/tokenkey.pem"
tokencert = os.getenv('JALIEN_TOKEN_CERT', tokencert_default)
tokenkey = os.getenv('JALIEN_TOKEN_KEY', tokenkey_default)

# Web socket static variables
fWSPort = 8097  # websocket port
fHostWS = ''
fHostWSUrl = ''

# Websocket endpoint to be used
server_central = 'alice-jcentral.cern.ch'
ws_path = '/websocket/json'
default_server = server_central

# jalien_py internal vars
fGridHome = str('')
currentdir = ''
commandlist = ''
site = ''
user = ''
error = ''
exitcode = ''

# current command in execution
ccmd = ''

# command history
cmd_hist = []


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

    try:
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_bytes)
    except Exception:
        return False

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
    global json_output, json_meta_output, getToken, currentdir, site, user, ccmd, error, exitcode
    if not message: return
    message.encode('ascii', 'ignore')
    json_dict = json.loads(message)
    currentdir = json_dict["metadata"]["currentdir"]
    site = json_dict["metadata"]["site"]
    user = json_dict["metadata"]["user"]

    # COMMENTED FOR NOW AS NOT ALL CMDS RETURN error AND exitcode
    #error = json_dict["metadata"]["error"]
    #exitcode = json_dict["metadata"]["exitcode"]

    # Processing of token command
    if getToken:
        tokencert_content = json_dict['results'][0]["tokencert"]
        if os.path.isfile(tokencert):
            os.chmod(tokencert, 0o700)
        with open(tokencert, "w") as tcert:
            print(f"{tokencert_content}", file=tcert)
            os.chmod(tokencert, 0o400)

        tokenkey_content = json_dict['results'][0]["tokenkey"]
        if os.path.isfile(tokenkey):
            os.chmod(tokenkey, 0o700)
        with open(tokenkey, "w") as tkey:
            print(f"{tokenkey_content}", file=tkey)
            os.chmod(tokenkey, 0o400)
        getToken = bool(False)
        ccmd = ''
        return  # after writing the token files we finished with the message

    if not json_meta_output:
        if 'metadata' in json_dict:
            del json_dict['metadata']

    if json_output:
        print(json.dumps(json_dict, sort_keys=True, indent=4))
    else:
        for item in json_dict['results']:
            print(item['message'])

    # reset the current executed command, the received message was processed
    ccmd = ''


async def JAlienConnect(jsoncmd = ''):
    global websocket, fHostWS, fHostWSUrl, ws_path, currentdir, site, commandlist, getToken, ccmd
    fHostWS = 'wss://' + default_server + ':' + str(fWSPort)
    fHostWSUrl = fHostWS + ws_path
    if str(fHostWSUrl).startswith("wss://"):
        ssl_context = create_ssl_context()
    else:
        ssl_context = None

    if DEBUG: print("Connecting to : ", fHostWSUrl)
    async with websockets.connect(fHostWSUrl, ssl=ssl_context, max_queue = 4, max_size = 16*1024*1024) as websocket:
        if cert == usercert:
            getToken = bool(True)
            await websocket.send(CreateJsonCommand('token'))
            result = await websocket.recv()
            ProcessReceivedMessage(result)

        if not commandlist:
            # get the command list to check validity of commands
            await websocket.send(CreateJsonCommand('commandlist'))
            result = await websocket.recv()
            result = result.lstrip()
            json_dict_list = json.loads("[{}]".format(result.replace('}{', '},{')))
            json_dict = json_dict_list[-1]
            # first executed commands, let's initialize the following (will re-read at each ProcessReceivedMessage)
            commandlist = json_dict["results"][0]["message"]
            currentdir = json_dict["metadata"]["currentdir"]
            site = json_dict["metadata"]["site"]
            user = json_dict["metadata"]["user"]

        if jsoncmd:  # command mode
            ccmd = jsoncmd
            signal.signal(signal.SIGINT, signal_handler)
            await websocket.send(jsoncmd)
            result = await websocket.recv()
            ProcessReceivedMessage(result)
        else:        # interactive/shell mode
            while True:
                signal.signal(signal.SIGINT, signal_handler)
                INPUT = ''
                try:
                    INPUT = input(f"jsh:{site}: {currentdir} > ")
                except EOFError:
                    exit_message()

                if not INPUT: continue
                input_list = INPUT.split()
                cmd = input_list[0]
                if (cmd == "?") or (cmd == "help"):
                    if len(input_list) > 1:
                        cmdhelp = input_list[1]
                        if cmdhelp in commandlist:
                            input_list.clear()
                            cmd = cmdhelp
                            input_list.append(cmd)
                            input_list.append('-h')
                    else:
                        print(commandlist)
                        continue

                input_list.pop(0)
                jsoncmd = CreateJsonCommand(cmd, input_list)
                ccmd = jsoncmd
                cmd_hist.append(jsoncmd)
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

    cmd = ''
    args = sys.argv

    if len(args) > 1:
        args.pop(0)  # remove script name from arg list
        cmd = args[0]
        args.pop(0)  # ALSO remove command from arg list - remains only command args or empty

    if cmd:
        jsoncmd = CreateJsonCommand(cmd, args)
        if DEBUG: print(jsoncmd)
        asyncio.get_event_loop().run_until_complete(JAlienConnect(jsoncmd))
    else:
        asyncio.get_event_loop().run_until_complete(JAlienConnect())



