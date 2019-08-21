#!/usr/bin/env python3

import sys
import os
import re
import subprocess
import signal
import json
import logging
import ssl
import OpenSSL
import readline
import shlex
import argparse
import tempfile
import cmd2
from datetime import datetime
from pathlib import Path
from enum import Enum
from urllib.parse import urlparse
import asyncio
import websockets
# import websockets.speedups


if sys.version_info[0] != 3 or sys.version_info[1] < 6:
    print("This script requires a minimum of Python version 3.6")
    sys.exit(1)

# environment debug variable
DEBUG = os.getenv('ALIENPY_DEBUG', '')
DEBUG_WS = os.getenv('ALIENPY_DEBUG_WS', '')
XRDDEBUG = os.getenv('ALIENPY_XRDDEBUG', '')
TIME_CONNECT = os.getenv('ALIENPY_TIMECONNECT', '')
CMD_TESTING = os.getenv('ALIENPY_NEWSHELL', '')
USE_JBOX = os.getenv('ALIENPY_JBOX', '')

# Steering output
json_output = bool(False)
json_meta_output = bool(False)

# other user oriented variables
homedir = Path.home().as_posix()
tmpdir = os.getenv('TMPDIR', '/tmp')
fUser = os.getenv('alien_API_USER', os.getenv('LOGNAME', 'USER'))

# SSL SETTINGS
cert = None
key = None
capath_default = os.getenv('X509_CERT_DIR', '/etc/grid-security/certificates')

user_globus_dir = homedir + '/.globus'
usercert_default = user_globus_dir + '/usercert.pem'
userkey_default = user_globus_dir + '/userkey.pem'

usercert = os.getenv('X509_USER_CERT', usercert_default)
userkey = os.getenv('X509_USER_KEY', userkey_default)

# token certificate
UID = os.getuid()
tokencert_default = tmpdir + "/tokencert_" + str(UID) + ".pem"
tokenkey_default = tmpdir + "/tokenkey_" + str(UID) + ".pem"
tokencert = os.getenv('JALIEN_TOKEN_CERT', tokencert_default)
tokenkey = os.getenv('JALIEN_TOKEN_KEY', tokenkey_default)

# Web socket static variables
websocket = None  # global websocket

if USE_JBOX:
    jalien_server = 'localhost'
else:
    jalien_server = 'alice-jcentral.cern.ch'

jalien_websocket_port = 8097  # websocket port
jalien_websocket_path = '/websocket/json'

wb_protol = 'wss://'
fHostWSUrl = wb_protol + jalien_server + ':' + str(jalien_websocket_port) + jalien_websocket_path

# jalien_py internal vars
alienHome = ''
currentdir = ''
commandlist = ''
user = ''
error = ''
exitcode = ''

ccmd = ''  # current command in execution
cmd_hist = []  # command history

local_file_system = True
cassandra_error = 'This command can only be run on jSh, use the "switch" command to change shell.'
ls_list = []

# xrdcp generic parameters (used by ALICE tests)
FirstConnectMaxCnt = 2
TransactionTimeout = 60
RequestTimeout = 60
ReadCacheSize = 0
xrdcp_args = f"&FirstConnectMaxCnt={FirstConnectMaxCnt}&TransactionTimeout={TransactionTimeout}&RequestTimeout={RequestTimeout}&ReadCacheSize={ReadCacheSize}"

# XRootD copy parameters
# inittimeout: copy initialization timeout(int)
# tpctimeout: timeout for a third-party copy to finish(int)
# coerce: ignore file usage rules, i.e. apply `FORCE` flag to open() (bool)
# :param checksummode: checksum mode to be used #:type    checksummode: string
# :param checksumtype: type of the checksum to be computed  #:type    checksumtype: string
# :param checksumpreset: pre-set checksum instead of computing it #:type  checksumpreset: string
hashtype = str('md5')
batch = int(1)   # from a list of copy jobs, start <batch> number of downloads
sources = int(1)  # max number of download sources
chunks = int(1)  # number of chunks that should be requested in parallel
chunksize = int(4194304)  # chunk size for remote transfers
makedir = bool(True)  # create the parent directories when creating a file
overwrite = bool(False)  # overwrite target if it exists
tpc = str('')  # do TPC if possible ("first")
posc = bool(True)  # persist on successful close; Files are automatically deleted should they not be successfully closed.


def xrdcp_help():
    print('''at least 2 arguments are needed : src dst
the command is of the form of (with the strict order of arguments):
cp args src dst
where src|dst are local files if prefixed with file:// or grid files otherwise
after each src,dst can be added comma separated arguments like: disk:N,SE1,SE2,!SE3
args are the following :
-h : print help
-f : replace any existing output file
-P : enable persist on successful close semantic
-tpc : enable TPC mode ("first" option; "only" option not implemented)
-y <nr_sources> : use up to the number of sources specified in parallel
-S <parallel nr chunks> : copy using the specified number of TCP connections
-chksz <bytes> : chunk size (bytes)
-T <nr_copy_jobs> : number of parralel copy jobs from a set (for recursive copy)

for the recursive copy of directories the following options (of the find command) can be used:
-select <pattern> : select only these files (AliEn find semantics) to be copied; defaults to all "."
-parent <parent depth> : in destination use this <parent depth> to add to destination ; defaults to 0
-a : copy also the hidden files .* (for recursive copy)
-j <queue_id> : select only the files created by the job with <queue_id>  (for recursive copy)
-l <count> : copy only <count> nr of files (for recursive copy)
-o <offset> : skip first <offset> files found in the src directory (for recursive copy)
''')


async def getEnvelope(lfn_list = [], specs = [], isWrite = bool(False)):
    global websocket
    access_list = []
    if not lfn_list: return access_list
    access_type = 'read'
    if isWrite: access_type = 'write'
    for lfn in lfn_list:
        get_envelope_arg_list = [access_type, lfn]
        if specs: get_envelope_arg_list.append(str(",".join(specs)))
        await websocket.send(CreateJsonCommand('access', get_envelope_arg_list))
        result = await websocket.recv()
        access_list.append({"lfn": lfn, "answer": result})
    return access_list


def setDst(file = '', parent = 0):
    p = Path(file)
    filename = p.parts[0]
    if parent >= (len(p.parts) - 1): parent = len(p.parts) - 1 - 1
    basedir = p.parents[parent].as_posix()
    if basedir == '/':
        return file
    else:
        return p.as_posix().replace(p.parents[parent].as_posix(), '', 1)


async def ProcessXrootdCp(xrd_copy_command):
    global websocket, currentdir, sources, chunks, chunksize, mkdir, overwrite, posc, batch, tpc
    if len(xrd_copy_command) < 2 or xrd_copy_command == '-h':
        xrdcp_help()
        return

    isSrcLocal = bool(False)
    isDstLocal = bool(False)
    isSrcDir = bool(False)
    isDstDir = bool(False)
    isDownload = bool(True)
    file_name = ''

    cwd_grid_path = Path(currentdir)
    home_grid_path = Path(alienHome)

    if '-f' in xrd_copy_command:
        overwrite = True
        xrd_copy_command.remove('-f')

    if '-P' in xrd_copy_command:
        posc = True
        xrd_copy_command.remove('-P')

    if '-tpc' in xrd_copy_command:
        tpc = str('first')
        xrd_copy_command.remove('-tpc')

    if '-y' in xrd_copy_command:
        y_idx = xrd_copy_command.index('-y')
        sources = xrd_copy_command.pop(y_idx + 1)
        xrd_copy_command.pop(y_idx)

    if '-S' in xrd_copy_command:
        s_idx = xrd_copy_command.index('-S')
        chunks = xrd_copy_command.pop(s_idx + 1)
        xrd_copy_command.pop(y_idx)

    if '-T' in xrd_copy_command:
        batch_idx = xrd_copy_command.index('-T')
        batch = xrd_copy_command.pop(batch_idx + 1)
        xrd_copy_command.pop(batch_idx)

    if '-chksz' in xrd_copy_command:
        chksz_idx = xrd_copy_command.index('-chksz')
        chunksize = xrd_copy_command.pop(chksz_idx + 1)
        xrd_copy_command.pop(chksz_idx)

    # find options for recursive copy of directories
    find_args = []
    parent = int(0)
    if '-parent' in xrd_copy_command:
        parent_idx = xrd_copy_command.index('-parent')
        parent = int(xrd_copy_command.pop(parent_idx + 1))
        xrd_copy_command.pop(parent_idx)

    if '-a' in xrd_copy_command:
        find_args.append('-a')
        xrd_copy_command.remove('-a')

    if '-j' in xrd_copy_command:
        qid_idx = xrd_copy_command.index('-j')
        find_args.append('-j')
        find_args.append(xrd_copy_command.pop(qid_idx + 1))
        xrd_copy_command.pop(qid_idx)

    if '-l' in xrd_copy_command:
        return_nr_idx = xrd_copy_command.index('-l')
        find_args.append('-l')
        find_args.append(xrd_copy_command.pop(return_nr_idx + 1))
        xrd_copy_command.pop(return_nr_idx)

    if '-o' in xrd_copy_command:
        skip_nr_idx = xrd_copy_command.index('-o')
        find_args.append('-o')
        find_args.append(xrd_copy_command.pop(skip_nr_idx + 1))
        xrd_copy_command.pop(skip_nr_idx)

    pattern = '.*'  # default pattern
    if '-select' in xrd_copy_command:
        select_idx = xrd_copy_command.index('-select')
        pattern = xrd_copy_command.pop(select_idx + 1)
        xrd_copy_command.pop(select_idx)

    # list of src files and coresponding dst names
    src_filelist = []
    dst_filelist = []

    # clean up and prepare the paths to be used in the xrdcp command
    src = ''
    src_specs_remotes = None  # let's record specifications like disk=3,SE1,!SE2
    if xrd_copy_command[-2].startswith('file://'):  # second to last argument (should be the source)
        isSrcLocal = True
        isDownload = False
        src = xrd_copy_command[-2].replace("file://", "")
        src = re.sub(r"^\~", Path.home().as_posix() + "/", src)
        src = re.sub(r"^\/*\.{2}", Path.cwd().parents[0].as_posix() + "/", src)
        src = re.sub(r"^\/*\.{1}", Path.cwd().as_posix() + "/", src)
        if not src.startswith('/'): src = Path.cwd().as_posix() + "/" + src
        src = re.sub(r"\/{2,}", "/", src)
        src_type = pathtype_local(src)
        if src_type == 'd': isSrcDir = bool(True)
    else:
        src = xrd_copy_command[-2]
        src = re.sub(r"\/*\%ALIEN", alienHome, src)
        src = re.sub(r"^\/*\.{2}", cwd_grid_path.parents[0].as_posix() + "/", src)
        src = re.sub(r"^\/*\.{1}", cwd_grid_path.as_posix() + "/", src)
        if not src.startswith('/'): src = currentdir + src
        src_specs_remotes = src.split(",")
        src = src_specs_remotes.pop(0)  # first item is the file path, let's remove it; it remains disk specifications
        src = re.sub(r"\/{2,}", "/", src)
        src_type = await pathtype_grid(src)
        if src_type == 'd': isSrcDir = bool(True)

    dst = ''
    dst_specs_remotes = None  # let's record specifications like disk=3,SE1,!SE2
    if xrd_copy_command[-1].startswith('file://'):  # last argument (should be the destination)
        isDstLocal = True
        dst = xrd_copy_command[-1].replace("file://", "")
        dst = re.sub(r"^\~", Path.home().as_posix(), dst)
        dst = re.sub(r"^\/*\.{2}", Path.cwd().parents[0].as_posix(), dst)
        dst = re.sub(r"^\/*\.{1}", Path.cwd().as_posix(), dst)
        if not dst.startswith('/'): dst = Path.cwd().as_posix() + "/" + dst
        dst = re.sub(r"\/{2,}", "/", dst)
        dst_type = pathtype_local(dst)
        if dst_type == 'd': isDstDir = bool(True)
    else:
        isDownload = False
        dst = xrd_copy_command[-1]
        dst = re.sub(r"\/*\%ALIEN", alienHome, dst)
        dst = re.sub(r"^\/*\.{2}", cwd_grid_path.parents[0].as_posix(), dst)
        dst = re.sub(r"^\/*\.{1}", cwd_grid_path.as_posix(), dst)
        if not dst.startswith('/'): dst = currentdir + dst
        dst_specs_remotes = dst.split(",")
        dst = dst_specs_remotes.pop(0)  # first item is the file path, let's remove it; it remains disk specifications
        dst = re.sub(r"\/{2,}", "/", dst)
        dst_type = await pathtype_grid(dst)
        if dst_type == 'd': isDstDir = bool(True)

    if isSrcLocal == isDstLocal:
        print("The operands cannot specify different source types: one must be local and one grid")
        return

    # if src is directory, then create list of files coresponding with options
    if isDownload:
        isWrite = bool(False)
        specs = src_specs_remotes
        if isSrcDir:  # src is GRID, we are DOWNLOADING from GRID directory
            find_args.append(src)
            find_args.append(pattern)
            await websocket.send(CreateJsonCommand('find', find_args))
            result = await websocket.recv()
            src_list_files_dict = json.loads(result.encode('ascii', 'ignore'))
            for file in src_list_files_dict['results']:
                src_filelist.append(file['lfn'])
                file_relative_name = file['lfn'].replace(src, '')
                dst_file = dst[:-1] + "/" + setDst(file['lfn'], parent)
                dst_file = re.sub(r"\/{2,}", "/", dst_file)
                dst_filelist.append(dst_file)
        else:
            src_filelist.append(src)
            if dst.endswith("/"): dst = dst[:-1] + setDst(src, parent)
            dst_filelist.append(dst)
    else:  # it is upload
        isWrite = bool(True)
        specs = dst_specs_remotes
        if isSrcDir:  # src is LOCAL, we are UPLOADING from LOCAL directory
            regex = re.compile(pattern)
            list = []
            for root, dirs, files in os.walk(src[:-1]):
                for file in files:
                    filepath = os.path.join(root, file)
                    if regex.match(filepath):
                        src_filelist.append(filepath)
                        file_relative_name = filepath.replace(src, '')
                        dst_file = dst[:-1] + "/" + setDst(filepath, parent)
                        dst_file = re.sub(r"\/{2,}", "/", dst_file)
                        dst_filelist.append(dst_file)
        else:
            src_filelist.append(src)
            if dst.endswith("/"): dst = dst[:-1] + setDst(src, parent)
            dst_filelist.append(dst)

    lfn_list = []
    if isDownload:
        lfn_list = src_filelist
    else:
        lfn_list = dst_filelist

    envelope_list = await getEnvelope(lfn_list, specs, isWrite)

    # clean up the entries with errors
    errors_list = []
    for item_idx, item in enumerate(envelope_list):
        lfn = item["lfn"]
        result = item["answer"]
        access_request = json.loads(result.encode('ascii', 'ignore'))
        if not access_request['results']:
            if access_request["metadata"]["error"] != '0':
                errors_list.append(item_idx)
        if XRDDEBUG:
            print(lfn)
            print(json.dumps(access_request, sort_keys=True, indent=4))

    if errors_list:
        print(errors_list)
        for idx in reversed(errors_list): envelope_list.remove(idx)  # make sure we remove from back to front the lfns with errors
    if not envelope_list: return  # if all errors and list empty, just return

    url_list_src = []
    url_list_dst = []
    if isDownload:
        for item_idx, item in enumerate(envelope_list):
            lfn = item["lfn"]
            result = item["answer"]
            access_request = json.loads(result.encode('ascii', 'ignore'))
            # multiple replicas are downloaded to a single file
            url_list_4meta = []
            for server in access_request['results']:
                complete_url = server['url'] + "?" + "authz=" + server['envelope'] + xrdcp_args
                url_list_4meta.append(complete_url)

            dst = dst_filelist[item_idx]
            url_list_dst.append({"url": dst})  # the local file destination

            size_4meta = access_request['results'][0]['size']  # size SHOULD be the same for all replicas
            md5_4meta = access_request['results'][0]['md5']  # the md5 hash SHOULD be the same for all replicas
            # let's check the destination, if existent, check the validity
            if not overwrite:
                if os.path.isfile(dst):  # first check
                    if int(os.stat(dst).st_size) != int(size_4meta): os.remove(dst)
                if os.path.isfile(dst):  # if the existent file survived the first check
                    if md5(dst) != md5_4meta: os.remove(dst)
                if os.path.isfile(dst):  # if the existent file survived the second check
                    print("File is already downloaded and size and md5 match the remote")
                    return

            src = src_filelist[item_idx]
            meta_fn = tmpdir + "/" + src.replace("/", "_") + ".meta4"
            create_metafile(meta_fn, dst, size_4meta, md5_4meta, url_list_4meta)
            url_list_src.append({"url": meta_fn})
    else:
        for item_idx, item in enumerate(envelope_list):
            lfn = item["lfn"]
            result = item["answer"]
            access_request = json.loads(result.encode('ascii', 'ignore'))
            for server in access_request['results']:
                complete_url = server['url'] + "?" + "authz=" + server['envelope'] + xrdcp_args
                url_list_dst.append({"url": complete_url})
                url_list_src.append({"url": src})

    if XRDDEBUG:
        for url in url_list_src: print("src:{}\n".format(url['url']))
        for url in url_list_dst: print("dst:{}\n".format(url['url']))

    # defer the list of url and files to xrootd processing - actual XRootD copy takes place
    token_list_upload_ok = XrdCopy(url_list_src, url_list_dst, isDownload)

    if (not isDownload) and token_list_upload_ok:  # it was an upload job that had succesfull uploads
        for item_idx, item in enumerate(envelope_list):
            result = item["answer"]
            access_request = json.loads(result.encode('ascii', 'ignore'))
            src = src_filelist[item_idx]
            dst = dst_filelist[item_idx]
            # common values for all commit commands
            lfn = dst
            size = os.path.getsize(src)
            md5sum = md5(lfn)
            perm = '644'
            expire = '0'
            for token in token_list_upload_ok:  # for each succesful token
                for server in access_request['results']:  # go over all received servers
                    if token in server['envelope']:  # for the server that have the succesful uploaded token
                        pfn = server['url']
                        se = server['se']
                        guid = server['guid']
                        # envelope size lfn perm expire pfn se guid md5
                        commit_args_list = [token, int(size), lfn, perm, expire, pfn, se, guid, md5sum]
                        await websocket.send(CreateJsonCommand('commit', commit_args_list))
                        if XRDDEBUG:
                            commit_results = await websocket.recv()  # useless return message
                            json_dict = json.loads(commit_results)
                            if 'metadata' in json_dict: del json_dict['metadata']
                            print(json.dumps(json_dict, sort_keys=True, indent=4))


def XrdCopy(src, dst, isDownload = bool(True)):
    from XRootD import client
    global overwrite, batch, sources, chunks, chunksize, makedir, posc, hashtype, tpc

    class MyCopyProgressHandler(client.utils.CopyProgressHandler):
        isDownload = bool(True)
        src = ''  # pass the source from begin to end
        dst = ''  # pass the target from begin to end
        token_list_upload_ok = []  # record the tokens of succesfully uploaded files. needed for commit to catalogue
        timestamp_begin = None
        total = None

        def begin(self, id, total, source, target):
            self.timestamp_begin = datetime.now().timestamp()
            print("jobID: {0}/{1} ... ".format(id, total), end = '')
            self.src = source
            self.dst = target
            if XRDDEBUG:
                print("CopyProgressHandler.source: {}".format(self.src))
                print("CopyProgressHandler.target: {}".format(self.dst))

        def end(self, jobId, results):
            results_message = results['status'].message
            results_status = results['status'].status
            results_errno = results['status'].errno
            results_code = results['status'].code
            status = ''
            if results['status'].ok: status = 'OK'
            if results['status'].error: status = 'ERROR'
            if results['status'].fatal: status = 'FATAL'

            if results['status'].ok:
                deltaT = datetime.now().timestamp() - self.timestamp_begin
                speed = self.total/deltaT
                bytes_s = 'bytes/s'
                kbytes_s = 'kB/s'
                mbytes_s = 'MB/s'
                unit = bytes_s
                if int(speed/1024) > 1:
                    speed = speed/1024
                    unit = kbytes_s
                if int(speed/(1024*1024)) > 1:
                    speed = speed/(1024*1024)
                    unit = mbytes_s
                print("STATUS: {0} ; SPEED = {1:.2f} {2} ; MESSAGE: {3}".format(status, speed, unit, results_message))
                if self.isDownload:
                    os.remove(urlparse(str(self.src)).path)  # remove the created metalink
                else:  # isUpload
                    link = urlparse(str(self.dst))
                    token = next((param for param in str.split(link.query, '&') if 'authz=' in param), None).replace('authz=', '')  # extract the token from url
                    self.token_list_upload_ok.append(str(token))
            else:
                print("STATUS: {0} ; ERRNO: {1} ; CODE: {2} ; MESSAGE: {3}".format(results_status, results_errno, results_code, results_message))

        def update(self, jobId, processed, total):
            self.total = total
            # print("jobID : {0} ; processed: {1}, total: {2}".format(jobId, processed, total))

    process = client.CopyProcess()
    handler = MyCopyProgressHandler()
    process.parallel(batch)
    handler.isDownload = isDownload
    for url_src, url_dst in zip(src, dst):
        process.add_job(url_src["url"], url_dst["url"],
                        sourcelimit = sources,
                        force = overwrite,
                        posc = posc,
                        mkdir = makedir,
                        chunksize = chunksize,
                        parallelchunks = chunks
                        )
    process.prepare()
    process.run(handler)
    return handler.token_list_upload_ok  # for upload jobs we must return the list of token for succesful uploads


def create_metafile(meta_filename, local_filename, size, hash_val, replica_list = []):
    published = str(datetime.now().replace(microsecond=0).isoformat())
    with open(meta_filename, 'w') as f:
        f.write('<?xml version="1.0" encoding="UTF-8"?>\n')
        f.write(' <metalink xmlns="urn:ietf:params:xml:ns:metalink">\n')
        f.write("   <published>{}</published>\n".format(published))
        f.write("   <file name=\"{}\">\n".format(local_filename))
        f.write("     <size>{}</size>\n".format(size))
        f.write("     <hash type=\"md5\">{}</hash>\n".format(hash_val))
        for url in replica_list:
            f.write("     <url><![CDATA[{}]]></url>\n".format(url))
        f.write('   </file>\n')
        f.write(' </metalink>\n')
        f.closed


def md5(file):
    import hashlib
    BLOCKSIZE = 65536
    hasher = hashlib.md5()
    with open(file, 'rb') as f:
        buf = f.read(BLOCKSIZE)
        while len(buf) > 0:
            hasher.update(buf)
            buf = f.read(BLOCKSIZE)
    return hasher.hexdigest()


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
    if IsValidCert(tokencert):
        cert = tokencert
        key  = tokenkey
    else:
        cert = usercert
        key  = userkey

    ctx = ssl.SSLContext()
    # CERT_NONE, CERT_OPTIONAL, CERT_REQUIRED
    if USE_JBOX:
        verify_mode = ssl.CERT_NONE
    else:
        verify_mode = ssl.CERT_REQUIRED
    ctx.verify_mode = verify_mode
    ctx.check_hostname = False
    ctx.load_verify_locations(capath=capath_default)
    ctx.load_verify_locations(capath=user_globus_dir)
    if USE_JBOX:
        if Path(tokencert).exists() and IsValidCert(tokencert): ctx.load_verify_locations(cafile=tokencert)
        ctx.load_cert_chain(certfile=usercert, keyfile=userkey)
        # ctx.load_cert_chain(certfile=cert, keyfile=key)
    else:
        ctx.load_cert_chain(certfile=cert, keyfile=key)
    return ctx


async def AlienConnect():
    ssl_context = None
    if wb_protol == 'wss://': ssl_context = create_ssl_context()  # will check validity of token and if invalid cert will be usercert

    if DEBUG: print("Connecting to : ", fHostWSUrl)
    """https://websockets.readthedocs.io/en/stable/api.html#websockets.protocol.WebSocketCommonProtocol"""
    # we use some conservative values, higher than this might hurt the sensitivity to intreruptions
    return await websockets.connect(fHostWSUrl, ssl=ssl_context, max_queue=4, max_size=16 * 1024 * 1024, ping_interval=10, ping_timeout=20, close_timeout=20)


def CreateJsonCommand(command, options=[]):
    cmd_dict = {"command": command, "options": options}
    jcmd = json.dumps(cmd_dict)
    jcmd.encode('ascii', 'ignore')
    return jcmd


async def AlienSendCmd(wb = None, cmdline = ''):
    if not wb: return
    if not cmdline: return
    cmd_parts = cmdline.split(" ")
    cmd = cmd_parts.pop(0)
    await websocket.send(CreateJsonCommand(cmd, cmd_parts))
    return await websocket.recv()


async def InitConnection():
    global websocket, ccmd, user, alienHome, currentdir, commandlist

    # implement a time command for measurement of sent/recv delay
    init_begin = None
    init_delta = None
    if TIME_CONNECT:
        init_begin = datetime.now().timestamp()

    websocket = await AlienConnect()

    # if the certificate used is not the token, then get one
    if cert == usercert: await token()

    # no matter if command or interactive mode, we need alienHome, currentdir, user and commandlist
    if not commandlist: await getSessionVars()
    if init_begin:
        init_delta = datetime.now().timestamp() - init_begin
        print(">>>   Time for websocket initialization + sessionVars : {}".format(init_delta))


async def token():
    global websocket, ccmd, tokencert, tokenkey
    await websocket.send(CreateJsonCommand('token'))
    result = await websocket.recv()
    json_dict = json.loads(result.lstrip().encode('ascii', 'ignore'))

    tokencert_content = json_dict['results'][0]["tokencert"]
    tokenkey_content  = json_dict['results'][0]["tokenkey"]

    if os.path.isfile(tokencert): os.chmod(tokencert, 0o700)  # make it writeable
    with open(tokencert, "w") as tcert: print(f"{tokencert_content}", file=tcert)  # write the tokencert
    os.chmod(tokencert, 0o400)  # make it readonly

    if os.path.isfile(tokenkey): os.chmod(tokenkey, 0o700)  # make it writeable
    with open(tokenkey, "w") as tkey: print(f"{tokenkey_content}", file=tkey)  # write the tokenkey
    os.chmod(tokenkey, 0o400)  # make it readonly
    ccmd = ''


async def getSessionVars():
    global websocket, ccmd, user, alienHome, currentdir, commandlist
    # get the command list to check validity of commands
    await websocket.send(CreateJsonCommand('commandlist'))
    result = await websocket.recv()
    json_dict = json.loads(result.lstrip().encode('ascii', 'ignore'))
    # first executed commands, let's initialize the following (will re-read at each ProcessReceivedMessage)
    commandlist = json_dict["results"][0]['message']
    user = json_dict["metadata"]["user"]

    # if we were intrerupted and re-connect than let's get back to the old currentdir
    if currentdir and not currentdir == json_dict["metadata"]["currentdir"]:
        await websocket.send(CreateJsonCommand('cd', [currentdir]))
    currentdir = json_dict["metadata"]["currentdir"]
    if not alienHome: alienHome = currentdir  # this is first query so current dir is alienHOME


def ProcessReceivedMessage(message='', shellcmd = None):
    global json_output, json_meta_output, currentdir, user, ccmd, error, exitcode
    if not message: return
    json_dict = json.loads(message.lstrip().encode('ascii', 'ignore'))
    currentdir = json_dict["metadata"]["currentdir"]

    error = ''
    if 'error' in json_dict["metadata"]: error = json_dict["metadata"]["error"]

    if json_output:
        if not json_meta_output:
            if 'metadata' in json_dict: del json_dict['metadata']
        print(json.dumps(json_dict, sort_keys=True, indent=4))
    else:
        websocket_output = '\n'.join(str(item['message']) for item in json_dict['results'])
        if shellcmd:
            # shlex.split(shellcmd)
            # shlex.quote(shellcmd)
            shell_run = subprocess.run(shellcmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, input=websocket_output, encoding='ascii', shell=True, env=os.environ)
            stdout = shell_run.stdout
            if stdout: print(stdout)
            stderr = shell_run.stderr
            if stderr: print(stderr)
        else:
            print(websocket_output)
            if error: print(error)

    ccmd = ''  # reset the current executed command, the received message was processed


async def get_completer_list():
    global websocket, ls_list
    await websocket.send(CreateJsonCommand('ls'))
    result = await websocket.recv()
    json_dict = json.loads(result.lstrip().encode('ascii', 'ignore'))
    ls_list = list(item['name'] for item in json_dict['results'])


async def pathtype_grid(path=''):
    if not path: return
    global websocket
    await websocket.send(CreateJsonCommand('stat', [path]))
    result = await websocket.recv()
    json_dict = json.loads(result.lstrip().encode('ascii', 'ignore'))

    error = json_dict["metadata"]["error"]
    if error: return error
    return str(json_dict['results'][0]["type"])


def pathtype_local(path=''):
    if not path: return
    p = Path(path)
    if p.is_dir(): return str('d')
    if p.is_file(): return str('f')
    return str('')


class Commander(cmd2.Cmd):
    global websocket, currentdir, commandlist, ccmd, alienHome, ls_list

    intro = 'Welcome to the jAliEn shell. Try ? or help to list commands.\nTo change between the grid and your local ' \
            'file system, use the "switch" command. '
    if local_file_system:
        prompt = os.path.abspath(os.curdir) + ' >'
    else:
        prompt = currentdir + ' >'

    file = None
    cd_parser = None
    parser = argparse.ArgumentParser()

    def __init__(self):
        if not websocket: InitConnection()
        self.websocket = websocket

        # Initiate cmd2. Set history file and allow the use of IPython to create scripts
        super().__init__(self, persistent_history_file= homedir + '/.alienpy_hist', use_ipython=True)

        # Give scripts made by the user access to this class
        self.locals_in_py = True

        # Sets the completer for lcd equal to the local file system
        self.complete_lcd = self.path_complete

        # Set the completer for cd equal to all files/directories in the current directory
        get_completer_list()
        self.cd_parser = self.parser.add_argument('cd', choices=ls_list, type=str)

    def decorator(self, local=local_file_system):
        get_completer_list()

    def do_echo(self, arg):
        """"Print what you write"""
        if local_file_system:
            readline.set_prompt('heisann')
            readline.rl_force_redisplay()
            self.run_on_local_shell('echo ' + arg)
        else:
            print(arg)

    def do_quit(self, arg):
        """"Exit the shell"""

        print('Goodbye!')
        exit(0)

    def do_lcd(self, arg):
        """Change local directory"""
        os.chdir(arg)
        self.prompt = os.path.abspath(os.curdir) + ' >'

    def do_cd(self, arg: argparse.Namespace):
        """Change directory"""
        if local_file_system:
            os.chdir(arg)
            self.prompt = os.path.abspath(os.curdir) + ' >'
        else:
            self.parseCMD(arg.__statement__.raw)
            self.prompt = alienHome + ' >'
            self.decorator()

    def do_ls(self, arg):
        """List of all entities in current path"""
        if local_file_system:
            print(os.listdir(os.curdir))
        else:
            self.parseCMD('ls ' + arg)
        return 5

    def do_less(self, arg):
        """Read content in file"""
        if local_file_system:
            self.run_on_local_shell('less ' + arg)

    def do_switch(self, arg):
        """Change between your local file system and the grid"""
        global local_file_system
        local_file_system = not local_file_system
        if local_file_system:
            self.prompt = os.path.abspath(os.curdir) + ' >'
        else:
            self.prompt = alienHome + ' >'

    def do_vim(self, arg):
        """Edit text file"""
        if local_file_system:

            EDITOR = os.environ.get('EDITOR') if os.environ.get('EDITOR') else 'vim'  # that easy!
            with tempfile.NamedTemporaryFile(suffix=".tmp") as tf:
                tf.flush()
                subprocess.call([EDITOR, tf.name])
                # do the parsing with `tf` using regular File operations.
                # for instance:
                tf.seek(0)
                edited_message = tf.read()

    def do_get(self, arg):
        """???"""
        if local_file_system:
            print("This command ")
        else:
            self.parseCMD('get ' + arg)

    def do_ls_csd(self, arg):
        """Runs the ls command in Cassandra. Can only be run on jSh"""
        global cassandra_error
        if local_file_system:
            print(cassandra_error)
        else:
            self.parseCMD('ls_csd ' + arg)

    def do_cat(self, arg):
        """Reads a file and writes it to output"""
        if local_file_system:
            self.run_on_local_shell('cat ' + arg)
        else:
            self.parseCMD('cat ' + arg)

    def do_cat_csd(self, arg):
        """Reads a file and writes it to output. Can only be run on jSh"""
        global cassandra_error
        if local_file_system:
            print(cassandra_error)
        else:
            self.parseCMD('cat_csd ' + arg)

    def do_whereis(self, arg):
        """Locates source/binary and manuals sections for specified files"""
        if local_file_system:
            self.run_on_local_shell('whereis ' + arg)
        else:
            self.parseCMD('whereis ' + arg)

    def do_whereis_csd(self, arg):
        """Locates source/binary and manuals sections for specified files"""
        if local_file_system:
            print(cassandra_error)
        else:
            self.parseCMD('whereis_csd ' + arg)

    def do_cp(self, arg):
        """Copies file"""
        if local_file_system:
            self.run_on_local_shell('cp ' + arg)
        else:
            self.parseCMD('cp ' + arg)

    def do_cp_csd(self, arg):
        """Copies File"""
        if local_file_system:
            print(cassandra_error)
        else:
            self.parseCMD('cp_csd ' + arg)

    def do_time(self, arg):
        """Usage: time <times> <command> [command_arguments]"""
        if local_file_system:
            self.run_on_local_shell('time ' + arg)
        else:
            self.parseCMD('time ' + arg)

    def do_mkdir(self, arg):
        """Create Directory"""
        if local_file_system:
            try:
                os.mkdir(arg)
            except FileExistsError:
                print('The directory ' + arg + ' already exist')
        else:
            self.parseCMD('mkdir ' + arg)

    def do_mkdir_csd(self, arg):
        """Create Directory"""
        if local_file_system:
            print(cassandra_error)
        else:
            self.parseCMD('mkdir_csd ' + arg)

    def do_find(self, arg):
        """Finds and locates matching filenames"""
        if local_file_system:
            self.run_on_local_shell('find ' + arg)
        else:
            self.parseCMD('find ' + arg)

    def do_find_csd(self, arg):
        """Finds and locates matching filenames"""
        if local_file_system:
            print(cassandra_error)
        else:
            self.parseCMD('find_csd ' + arg)

    def do_listFilesFromCollection(self, arg):
        """..."""
        if local_file_system:
            print('Cannot run locally')
        else:
            self.parseCMD('listFilesFromCollection ' + arg)

    def do_submit(self, arg):
        """Submits file"""
        if local_file_system:
            print('Cannot run locally')
        else:
            self.parseCMD('submit ' + arg)

    def do_motd(self, arg):
        """Message of the day!"""
        if local_file_system:
            print('Have a great day!')
        else:
            self.parseCMD('motd ' + arg)

    def do_access(self, arg):
        """..."""
        if local_file_system:
            print('Cannot be run locally')
        else:
            self.parseCMD('access ' + arg)

    def do_commit(self, arg):
        """..."""
        if local_file_system:
            print('Cannot run locally')
        else:
            self.parseCMD('commit ' + arg)

    def do_packages(self, arg):
        """List available packages"""
        if local_file_system:
            print('Cannot be run locally')
        else:
            self.parseCMD('packages ' + arg)

    def do_pwd(self, arg):
        """Prints current directory"""
        if local_file_system:
            self.run_on_local_shell('pwd ' + arg)
        else:
            self.parseCMD('pwd ' + arg)

    def do_ps(self, arg):
        """Reports information on running processes"""
        if local_file_system:
            self.run_on_local_shell('ps ' + arg)
        else:
            self.parseCMD('ps ' + arg)

    def do_rmdir(self, arg):
        """Remove directories"""
        if local_file_system:
            self.run_on_local_shell('rmdir ' + arg)
        else:
            self.parseCMD('rmdir ' + arg)

    def do_rm(self, arg):
        """Remove files"""
        if local_file_system:
            self.run_on_local_shell('rm ' + arg)
        else:
            self.parseCMD('rm ' + arg)

    def do_rm_csd(self, arg):
        """Remove files"""
        if local_file_system:
            print(cassandra_error)
        else:
            self.parseCMD('rm_csd ' + arg)

    def do_mv(self, arg):
        """Move files"""
        if local_file_system:
            self.run_on_local_shell('mv ' + arg)
        else:
            self.parseCMD('mv ' + arg)

    def do_mv_csd(self, arg):
        """Move files"""
        if local_file_system:
            print(cassandra_error)
        else:
            self.parseCMD('mv_csd ' + arg)

    def do_masterjob(self, arg):
        """..."""
        if local_file_system:
            print('Cannot be run locally')
        else:
            self.parseCMD('masterjob ' + arg)

    def do_user(self, arg):
        """Change role of user specified"""
        if local_file_system:
            print('Cannot be run locally')
        else:
            self.parseCMD('user ' + arg)

    def do_touch(self, arg):
        """Create file"""
        if local_file_system:
            self.run_on_local_shell('touch ' + arg)
        else:
            self.parseCMD('touch ' + arg)

    def do_touch_csd(self, arg):
        """Create file"""
        if local_file_system:
            print(cassandra_error)
        else:
            self.parseCMD('touch_csd ' + arg)

    def do_type(self, arg):
        """..."""
        if local_file_system:
            self.run_on_local_shell('type ' + arg)
        else:
            self.parseCMD('type ' + arg)

    def do_kill(self, arg):
        """Kill process"""
        if local_file_system:
            self.run_on_local_shell('kill ' + arg)
        else:
            self.parseCMD('kill ' + arg)

    def do_lfn2guid(self, arg):
        """Prints guid for given lfn"""
        if local_file_system:
            print('Cannot be run locally')
        else:
            self.parseCMD('lfn2guid ' + arg)

    def do_guid2lfn(self, arg):
        """Prints lfn for given guid"""
        if local_file_system:
            print('Cannot be run locally')
        else:
            self.parseCMD('guid2lfn ' + arg)

    def do_guid2lfn_csd(self, arg):
        """Prints lfn for given guid"""
        if local_file_system:
            print('Cannot be run locally')
        else:
            self.parseCMD('guid2lfn_csd ' + arg)

    def do_w(self, arg):
        """Get list of active/waiting jobs"""
        if local_file_system:
            print('Cannot be run locally')
        else:
            self.parseCMD('w ' + arg)

    def do_uptime(self, arg):
        """Get list of running/waiting jobs and active users"""
        if local_file_system:
            print('Cannot be run locally')
        else:
            self.parseCMD('uptime ' + arg)

    def do_chown(self, arg):
        """Changes an owner or a group for a file"""
        if local_file_system:
            self.run_on_local_shell('chown ' + arg)
        else:
            self.parseCMD('chown ' + arg)

    def do_chown_csd(self, arg):
        """Changes an owner or a group for a file"""
        if local_file_system:
            print(cassandra_error)
        else:
            self.parseCMD('chown_csd ' + arg)

    def do_deleteMirror(self, arg):
        """Removes a replica of a file from the catalogue"""
        if local_file_system:
            print('Cannot be run locally')
        else:
            self.parseCMD('deleteMirror ' + arg)

    def do_df(self, arg):
        """Shows free disk space"""
        if local_file_system:
            self.run_on_local_shell('df ' + arg)
        else:
            self.parseCMD('df ' + arg)

    def do_du(self, arg):
        """Gives the disk space usage of a directory"""
        if local_file_system:
            self.run_on_local_shell('du ' + arg)
        else:
            self.parseCMD('du ' + arg)

    def do_fquota(self, arg):
        """Displays information about File Quotas"""
        if local_file_system:
            print('Cannot be run locally')
        else:
            self.parseCMD('fquota ' + arg)

    def do_jquota(self, arg):
        """Displays information about Job Quotas"""
        if local_file_system:
            print('Cannot be run locally')
        else:
            self.parseCMD('jquota ' + arg)

    def do_listSEDistance(self, arg):
        """Returns the closest working SE for a particular site"""
        if local_file_system:
            print('Cannot be run locally')
        else:
            self.parseCMD('listSEDistance ' + arg)

    def do_listTransfer(self, arg):
        """Returns all the transfers that are waiting in the system"""
        if local_file_system:
            print('Cannot be run locally')
        else:
            self.parseCMD('listTransfer ' + arg)

    def do_md5sum(self, arg):
        """Returns MD5 checksum of given filename or guid"""
        if local_file_system:
            print('Cannot be run locally')
        else:
            self.parseCMD('md5sum ' + arg)

    def do_mirror(self, arg):
        """Mirror copies a file into another SE"""
        if local_file_system:
            print('Cannot be run locally')
        else:
            self.parseCMD('mirror ' + arg)

    def do_resubmit(self, arg):
        """Resubmits a job or a group of jobs by IDs"""
        if local_file_system:
            print('Cannot be run locally')
        else:
            self.parseCMD('resubmit ' + arg)

    def do_top(self, arg):
        """Display and update information about running processes"""
        if local_file_system:
            self.run_on_local_shell('top ' + arg)
        else:
            self.parseCMD('top ' + arg)

    def do_groups(self, arg):
        """Shows the groups current user is a member of"""
        if local_file_system:
            print('Cannot be run locally')
        else:
            self.parseCMD('groups ' + arg)

    def do_token(self, arg):
        """..."""
        if local_file_system:
            print('Cannot be run locally')
        else:
            self.parseCMD('token ' + arg)

    def do_uuid(self, arg):
        """Returns info about given lfn"""
        if local_file_system:
            print('Cannot be run locally')
        else:
            self.parseCMD('uuid ' + arg)

    def do_stat(self, arg):
        """..."""
        if local_file_system:
            self.run_on_local_shell('stat ' + arg)
        else:
            self.parseCMD('stat ' + arg)

    def do_listSEs(self, arg):
        """Print all (or a subset) of the defined SEs with their details"""
        if local_file_system:
            print('Cannot be run locally')
        else:
            self.parseCMD('listSEs ' + arg)

    def do_xrdstat(self, arg):
        """..."""
        if local_file_system:
            print('Cannot be run locally')
        else:
            self.parseCMD('xrdstat ' + arg)

    def do_whois(self, arg):
        """Usage: whois [account name]"""
        if local_file_system:
            self.run_on_local_shell('whois ' + arg)
        else:
            self.parseCMD('whois ' + arg)

    '''
    def do_(self, arg):
        """XX"""
        if local_file_system:
            self.run_on_local_shell(' ' + arg)
        else:
            self.parseCMD(' ' + arg)
    '''

    def parseCMD(self, args = []):
        args = shlex.split(args)
        cmd1 = args.pop(0)
        # jsoncmd = CreateJsonCommand(cmd1, args)
        # if DEBUG: print(jsoncmd)
        asyncio.get_event_loop().run_until_complete(JAlienCmd(cmd1, args))

    def run_on_local_shell(self, arg):
        shellcmd_out = subprocess.Popen(arg, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
        stdout, stderr = shellcmd_out.communicate()
        if stdout: print(stdout.decode())
        if stderr: print(stderr.decode())


async def JAlienCmd(cmd = '', args = []):
    global websocket, currentdir, alienHome
    await InitConnection()

    # implement a time command for measurement of sent/recv delay
    message_begin = None
    message_delta = None
    if cmd == 'time':
        cmd = args.pop(0)
        message_begin = datetime.now().timestamp()

    cwd_grid_path = Path(currentdir)
    home_grid_path = Path(alienHome)

    signal.signal(signal.SIGINT, signal_handler)
    if (cmd.startswith("cp")):  # defer cp processing to ProcessXrootdCp
        await ProcessXrootdCp(args)
    else:
        if (cmd.startswith("ls")) or (cmd.startswith("stat")) or (cmd.startswith("find")) or (cmd.startswith("xrdstat")) or (cmd.startswith("rm")) or (cmd.startswith("lfn2guid")):
            for i, arg in enumerate(args):
                args[i] = re.sub(r"\/*\.\/+", cwd_grid_path.as_posix() + "/", arg)
                args[i] = re.sub(r"\/*\.\.\/+", cwd_grid_path.parent.as_posix() + "/", arg)
                args[i] = re.sub(r"%ALIEN", home_grid_path.as_posix() + "/", arg)

        if not DEBUG: args.insert(0, '-nokeys')
        jsoncmd = CreateJsonCommand(cmd, args)
        if DEBUG: print(jsoncmd)

        await websocket.send(jsoncmd)
        result = await websocket.recv()
        if message_begin:
            message_delta = datetime.now().timestamp() - message_begin
            print(">>>   Time for send/receive command : {}".format(message_delta))
        ProcessReceivedMessage(result)


async def JAlienShell():
    global websocket, currentdir, commandlist, ccmd, alienHome
    await InitConnection()

    cwd_grid_path = Path(currentdir)
    home_grid_path = Path(alienHome)

    while True:
        signal.signal(signal.SIGINT, signal_handler)
        INPUT = ''
        try:
            INPUT = input(f"jsh: {currentdir} >")
        except EOFError:
            exit_message()

        if not INPUT: continue

        # make sure we have with whom to talk to; if not, lets redo the connection
        # we can consider any message/reply pair as atomic, we cannot forsee and treat the connection lost in the middle of reply
        # (if the end of message frame is not received then all message will be lost as it invalidated)
        try:
            ping = await websocket.ping()
        except websockets.ConnectionClosed:
            await InitConnection()

        # list of directories in CWD (to be used for autocompletion?)
        cwd_list = await get_completer_list()

        # if shell command, just run it and return
        if re.match("!", INPUT):
            sh_cmd = re.sub(r'^!', '', INPUT)
            # sh_cmd = shlex.quote(sh_cmd)
            shcmd_out = subprocess.run(sh_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True, env=os.environ)
            stdout = shcmd_out.stdout
            if stdout: print(stdout.decode())
            stderr = shcmd_out.stderr
            if stderr: print(stderr.decode())
            continue

        # process the input and take care of pipe to shell
        input_list = []
        pipe_to_shell_cmd = ''
        if "|" in str(INPUT):  # if we have pipe to shell command
            input_split_pipe = INPUT.split('|', maxsplit=1)  # split in before pipe (jalien cmd) and after pipe (shell cmd)
            input_list = input_split_pipe[0].split()  # the list of arguments sent to websocket
            pipe_to_shell_cmd = input_split_pipe[1]  # the shell command
            pipe_to_shell_cmd.encode('ascii', 'unicode-escape')
        else:
            input_list = INPUT.split()

        cmd = input_list.pop(0)  # set the cmd as first item in list and remove it (the rest of list are the arguments)

        # implement a time command for measurement of sent/recv delay
        message_begin = None
        message_delta = None
        if cmd == 'time':
            cmd = input_list.pop(0)  # remove the time command, leave the actual cmd+args list
            message_begin = datetime.now().timestamp()

        if (cmd.startswith("ls")) or (cmd.startswith("stat")) or (cmd.startswith("find")) or (cmd.startswith("xrdstat")) or (cmd.startswith("rm")) or (cmd.startswith("lfn2guid")):
            for i, arg in enumerate(input_list):
                input_list[i] = re.sub(r"\/*\.\/+", cwd_grid_path.as_posix() + "/", arg)
                input_list[i] = re.sub(r"\/*\.\.\/+", cwd_grid_path.parent.as_posix() + "/", arg)
                input_list[i] = re.sub(r"%ALIEN", home_grid_path.as_posix() + "/", arg)

        # defer to cp xrootd function
        if cmd.startswith("cp"):  # defer cp processing to ProcessXrootdCp
            await ProcessXrootdCp(input_list)
            continue

        # process help commands
        if (cmd == "?") or (cmd == "help"):
            if len(input_list) > 0:
                cmdhelp = input_list[0]
                if cmdhelp in commandlist:
                    input_list.clear()
                    cmd = cmdhelp
                    input_list.append(cmd)
                    input_list.append('-h')
            else:
                print(commandlist)
                continue

        if not DEBUG: input_list.insert(0, '-nokeys')
        jsoncmd = CreateJsonCommand(cmd, input_list)  # make json with cmd and the list of arguments
        ccmd = jsoncmd  # keep a global copy of the json command that is run
        cmd_hist.append(jsoncmd)
        if DEBUG: print(jsoncmd)

        await websocket.send(jsoncmd)
        result = await websocket.recv()
        if message_begin:
            message_delta = datetime.now().timestamp() - message_begin
            print(">>>   Time for send/receive command : {}".format(message_delta))
        ProcessReceivedMessage(result, pipe_to_shell_cmd)


def main():
    global json_output, json_meta_output

    # Let's start the connection
    logger = logging.getLogger('websockets')
    logger.setLevel(logging.ERROR)
    if DEBUG_WS:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.ERROR)
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
        asyncio.get_event_loop().run_until_complete(JAlienCmd(cmd, args))
    else:
        if CMD_TESTING:
            app = Commander()
            app.cmdloop()
        else:
            asyncio.get_event_loop().run_until_complete(JAlienShell())


if __name__ == '__main__':
    main()

