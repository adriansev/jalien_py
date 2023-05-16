'''alienpy:: Functions that use WebSocket to talk with central services'''

import traceback
from typing import Union
from .data_structs import *  # nosec PYL-W0614
from .global_vars import *  # nosec PYL-W0614
from .setup_logging import print_out, print_err
from .wb_api import *  # nosec PYL-W0614
from .connect_ssl import get_certs_names
from .tools_files import path_readable


def token(wb, args: Union[None, list] = None) -> int:
    """(Re)create the tokencert and tokenkey files"""
    if not wb: return 1
    if not args: args = []
    certs_info = get_certs_names()

    ret_obj = SendMsg(wb, 'token', args, opts = 'nomsg')
    if ret_obj.exitcode != 0:
        logging.error('Token request returned error')
        return retf_print(ret_obj, 'err')
    tokencert_content = ret_obj.ansdict.get('results')[0].get('tokencert', '')
    tokenkey_content = ret_obj.ansdict.get('results')[0].get('tokenkey', '')
    if not tokencert_content or not tokenkey_content:
        logging.error('Token request valid but empty fields!!')
        return int(42)  # ENOMSG

    try:
        if path_readable(certs_info.token_cert):
            os.chmod(certs_info.token_cert, 0o600)  # make it writeable
            os.remove(certs_info.token_cert)
        with open(certs_info.token_cert, "w", encoding = "ascii", errors = "replace") as tcert: print(f"{tokencert_content}", file = tcert)  # write the tokencert
        os.chmod(certs_info.token_cert, 0o400)  # make it readonly
    except Exception:
        print_err(f'Error writing to file the aquired token cert; check the log file {DEBUG_FILE}!')
        logging.debug(traceback.format_exc())
        return 5  # EIO

    try:
        if path_readable(certs_info.token_key):
            os.chmod(certs_info.token_key, 0o600)  # make it writeable
            os.remove(certs_info.token_key)
        with open(certs_info.token_key, "w", encoding = "ascii", errors = "replace") as tkey: print(f"{tokenkey_content}", file = tkey)  # write the tokenkey
        os.chmod(certs_info.token_key, 0o400)  # make it readonly
    except Exception:
        print_err(f'Error writing to file the aquired token key; check the log file {DEBUG_FILE}!')
        logging.debug(traceback.format_exc())
        return 5  # EIO
    if 'AlienSessionInfo' in globals(): 
        AlienSessionInfo['token_cert'] = certs_info.token_cert
        AlienSessionInfo['token_key'] = certs_info.token_key
    return int(0)


def token_regen(wb, args: Union[None, list] = None):
    """Do the disconnect, connect with user cert, generate token, re-connect with token procedure"""
    wb_usercert = None
    if not args: args = []

    if 'AlienSessionInfo' in globals() and not AlienSessionInfo['use_usercert']:
        wb_close(wb, code = 1000, reason = 'Lets connect with usercert to be able to generate token')
        try:
            wb_usercert = InitConnection(wb, args, use_usercert = True)  # we have to reconnect with the new token
        except Exception:
            logging.debug(traceback.format_exc())
            return None  # we failed usercert connection

    # now we are connected with usercert, so we can generate token
    if token(wb_usercert, args) != 0: return wb_usercert
    # we have to reconnect with the new token
    wb_close(wb_usercert, code = 1000, reason = 'Re-initialize the connection with the new token')
    if 'AlienSessionInfo' in globals(): AlienSessionInfo['use_usercert'] = False
    wb_token_new = None
    try:
        wb_token_new = InitConnection(wb_token_new, args)
        __ = SendMsg(wb_token_new, 'pwd', [], opts = 'nokeys')  # just to refresh cwd
    except Exception:
        logging.exception('token_regen:: error re-initializing connection')
    return wb_token_new


def get_list_entries(wb, lfn, fullpath: bool = False) -> list:
    """return a list of entries of the lfn argument, full paths if 2nd arg is True"""
    key = 'path' if fullpath else 'name'
    ret_obj = SendMsg(wb, 'ls', ['-nomsg', '-a', '-F', os.path.normpath(lfn)])
    if ret_obj.exitcode != 0: return []
    return [item[key] for item in ret_obj.ansdict['results']]


def lfn_list(wb, lfn: str = ''):
    """Completer function : for a given lfn return all options for latest leaf"""
    if not wb: return []
    if not lfn: lfn = '.'  # AlienSessionInfo['currentdir']
    list_lfns = []
    lfn_path = Path(lfn)
    base_dir = '/' if lfn_path.parent.as_posix() == '/' else f'{lfn_path.parent.as_posix()}/'
    name = f'{lfn_path.name}/' if lfn.endswith('/') else lfn_path.name

    def item_format(base_dir, name, item):
        # print_out(f'\nbase_dir: {base_dir} ; name: {name} ; item: {item}')
        if name.endswith('/') and name != '/':
            return f'{name}{item}' if base_dir == './' else f'{base_dir}{name}{item}'
        return item if base_dir == './' else f'{base_dir}{item}'

    if lfn.endswith('/'):
        listing = get_list_entries(wb, lfn)
        list_lfns = [item_format(base_dir, name, item) for item in listing]
    else:
        listing = get_list_entries(wb, base_dir)
        list_lfns = [item_format(base_dir, name, item) for item in listing if item.startswith(name)]
    return list_lfns


def wb_ping(wb) -> float:
    """Websocket ping function, it will return rtt in ms"""
    init_begin = time.perf_counter()
    if IsWbConnected(wb):
        return float(deltat_ms_perf(init_begin))
    return float(-1)


def cd(wb, args: Union[str, list] = None, opts: str = '') -> RET:
    """Override cd to add to home and to prev functions"""
    if args is None: args = []
    if isinstance(args, str): args = args.split()
    if is_help(args): return get_help_srv(wb, 'cd')
    if args:
        if args[0] == '-': args = [AlienSessionInfo['prevdir']]
        if 'nocheck' not in opts and AlienSessionInfo['currentdir'].rstrip('/') == args[0].rstrip('/'): return RET(0)  # type: ignore [call-arg]
    return SendMsg(wb, 'cd', args, opts)


def get_help_srv(wb, cmd: str = '') -> RET:
    """Return the help option for server-side known commands"""
    if not cmd: return RET(1, '', 'No command specified for help request')
    return SendMsg(wb, f'{cmd} -h')


if __name__ == '__main__':
    print('This file should not be executed!', file = sys.stderr, flush = True)
    sys.exit(95)

