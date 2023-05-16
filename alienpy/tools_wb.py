'''alienpy:: Functions that use WebSocket to talk with central services'''

import traceback
from typing import Union
from .data_structs import *  # nosec PYL-W0614
from .global_vars import *  # nosec PYL-W0614
from .setup_logging import print_out, print_err

from .wb_async import IsWbConnected
from .wb_api import SendMsg  # nosec PYL-W0614
from .connect_ssl import get_certs_names
from .tools_files import path_readable


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


def get_help_srv(wb, cmd: str = '') -> RET:
    """Return the help option for server-side known commands"""
    if not cmd: return RET(1, '', 'No command specified for help request')
    return SendMsg(wb, f'{cmd} -h')


if __name__ == '__main__':
    print('This file should not be executed!', file = sys.stderr, flush = True)
    sys.exit(95)

