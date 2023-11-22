"""alienpy:: setup cwd restoration"""

import os
import logging
import sys

from .setup_logging import DEBUG
from .global_vars import AlienSessionInfo
from .tools_nowb import read_conf_file
from .wb_api import cd


def GetSessionFilename() -> str: return os.path.join(os.path.expanduser("~"), ".alienpy_session")


def SessionSave() -> None:
    """Save CWD and previous CWD in .alienpy_session file"""
    session_filename = GetSessionFilename()
    if 'AlienSessionInfo' not in globals(): return
    try:
        with open(session_filename, "w", encoding="ascii", errors="replace") as f:
            line1 = f"CWD = {AlienSessionInfo['currentdir']}\n"
            if not AlienSessionInfo['prevdir']: AlienSessionInfo['prevdir'] = AlienSessionInfo['currentdir']
            line2 = f"CWDPREV = {AlienSessionInfo['prevdir']}\n"
            f.writelines([line1, line2])
    except Exception as e:
        logging.error('SessionSave:: failed to write session information to %s', session_filename)
        if DEBUG: logging.exception(e)


def SessionRestore(wb) -> None:
    if os.getenv('ALIENPY_NO_CWD_RESTORE'): return
    session = read_conf_file(GetSessionFilename())
    if not session: return
    if 'AlienSessionInfo' in globals():
        sys_cur_dir = AlienSessionInfo['currentdir']
        if 'CWD' in session: AlienSessionInfo['currentdir'] = session['CWD']
        if 'CWDPREV' in session: AlienSessionInfo['prevdir'] = session['CWDPREV']
        if AlienSessionInfo['currentdir'] and (sys_cur_dir != AlienSessionInfo['currentdir']): cd(wb, AlienSessionInfo['currentdir'], opts = 'nocheck')


if __name__ == '__main__':
    print('This file should not be executed!', file = sys.stderr, flush = True)
    sys.exit(95)
