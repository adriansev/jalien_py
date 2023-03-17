"""alienpy:: setup cwd restoration"""

from .global_vars import *  # nosec PYL-W0614
from .wb_api import cd
from .tools_misc import read_conf_file


def GetSessionFilename() -> str: return os.path.join(os.path.expanduser("~"), ".alienpy_session")


def SessionSave():
    session_filename = GetSessionFilename()
    try:
        with open(session_filename, "w", encoding="ascii", errors="replace") as f:
            line1 = f"CWD = {AlienSessionInfo['currentdir']}\n"
            if not AlienSessionInfo['prevdir']: AlienSessionInfo['prevdir'] = AlienSessionInfo['currentdir']
            line2 = f"CWDPREV = {AlienSessionInfo['prevdir']}\n"
            f.writelines([line1, line2])
    except Exception as e:
        logging.error('SessionSave:: failed to write session information to %s', session_filename)
        if DEBUG: logging.exception(e)


def SessionRestore(wb):
    if os.getenv('ALIENPY_NO_CWD_RESTORE'): return
    session = read_conf_file(GetSessionFilename())
    if not session: return
    sys_cur_dir = AlienSessionInfo['currentdir']
    if 'CWD' in session: AlienSessionInfo['currentdir'] = session['CWD']
    if 'CWDPREV' in session: AlienSessionInfo['prevdir'] = session['CWDPREV']
    if AlienSessionInfo['currentdir'] and (sys_cur_dir != AlienSessionInfo['currentdir']):
        cd(wb, AlienSessionInfo['currentdir'], opts = 'nocheck')


if __name__ == '__main__':
    print('This file should not be executed!', file = sys.stderr, flush = True)
    sys.exit(95)
    
 