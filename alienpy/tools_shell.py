"""alienpy:: Misc tooling functions"""

import re
import sys
import subprocess  # nosec B404:blacklist
import shlex
from typing import Union
from shutil import which

from .data_structs import RET
from .setup_logging import print_err


def runShellCMD(INPUT: str = '', captureout: bool = True, do_shell: bool = False, timeout: Union[str, int, None] = None) -> RET:
    """Run shell command in subprocess; if exists, print stdout and stderr"""
    if not INPUT: return RET(1, '', 'No command to be run provided')
    sh_cmd = re.sub(r'^!', '', INPUT)
    args = sh_cmd if do_shell else shlex.split(sh_cmd)
    capture_args = {'stdout': subprocess.PIPE, 'stderr': subprocess.PIPE} if captureout else {}
    if timeout: timeout = int(timeout)
    status = exitcode = except_msg = None
    msg_out = msg_err = ''
    try:
        status = subprocess.run(args, encoding = 'utf-8', errors = 'replace', shell = do_shell, timeout = timeout, **capture_args)  # pylint: disable=subprocess-run-check  # nosec
    except subprocess.TimeoutExpired:
        print_err(f"Expired timeout: {timeout} for: {sh_cmd}")
        exitcode = int(62)
    except FileNotFoundError:
        print_err(f"Command not found: {sh_cmd}")
        exitcode = int(2)
    except Exception:
        ex_type, ex_value, ex_traceback = sys.exc_info()
        except_msg = f'Exception:: {ex_type} -> {ex_value}\n{ex_traceback}\n'
        exitcode = int(1)

    if status:
        if status.stdout: msg_out = status.stdout.strip()
        if status.stderr: msg_err = status.stderr.strip()
        exitcode = status.returncode
    if except_msg: msg_err = f'{except_msg}\n{msg_err}'
    return RET(exitcode, msg_out, msg_err)


def is_cmd(cmd:str = '') -> bool:
    """Check if cmd is available in shell"""
    return which(cmd) is not None


if __name__ == '__main__':
    print('This file should not be executed!', file = sys.stderr, flush = True)
    sys.exit(95)
