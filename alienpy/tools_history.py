"""alienpy:: Setup history for interactive shell"""

import os
import sys
from pathlib import Path

from .global_vars import AlienSessionInfo
from .wb_api import lfn_list  # nosec PYL-W0614


HAS_READLINE = False

__platform = sys.platform.lower()
if __platform == 'darwin':
    try:
        import gnureadline as rl  # type: ignore  # mypy: no-redef
        HAS_READLINE = True
    except ImportError:
        pass
else:
    try:
        import readline as rl  # type: ignore
        HAS_READLINE = True
    except ImportError:
        pass


def setupHistory(wb) -> None:
    """Setup up history mechanics for readline module"""
    if not HAS_READLINE or 'AlienSessionInfo' not in globals() or not wb: return

    histfile = os.path.join(os.path.expanduser("~"), ".alienpy_history")
    if not os.path.exists(histfile): Path(histfile).touch(exist_ok = True)
    rl.set_history_length(-1)  # unlimited history
    rl.read_history_file(histfile)

    rl.parse_and_bind("tab: complete")
    rl.set_completer_delims(" ")

    def complete(text: str, state: str) -> list:
        prompt_line = rl.get_line_buffer()
        tokens = prompt_line.split()
        results = []
        if len(tokens) == 0:
            results = [f'{x} ' for x in AlienSessionInfo['commandlist']]
        elif len(tokens) == 1 and not prompt_line.endswith(' '):
            results = [f'{x} ' for x in AlienSessionInfo['commandlist'] if x.startswith(text)] + [None]
        else:
            results = lfn_list(wb, text) + [None]
        return results[state]

    rl.set_completer(complete)

    def startup_hook() -> None:
        rl.append_history_file(1, histfile)  # before next prompt save last line
    rl.set_startup_hook(startup_hook)


if __name__ == '__main__':
    print('This file should not be executed!', file = sys.stderr, flush = True)
    sys.exit(95)
