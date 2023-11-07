"""alienpy:: command stack manipulation"""

import sys
from collections import deque

from .global_vars import AlienSessionInfo


def push2stack(path: str) -> None:
    if not str or 'AlienSessionInfo' not in globals(): return
    home = ''
    if AlienSessionInfo['alienHome']: home = AlienSessionInfo['alienHome'][:-1]
    if home and home in path: path = path.replace(home, '~')
    AlienSessionInfo['pathq'].appendleft(path)


def deque_pop_pos(dq: deque, pos: int = 1) -> str:
    if abs(pos) > len(dq) - 1: return ''
    pos = - pos
    dq.rotate(pos)
    val = ''
    if pos > 0:
        val = dq.pop()
        if len(dq) > 1: dq.rotate(- (pos - 1))
    else:
        val = dq.popleft()
        if len(dq) > 1: dq.rotate(abs(pos) - 1)
    return val  # noqa: R504


if __name__ == '__main__':
    print('This file should not be executed!', file = sys.stderr, flush = True)
    sys.exit(95)
