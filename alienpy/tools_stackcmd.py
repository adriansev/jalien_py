"""alienpy:: command stack manipulation"""

import collections
from .global_vars import *  # nosec PYL-W0614


deque = collections.deque

def push2stack(path: str):
    if not str: return
    home = ''
    if AlienSessionInfo['alienHome']: home = AlienSessionInfo['alienHome'][:-1]
    if home and home in path: path = path.replace(home, '~')
    AlienSessionInfo['pathq'].appendleft(path)


def deque_pop_pos(dq: deque, pos: int = 1) -> str:
    if abs(pos) > len(dq) - 1: return ''
    pos = - pos
    dq.rotate(pos)
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
    

