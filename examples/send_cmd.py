#!/usr/bin/env python3

import sys
import asyncio
import json
import alien


async def session(cmd = ''):
    if not cmd: sys.exit(0)
    wb = await alien.AlienConnect()
    res = await alien.AlienSendCmd(wb, 'pwd')
    print(json.dumps(res, sort_keys=True, indent=4), flush = True)


def main():
    sys.argv.pop(0)  # remove the name of the script(alien.py)
    cmd = ' '.join(sys.argv)
    asyncio.get_event_loop().run_until_complete(session(cmd))


if __name__ == '__main__':
    main()
