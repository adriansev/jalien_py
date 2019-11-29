#!/usr/bin/env python3

import sys
import json
import alien


def main():
    sys.argv.pop(0)  # remove the name of the script(alien.py)
    cmd = ' '.join(sys.argv)
    out = alien.AlienSendCmd(alien.CreateJsonCommand(cmd))
    print(json.dumps(out, sort_keys=True, indent=4), flush = True)


if __name__ == '__main__':
    main()
