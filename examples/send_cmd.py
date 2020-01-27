#!/usr/bin/env python3

import sys
import json
import alien


def main():
    sys.argv.pop(0)  # remove the name of the script(alien.py)
    cmd = ' '.join(sys.argv)
    out = alien.AlienSendCmd(alien.CreateJsonCommand(cmd))
    alien.PrintDict(json.loads(out))


if __name__ == '__main__':
    main()
