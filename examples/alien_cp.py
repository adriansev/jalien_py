#!/usr/bin/env python3
import sys

try:
    from alienpy import alien
except Exception:
    try:
        from xjalienfs import alien
    except Exception:
        print("Can't load alienpy, exiting...")
        sys.exit(1)


alien.setup_logging()
wb = alien.InitConnection()
silent = ''  # set to quiet or silet to disable output
sys.exit(alien.retf_print(alien.DO_XrootdCp(wb, sys.argv, silent)))
