#!/usr/bin/env python3

import sys

try:
    from alienpy import alien
except Exception as e:
    try:
        from xjalienfs import alien
    except Exception as e:
        print("Can't load alienpy, exiting...")
        sys.exit(1)


alien.setup_logging()
j = alien.AliEn()

# in the case of AliEn class the run method will process the command exactly as it is process within shell or command
# all aliases and client side implementation are available (like cp)
j.ProcessMsg('whoami -v')
print()
j.ProcessMsg('pwd')
print()
j.ProcessMsg('ll')

