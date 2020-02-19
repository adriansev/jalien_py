#!/usr/bin/env python3

import os
import sys
import logging
from pathlib import Path
import asyncio
import websockets
import xjalienfs.alien as alien


alien.DEBUG = 1
alienpy_logfile = Path.home().as_posix() + '/alien_py_connection_time.log'
log = logging.basicConfig(filename=alienpy_logfile, filemode='w', level=logging.DEBUG)

sys.argv.pop(0)  # remove the name of the script(alien.py)
logger_wb = logging.getLogger('websockets')
if 'wbdebug' in sys.argv:
    logger_wb.setLevel(logging.DEBUG)
else:
    logger_wb.setLevel(logging.ERROR)

wb = alien.AlienConnect()

