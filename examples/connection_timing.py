#!/usr/bin/env python3

import os
import sys
import logging
from pathlib import Path
import asyncio
import websockets
import alien


DEBUG = 1
TIME_CONNECT = 1

# alien.py log file
alienpy_logfile = Path.home().as_posix() + '/alien_py_connection_time.log'
MSG_LVL = logging.DEBUG
log = logging.basicConfig(filename=alienpy_logfile, filemode='w', level=MSG_LVL)

logger_wb = logging.getLogger('websockets')
logger_wb.setLevel(MSG_LVL)

asyncio.get_event_loop().run_until_complete(alien.AlienConnect())
os._exit(int(0))

