#!/usr/bin/env python3

from pathlib import Path
import xjalienfs.alien as alien

alien.DEBUG = 1
alien.DEBUG_FILE = Path.home().as_posix() + '/alien_py_connection_time.log'
alien.setup_logging()
wb = alien.AlienConnect()

