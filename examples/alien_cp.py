#!/usr/bin/env python3
import sys
import os
import websockets
import xjalienfs.alien as alien

alien.setup_logging()
wb = alien.InitConnection()
sys.exit(alien.ProcessXrootdCp(wb, sys.argv))
