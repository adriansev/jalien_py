#!/usr/bin/env python3
import sys
import os
import websockets
import alienpy.alien as alien

alien.setup_logging()
wb = alien.InitConnection()
sys.exit(alien.retf_print(alien.ProcessXrootdCp(wb, sys.argv)))
