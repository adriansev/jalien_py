#!/usr/bin/env python3
import sys
import alienpy.alien as alien

alien.setup_logging()
wb = alien.InitConnection()
silent = ''  # set to quiet or silet to disable output
sys.exit(alien.retf_print(alien.DO_XrootdCp(wb, sys.argv, silent)))
