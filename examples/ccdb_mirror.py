#!/usr/bin/env python3

import argparse
import sys
import os
from pathlib import Path
from rich.pretty import pprint

# import alienpy functions
try:
    from alienpy.wb_api import PrintDict, retf_print
    from alienpy.alien import *  # nosec PYL-W0614
    from alienpy.tools_nowb import fileline2list
except Exception:
    print("Can't load alienpy, exiting...")
    sys.exit(1)

########################################
##   REQUIRED INITIAILZATION

# Enable and setup logging
setup_logging()  # type: ignore

# Create connection to JAliEn services
wb = InitConnection(cmdlist_func = constructCmdList)  # type: ignore

##   END OF INITIALIZATION
########################################

parser = argparse.ArgumentParser(description = 'CCDB mirror of a list of objects for a given run')

parser.add_argument('-t', '--target', nargs = 1, required = True, help = 'Base/root directory where the mirroring will be done', dest = 'dst', metavar = 'BASE_DIR')
parser.add_argument('-r', '--runnr', nargs = 1, required = True, type = int, help = 'Run number for the CCDB objects', dest = 'runnr', metavar = 'RUN_NUMBER')
parser.add_argument('-i', '--input', nargs = 1, help = 'Input file with CCDB paths to be mirrored (one per line)', dest = 'inputf', metavar = 'INPUT_FILE')

args, ccdb_paths = parser.parse_known_args()

dst_dir = os.path.realpath(args.dst[0])
if not os.path.isdir(dst_dir):
    try:
        Path(dst_dir).mkdir(parents = True, exist_ok = True)
    except Exception as e:
        print(f'{e}\nCould not create destination directory >{dst_dir}<', file = sys.stderr, flush = True)
        sys.exit(1)

runnr = args.runnr[0]

input_list = None
if args.inputf:
    input_list = fileline2list(args.inputf[0])
ccdb_paths.extend(input_list)

for path in ccdb_paths:
    mirror_args = ['-history', '-limit', '9999', '-run', runnr, '-mirror', '-dst', dst_dir, path]
    rez = DO_ccdb_query(mirror_args)
    exitcode = retf_print(rez)

