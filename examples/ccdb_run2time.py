#!/usr/bin/env python3

import argparse
import sys
import os
from pathlib import Path
from rich.pretty import pprint

# import alienpy functions
try:
    from alienpy.wb_api import retf_print
    from alienpy.alien import *  # nosec PYL-W0614
    from alienpy.tools_nowb import fileline2list, unixtime2local, PrintDict
except Exception:
    try:
        from xjalienfs.wb_api import retf_print
        from xjalienfs.alien import *  # nosec PYL-W0614
        from xjalienfs.tools_nowb import fileline2list, unixtime2local, PrintDict
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

parser = argparse.ArgumentParser(description = 'CCDB :: get Start/Stop for run')
parser.add_argument('runnr', nargs = '+', help = 'Run number or a list of run numbers')
parser.add_argument('-json', help = 'JSON output', action='store_true')
args = parser.parse_known_args()

rez_list = []
for r in args[0].runnr:
    run_info = ccdb_runinfo(r)
    if not 'objects' in run_info or not run_info['objects']:
        print(f'No information found for {r}', file = sys.stderr, flush = True)
        continue

    sor_nice = unixtime2local(run_info['objects'][0]['SOR'])
    eor_nice = unixtime2local(run_info['objects'][0]['EOR'])

    r_info = { 'run': r,
               'sor': run_info['objects'][0]['SOR'], 'eor': run_info['objects'][0]['EOR'],
               'sor_nice': sor_nice, 'eor_nice': eor_nice}

    if 'STF' in run_info['objects'][0]:
        r_info['stf'] = run_info['objects'][0]['STF']
        r_info['stf_nice'] = unixtime2local(run_info['objects'][0]['STF'])

    if 'ETF' in run_info['objects'][0]:
        r_info['etf'] = run_info['objects'][0]['ETF']
        r_info['etf_nice'] = unixtime2local(run_info['objects'][0]['ETF'])

    if 'SOX' in run_info['objects'][0]:
        r_info['sox'] = run_info['objects'][0]['SOX']
        r_info['sox_nice'] = unixtime2local(run_info['objects'][0]['SOX'])

    if 'EOX' in run_info['objects'][0]:
        r_info['eox'] = run_info['objects'][0]['EOX']
        r_info['eox_nice'] = unixtime2local(run_info['objects'][0]['EOX'])

    rez_list.append(r_info)

# rezults presentation
if args[0].json:
    PrintDict(rez_list)
    sys.exit()

for i in rez_list:
    print(f'run="{i["run"]}"  sor="{i["sor"]}"  eor="{i["eor"]}"  sor_nice="{i["sor_nice"]}"  eor_nice="{i["eor_nice"]}"')

