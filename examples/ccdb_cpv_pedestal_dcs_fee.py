#!/usr/bin/env python3

import sys
from rich.console import Console
from rich.table import Table

# import alienpy functions
try:
    from alienpy.wb_api import retf_print
    from alienpy.tools_nowb import PrintDict, unixtime2local
    from alienpy.alien import *  # nosec PYL-W0614
except Exception:
    try:
        from xjalienfs.wb_api import retf_print
        from xjalienfs.tools_nowb import PrintDict, unixtime2local
        from xjalienfs.alien import *  # nosec PYL-W0614
    except Exception:
        print("Can't load alienpy, exiting...")
        sys.exit(1)

########################################
##   REQUIRED INITIAILZATION

# Enable and setup logging
setup_logging()  # type: ignore

console = Console()

DCS_HOST='ali-calib-dcs.cern.ch:8083'

common_dir = 'CPV/PedestalRun/'
obj_list = [ 'FEEThresholds' ]

msg_obj_list = []

table = Table(title = f"CCDB Objects in {DCS_HOST}{common_dir}", title_justify = 'center', highlight = True, pad_edge = False, padding = 0, show_edge = True)
table.add_column("Object")
table.add_column("Run")
table.add_column("Size", justify = "right")
table.add_column("LastMod")
table.add_column("ValidTo")

table_filled = False

for obj in obj_list:
    try:
        rez = DO_ccdb_query(['-host', f'{DCS_HOST}', f'/{common_dir}{obj}'])
    except Exception as e:
        console.print(e)
        break

    for q in rez.ansdict['objects']:
        run = q.get("runNumber", '-1')
        table.add_row(q["path"].replace(common_dir,""), run, str(q["Content-Length"]), unixtime2local(q["Last-Modified"]), unixtime2local(q["Valid-Until"]))
        table_filled = True

if table_filled: console.print(table)
