#!/usr/bin/env python3

import sys

# import alienpy functions
try:
    from alienpy.wb_api import PrintDict, retf_print
    from alienpy.tools_nowb import unixtime2local
    from alienpy.alien import *  # nosec PYL-W0614
except Exception:
    try:
        from xjalienfs.wb_api import PrintDict, retf_print
        from xjalienfs.tools_nowb import unixtime2local
        from xjalienfs.alien import *  # nosec PYL-W0614
    except Exception:
        print("Can't load alienpy, exiting...")
        sys.exit(1)

from rich.console import Console
from rich.table import Table

########################################
##   REQUIRED INITIAILZATION

# Enable and setup logging
setup_logging()  # type: ignore

common_dir = 'ITS/Calib/'
obj_list = [ 'ITS/Calib/THR']

msg_obj_list = []

table = Table(title = f"CCDB Objects in {common_dir}", title_justify = 'center', highlight = True, pad_edge = False, padding = 0, show_edge = True)
table.add_column("Object")
table.add_column("Run")
table.add_column("Size", justify = "right")
table.add_column("LastMod")
table.add_column("ValidTo")

for obj in obj_list:
    rez = DO_ccdb_query([obj])
    for q in rez.ansdict['objects']:
        run = q.get("runNumber", '-1')
        table.add_row(q["path"].replace(common_dir,""), str(run), str(q["Content-Length"]), str(unixtime2local(q["Last-Modified"])), str(unixtime2local(q["Valid-Until"])))

console = Console()
console.print(table)
