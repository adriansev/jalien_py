#!/usr/bin/env python3

import sys

# import alienpy functions
try:
    from alienpy.wb_api import PrintDict, retf_print
    from alienpy.alien import *  # nosec PYL-W0614
except Exception:
    try:
        from xjalienfs.wb_api import PrintDict, retf_print
        from xjalienfs.alien import *  # nosec PYL-W0614
    except Exception:
        print("Can't load alienpy, exiting...")
        sys.exit(1)

# enable automatic pretty printing
from rich import print

########################################
##   REQUIRED INITIAILZATION

# Enable and setup logging
setup_logging()  # type: ignore

common_dir = 'MFT/Calib/'
obj_list = [ 'MFT/Calib/NoiseMap']

header = f'Check objects in >>> {common_dir} <<<\nObject{" "*2}Run{" "*5}Size{" "*5}LastMod{" "*25}Valid'
msg_obj_list = []

for obj in obj_list:
    rez = DO_ccdb_query([obj])
    for q in rez.ansdict['objects']:
        run = q.get("runNumber", '-1')
        msg_obj_list.append(f'{q["path"].replace(common_dir,"")}  {run}  {q["Content-Length"]}  \"{q["Last-Modified"]}\"  \"{q["Valid-Until"]}\"')

msg_obj = f'{os.linesep}'.join(msg_obj_list) if msg_obj_list else ''
if msg_obj: msg_obj = f'{header}\n{msg_obj}'
print(msg_obj)

