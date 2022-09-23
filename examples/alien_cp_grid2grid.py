#!/usr/bin/env python3

import atexit
import sys
import os
from pathlib import Path
import shlex
import tempfile
import uuid
import shutil

try:
    from alienpy import alien
except Exception:
    try:
        from xjalienfs import alien
    except Exception:
        print("Can't load alienpy, exiting...")
        sys.exit(1)


def cleanup_temp(to_delete:str):
    if os.path.exists(to_delete): shutil.rmtree(to_delete)


exec_name = Path(sys.argv.pop(0)).name  # remove the name of the script
arg_list_expanded = []
for arg in sys.argv:
    for item in shlex.split(arg):
        arg_list_expanded.append(item)

DST_ARG = arg_list_expanded.pop(-1)
SRC_ARG = arg_list_expanded.pop(-1)
if SRC_ARG.startswith("file:") or DST_ARG.startswith("file:"):
    alien.print_err('This script is only for grid to grid copy')
    sys.exit(1)

DST_ARG = alien.lfn_prefix_re.sub('', DST_ARG)
SRC_ARG = alien.lfn_prefix_re.sub('', SRC_ARG)

# create local directory
tmpdir = tempfile.mkdtemp(suffix = f'_{str(uuid.uuid4())}', dir = tempfile.gettempdir())
atexit.register(cleanup_temp, tmpdir)

alien.setup_logging()
wb = alien.InitConnection()
silent = ''  # set to quiet or silet to disable output

# Stage1 - download
local_arg = f'file:{tmpdir}/'

download_args = arg_list_expanded.copy()
download_args.append(SRC_ARG)
download_args.append(local_arg)
download_results = alien.DO_XrootdCp(wb, download_args, silent)
alien.retf_print(download_results)

# Stage2 - upload
upload_args = arg_list_expanded.copy()
src_lfn = alien.specs_split.split(SRC_ARG, maxsplit = 1)[0]
if alien.pathtype_grid(wb,src_lfn) == 'f':
    local_arg = f'{local_arg}{os.path.basename(src_lfn)}'
upload_args.append(local_arg)
upload_args.append(DST_ARG)
upload_results = alien.DO_XrootdCp(wb, upload_args, silent)
alien.retf_print(upload_results)

