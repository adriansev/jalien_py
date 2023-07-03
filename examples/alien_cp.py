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
#from rich import print

########################################
##   REQUIRED INITIAILZATION

# Enable and setup logging
setup_logging()  # type: ignore

# Create connection to JAliEn services
wb = InitConnection(cmdlist_func = constructCmdList)  # type: ignore

##   END OF INITIALIZATION
########################################

silent = ''  # set to quiet or silet to disable output
sys.exit(retf_print(DO_XrootdCp(wb, sys.argv, silent)))

