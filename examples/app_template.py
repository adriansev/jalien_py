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

# Running commands
# There are 2 ways to run commands:
# 1. The actual client interface:
#    ProcessCommandChain(wb, cmd_chain: str = '') -> int
#       wb is the connection socket (created above)
#       cmd_chain is the string that defines the command (or ";" delimited array of commands)
#     return the exitcode of the command (or last command from array)
# 2. The programmatic way, where ProcessInput is used for individual network-related commands
#    and the client-side commands are to be used directly
#    ProcessInput(wb, cmd: str, args: Union[list, None] = None, shellcmd: Union[str, None] = None) -> RET
#       wb is the connection socket (created above)
#       cmd is the command(verb) - is a single individual command
#       arsg is a list of arguments, individual strings per each element
#       shellcmd is the shell command that will process the output of JAliEn command (right side of the pipe)
#     returns a RET object
#       with the members: exitcode:int, out: str, err: str, ansdict: dict
#           ansdict being the dictionary of the answer received from the server
#       the member function: print(opts:str)
#           where options being:
#               json : prints the string form of the returned dictionary
#               if exitcode == 0 : noout|noprint will disable the printing of the "out" string
#               if exitcode !=0  :
#                   info|warn|err|debug will log the error string of the object to the corresponding facilities
#                   noerr|noprint will disable the printing of the "err" string

# client style interaction - single command
ret_int = ProcessCommandChain(wb, 'pwd')  # type: ignore
print(f'exit code of above command: {ret_int}\n')

# client style interaction - multiple commands
ret_int = ProcessCommandChain(wb, 'll; whoami -v')  # type: ignore
print(f'exit code of above command: {ret_int}\n')

# programmatic interaction
# all DO_ functions (implementations of commands) (with the exception of ProcessCommandChain) return a RET object
ret_obj = ProcessInput(wb, 'ls', ['-c', '/alice/cern.ch/user/a/admin/referenceData'])  # type: ignore
print(f'This is the response object:\n{ret_obj}\n')

# In principle, the dictionary output of command have more information than stdout/stderr of the command
# and is programmatically easier to work with
print('This is the dictionary form of the server response:')
PrintDict(ret_obj.ansdict)
print('\n')

# Example of usage of find
# N.B.!
# '-a' : show all files (including name beginning with dot)
# '-s' : do not sort the answer
# '-r' : make find to interpret pattern as regex
# '-f' : fill the answer dictionary with all file properties, so selections can be easily applied
ret_obj = ProcessInput(wb, 'find', ['-f', '-a', '-s', '/alice/cern.ch/user/a/admin/referenceData', 'std*.log'])  # type: ignore
print('Example of find usage:')
PrintDict(ret_obj.ansdict)
print('\n')

print('Example of selection (size > 40000):')
selection_list = [item for item in ret_obj.ansdict['results'] if int(item['size']) > 40000]
for i in selection_list: print(f'{i}')
print('\n')

# Client-side, functions (that do not require the JAliEn connection) can be used directly
# in fact _ANYTHING_ can be used directly but it require the study of alien.py code
print('Usage of direct usage of token-info command implementation:')
ret_obj = DO_tokeninfo()  # type: ignore

## def retf_print(ret_obj: RET, opts: str = '') -> int:
## Process a RET object; it will return the exitcode
## opts content will steer the logging and message printing:
## - noprint : silence all stdout/stderr printing
## - noerr/noout : silence the respective messages
## - info/warn/err/debug : will log the stderr to that facility
## - json : will print just the json of the RET object (if present)
cmd_exitcode = retf_print(ret_obj)

