#!/usr/bin/env python3

# import shutil
# import os
import sys

try:
    from alienpy import alien
except Exception:
    try:
        from xjalienfs import alien
    except Exception:
        print("Can't load alienpy, exiting...")
        sys.exit(1)


alien.setup_logging()
j = alien.AliEn()

f_client_nowb = {**alien.AlienSessionInfo['cmd2func_map_nowb']}
f_client_wb = {**alien.AlienSessionInfo['cmd2func_map_client']}
f_server_wb = {**alien.AlienSessionInfo['cmd2func_map_srv']}


def help2markup(cmd: str):
    if not cmd: return
    if cmd in f_client_nowb:  # these commands do NOT need wb connection
        result = f_client_nowb[cmd](['-h'])
    if cmd in f_client_wb:  # lookup in client-side implementations list
        result = f_client_wb[cmd](j.wb(), ['-h'])
    elif cmd in f_server_wb:  # lookup in server-side list
        result = f_server_wb[cmd](j.wb(), cmd, ['-h'])
    else:
        return
    if not result.out: return
    help_txt = result.out
    help_txt = help_txt.replace('                ', '')
    alien.print_out(f'\n### {cmd}\n```\n{help_txt}\n```\n')
    if cmd in alien.AlienSessionInfo['cmd2func_map_nowb']:
        alien.print_out('!!! warning "client-side implementation"\n\n!!! note "No connection to central servers needed"\n')
    if cmd in alien.AlienSessionInfo['cmd2func_map_client']:
        alien.print_out('!!! warning "client-side implementation"\n')
    alien.print_out('---')


alien.print_out('# alien.py Command reference guide')
for c in alien.AlienSessionInfo['commandlist']: help2markup(c)
print()

