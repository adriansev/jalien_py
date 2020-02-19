#!/usr/bin/env python3

import os
import sys
import websockets
import xjalienfs.alien as alien

# token_args: Union[None, list] = None, use_usercert: bool = False
wb = alien.InitConnection()

cmd = 'pwd'
alien.ProcessInput(wb, cmd)
print('', flush = True)

cmd = 'whoami'
alien.ProcessInput(wb, cmd)
print('', flush = True)

cmd = 'lla'
bash_cmd = 'head -n3'
alien.ProcessInput(wb, cmd, bash_cmd)

