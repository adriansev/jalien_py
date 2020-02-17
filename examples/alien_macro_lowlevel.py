#!/usr/bin/env python3

import os
import sys
import websockets
import xjalienfs.alien as alien

# token_args: Union[None, list] = None, use_usercert: bool = False
wb = alien.InitConnection()

cmd = 'ls -la /alice'
result = alien.SendMsg_str(wb, cmd)
json_dict = alien.GetDict(result)
alien.PrintDict(json_dict)

