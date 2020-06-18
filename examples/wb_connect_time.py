#!/usr/bin/env python3

import os
import sys
import logging
from pathlib import Path
import time
from datetime import datetime, timezone
import traceback
import statistics
import math
import alienpy.alien as alien

alien.setup_logging()

jalien_websocket_port = os.getenv("ALIENPY_JCENTRAL_PORT", '8097')  # websocket port
jalien_websocket_path = '/websocket/json'
jalien_server = os.getenv("ALIENPY_JCENTRAL", 'alice-jcentral.cern.ch')  # default value for JCENTRAL
connect_tries = int(os.getenv('ALIENPY_CONNECT_TRIES', 3))
connect_tries_interval = int(os.getenv('ALIENPY_CONNECT_TRIES_INTERVAL', 0.5))
use_usercert = False
localConnect = False


def do_wb_connect():
    wb = None
    nr_tries = 0
    init_delta = float(-999.0)
    init_begin = datetime.now().timestamp()
    while wb is None:
        try:
            nr_tries += 1
            wb = alien.wb_create(jalien_server, str(jalien_websocket_port), jalien_websocket_path, use_usercert, localConnect)
        except Exception as e:
            logging.debug(traceback.format_exc())
        if not wb:
            if nr_tries + 1 > connect_tries:
                logging.debug(f"We tried on {jalien_server}:{jalien_websocket_port}{jalien_websocket_path} {nr_tries} times")
                break
            time.sleep(connect_tries_interval)

    init_end = datetime.now().timestamp()
    init_delta = float((init_end - init_begin) * 1000)
    if wb:
        alien.wb_close(wb, 1000, "just close")
        return init_delta
    else:
        return float(999999.0)


if len(sys.argv) > 1 and sys.argv[0].isdigit():
    count = int(sys.argv[0])
else:
    count = int(3)
if count < 1: count = 1

results = []
for i in range(count):
    p = do_wb_connect()
    results.append(p)

rtt_min = min(results)
rtt_max = max(results)
rtt_avg = statistics.mean(results)
rtt_stddev = statistics.stdev(results) if len(results) > 1 else 0.0
print(f"Websocket connect time : {count} time(s) to {jalien_server}\nrtt min/avg/max/mdev (ms) = {rtt_min:.3f}/{rtt_avg:.3f}/{rtt_max:.3f}/{rtt_stddev:.3f}", flush = True)








