#!/usr/bin/env bash

clean_logs () { rm -f log.txt xrdlog.txt referenceData.xml out.log &> /dev/null; }

clean_logs
export XRD_LOGLEVEL='Dump' XRD_LOGFILE=xrdlog.txt ALIENPY_DEBUG=1 ALIENPY_DEBUG_FILE=log.txt ALIENPY_DEBUG_APPEND=1

TEST_SCRIPT="$(realpath ${0})"
THIS_TEST="$(basename $(dirname ${TEST_SCRIPT}))/$(basename ${TEST_SCRIPT})"

dst="referenceData.xml"
[[ -f "${dst}" ]] && rm -f ${dst}
alien.py cp -retry 2 /alice/cern.ch/user/a/admin/referenceData/referenceData.xml "file:${dst}" &> out.log && { clean_logs; } || { EXITCODE="${?}"; echo "Failed download in ${THIS_TEST} with code ${EXITCODE}"; cat out.log; exit ${EXITCODE}; }

