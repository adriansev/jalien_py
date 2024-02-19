#!/usr/bin/env bash

clean_logs () { rm -f log.txt cmdout.txt &> /dev/null; }

clean_logs
export ALIENPY_DEBUG=1 ALIENPY_DEBUG_FILE=log.txt ALIENPY_DEBUG_APPEND=1

TEST_SCRIPT="$(realpath ${0})"
THIS_TEST="$(basename $(dirname ${TEST_SCRIPT}))/$(basename ${TEST_SCRIPT})"

GOOD_RESULT="4"
EXITCODE="0"
alien.py find '/alice/cern.ch/user/a/admin/referenceData .log' &> cmdout.txt || { EXITCODE="${?}"; echo "Error running alien_find in ${THIS_TEST}!"; cat cmdout.txt; exit "${EXITCODE}"; }

FILE_COUNT=$(grep referenceData cmdout.txt | wc -l)
[[ "${FILE_COUNT}" -eq "${GOOD_RESULT}" ]] && { clean_logs; exit "${EXITCODE}"; } || { echo "Wrong count of files in ${THIS_TEST}"; exit 1; }

