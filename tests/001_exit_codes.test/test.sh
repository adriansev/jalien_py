#!/usr/bin/env bash

rm -rf log.txt &> /dev/null
export ALIENPY_DEBUG=1 ALIENPY_DEBUG_FILE=log.txt ALIENPY_DEBUG_APPEND=1

alien.py ls
echo "ls :: Expected == 0 ; Got ${?}"

alien.py ls doesnotexist
echo "ls invalid :: Expected != 0 ; Got ${?}"

TESTDIR="test_$(date +%s)"
alien.py mkdir "${TESTDIR}"
echo "mkdir :: Expected == 0 ; Got ${?}"

alien.py rm -rf "${TESTDIR}"
echo "rm :: Expected == 0 ; Got ${?}"

alien.py mkdir "/fail/no/permissions/${TESTDIR}"
echo "rm invalid :: Expected == 0 ; Got ${?}"

alien.py "stat ."
echo "stat :: Expected == 0 ; Got ${?}"

alien.py stat /fail/no/permissions
echo "stat invalid :: Expected != 0 ; Got ${?}"
