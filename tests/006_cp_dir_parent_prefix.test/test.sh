#!/usr/bin/env bash

# The purpose of this test is to check the mechanism of -parent and -rmprefix arguments of cp

clean_logs () { rm -rf xrdlog_*.txt xrdlog.txt log.txt cmdout.txt ci_test_dir out.log &> /dev/null ; }
clean_logs

export XRD_LOGLEVEL='Dump' XRD_LOGFILE=xrdlog.txt ALIENPY_DEBUG=1 ALIENPY_DEBUG_FILE=log.txt ALIENPY_DEBUG_APPEND=1
TEST_SCRIPT="$(realpath ${0})"
THIS_TEST="$(basename $(dirname ${TEST_SCRIPT}))/$(basename ${TEST_SCRIPT})"

ALIEN_HOME="$(ALIENPY_NO_CWD_RESTORE=yes alien.py home)"
EXITCODE="${?}"
[[ -z ${ALIEN_HOME} ]] && { echo "Could not get ALIEN_HOME in ${THIS_TEST}"; exit "${EXITCODE}"; }

NOW="$(date +%Y%m%d_%H%M%S)"
TESTDIR_REMOTE="${ALIEN_HOME}alienpy_ci_test_dir_${NOW}" # home already includes slash at the end
TESTDIR_LOCAL="ci_test_dir"

alienpy_clean_testdir_remote () {
local TESTDIR_R TESTDIR_L
TESTDIR_R="${1}"
alien.py rm -rf "${TESTDIR_R}" &> /dev/null # let's try to clean up, does not matter if missing
}

alienpy_clean_testdir_local () {
local TESTDIR_L
TESTDIR_L="${1}"
[[ -d "${TESTDIR_L}" ]] && { rm -rf "${TESTDIR_L}" &> /dev/null; } # clean up also the local dir if prezent
}

# alienpy_clean_testdir_remote "${TESTDIR_REMOTE}"
alienpy_clean_testdir_local "${TESTDIR_LOCAL}"

echo -ne "Testing downloading with -parent 2 of a file in ${TESTDIR_LOCAL} .. "
export XRD_LOGFILE=xrdlog_download.txt
alien.py cp -retry 3 -parent 2 "/alice/cern.ch/user/a/admin/referenceData/referenceData.xml" "file:${TESTDIR_LOCAL}/" &> out.log || { EXITCODE="${?}"; echo "Could not download reference files in ${THIS_TEST}"; cat out.log; exit "${EXITCODE}"; }
FILE="${TESTDIR_LOCAL}/admin/referenceData/referenceData.xml"
stat "${FILE}" &> /dev/null && { echo "OK"; rm -rf "${FILE}"; } || { echo "FAIL!! File not found in proper location"; exit 1; }

alienpy_clean_testdir_local "${TESTDIR_LOCAL}"

echo -ne "Testing downloading with -rmprefix 4 of a file in ${TESTDIR_LOCAL} .. "
export XRD_LOGFILE=xrdlog_download.txt
alien.py cp -retry 3 -rmprefix 4 "/alice/cern.ch/user/a/admin/referenceData/referenceData.xml" "file:${TESTDIR_LOCAL}/" &> out.log || { EXITCODE="${?}"; echo "Could not download reference files in ${THIS_TEST}"; cat out.log; exit "${EXITCODE}"; }
FILE="${TESTDIR_LOCAL}/admin/referenceData/referenceData.xml"
stat "${FILE}" &> /dev/null && { echo "OK"; rm -rf "${FILE}"; } || { echo "FAIL!! File not found in proper location"; exit 1; }

alienpy_clean_testdir_local "${TESTDIR_LOCAL}"
clean_logs

echo "Testing downloading with -parent 2 of dir with selection in ${TESTDIR_LOCAL} .. "
export XRD_LOGFILE=xrdlog_download.txt
alien.py cp -retry 3 -parent 2 -glob "*.log" "/alice/cern.ch/user/a/admin/referenceData/001/" "file:${TESTDIR_LOCAL}/" &> out.log || { EXITCODE="${?}"; echo "Could not download reference files in ${THIS_TEST}"; cat out.log; exit "${EXITCODE}"; }

FILE1="${TESTDIR_LOCAL}/referenceData/001/stdout.log"
FILE2="${TESTDIR_LOCAL}/referenceData/001/stderr.log"

stat "${FILE1}" &> /dev/null && { echo "OK"; rm -rf "${FILE}"; } || { echo "FAIL!! File1 not found in proper location"; exit 1; }
stat "${FILE2}" &> /dev/null && { echo "OK"; rm -rf "${FILE}"; } || { echo "FAIL!! File2 not found in proper location"; exit 1; }

alienpy_clean_testdir_local "${TESTDIR_LOCAL}"
clean_logs

echo "Testing downloading with -rmprefix 5 of dir with selection in ${TESTDIR_LOCAL} .. "
export XRD_LOGFILE=xrdlog_download.txt
alien.py cp -retry 3 -rmprefix 5 -glob "*.log" "/alice/cern.ch/user/a/admin/referenceData/001/" "file:${TESTDIR_LOCAL}/" &> out.log || { EXITCODE="${?}"; echo "Could not download reference files in ${THIS_TEST}"; cat out.log; exit "${EXITCODE}"; }

FILE1="${TESTDIR_LOCAL}/referenceData/001/stdout.log"
FILE2="${TESTDIR_LOCAL}/referenceData/001/stderr.log"

stat "${FILE1}" &> /dev/null && { echo "OK"; rm -rf "${FILE}"; } || { echo "FAIL!! File1 not found in proper location"; exit 1; }
stat "${FILE2}" &> /dev/null && { echo "OK"; rm -rf "${FILE}"; } || { echo "FAIL!! File2 not found in proper location"; exit 1; }

alienpy_clean_testdir_local "${TESTDIR_LOCAL}"
clean_logs
exit 0
