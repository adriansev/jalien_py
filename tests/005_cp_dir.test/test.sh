#!/usr/bin/env bash

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

alienpy_clean_testdir () {
local TESTDIR_R TESTDIR_L
TESTDIR_R="${1}"
TESTDIR_L="${2}"
alien.py rm -rf "${TESTDIR_R}" &> /dev/null # let's try to clean up, does not matter if missing
[[ -d "${TESTDIR_L}" ]] && { rm -rf "${TESTDIR_L}" &> /dev/null; } # clean up also the local dir if prezent
}

alienpy_clean_testdir "${TESTDIR_REMOTE}" "${TESTDIR_LOCAL}"

# get the files for upload test
echo -ne "Download reference files in ${TESTDIR_LOCAL} .. "
export XRD_LOGFILE=xrdlog_download.txt
alien.py cp -retry 3 "/alice/cern.ch/user/a/admin/referenceData/*.log" "file:${TESTDIR_LOCAL}/" &> out.log || { EXITCODE="${?}"; echo "Could not download reference files in ${THIS_TEST}"; cat out.log; exit "${EXITCODE}"; }
echo "OK"

# do the upload
# use 2 + CERN for the safety of the test, we do not want a fail test due to oveloaded server
echo -ne "Uploading the ci_test_dir to GRID .. "
export XRD_LOGFILE=xrdlog_upload.txt
alien.py cp "file:${TESTDIR_LOCAL}/" "${TESTDIR_REMOTE}/@disk:2,ALICE::CERN::EOS" &> out.log || { EXITCODE="${?}"; echo "Could not upload reference files in ${THIS_TEST}"; cat out.log; exit "${EXITCODE}"; }
echo "OK"

# get the number of uploaded files
FOUND_REMOTE_FILES=$(alien.py find "${TESTDIR_REMOTE} .log" | grep ${TESTDIR_REMOTE} | wc -l)
GOOD_RESULT="4"
echo -ne "Checking correct number of uploaded files .. "
[[ "${FOUND_REMOTE_FILES}" -eq "${GOOD_RESULT}" ]] || { echo "Wrong count of files in ${THIS_TEST} but operations successful so far!! Send the logs to developer!"; exit 1; }
echo "OK"

# clean ci dir
alienpy_clean_testdir "${TESTDIR_REMOTE}" "${TESTDIR_LOCAL}"
clean_logs
exit 0
