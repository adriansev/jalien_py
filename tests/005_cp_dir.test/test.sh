#!/usr/bin/env bash

clean_logs () { rm -rf xrdlog.txt xrdlog_*.txt log.txt cmdout.txt ci_test_dir &> /dev/null ; }
clean_logs

export XRD_LOGLEVEL='Dump' XRD_LOGFILE=xrdlog.txt ALIENPY_DEBUG=1 ALIENPY_DEBUG_FILE=log.txt ALIENPY_DEBUG_APPEND=1
TEST_SCRIPT="$(realpath ${0})"
THIS_TEST="$(basename $(dirname ${TEST_SCRIPT}))/$(basename ${TEST_SCRIPT})"

ALIEN_HOME="$(ALIENPY_NO_CWD_RESTORE=yes alien.py home)"
[[ -z ${ALIEN_HOME} ]] && { echo "Could not get ALIEN_HOME in ${THIS_TEST}"; exit 1; }

NOW="$(date +%Y%m%d_%H%M%S)"
WORKSPACE="${ALIEN_HOME}ci_test_dir_${NOW}" # home already includes slash at the end

echo "Clean up WORKSPACE: ${WORKSPACE}"
alien.py rm -rf "${WORKSPACE}" &> /dev/null # let's try to clean up, does not matter if missing
[[ -d ci_test_dir ]] && rm -rf ci_test_dir # clean up also the local dir

# get the files for upload test
echo "Downlod reference files in local ci_test_dir"
alien.py cp -retry 3 "/alice/cern.ch/user/a/admin/referenceData/*.log" "file:ci_test_dir/" ||  { echo "Could not download reference files in ${THIS_TEST}"; exit 1; }
mv xrdlog.txt xrdlog_download.txt

# do the upload
# use 2 + CERN for the safety of the test, we do not want a fail test due to oveloaded server
echo "Uploading the ci_test_dir to GRID"
alien.py cp "file:ci_test_dir/" "${WORKSPACE}/@disk:2,ALICE::CERN::EOS"
mv xrdlog.txt xrdlog_upload.txt

# get the number of uploaded files
FOUND_REMOTE_FILES=$(alien.py find "${WORKSPACE} .log" | grep ${WORKSPACE} | wc -l)
GOOD_RESULT="4"
[[ "${FOUND_REMOTE_FILES}" -eq "${GOOD_RESULT}" ]] && { echo "OK"; clean_logs; }  || { echo "Wrong count of files in ${THIS_TEST}"; exit 1; }

# clean ci dir
echo "Clean up WORKSPACE: ${WORKSPACE}"
alien.py rm -rf "${WORKSPACE}"
clean_logs
exit 0
