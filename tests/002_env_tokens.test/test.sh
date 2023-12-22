#!/usr/bin/env bash

clean_logs () { rm -f log.txt output.txt &> /dev/null; }

command -v alien.py &> /dev/null || { echo "alien.py command not found; skip test"; exit; }

export ALIENPY_DEBUG=1 ALIENPY_DEBUG_FILE=log.txt ALIENPY_DEBUG_APPEND=1
clean_logs
# Clear env if set
unset ${JALIEN_TOKEN_CERT} ${JALIEN_TOKEN_KEY}

tokens_backup () {
token1="$(realpath ${1})"
shift
token2="$(realpath ${1})"
shift
mv -f "${token1}" "${token1}_backup"
mv -f "${token2}" "${token2}_backup"
}

tokens_restore () {
token1="$(realpath ${1})"
shift
token2="$(realpath ${1})"
shift
mv -f "${token1}_backup" "${token1}"
mv -f "${token2}_backup" "${token2}"
}

TMPDIR=${TMPDIR:-/tmp}
FILECERT="${TMPDIR}/tokencert_$(id -u).pem"
FILEKEY="${TMPDIR}/tokenkey_$(id -u).pem"

# backup tokens
tokens_backup "${FILECERT}" "${FILEKEY}"

# check that error is thrown if tokens are missing
alien-token-info &>> output.txt && { echo "The missing tokens case should fail"; exit 1; }

export JALIEN_TOKEN_CERT="$(< ${FILECERT}_backup)"
export JALIEN_TOKEN_KEY="$(< ${FILEKEY}_backup)"
alien-token-info &>> output.txt || { echo "FAIL! No alien token found"; STATUS="1"; } && { echo "OK! valid tokens found in environment"; STATUS="0"; }
[[ "${STATUS}" == "1" ]] && { tokens_restore "${FILECERT}" "${FILEKEY}"; exit ${STATUS}; }

alien.py pwd &>> output.txt && { echo "OK! valid connection to JAliEn services"; STATUS="0"; clean_logs; } || { echo "FAIL! error connecting to JAliEn Services"; STATUS="1"; }
tokens_restore "${FILECERT}" "${FILEKEY}";
exit ${STATUS};

