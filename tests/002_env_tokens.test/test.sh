#!/usr/bin/env bash

clean_logs () { rm -f log.txt &> /dev/null; }

command -v alien.py &> /dev/null || { echo "alien.py command not found; skip test"; exit; }

export ALIENPY_DEBUG=1 ALIENPY_DEBUG_FILE=log.txt ALIENPY_DEBUG_APPEND=1
clean_logs

tokens_backup () {
echo ${1}
echo ${2}
mv "${1}" "${1}_backup"
mv "${2}" "${2}_backup"
}

tokens_restore () {
mv "${1}_backup" "${1}"
mv "${2}_backup" "${2}"
}

TMPDIR=${TMPDIR:-/tmp}
FILECERT="${TMPDIR}/tokencert_$(id -u).pem"
FILEKEY="${TMPDIR}/tokenkey_$(id -u).pem)"

# Clear env if set
unset ${JALIEN_TOKEN_CERT} ${JALIEN_TOKEN_KEY}

# backup tokens
tokens_backup "${FILECERT}" "${FILEKEY}"

exit

# check that error is thrown if tokens are missing
alien-token-info &> /dev/null && { echo "exitcode == 0 when it should fail"; exit 1; }

export JALIEN_TOKEN_CERT="$(< ${FILECERT})"
export JALIEN_TOKEN_KEY="$(< ${FILEKEY})"
alien-token-info &> /dev/null || { echo "No alien token found"; tokens_restore "${FILECERT}" "${FILEKEY}"; exit 1; }

alien.py pwd &> /dev/null && { clean_logs; } || { echo "Error running pwd"; tokens_restore "${FILECERT}" "${FILEKEY}"; exit 1; }

tokens_restore "${FILECERT}" "${FILEKEY}"

