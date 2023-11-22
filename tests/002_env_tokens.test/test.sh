#!/usr/bin/env bash

command -v alien.py &> /dev/null || { echo "alien.py command not found; skip test"; exit; }

export ALIENPY_DEBUG=1 ALIENPY_DEBUG_FILE=log.txt ALIENPY_DEBUG_APPEND=1
rm -f log.txt &> /dev/null

tokens_backup () {
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

[[ -z "${JALIEN_TOKEN_CERT}" ]] && export JALIEN_TOKEN_CERT_BCK="$(< ${FILECERT})"
[[ -z "${JALIEN_TOKEN_KEY}" ]] && export JALIEN_TOKEN_KEY_BCK="$(< ${FILEKEY})"

tokens_backup "${FILECERT}" "${FILEKEY}"

# check that error is thrown if tokens are missing
alien-token-info &> /dev/null && { echo "exitcode == 0 when it should fail"; exit 1; }

# have the proken JALIEN_ variables with the token content
export JALIEN_TOKEN_CERT="${JALIEN_TOKEN_CERT_BCK}"
export JALIEN_TOKEN_KEY="${JALIEN_TOKEN_KEY_BCK}"
alien-token-info &> /dev/null || { echo "No alien token found"; tokens_restore "${FILECERT}" "${FILEKEY}"; exit 1; }

alien.py pwd &> /dev/null && rm -rf log.txt || { echo "Error running pwd"; tokens_restore "${FILECERT}" "${FILEKEY}"; exit 1; }

tokens_restore "${FILECERT}" "${FILEKEY}"

