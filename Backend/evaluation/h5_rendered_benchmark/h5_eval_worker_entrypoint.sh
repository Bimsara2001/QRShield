#!/bin/sh
# Create a fresh NSS database for one evaluation-worker invocation. The CA
# path is supplied only by the isolated benchmark controller; normal workers
# retain their original entry point and have no access to this script.
set -eu

if [ "${QRSHIELD_H5_EVAL_MODE:-}" != "1" ]; then
    echo "H5 evaluation mode must be explicitly enabled." >&2
    exit 64
fi

ca_file="${QRSHIELD_H5_EVAL_CA_FILE:-}"
if [ -z "$ca_file" ] || [ ! -r "$ca_file" ]; then
    echo "H5 evaluation CA is unavailable." >&2
    exit 65
fi

nss_dir="${HOME}/.pki/nssdb"
mkdir -p "$nss_dir"
certutil -N -d "sql:${nss_dir}" --empty-password
certutil -A -d "sql:${nss_dir}" -n "QRShield H5 Evaluation CA" -t "C,," -i "$ca_file"

exec python /app/worker.py
