#!/usr/bin/env bash

set -Eeuo pipefail

declare -r url="$1"
declare \
	host='' \
	port='' \
	san='' \
	noschema=''
san="$(mktemp)"
readonly san

trap "rm -f '$san'" EXIT

# Ignore HTTP endpoints
if [[ ${url#"http://"} != "$url" ]]; then
	echo "WARNING: ${url} is not an HTTPS endpoint"
	exit 0
fi

# Remove the schema from the URL
noschema=${url#"https://"}

# Remove the path and only keep host and port
noschema="${noschema%%/*}"
host="${noschema%%:*}"
port="${noschema##*:}"

# Add the port if was implicit
if [[ "$port" == "$host" ]]; then
	port='443'
fi

# Get the SAN fields
openssl s_client -showcerts -servername "$host" -connect "$host:$port" </dev/null 2>/dev/null \
	| openssl x509 -noout -ext subjectAltName \
	> "$san"

# openssl returns the empty string if no SAN is found.
# If a SAN is found, openssl is expected to return something like:
#
#    X509v3 Subject Alternative Name:
#        DNS:standalone, DNS:osp1, IP Address:192.168.2.1, IP Address:10.254.1.2
if [[ "$(grep -c "Subject Alternative Name" "$san" || true)" -gt 0 ]]; then
	echo "PASS: ${url}"
	exit 0
else
	echo "INVALID (missing SAN): ${url}"
	exit 1
fi
