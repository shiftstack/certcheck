#!/usr/bin/env bash

set -Eeuo pipefail

declare -r \
	kind="${1:-valid}" \
        domain_name='certcheck.example.com' \
        ca_key='caKey.pem' \
        ca_cert='caCert.pem' \
        server_key='serverKey.pem' \
        server_csr='serverCert.csr' \
        server_cert='serverCert.pem'

server_conf() {
        cat <<- EOF
		[req]
		req_extensions = v3_req
		distinguished_name = req_distinguished_name
		[req_distinguished_name]
		[ v3_req ]
		basicConstraints = CA:FALSE
		keyUsage = nonRepudiation, digitalSignature, keyEncipherment
		extendedKeyUsage = clientAuth, serverAuth
	EOF
	
	if [ "$kind" == 'valid' ]; then
		cat <<- EOF
			subjectAltName = @alt_names
			[alt_names]
			DNS.1 = ${domain_name}
		EOF
	fi
}

# Generate a CA
openssl genrsa -out "$ca_key" 2048
openssl req \
        -x509 -new \
        -nodes \
        -key "$ca_key" \
        -days 1000 \
        -subj '/CN=test_ca' \
        -out "$ca_cert"

# Server creates a Certificate Signing Request
openssl genrsa -out "$server_key" 2048
openssl req \
        -new \
        -key "$server_key" \
        -out "$server_csr" \
        -subj "/CN=${domain_name}" \
        -config <(server_conf)

# CA signs the certificate
openssl x509 \
        -req \
        -days 1000 \
        -in "$server_csr" \
        -CA "$ca_cert" \
        -CAkey "$ca_key" \
        -CAcreateserial \
        -extensions v3_req \
        -extfile <(server_conf) \
        -out "$server_cert"
