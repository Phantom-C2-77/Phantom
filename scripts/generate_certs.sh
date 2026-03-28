#!/bin/bash
# Generate self-signed TLS certificates for Phantom C2

set -e

CERT_DIR="configs"
DAYS=365
CN="phantom.local"

echo "[*] Generating self-signed TLS certificate..."
echo "    CN: ${CN}"
echo "    Valid for: ${DAYS} days"
echo ""

openssl req -x509 -newkey rsa:2048 \
    -keyout "${CERT_DIR}/server-tls.key" \
    -out "${CERT_DIR}/server.crt" \
    -days ${DAYS} \
    -nodes \
    -subj "/C=US/ST=State/L=City/O=Phantom/CN=${CN}" \
    2>/dev/null

echo "[+] Certificate: ${CERT_DIR}/server.crt"
echo "[+] Private key: ${CERT_DIR}/server-tls.key"
echo ""
echo "[*] Certificate details:"
openssl x509 -in "${CERT_DIR}/server.crt" -noout -subject -dates
