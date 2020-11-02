#!/usr/bin/env bash

set -eo pipefail

trap "echo 'Tests failed!'" ERR
trap "rm -f plaintext_test_file ciphertext_test_file decrypted_file alice* bob*" EXIT

echo "Starting tests..."

openssl genrsa 2048 > alice.key 2>/dev/null && chmod 400 alice.key
echo -e "\n\n\n\n\n\n\n" | openssl req -new -x509 -nodes -sha256 -days 365 -key alice.key -out alice.crt &>/dev/null
openssl genrsa 2048 > bob.key 2>/dev/null && chmod 400 bob.key
echo -e "\n\n\n\n\n\n\n" | openssl req -new -x509 -nodes -sha256 -days 365 -key bob.key -out bob.crt &>/dev/null

dd if=/dev/urandom of=plaintext_test_file bs=65536 count=1 &>/dev/null
python3 fcrypt.py --encrypt bob.crt plaintext_test_file ciphertext_test_file
python3 fcrypt.py --decrypt bob.key ciphertext_test_file decrypted_file
cmp --silent plaintext_test_file decrypted_file

echo "Tests succeeded!"
