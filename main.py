#!/usr/bin/env python3

# Copyright Antony Kellermann 2020
# Usage: fcrypt.py [--encrypt|--decrypt] <receiver_public_key> <plaintext_file> <encrypted_file>

import sys
import zlib

from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Cipher import AES

if __name__ == '__main__':
    if len(sys.argv) != 5:
        print("Usage:")
        print("\tfcrypt --encrypt <receiver_public_key> <plaintext_file> <encrypted_file>")
        print("\tfcrypt --decrypt <receiver_private_key> <encrypted_file> <decrypted_file>")
        exit(1)

    with open(sys.argv[2], "r") as f:
        receiver_key = RSA.import_key(f.read())

    with open(sys.argv[3], "r") as f:
        message = bytes(f.read(), encoding="ascii")

    # https://www.freecodecamp.org/news/understanding-pgp-by-simulating-it-79248891325f/
    if sys.argv[1] == "--encrypt":
        message_hash = SHA256.new(message)  # H
        sender_private_key = RSA.generate(2048)  # PR
        encrypted_hash = pkcs1_15.new(sender_private_key).sign(message_hash)  # EH
        to_zip = [message, encrypted_hash]
        zipped = [zlib.compress(msg) for msg in to_zip]  # Z
        session_key = get_random_bytes(32)  # SecretKey
        cipher = AES.new(session_key, AES.MODE_EAX)
        nonce = cipher.nonce
        ciphertexts_and_tags = [list(cipher.encrypt_and_digest(z)) for z in zipped]
        final_message = [nonce + lst[1] + lst[0] for lst in ciphertexts_and_tags]
        final_message.append(pkcs1_15.new(receiver_key).sign(session_key))

