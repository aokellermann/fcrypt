#!/usr/bin/env python3

# Copyright Antony Kellermann 2020
# Usage: fcrypt.py [--encrypt|--decrypt] [<receiver_public_key>|<receiver_private_key>] <plaintext_file> <encrypted_file>

import sys
import zlib

from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Cipher import AES, PKCS1_v1_5


def write_plaintext(to_write: bytes, fname: str):
    with open(fname, "wb") as w:
        w.write(to_write)


def write_encrypted(to_write: list, fname: str):
    with open(fname, "wb") as w:
        w.write(b''.join(len(msg).to_bytes(8, byteorder='little') + msg for msg in to_write))


def read_encrypted(fname: str):
    with open(fname, "rb") as r:
        msgs = [r.read(int.from_bytes(r.read(8), byteorder='little')) for _ in range(3)]
        return msgs


def read_plaintext(fname: str):
    with open(fname, "rb") as r:
        return r.read()


if __name__ == '__main__':
    if len(sys.argv) != 5:
        print("Usage:")
        print("\tfcrypt --encrypt <receiver_public_key> <plaintext_file> <encrypted_file>")
        print("\tfcrypt --decrypt <receiver_private_key> <encrypted_file> <decrypted_file>")
        exit(1)

    sender_public_key = RSA.import_key(read_plaintext("alice.crt"))
    sender_private_key = RSA.import_key(read_plaintext("alice.key"))
    receiver_key = RSA.import_key(read_plaintext(sys.argv[2]))

    if sys.argv[1] == "--encrypt":
        message = read_plaintext(sys.argv[3])
        message_hash = SHA256.new(message)
        encrypted_hash = pkcs1_15.new(sender_private_key).sign(message_hash)
        to_zip = [encrypted_hash, message]
        zipped = [zlib.compress(msg) for msg in to_zip]
        session_key = get_random_bytes(32)
        encrypted_zipped = [AES.new(session_key, AES.MODE_OPENPGP).encrypt(z) for z in zipped]
        final_message = [PKCS1_v1_5.new(receiver_key).encrypt(session_key)] + encrypted_zipped
        write_encrypted(final_message, sys.argv[4])
        print("Successful encryption!")
    elif sys.argv[1] == "--decrypt":
        encrypted_session_key, encrypted_hash, ciphertext = tuple(read_encrypted(sys.argv[3]))
        sentinel = get_random_bytes(16)
        session_key = PKCS1_v1_5.new(receiver_key).decrypt(encrypted_session_key, sentinel)
        if session_key == sentinel:
            print("Failed to decrypt session key!")
            exit(1)
        zipped_plaintexts = []
        for to_decrypt in [encrypted_hash, ciphertext]:
            try:
                zipped_plaintexts.append(AES.new(session_key, AES.MODE_OPENPGP, iv=to_decrypt[:18]).decrypt(to_decrypt[18:]))
            except ValueError or KeyError:
                print("Failed to decrypt!")
                exit(1)

        plaintext_hash, plaintext_message = tuple(zlib.decompress(plaintext) for plaintext in zipped_plaintexts)
        try:
            pkcs1_15.new(sender_public_key).verify(SHA256.new(plaintext_message), plaintext_hash)
        except ValueError:
            print("Failed to authenticate!")
            exit(1)
        write_plaintext(plaintext_message, sys.argv[4])
        print("Successful decryption!")
