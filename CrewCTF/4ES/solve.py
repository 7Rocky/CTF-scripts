#!/usr/bin/env python3

from hashlib import sha256
from itertools import product

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


with open('output.txt') as f:
    pt = bytes.fromhex(f.readline().strip().split(' = ')[1])
    ct = bytes.fromhex(f.readline().strip().split(' = ')[1])
    enc_flag = bytes.fromhex(f.readline().strip().split(' = ')[1])

L = 3
chars = b'crew_AES*4=$!?'
char_keys = list(map(bytes, product(chars, repeat=L)))


def encrypt_aes(key, plaintext):
    return AES.new(key, AES.MODE_ECB).encrypt(plaintext)


def decrypt_aes(key, ciphertext):
    return AES.new(key, AES.MODE_ECB).decrypt(ciphertext)


def mitm():
    middle = {}

    for w in char_keys:
        k1 = sha256(w).digest()

        for x in char_keys:
            k2 = sha256(x).digest()
            enc = encrypt_aes(k2, encrypt_aes(k1, pt))
            middle[enc] = (w, x)

    for z in char_keys:
        k4 = sha256(z).digest()

        for y in char_keys:
            k3 = sha256(y).digest()
            dec = decrypt_aes(k3, decrypt_aes(k4, ct))

            if dec in middle:
                return middle[dec] + (y, z)


wxyz = mitm()
assert wxyz is not None, 'MITM attack failed'

w, x, y, z = wxyz

k1 = sha256(w).digest()
k2 = sha256(x).digest()
k3 = sha256(y).digest()
k4 = sha256(z).digest()

assert ct == encrypt_aes(k4, encrypt_aes(k3, encrypt_aes(k2, encrypt_aes(k1, pt)))), 'Wrong keys found'

key = sha256(b''.join(wxyz)).digest()
FLAG = unpad(decrypt_aes(key, enc_flag), AES.block_size)
print(FLAG.decode())
