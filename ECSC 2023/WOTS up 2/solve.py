#!/usr/bin/env python3

import json
import hashlib

from Crypto.Cipher import AES

data = json.load(open('data.json'))


def decrypt(key):
    iv = bytes.fromhex(data.get('iv'))
    ct = bytes.fromhex(data.get('enc'))
    return AES.new(key, AES.MODE_CBC, iv).decrypt(ct)


pub_key = data.get('public_key')
pk = pub_key

message2 = f"{pub_key[0]} sent 999999 WOTScoins to me".encode()
m2 = list(hashlib.sha256(message2).digest())
key = [-1] * 32

for dd in data.get('signatures'):
    m1_source = list(hashlib.sha256(dd.get('message').encode()).digest())
    for i, (source, target) in enumerate(zip(m1_source, m2)):
        if source >= target:
            h1_source = bytes.fromhex(dd.get('signature')[i])
            for _ in range(source - target):
                h1_source = hashlib.sha256(h1_source).digest()
            key[i] = h1_source[0]

print(decrypt(bytes(key)).decode())
