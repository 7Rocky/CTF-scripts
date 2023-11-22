#!/usr/bin/env python3

from chal import AES, hashlib, json, Winternitz

data = json.load(open('data.json'))
priv = [bytes.fromhex(data.get('signature')[0])]

while len(priv) != 32:
    priv.append(hashlib.sha256(priv[-1]).digest())

w = Winternitz()
w.priv_key = priv

message2 = b"Sign for flag"
signature2 = w.sign(message2)

ct, iv = map(bytes.fromhex, [data.get('enc'), data.get('iv')])

aes_key = bytes([s[0] for s in signature2])
cipher = AES.new(aes_key, AES.MODE_CBC, iv)
print(cipher.decrypt(ct).decode())
