#!/usr/bin/env python3

from hashlib import sha256
from pwn import process, remote, sys


def get_process():
    if len(sys.argv) == 1:
        return process(['python3', 'server.py'], level='DEBUG')

    host, port = sys.argv[1], sys.argv[2]
    return remote(host, port)


'''
>>> from hashlib import sha256
>>> import os
>>>
>>> while True:
...     msg = os.urandom(32)
...     h = sha256(msg).digest()
...     if all(hh >= 0x80 for hh in h):
...         break
>>> msg
b'\xa8\xf1\x16\xa4\xf6#sH|\xa4\xbbV\xc5\x08\xeaY\x1b\xc8\x0f\x9bbC:\x19\x0c\xd8i\x1d*\xa7M)'
>>>
>>>
>>> while True:
...     msg = os.urandom(32)
...     h = sha256(msg).digest()
...     if all(hh < 0x80 for hh in h):
...         break
>>> msg
b'C:\xe5\xf71\xec\xf7![n/\xaa\xed6\xbb\xdd\x14\xc8\xd6E\xb7\xc0\n}9\x19\x13\xd3g\x1a\x86\xc3'
'''


def sha256_n(msg, n):
    for _ in range(n):
        msg = sha256(msg).digest()
    return msg


msg1 = b'\xa8\xf1\x16\xa4\xf6#sH|\xa4\xbbV\xc5\x08\xeaY\x1b\xc8\x0f\x9bbC:\x19\x0c\xd8i\x1d*\xa7M)'
msg2 = b'C:\xe5\xf71\xec\xf7![n/\xaa\xed6\xbb\xdd\x14\xc8\xd6E\xb7\xc0\n}9\x19\x13\xd3g\x1a\x86\xc3'

h1, h2 = sha256_n(msg1, 1), sha256_n(msg2, 1)
assert all(a > b for a, b in zip(h1, h2))

io = get_process()

io.sendlineafter(b'give me a message (hex): ', msg1.hex().encode())
io.recvuntil(b'here is the signature (hex): ')
sig1 = bytes.fromhex(io.recvline().decode())

sig2 = b''

for i in range(0, len(sig1), 32):
    sig2 += sha256_n(sig1[i: i + 32], h1[i // 32] - h2[i // 32])

io.sendlineafter(b'give me a new message (hex): ', msg2.hex().encode())
io.sendlineafter(b'give me the signature (hex): ', sig2.hex().encode())
io.success(io.recvline().decode())
