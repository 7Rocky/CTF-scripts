#!/usr/bin/env python3

import json

from hashlib import sha256
from pwn import remote, sys

from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes
from Crypto.Util.Padding import unpad


def main():
    host, port = sys.argv[1].split(':')
    io = remote(host, port)

    io.sendlineafter(b'> ', b'1')
    data = json.loads(io.recvline().decode())

    p = int(data['p'], 16)

    io.sendlineafter(b'> ', b'2')
    data = json.loads(io.recvline().decode())
    x1, y1 = int(data['x'], 16), int(data['y'], 16)

    io.sendlineafter(b'> ', b'2')
    data = json.loads(io.recvline().decode())
    x2, y2 = int(data['x'], 16), int(data['y'], 16)

    a = (y1 ** 2 - y2 ** 2 - x1 ** 3 + x2 ** 3) * pow(x1 - x2, -1, p) % p
    b = (y1 ** 2 - x1 ** 3 - a * x1) % p

    io.sendlineafter(b'> ', b'3')
    data = json.loads(io.recvline().decode())
    iv, enc = bytes.fromhex(data['iv']), bytes.fromhex(data['enc'])

    key = sha256(long_to_bytes(pow(a, b, p))).digest()[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    io.success(unpad(cipher.decrypt(enc), 16).decode())


if __name__ == '__main__':
    main()
