#!/usr/bin/env python3

import json

from math import gcd

from pwn import process, remote, sys, xor

from Crypto.Util.Padding import unpad


def get_process():
    if len(sys.argv) == 1:
        return process(['python3', 'chall.py'])
    
    host, port = sys.argv[1], sys.argv[2]
    return remote(host, port)


io = get_process()

io.recvuntil(b'n = ')
n = int(io.recvline())

io.sendlineafter(b'>>> ', b'1')
io.sendlineafter(b'Message: ', (b'\0' * 31 + b'\x01').hex().encode())
kp_minus_1 = int(json.loads(io.recvline().decode()).get('blocks', [])[0], 16)
p = gcd(kp_minus_1 + 1, n)

assert p.bit_length() == 256
io.info(f'{p = }')
q = n // p
d = pow(0x10001, -1, (p - 1) * (q - 1))

io.sendlineafter(b'>>> ', b'2')
blocks = json.loads(io.recvline().decode()).get('blocks', [])

flag = []
prev_block = p.to_bytes(32, 'big')

for b in blocks:
    m = pow(int(b, 16), d, n)
    flag.append(xor(m.to_bytes(32, 'big'), prev_block)[:32])
    prev_block = bytes.fromhex(b)

io.success(unpad(b''.join(flag), 32).decode())
