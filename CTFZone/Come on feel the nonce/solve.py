#!/usr/bin/env python3

import json

from hashlib import sha256
from sage.all import Matrix, QQ
from pwn import b64d, xor

from Crypto.Util.number import long_to_bytes


n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
p = n

h, r, s = [], [], []

with open('log.txt') as f:
    enc_flag = b64d(f.readline().split(' = ')[1].strip())

    while (line := f.readline()):
        h.append(int(line.split(' = ')[1]))
        r.append(int(f.readline().split(' = ')[1]))
        s.append(int(f.readline().split(' = ')[1]))

a = list(map(lambda s_i, h_i: pow(s_i, -1, p) * h_i % p, s, h))
t = list(map(lambda r_i, s_i: pow(s_i, -1, p) * r_i % p, r, s))

X = 2 ** 64

raw_matrix = []

for i in range(len(a)):
    raw_matrix.append([0] * i + [p] + [0] * (len(a) - i + 1))

raw_matrix.append(t + [X / p, 0])
raw_matrix.append(a + [    0, X])

M = Matrix(QQ, raw_matrix)
L = M.LLL()

for row in L.rows():
    if row[-1] == X:
        k = list(map(int, row[:-2]))
        x = (s[0] * k[0] - h[0]) * pow(r[0], -1, p) % p
        key = sha256(long_to_bytes(x)).digest()
        flag = xor(enc_flag, key)
        print(flag.decode())
