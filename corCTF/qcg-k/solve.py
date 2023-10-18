#!/usr/bin/env python3

from ast import literal_eval
from functools import cache
from hashlib import sha256

from sage.all import GF, PolynomialRing

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


def k_ij(i, j):
    return x * (r[i] / s[i] - r[j] / s[j]) + h[i] / s[i] - h[j] / s[j]


@cache
def dpoly(n, i, j):
    if i == 0:
        return k_ij(j + 1, j + 2) ** 2 - k_ij(j + 2, j + 3) * k_ij(j, j + 1)

    left = dpoly(n, i - 1, j)
    for m in range(1, i + 2):
        left *= k_ij(j + m, j + i + 2)

    right = dpoly(n, i - 1, j + 1)
    for m in range(1, i + 2):
        right *= k_ij(j, j + m)

    return left - right


h, r, s = [], [], []

q = 77897050769654696452572824710099972349639759246855689360228775736949644730457
Fq = GF(q)

with open('quotes.txt', 'rb') as quotes, open('qcgk_out.txt') as out:
    for m, r_s in zip(quotes, out):
        h.append(Fq(int(sha256(m.strip()).hexdigest(), 16)))
        r.append(Fq(literal_eval(r_s)[0]))
        s.append(Fq(literal_eval(r_s)[1]))

    ct = bytes.fromhex(out.readline())
    iv = bytes.fromhex(out.readline())

N = 18
x = PolynomialRing(Fq, 'x').gens()[0]
pol = dpoly(N - 4, N - 4, 0)
secret = pol.roots()[0][0]

key = sha256(str(secret).encode()).digest()
print(unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct), AES.block_size).decode())
