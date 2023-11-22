#!/usr/bin/env python3

from ast import literal_eval
from random import Random
from sympy.ntheory.modular import crt
from sympy.ntheory.primetest import isprime


def get_prime(seed):
    p = 1
    r = Random()
    r.seed(seed)
    while not isprime(p):
        p = r._randbelow(2**256) | 1
    return p


with open('output.txt') as f:
    n, c = map(literal_eval, f.read().split())

factors = []

for seed in range(2 ** 128):
    p = get_prime(seed)
    if n % p == 0:
        factors.append(p)
        n //= p
    if len(factors) == 5:
        break

e = 0x10001
c_i = []

for p_i in factors:
    d_i = pow(e, -1, p_i - 1)
    c_i.append(pow(c, d_i, p_i))

print(bytes.fromhex(hex(crt(factors, c_i)[0])[2:]).decode())
