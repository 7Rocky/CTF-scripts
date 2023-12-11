#!/usr/bin/env sage

from ast import literal_eval
from fractions import Fraction
from hashlib import sha256


def magic(ar):
    a, b, c = ar
    return Fraction(a, b) + Fraction(b, c) + Fraction(c, a)


with open('output.txt') as fp:
    pub = literal_eval(fp.readline().split(' = ')[1])
    mix = literal_eval(fp.readline().split(' = ')[1])

P, Q, R = pub
f = magic(pub)
N, D = f.numerator, f.denominator
nb = (f.denominator.bit_length() + 7) // 8

r = gcd(gcd(Q, D), gcd(R, D))
p = gcd(Q, D) // r
q = gcd(R, D) // r

assert is_prime(p) and int(p).bit_length() <= 1024
assert is_prime(q) and int(q).bit_length() <= 1024
assert is_prime(r) and int(r).bit_length() <= 1024

assert p^2 * r + q^2 * p + r^2 * q == N
assert p * q * r == D

d = pow(N, -1, (p - 1) * (q - 1) * (r - 1))
s1_p_s2 = pow(mix[0], d, D)
s1_m_s2 = pow(mix[1], d, D)

s1 = (s1_p_s2 + s1_m_s2) * pow(2, -1, D) % D
s2 = (s1_p_s2 - s1_m_s2) * pow(2, -1, D) % D

R = pow(s1, N, D)
c = pow(s2, N, D)
assert c.bit_length() <= nb

load('coppersmith.sage')

m, h = PolynomialRing(Zmod(D), 'm, h').gens()
PP = m^2 * c + m * h^2 + h * c^2 - c * m * h * R
roots = small_roots(PP, bounds=(2 ** 512, 2 ** 256))

for root in roots:
    if root != (0, 0):
        m, h = root
        assert int(sha256(int(m).to_bytes(nb, 'big')).hexdigest(), 16) == h
        print(bytes.fromhex(hex(m)[2:]).decode())
