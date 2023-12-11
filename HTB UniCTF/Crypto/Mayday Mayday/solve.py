#!/usr/bin/env python3

from sage.all import divisors, PolynomialRing, Zmod


with open('output.txt') as f:
    n = int(f.readline().split(' = ')[1], 16)
    e = int(f.readline().split(' = ')[1], 16)
    c = int(f.readline().split(' = ')[1], 16)
    dp_hint = int(f.readline().split(' = ')[1], 16) << 512
    dq_hint = int(f.readline().split(' = ')[1], 16) << 512

kp_kq = (e * dp_hint - 1) * (e * dq_hint - 1) // n + 1

divs = divisors(kp_kq)

possible_kp_kq = set()

for div in divs:
    kp, kq = div, kp_kq // div
    pH = (e * (dp_hint + 2 ** 512) - 1 + kp) // kp
    pL = (e * (dp_hint + 0) - 1 + kp) // kp
    qH = (e * (dq_hint + 2 ** 512) - 1 + kq) // kq
    qL = (e * (dq_hint + 0) - 1 + kq) // kq

    if all(int(x).bit_length() == 1024 for x in [pH, pL, qH, qL]):
        possible_kp_kq.add((kp, kq))

x = PolynomialRing(Zmod(n), 'x').gens()[0]

for kp, kq in possible_kp_kq:
    d_kp = int((pow(e, -1, kp) - dp_hint) % kp)
    P = (e * (dp_hint + kp * x + d_kp) - 1 + kp).monic()
    roots = P.small_roots(beta=0.5)

    if roots and roots[0] != n:
        p = int((e * (dp_hint + kp * roots[0] + d_kp) - 1 + kp) // kp)
        assert n % p == 0
        q = n // p
        d = pow(e, -1, (p - 1) * (q - 1))
        m = pow(c, d, n)
        print(bytes.fromhex(hex(m)[2:]).decode())
        break
