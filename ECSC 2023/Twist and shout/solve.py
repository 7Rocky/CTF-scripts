#!/usr/bin/env python3

from pwn import remote, sys
from sage.all import crt, discrete_log, EllipticCurve, factor, GF

q = 2 ** 128 - 159
a = 1
b = 1494

K = GF(q)
K2 = GF(q ** 2)

E = EllipticCurve(K, [a, b])
E2 = EllipticCurve(K2, [a, b])

P = E2.lift_x(K(1))
order = P.order()
factors = factor(order)


def dlog(G, nG):
    dlogs = []
    new_factors = []

    for p, e in factors:
        new_factors.append(p ** e)
        t = order // new_factors[-1]
        dlogs.append(discrete_log(t * nG, t * G, operation='+'))

    return crt(dlogs, new_factors)


host, port = sys.argv[1], sys.argv[2]
io = remote(host, port)

io.sendlineafter(b'x-coordinate: ', b'1')
dP = E2.lift_x(K2(int(io.recvline())))
io.close()

d = int(dlog(P, dP))
io.success('ECSC{' + bytes.fromhex(hex(d)[2:]).decode() + '}')
