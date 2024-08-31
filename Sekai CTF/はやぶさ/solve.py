#!/usr/bin/env python3

from ast import literal_eval
from pwn import process, remote, sys

from sage.all import identity_matrix, Matrix, Mod, PolynomialRing, Zmod, ZZ

from falcon.ntrugen import ntru_solve
from falcon import falcon


def get_process():
    if len(sys.argv) == 1:
        return process(['python3', 'chall.py'])

    host, port = sys.argv[1], sys.argv[2]
    return remote(host, port, ssl=True)


q = 12 * 1024 + 1
n = 64

P = PolynomialRing(Zmod(q), names='x')
x = P.gens()[0]
R = P.quotient(x ** n + 1)

io = get_process()

io.recvuntil(b'h = ').decode()
h = R(literal_eval(io.recvlineS()))

M = Matrix(ZZ, 2 * n, 2 * n)

M[:n, :n] = identity_matrix(ZZ, n)
M[n:, n:] = q * identity_matrix(ZZ, n)
M[:n, n:] = Matrix(ZZ, [(h * R([0] * i + [1])).list() for i in range(n)])

L = M.BKZ(block_size=n // 2)
row = L[0]

center = lambda x: int(Mod(x, q).lift_centered())

f, g = R(list(row[:n])), R(list(row[n:]))
assert h == g * f.inverse()

f_list = list(map(center, f.list()))
g_list = list(map(center, g.list()))
F_list, G_list = ntru_solve(f_list, g_list)
F, G = R(F_list), R(G_list)
assert f * G - g * F == 0

sk = falcon.SecretKey(n, polys=(f_list, g_list, F_list, G_list))
sig = sk.sign(b'Can you break me')

io.sendlineafter(b'what is your sig? >', sig.hex().encode())
io.recvuntil(b'well done!!\n')
io.success(io.recvlineS())
