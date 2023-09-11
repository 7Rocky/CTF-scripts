#!/usr/bin/env python3

from pwn import process, re, remote, sleep, sys
from multiprocessing import Pool

from sage.all import CRT, GF, PolynomialRing


def get_process():
    if len(sys.argv) == 1:
        return process(['python3', 'server.py'])

    host, port = sys.argv[1], sys.argv[2]
    return remote(host, port)


def callback(t):
    crt_remainders[t[0]] = t[1]


def get_secret_mod(p, all_shares):
    P = polys[p]
    possible = set()
    shares = next(all_shares)

    for sx in range(p):
        ret = P.lagrange_polynomial(enumerate([sx] + shares)).coefficients(sparse=False)

        if p - 1 not in ret[1:]:
            possible.add(sx)

    while len(possible) != 1:
        try:
            shares = next(all_shares)
        except StopIteration:
            break

        for sx in list(possible):
            ret = P.lagrange_polynomial(enumerate([sx] + shares)).coefficients(sparse=False)

            if p - 1 in ret[1:] and sx in possible:
                possible.remove(sx)

    return p, list(possible)[0]


primes = [107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293]

crt_remainders = {p: -1 for p in primes}
polys = {p: PolynomialRing(GF(p), 'x') for p in primes}
length = 9

io = get_process()
io.recv()

with Pool(processes=8) as pool:
    for p in primes[::-1]:
        io.send((f'{p}\n{p - 1}\n' * length).encode())
        sleep(.8)

        data = b''.join(io.recvuntil(b'share') for _ in range(length)) + io.recvline()
        io.recv()

        shares = map(eval, re.findall(r'shares = (.*?)\n', data.decode()))
        pool.apply_async(get_secret_mod, (p, shares), callback=callback)

    while -1 in crt_remainders.values():
        pass

primes, remainders = [], []

for p, r in crt_remainders.items():
    primes.append(p)
    remainders.append(r)

s = CRT(remainders, primes)

if 240 <= int(s).bit_length() <= 256:
    io.info(f'Secret: {s}')
    io.sendline(b'0')
    io.sendlineafter(b'n = ', b'0')
    io.sendlineafter(b'secret = ', str(s).encode())

    try:
        io.success(io.recv().decode())
    except EOFError:
        io.failure('FAIL')
else:
    io.failure('FAIL')
    exit()
