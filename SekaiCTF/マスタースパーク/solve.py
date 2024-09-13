#!/usr/bin/env python3

from itertools import product
from pwn import process, remote, sys

from Crypto.Util.number import isPrime

from sage.all import crt, EllipticCurve, factor, GF, prod, random_prime


def get_process():
    if len(sys.argv) == 1:
        return process(['sage', 'challenge.sage'])

    host, port = sys.argv[1], sys.argv[2]
    io = remote(host, port, ssl=True)
    io.recvuntil(b'proof of work: ')
    cmd = io.recvlineS().strip()
    p = process(['bash', '-c', cmd])
    solution = p.recvline().strip()
    p.close()
    io.sendlineafter(b'solution: ', solution)
    return io


choice = set()


def check(p):
    assert isPrime(p)
    assert p.bit_length() <= 96
    assert ((p + 1) // 4) % 2 == 1
    prime_list = []
    cnt = 0

    for p, i in factor((p + 1) // 4):
        assert not p in choice
        if i > 1:
            cnt += 1
            choice.add(p)
            assert int(p).bit_length() <= 32
        else:
            prime_list.append(p)
            choice.add(p)

    assert all([int(p).bit_length() <= 16 for p in prime_list])
    assert cnt == 1

    return prime_list


def gen_prime():
    global choice
    prev_choice = set(choice)

    while True:
        p = 4 * prod(random_prime(2 ** 8) for _ in range(4)) * random_prime(2 ** 14) ** 2 - 1
        try:
            check(p)
            return p
        except AssertionError:
            choice = set(prev_choice)
            pass


io = get_process()

dlogs, mods = [], []

for _ in range(8):
    p = gen_prime()
    Fp = GF(p)
    Fp2 = GF(p ** 2, modulus=[1, 0, 1], names='j')
    j = Fp2.gens()[0]

    io.sendlineafter(b'input your prime number or secret > ', str(p).encode())
    io.recvuntil(b'(')
    Px = j * int(io.recvuntil(b'*j + ', drop=True).decode()) + int(io.recvuntil(b', ', drop=True).decode())
    Py = j * int(io.recvuntil(b'*j + ', drop=True).decode()) + int(io.recvuntil(b')', drop=True).decode())
    io.recvuntil(b'(')
    Qx = j * int(io.recvuntil(b'*j + ', drop=True).decode()) + int(io.recvuntil(b', ', drop=True).decode())
    Qy = j * int(io.recvuntil(b'*j + ', drop=True).decode()) + int(io.recvuntil(b')', drop=True).decode())

    A = (Py ** 2 - Px ** 3 - Px) / (Px ** 2)
    Eab = EllipticCurve(Fp2, [0, A, 0, 1, 0])

    P = Eab(Px, Py)
    Q = Eab(Qx, Qy)

    dlogs.append(Q.log(P))
    mods.append(P.order())


for signs in product((-1, 1), repeat=len(dlogs)):
    try:
        secret = crt([s * d for s, d in zip(signs, dlogs)], mods)

        if secret.bit_length() != 256:
            continue

        io.info(f'Testing {secret = }')
        io.sendlineafter(b'input your prime number or secret > ', str(secret).encode())

        if 'not flag T_T' not in (msg := io.recvlineS()):
            io.success(msg)
            break
    except ValueError:
        pass
