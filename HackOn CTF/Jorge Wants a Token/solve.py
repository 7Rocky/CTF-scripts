#!/usr/bin/env python3

import json

from hashlib import sha256
from pwn import base64, process, remote, sys

from ecdsa.ecdsa import generator_384
from sage.all import crt, Matrix, QQ

from Crypto.Util.number import bytes_to_long, getPrime, inverse, long_to_bytes

from library import JWS


def get_process():
    if len(sys.argv) == 1:
        return process(['python3', 'administration.py'])

    host, port = sys.argv[1], sys.argv[2]
    return remote(host, port)


def base64_url_decode(data: bytes) -> bytes:
    res = len(data) % 4
    if res > 0:
        data += b'=' * (4 - res)
    return base64.urlsafe_b64decode(data)


def register(username: str, alg: str) -> str:
    io.sendlineafter(b'[*]Option: ', b'2')
    io.sendlineafter(b'Username: ', username.encode())
    io.sendlineafter(b'Alg: ', alg.encode())
    return io.recvline().decode().strip()


def get_private_key():
    h, r, s = [], [], []

    for _ in range(31):
        token = register('a', 'ESBLK')
        header, payload, signature = token.encode().split(b'.')
        r_i, s_i = map(bytes_to_long, base64_url_decode(signature).split(b'&&'))
        h.append(bytes_to_long(sha256(base64_url_decode(header) + b'.' + base64_url_decode(payload)).digest()))
        r.append(r_i)
        s.append(s_i)

    p = int(generator_384.order())
    a = list(map(lambda s_i, h_i: pow(s_i, -1, p) * h_i % p, s, h))
    t = list(map(lambda r_i, s_i: pow(s_i, -1, p) * r_i % p, r, s))

    X = 256 ** 46

    raw_matrix = []

    for i in range(len(a)):
        raw_matrix.append([0] * i + [p] + [0] * (len(a) - i + 1))

    raw_matrix.append(t + [X / p, 0])
    raw_matrix.append(a + [0, X])

    M = Matrix(QQ, raw_matrix)
    L = M.LLL()

    for row in L.rows():
        if row[-1] == X:
            k = list(map(int, row[:-2]))
            x = (s[0] * k[0] - h[0]) * pow(r[0], -1, p) % p
            io.info(f'Private key: {x}')
            return x


def dlog_mod_power_prime(g, g_x, p, e):
    """
    Discrete Logarithm modulo prime power
    - Calculate x, such that g_x = g^x mod p^e
    Implementation source: Discrete Logarithms and Factoring, Eric Bach
    https://www2.eecs.berkeley.edu/Pubs/TechRpts/1984/CSD-84-186.pdf
    """

    def theta(x, p, e):
        p_2e_1 = pow(p, 2 * e - 1)
        ret = pow(x, (p - 1) * pow(p, e - 1), p_2e_1) - 1 # we can use ^ 2*(p-1)p^(e-1)

        assert ret % (p ** e) == 0
        return ret // (p ** e)

    p_e_1 = p ** (e-1)
    theta_a = theta(g, p, 2)
    theta_b = theta(g_x, p, 2)
    x = (theta_b * inverse(theta_a, p_e_1)) % p_e_1
    return x

crt_r, crt_m = [], []

for _ in range(4):
    io = get_process()
    x = get_private_key()

    key = long_to_bytes(x)
    jws = JWS(key)
    dfh = getPrime(200)
    token = jws.encode(json.dumps({
        'iat': dfh + 1,
        'status': 'Rector',
        'dfh': dfh,
        'username': '7Rocky',
    }))

    io.sendlineafter(b'[*]Option: ', b'1')
    io.sendlineafter(b'Token, please: ', token.encode())
    io.recvuntil(b'Rector, this belongs to you: ')
    enc = int(io.recvline().decode())
    io.close()

    f = dlog_mod_power_prime(dfh + 1, enc, dfh, 2)
    assert pow(dfh + 1, f, dfh ** 2) == enc
    crt_r.append(f)
    crt_m.append(dfh)

io.success(long_to_bytes(crt(crt_r, crt_m)).decode())
