#!/usr/bin/env python3

import hmac

from cryptod import derive_symkey
from proofofwork import solve_pow

from ecdsa import NIST256p
from pwn import process, remote, sys
from typing import Tuple

from ecdsa.ecdsa import ellipticcurve
from sage.all import EllipticCurve, GF, Matrix, QQ

from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Util.number import long_to_bytes

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.kbkdf import CounterLocation, KBKDFHMAC, Mode


p = 115792089210356248762697446949407573530086143415290314195533631308867097853951
a = -3
b = 41058363725152142129326129780047268409114441015993725554835256314039467401291

Fp = GF(p)
E = EllipticCurve(Fp, [a, b])

n = 115792089210356248762697446949407573529996955224135760342422259061068512044369
Gx = 48439561293906451759052585252797914202762949526041747995844080717082404635286
Gy = 36134250956749795798585127919587881956611106672985015071877198253568414405109

G = E(Gx, Gy)


def get_process():
    if len(sys.argv) == 1:
        return process(['python3', 'app copy.py'])

    host, port = sys.argv[1], sys.argv[2]
    return remote(host, port)


def sign(m: bytes) -> Tuple[int, int]:
    io.sendlineafter(b'Enter a message to sign: >', m)
    io.recvuntil(b'Signature ')
    r, s = map(lambda x: int(x, 16), io.recvline().decode().split('deadbeef'))
    return r, s


def decrypt_sym(ct: bytes, key: bytes, nonce: bytes, tag: bytes) -> bytes:
    return ChaCha20_Poly1305.new(key=key, nonce=nonce).decrypt_and_verify(ct, tag)


io = get_process()

io.recvuntil(b'Please provide a string that starts with ')
challenge = io.recvuntil(b' and whose sha256 hash starts with', drop=True).decode()
prefix = io.recvline().decode().strip()

result = solve_pow(challenge, prefix)

io.sendlineafter(b'POW: >', result.encode())

io.recvuntil(b'Here is the encrypted flag: ')
enc_data = bytes.fromhex(io.recvline().decode())

m0 = b'asdf0'
r0, s0 = sign(m0)
h0 = int(hmac.new(b'\0', m0, 'sha224').hexdigest(), 16)

m1 = b'asdf1'
r1, s1 = sign(m1)

for P in E.lift_x(Fp(r0), all=True):
    Q = pow(r0, -1, n) * (s0 * P - h0 * G)
    h1 = int(hmac.new(long_to_bytes(int(Q[0])), m1, 'sha224').hexdigest(), 16)

    if (pow(s1, -1, n) * (h1 * G + r1 * Q))[0] == r1:
        break
else:
    io.failure('Failed to find public ECDSA key')
    exit(1)

io.info(f'Public ECDSA key: {Q}')
h, r, s = [h0, h1], [r0, r1], [s0, s1]

for i in range(2, 9):
    mi = f'asdf{i}'.encode()
    ri, si = sign(mi)
    hi = hmac.new(long_to_bytes(int(Q[0]) * i), mi, 'sha224').hexdigest()
    h.append(int(hi, 16))
    r.append(ri)
    s.append(si)

p = n
a = list(map(lambda s_i, h_i: pow(s_i, -1, p) * h_i % p, s, h))
t = list(map(lambda r_i, s_i: pow(s_i, -1, p) * r_i % p, r, s))

X = 2 ** 225

raw_matrix = []

for i in range(len(a)):
    raw_matrix.append([0] * i + [p] + [0] * (len(a) - i + 1))

raw_matrix.append(t + [X / p, 0])
raw_matrix.append(a + [0, X])

M = Matrix(QQ, raw_matrix)
L = M.LLL()

enc_flag, R_bytes = enc_data.split(b'\xde\xad\xbe\xef')
R_mpz = ellipticcurve.Point.from_bytes(NIST256p.curve, R_bytes)
R = E(R_mpz.x(), R_mpz.y())
ct, tag, nonce = enc_flag[:-28], enc_flag[-28:-12], enc_flag[-12:]

for row in L.rows():
    if row[-1] == X:
        k = list(map(int, row[:-2]))
        x = (s[0] * k[0] - h[0]) * pow(r[0], -1, p) % p
        io.info(f'Private key: {x}')
        S = x * R
        key = derive_symkey(long_to_bytes(int(S[0])))

        try:
            io.success(f'Flag: {decrypt_sym(ct, key, nonce, tag).decode()}')
            exit(0)
        except ValueError:
            io.failure('MAC check failed')
            continue

exit(1)
