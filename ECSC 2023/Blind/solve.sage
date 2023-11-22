#!/usr/bin/env python3

import bcrypt
import hashlib
import operator

from ast import literal_eval
from tqdm import tqdm

from Crypto.Cipher import AES


def get_curve():
    # https://neuromancer.sk/std/other/Ed448
    p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    K = GF(p)
    a = K(0x01)
    d = K(0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffff6756)
    E = EllipticCurve(K, (K(-1/48) * (a^2 + 14*a*d + d^2),K(1/864) * (a + d) * (-a^2 + 34*a*d - d^2)))
    def to_weierstrass(x, y):
        return ((5*a + a*y - 5*d*y - d)/(12 - 12*y), (a + a*y - d*y -d)/(4*x - 4*x*y))
    def to_twistededwards(u, v):
        y = (5*a - 12*u - d)/(-12*u - a + 5*d)
        x = (a + a*y - d*y -d)/(4*v - 4*v*y)
        return (x, y)
    G = E(*to_weierstrass(K(0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa955555555555555555555555555555555555555555555555555555555), K(0xae05e9634ad7048db359d6205086c2b0036ed7a035884dd7b7e36d728ad8c4b80d6565833a2a3098bbbcb2bed1cda06bdaeafbcdea9386ed)))
    E.set_order(0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3 * 0x04)
    # This curve is a Weierstrass curve (SAGE does not support TwistedEdwards curves) birationally equivalent to the intended curve.
# You can use the to_weierstrass and to_twistededwards functions to convert the points.
    return E, G, to_weierstrass, to_twistededwards

q = 2^448 - 2^224 - 1
E, G, to_weierstrass, to_twistededwards = get_curve()
p = int(G.order())
k = 8*((len(bin(p)) - 2 + 7) // 8)
k2 = 128
k1 = 8*((7 + len(bin(q)) - 2)//8) - k2

def Hash(x, nin, n, div):
    assert nin % 8 == n % 8 == 0
    nin //= 8
    n //= 8
    assert len(x) == nin
    r = b""
    i = 0
    while len(r) < n:
        r += hashlib.sha256(x + b"||" + div + int(i).to_bytes(8, "big")).digest()
        i += 1
    return r[:n]

F1 = lambda x: Hash(x, k2, k1, b"1")
F2 = lambda x: Hash(x, k1, k2, b"2")
H = lambda x: Hash(x, k1+k2, k, b"H")

def xor(a, b):
    assert len(a) == len(b)
    return bytes(map(operator.xor, a, b))


def try_decrypt(k):
    key = bcrypt.kdf(k, b'ICC_CHALLENGE', 16, 31337)
    cipher = AES.new(key, AES.MODE_CTR, nonce=b'')
    return cipher.decrypt(ct)


with open('output.txt') as f:
    Y = E(*to_weierstrass(*literal_eval(f.readline().split(' = ')[1])))
    ct = bytes.fromhex(f.readline().split(' = ')[1])
    sigs = literal_eval(f.readline())

for r_hex, z in tqdm(sigs):
    r = int(r_hex, 16)
    c = int.from_bytes(H(bytes.fromhex(r_hex)), 'big')
    wG = int((z * G + c * Y)[0]).to_bytes((k1 + k2) // 8, 'big')
    _xor = xor(bytes.fromhex(r_hex), wG)
    f1 = _xor[:40]
    f2 = F2(f1)
    m = xor(_xor[40:], f2)

    if F1(m) == f1:
        print(try_decrypt(m).decode())
        break
