#!/usr/bin/env python3

from sage.all import EllipticCurve, GF
from Crypto.PublicKey import ECC

p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
a = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b

E = EllipticCurve(GF(p), [a, b])
G = E(0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296, 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)

dk = 0xdfb3ccae87f774d0a97aec2c494ba96da521dfffbbf9e0e7447fb7
Q = E(0x7bd81aa93dd37b54e1d39c04f4db67dc65e6b9521107dd11c80e871ef3bd614b, 0x1a17ad5a51b6cc7517618881702a23fe8cc6e4bb06af3a5c5c4dc7b84ccf1108)

table_points = {}
H = (256 ** 2 * dk) * G

for i in range(2 ** 16):
    table_points[H.xy()] = i
    H += G

P = (256 ** 29) * G
K = Q

for j in range(2 ** 24):
    if (i := table_points.get(K.xy())):
        d = (256 ** 29) * j + (256 ** 2) * dk + i
        assert Q == d * G
        with open('id_ecdsa', 'w') as f:
            f.write(ECC.EccKey(curve='NIST P-256', d=d).export_key(format='PEM'))
        break
    K -= P
