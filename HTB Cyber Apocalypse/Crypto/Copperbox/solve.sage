#!/usr/bin/env sage

p = 0x31337313373133731337313373133731337313373133731337313373133732ad
a = 0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef
b = 0xdeadc0dedeadc0dedeadc0dedeadc0dedeadc0dedeadc0dedeadc0dedeadc0de

trunc = 48

hint1 = 77759147870011250959067600299812670660963056658309113392093130
hint2 = 50608194198883881938583003429122755064581079722494357415324546


Y, Z = PolynomialRing(Zmod(p), 'Y, Z').gens()

A = [sum(a ** m for m in range(i + 1)) for i in range(4)]

H1 = hint1 << trunc
H2 = hint2 << trunc

HY = a * H1 + a * Y - 1
HZ = a * H2 + a * Z - 1

P = a ** 2 * HZ * ((H1 + Y) * A[1] - A[0]) - HY * ((H2 + Z) * A[3] - A[2])

load('coppersmith.sage')
y, z = small_roots(P, (2 ** trunc, 2 ** trunc))[0]
print(f'{y = }; {z = }')

h1 = H1 + y
h2 = H2 + z

x = b * (A[0] - A[1] * h1) * pow(a ** 2 * h1 - a, -1, p) % p
assert x == b * (A[2] - A[3] * h2) * pow(a ** 4 * h2 - a ** 3, -1, p) % p

print(bytes.fromhex(hex(x)[2:]))
