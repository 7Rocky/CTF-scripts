#!/usr/bin/env python3

from hashlib import sha512

from xorshiro256 import MASK64, Xoshiro256estrellaestrella


hhh = int(sha512(b"What is going on????").hexdigest(), 16)
www = int(sha512(b"-_-").hexdigest(), 16)

with open('output.txt') as f:
    output = [int(f.readline()) for _ in range(5)]
    enc_flag = bytes.fromhex(f.readline().split(': ')[1])

eee = [(o % (hhh * www)) // www for o in output]

rng_outputs = []

for e in eee:
    rng_outputs.append(Xoshiro256estrellaestrella.untemper((e >> 128) & MASK64))
    rng_outputs.append(Xoshiro256estrellaestrella.untemper((e >> 64) & MASK64))
    rng_outputs.append(Xoshiro256estrellaestrella.untemper(e & MASK64))


from sage.all import BooleanPolynomialRing, Sequence


n2b = lambda n: list(map(int, f'{n:064b}'))
b2n = lambda b: int(''.join(map(str, b)), 2)

s_bits = BooleanPolynomialRing(','.join(','.join(f's{k}_{i}' for i in range(64)) for k in range(4))).gens()

s0_bits = list(s_bits[0:64])
s1_bits = list(s_bits[64:128])
s2_bits = list(s_bits[128:192])
s3_bits = list(s_bits[192:256])

s = [s0_bits, s1_bits, s2_bits, s3_bits]


def step():
    global s
    s0, s1, s2, s3 = s
    result = s1
    t = s1[17:] + [0] * 17
    s2 = [s0_i + s2_i for s0_i, s2_i in zip(s0, s2)]
    s3 = [s1_i + s3_i for s1_i, s3_i in zip(s1, s3)]
    s1 = [s1_i + s2_i for s1_i, s2_i in zip(s1, s2)]
    s0 = [s0_i + s3_i for s0_i, s3_i in zip(s0, s3)]
    s2 = [t_i + s2_i for t_i, s2_i in zip(t, s2)]
    s3 = s3[45:] + s3[:45]
    s = [s0, s1, s2, s3]
    return result


eqs = []

for i, r in enumerate(rng_outputs):
    for r_i, sym_r_i in zip(n2b(r), step()):
        eqs.append(r_i + sym_r_i)

A, _ = Sequence(eqs).coefficients_monomials(sparse=False)
sol = A.right_kernel_matrix()[0]

s0 = b2n(sol[0:64])
s1 = b2n(sol[64:128])
s2 = b2n(sol[128:192])
s3 = b2n(sol[192:256])
print([s0, s1, s2, s3])


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def otp():
    return (rng() << 128) | (rng() << 64) | rng()


rng = Xoshiro256estrellaestrella([s0, s1, s2, s3])

for i in range(5):
    assert otp() == eee[i]

print(xor(enc_flag, b''.join(otp().to_bytes(24, 'big') for _ in range(4))).decode())
