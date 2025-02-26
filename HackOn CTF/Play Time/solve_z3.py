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


from z3 import BitVec, RotateLeft, sat, Solver


s = [BitVec(f's{i}', 64) for i in range(4)]


def z3_step():
    result = s[1]
    t = (s[1] << 17) & MASK64
    s[2] ^= s[0]
    s[3] ^= s[1]
    s[1] ^= s[2]
    s[0] ^= s[3]
    s[2] ^= t
    s[3] = RotateLeft(s[3], 45)
    return result


solver = Solver()

for e in rng_outputs:
    solver.add(z3_step() == e)

if solver.check() != sat:
    exit(1)

model = solver.model()

s0, s1, s2, s3 = [model[BitVec(f's{i}', 64)].as_long() for i in range(4)]
print([s0, s1, s2, s3])


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def otp():
    return (rng() << 128) | (rng() << 64) | rng()


rng = Xoshiro256estrellaestrella([s0, s1, s2, s3])

for i in range(5):
    assert otp() == eee[i]

print(xor(enc_flag, b''.join(otp().to_bytes(24, 'big') for _ in range(4))).decode())
