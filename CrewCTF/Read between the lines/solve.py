#!/usr/bin/env python3

from sage.all import Matrix

with open('output.txt') as f:
    exec(f.read())

N = 100
cts = [pow(m + 0x1337, e, n) for m in range(N)]

R = 2 ** 1024
M = Matrix([
    [*cts, n, -c],
    *[[0] * i + [1] + [0] * (len(cts) - i + 1) for i in range(len(cts))],
    [0] * len(cts) + [0, R]
])

L = M.T.LLL()
assert L[-1][0] == 0 and L[-1][-1] == R
res = L[-1][1:-1]

flag = [v for v in res if v != 0]
print(bytes(flag).decode())
