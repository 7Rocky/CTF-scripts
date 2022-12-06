#!/usr/bin/env python3

from functools import reduce
from z3 import BitVec, Solver

x = [BitVec(f'x{i}', 8) for i in range(58)]
s = Solver()

a = [-43, 61, 58, 5, -4, -11, 64, -40, -43, 61, 62, -51, 46, 15, -49, -44, 47, 4, 6, -7, 47, 7, -59, 52, -15, 11, 7, 61, 0]
b = [6, 106, 10, 0, 119, 52, 51, 101, 0, 0, 15, 48, 116, 22, 10, 58, 125, 100, 102, 33]
c = [304, 357, 303, 320, 304, 307, 349, 305, 257, 337, 340, 309, 428, 270, 66]
d = [52, 52, 95, 95, 110, 49, 51, 51, 95, 110, 110, 53]

for i in range(0, 58, 2):
    s.add(reduce(lambda x, y: x - y, x[i : i + 2]) == a[i // 2])

for i in range(0, 58, 3):
    s.add(reduce(lambda x, y: x ^ y, x[i : i + 3]) == b[i // 3])

for i in range(0, 58, 4):
    s.add(reduce(lambda x, y: x + y, x[i : i + 4]) == c[i // 4])

for i in range(0, 58, 5):
    s.add(x[i] == d[i // 5])

for i in range(58):
    s.add(x[i] <= 0x7f)
    s.add(0x20 <= x[i])

s.check()
model = s.model()

flag = ''.join(chr(model[i].as_long()) for i in x)

print('HTB{' + flag + '}')
