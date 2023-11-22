#!/usr/bin/env python3

from ast import literal_eval

from sage.all import GF, Matrix, vector


enc_data = []

with open('output.txt') as f:
    while (line := f.readline()):
        enc_data.append(literal_eval(line))


a_s = []
b_s = []

for i in range(7, len(enc_data), 8):
    for a, b in enc_data[i]:
        a_s.append(list(map(int, f'{int(a.hex(), 16):0256b}')))
        b_s.append(b)

s2 = Matrix(GF(2), a_s).solve_right(vector(GF(2), b_s)).list()

flag_bits = []

for enc in enc_data:
    for a, b in enc:
        a_s = list(map(int, f'{int(a.hex(), 16):0256b}'))
        if sum(a_i * s_i for a_i, s_i in zip(a_s, s2)) % 2 != b % 2:
            flag_bits.append(1)
            break
    else:
        flag_bits.append(0)

flag = []

for i in range(0, len(flag_bits), 8):
    flag.append(int(''.join(map(str, flag_bits[i:i+8]))[::-1], 2))

print(bytes(flag).decode())
