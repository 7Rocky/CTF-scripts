#!/usr/bin/env python3

from ast import literal_eval
from random import getrandbits, randbytes, randrange, setstate, shuffle

from pwn import process, remote, sys
from randcrack import RandCrack
from tqdm import trange


def get_process():
    if len(sys.argv) == 1:
        return process(['python3', 'server.py'])

    host, port = sys.argv[1], sys.argv[2]
    return remote(host, port, ssl=True)


sys.setrecursionlimit(1337 * 1337)

n = 1337
x = 1337  # Up to 1630 is OK

io = get_process()

io.sendlineafter(b'> ', b'1')
io.recvuntil(b's: ')
s = literal_eval(io.recvline().decode())

io.sendlineafter(b'> ', b'2')
io.sendlineafter(b'x: ', str(x).encode())
io.recvuntil(b'y: ')
y = literal_eval(io.recvline().decode())


def backtracking(i, v):
    if i == n:
        return v == 0

    r = v % x

    for c in m[r]:
        m[r].remove(c)
        a[i] = c

        if backtracking(i + 1, (v - c) // x):
            return True

        m[r].add(c)


a = [1337] * n
m = {i: set() for i in range(x)}

for r in trange(n):
    si, s[r] = s[r], 1337

    for b in s:
        m[b % x].add(b)

    if backtracking(0, y) and sorted(a) == sorted(s):
        s[r] = si
        break

    s[r] = si
else:
    exit(1)

index = a.index(1337)
a[index] = list(set(s).difference(set(a) - {1337}))[0]

rc = RandCrack()
list(map(rc.submit, a[:624]))

setstate((3, (*[int(''.join(map(str, rc.mt[i])), 2) for i in range(len(rc.mt))], 0), None))

assert all(a_i == getrandbits(32) for a_i in a[624:])

shuffled = a.copy()
shuffle(shuffled)
assert shuffled == s

assert index == randrange(0, n)

io.sendlineafter(b'> ', b'3')
io.sendlineafter(b'k: ', randbytes(1337).hex().encode())
io.success(io.recvline().decode())
