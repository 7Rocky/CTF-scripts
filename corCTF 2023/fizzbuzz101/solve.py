#!/usr/bin/env python3

from Crypto.Util.number import long_to_bytes
from pwn import process, remote, sys


def get_process():
    if len(sys.argv) == 1:
        return process(['python3', 'fizzbuzz101.py'])

    host, port = sys.argv[1], sys.argv[2]
    return remote(host, port)


def binary_search(left, right, reverse=False):
    while left < right - 1:
        mid = (left + right) // 2

        if oracle(mid) ^ reverse:
            right = mid
        else:
            left = mid

    return left, right


def oracle(x):
    io.sendlineafter(b'> ', str(pow(x, e, n) * ct % n).encode())
    return b'Buzz' not in io.recvline()


while True:
    io = get_process()
    io.recvuntil(b'n = ')
    n = int(io.recvline().decode())
    io.recvuntil(b'e = ')
    e = int(io.recvline().decode())
    io.recvuntil(b'ct = ')
    ct = int(io.recvline().decode())

    if not oracle(2):
        break

    io.close()

k = 1

while True:
    k *= 2
    if oracle(k):
        break

left, right = binary_search(k // 2, k)

prog = io.progress('Flag')

for i in range(1, 1000):
    left, right = binary_search(5 * left, 5 * right, reverse=True)
    prog.status(str(long_to_bytes(5 ** i * n // right)[16:-16]))
