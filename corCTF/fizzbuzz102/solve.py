#!/usr/bin/env python3

from pwn import process, remote, sys
from Crypto.Util.number import long_to_bytes


def get_process():
    if len(sys.argv) == 1:
        return process(['python3', 'fizzbuzz102.py'])

    host, port = sys.argv[1], sys.argv[2]
    return remote(host, port)


def binary_search(left, right, reverse=False, ct=1):
    while left < right - 1:
        mid = (left + right) // 2
        io.sendlineafter(b'> ', str(pow(mid, e, n) * ct % n).encode())

        if (b'Buzz' not in io.recvline()) ^ reverse:
            right = mid
        else:
            left = mid

    return left, right


while True:
    io = get_process()
    io.recvuntil(b'n = ')
    n = int(io.recvline().decode())
    io.recvuntil(b'e = ')
    e = int(io.recvline().decode())
    io.recvuntil(b'ct = ')
    ct = int(io.recvline().decode())

    io.sendlineafter(b'> ', b'0')

    if b'Buzz' not in io.recvline():
        io.close()
        continue

    io.sendlineafter(b'> ', b'1')

    if b'Buzz' not in io.recvline():
        io.close()
        continue

    break

k = 1

while True:
    k *= 5
    io.sendlineafter(b'> ', str(pow(k, e, n)).encode())

    if b'Buzz' not in io.recvline():
        break

left, right = k // 5, k
left, right = binary_search(left, right)

prog = io.progress('a')
a = n // right

for i in range(1, 500):
    prog.status(str(a))
    left, right = binary_search(5 * left - 5, 5 * right + 5, reverse=True)
    a = 5 ** i * n // right

if a % 5 != 0:
    a += 5 - (a % 5)

prog.success(str(a))

ct = pow(a, -e, n) * ct % n

k = 1

while True:
    k *= 2
    io.sendlineafter(b'> ', str(pow(k, e, n) * ct % n).encode())

    if b'Buzz' not in io.recvline():
        break

left, right = k // 2, k
left, right = binary_search(left, right, ct=ct)

prog = io.progress('Flag')
flag = long_to_bytes(n // right)

for i in range(1, 500):
    left, right = binary_search(5 * left, 5 * right, reverse=True, ct=ct)
    flag = long_to_bytes(5 ** i * n // right)
    prog.status(str(flag[16:-16]))

if b'corctf{' not in flag:
    prog.failure(str(flag[16:-16]))
    exit(1)

prog.success(str(flag[16:-16]))
