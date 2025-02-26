#!/usr/bin/env python3

from pwn import process, remote, sys


def get_process():
    if len(sys.argv) == 1:
        return process(['python3', 'chall.py'])

    host, port = sys.argv[1], sys.argv[2]
    return remote(host, port)


def get_var(name: str) -> int:
    io.recvuntil(f'{name} = '.encode())
    return int(io.recvline())


io = get_process()

q = get_var('q')
g = get_var('g')
h = get_var('h')
A = get_var('A')

for r in range(5):
    k = get_var('k')

    s1 = s2 = r
    T = pow(A, -k, q) * pow(g * h, r, q) % q
    assert pow(g, s1, q) * pow(h, s2, q) % q == T * pow(A, k, q) % q

    io.sendlineafter(b'>>> ', str(T).encode())
    io.sendlineafter(b'>>> ', str(s1).encode())
    io.sendlineafter(b'>>> ', str(s2).encode())

io.success(io.recvline().decode())
